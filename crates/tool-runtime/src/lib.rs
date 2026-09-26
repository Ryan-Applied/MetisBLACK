//! All live I/O crosses this boundary; shell execution requires explicit expert overrides.
use anyhow::{anyhow, ensure, Context, Result};
use domain::{
    ApiProbeMethod, ApiRequestProvenance, ApiSchemaObservation, AuthorizationProvenance, Control,
    JsonBodyClassification, JsonPropertyShape, JsonShape, ObservationKind, OpenRedirectObservation,
    Receipt, ToolAction, ToolOutput, API_SCHEMA_OBSERVATION_SCHEMA_VERSION,
    OPEN_REDIRECT_OBSERVATION_SCHEMA_VERSION,
};
use evidence::EvidenceStore;
use policy::Policy;
use serde_json::json;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use storage::{hash, Redactor};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
    time::{sleep, timeout, Instant},
};

fn normalize_media_type(raw: &str) -> Option<String> {
    let media_type = raw.split(';').next()?.trim().to_ascii_lowercase();
    (!media_type.is_empty()
        && media_type.len() <= 127
        && media_type.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'/' | b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'*'
                )
        }))
    .then_some(media_type)
}

fn canonical_api_addresses(addrs: &[SocketAddr]) -> Result<Vec<String>> {
    let mut canonical = addrs.iter().map(ToString::to_string).collect::<Vec<_>>();
    canonical.sort();
    canonical.dedup();
    ensure!(
        canonical.len() <= 64,
        "API schema resolved-address count exceeds the hard ceiling"
    );
    Ok(canonical)
}

fn json_shape(
    value: &serde_json::Value,
    remaining: &mut u32,
    depth: u16,
    max_depth: u16,
    max_properties: u32,
    max_array_items: u32,
) -> Option<JsonShape> {
    if *remaining == 0 || depth > max_depth {
        return None;
    }
    *remaining -= 1;
    match value {
        serde_json::Value::Null => Some(JsonShape::Null),
        serde_json::Value::Bool(_) => Some(JsonShape::Boolean),
        serde_json::Value::Number(number) => Some(if number.is_i64() || number.is_u64() {
            JsonShape::Integer
        } else {
            JsonShape::Number
        }),
        serde_json::Value::String(_) => Some(JsonShape::String),
        serde_json::Value::Array(values) => {
            if values.len() > usize::try_from(max_array_items).ok()? {
                return None;
            }
            let mut elements = Vec::with_capacity(values.len().min(*remaining as usize));
            for value in values {
                elements.push(json_shape(
                    value,
                    remaining,
                    depth.saturating_add(1),
                    max_depth,
                    max_properties,
                    max_array_items,
                )?);
            }
            Some(JsonShape::Array { elements })
        }
        serde_json::Value::Object(values) => {
            if values.len() > usize::try_from(max_properties).ok()?
                || values.keys().any(|key| key.len() > 4096)
            {
                return None;
            }
            let mut properties = Vec::with_capacity(values.len().min(*remaining as usize));
            for (key, value) in values {
                properties.push(JsonPropertyShape {
                    name: key.clone(),
                    shape: json_shape(
                        value,
                        remaining,
                        depth.saturating_add(1),
                        max_depth,
                        max_properties,
                        max_array_items,
                    )?,
                });
            }
            properties.sort_by(|left, right| left.name.cmp(&right.name));
            Some(JsonShape::Object { properties })
        }
    }
}

fn classify_json_shape(
    bytes: &[u8],
    max_shape_nodes: u32,
    max_shape_depth: u16,
    max_properties: u32,
    max_array_items: u32,
) -> Result<(JsonBodyClassification, Option<JsonShape>, u32, bool)> {
    if bytes.is_empty() {
        return Ok((JsonBodyClassification::Empty, None, 0, false));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok((JsonBodyClassification::InvalidUtf8, None, 0, false));
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok((JsonBodyClassification::InvalidJson, None, 0, false));
    };
    let mut remaining = max_shape_nodes;
    let Some(shape) = json_shape(
        &value,
        &mut remaining,
        0,
        max_shape_depth,
        max_properties,
        max_array_items,
    ) else {
        return Ok((JsonBodyClassification::ValidJson, None, 0, true));
    };
    let count = max_shape_nodes - remaining;
    Ok((JsonBodyClassification::ValidJson, Some(shape), count, false))
}

/// The generated credential is retained only after a successful account response.
/// Dropping the HTTP future on timeout/cancellation also invalidates the secret.
struct PendingAccountSecret {
    vault: Arc<storage::Vault>,
    reference: domain::SecretRef,
    audit_path: std::path::PathBuf,
    audit: serde_json::Value,
    armed: bool,
}
impl PendingAccountSecret {
    fn finish(mut self, retain: bool, outcome: &str, status: Option<u64>) -> Result<()> {
        self.audit["outcome"] = json!(outcome);
        self.audit["http_status"] = json!(status);
        if !retain {
            self.vault.forget(&self.reference)?;
            self.armed = false;
        }
        self.audit["secret_retained"] = json!(retain);
        self.audit["local_cleanup"] = json!(if retain {
            "retained_for_account_cleanup"
        } else {
            "generated_secret_deleted"
        });
        self.audit["updated_ms"] = json!(domain::now_ms());
        storage::write_json(&self.audit_path, &self.audit)?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for PendingAccountSecret {
    fn drop(&mut self) {
        if self.armed {
            let removed = self.vault.forget(&self.reference).is_ok();
            if self.audit["outcome"] == "pending" {
                self.audit["outcome"] = json!("interrupted_remote_state_unknown");
            }
            self.audit["secret_retained"] = json!(!removed);
            self.audit["local_cleanup"] = json!(if removed {
                "generated_secret_deleted"
            } else {
                "cleanup_failed_operator_action_required"
            });
            self.audit["updated_ms"] = json!(domain::now_ms());
            let _ = storage::write_json(&self.audit_path, &self.audit);
        }
    }
}

#[derive(Clone)]
pub struct Runtime {
    pub policy: Policy,
    pub evidence: EvidenceStore,
    pub cancelled: Arc<AtomicBool>,
    next_request: Arc<Mutex<Instant>>,
    redactor: Redactor,
    permits: Arc<Semaphore>,
    vault: Option<Arc<storage::Vault>>,
    journal: Option<std::path::PathBuf>,
    journal_lock: Arc<Mutex<()>>,
    authorized: bool,
}
impl Runtime {
    pub fn new(policy: Policy, evidence: EvidenceStore, redactor: Redactor) -> Self {
        let permits = Arc::new(Semaphore::new(policy.scope().max_concurrency.max(1)));
        Self {
            policy,
            evidence,
            cancelled: Arc::new(AtomicBool::new(false)),
            next_request: Arc::new(Mutex::new(Instant::now())),
            redactor,
            permits,
            vault: None,
            journal: None,
            journal_lock: Arc::new(Mutex::new(())),
            authorized: false,
        }
    }
    pub fn attach_vault(&mut self, path: &std::path::Path) -> Result<()> {
        self.vault = Some(Arc::new(storage::Vault::open(path)?));
        self.journal = path.parent().map(|p| p.join("usage.json"));
        Ok(())
    }
    pub fn authorize(&mut self, authorized: bool) {
        self.authorized = authorized;
    }
    async fn persist_usage(&self) -> Result<()> {
        if let Some(path) = &self.journal {
            let _guard = self.journal_lock.lock().await;
            let u = self.policy.usage();
            storage::write_json(
                path,
                &json!({"requests":u.requests,"state_changes":u.state_changes,"accounts":u.accounts}),
            )?;
        }
        Ok(())
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    fn check_cancelled(&self) -> Result<()> {
        ensure!(!self.cancelled.load(Ordering::SeqCst), "run cancelled");
        Ok(())
    }
    async fn slot(&self) -> Result<()> {
        self.slot_with_impact(false, false).await
    }
    async fn slot_with_impact(&self, state_change: bool, account: bool) -> Result<()> {
        self.check_cancelled()?;
        self.policy.reserve(state_change, account)?;
        self.persist_usage().await?;
        if self.policy.bypasses(Control::RateLimit) {
            return Ok(());
        }
        let mut next = self.next_request.lock().await;
        let now = Instant::now();
        if *next > now {
            sleep(*next - now).await;
        }
        *next = Instant::now()
            + Duration::from_secs_f64(1.0 / f64::from(self.policy.scope().requests_per_second));
        self.check_cancelled()
    }
    pub async fn execute(&self, actor: &str, action: ToolAction) -> Result<Receipt> {
        self.check_cancelled()?;
        let _permit = if self.policy.bypasses(Control::Concurrency) {
            None
        } else {
            Some(
                self.permits
                    .acquire()
                    .await
                    .context("concurrency limiter closed")?,
            )
        };
        let operation = async {
            if self.policy.bypasses(Control::Timeouts) {
                self.perform(actor, &action).await
            } else {
                match timeout(
                    Duration::from_millis(self.policy.scope().tool_timeout_ms),
                    self.perform(actor, &action),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("tool timeout")),
                }
            }
        };
        let result = tokio::select! {
         result=operation=>result,
         _=async {loop {if self.cancelled.load(Ordering::SeqCst){break;}sleep(Duration::from_millis(50)).await;}}=>Err(anyhow!("run cancelled")),
        };
        let mut output = match result {
            Ok((data, truncated)) => {
                let successful = !matches!(action, ToolAction::CreateAccount { .. })
                    || data["status"]
                        .as_u64()
                        .is_some_and(|s| (200..300).contains(&s));
                ToolOutput {
                    action,
                    successful,
                    data,
                    truncated,
                }
            }
            Err(e) => ToolOutput {
                action,
                successful: false,
                data: json!({"error":self.redactor.text(&e.to_string())}),
                truncated: false,
            },
        };
        // Strict typed observations carry authorization in their own schema.
        // Do not append an untyped field that would make deny_unknown_fields
        // replay fail.
        if !matches!(output.action, ToolAction::ApiSchemaProbe { .. }) {
            output.data["authorization_provenance"] = json!({"authorized":self.authorized,"explicit_override":self.policy.bypasses(Control::Authorization)});
        }
        self.evidence
            .capture_with_override(actor, output, self.policy.overrides())
    }
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.resolve_with_policy(&self.policy, host, port).await
    }
    async fn resolve_with_policy(
        &self,
        policy: &Policy,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>> {
        policy.check_host(host, Some(port))?;
        let addresses = if policy.bypasses(Control::Timeouts) {
            tokio::net::lookup_host((host, port)).await?
        } else {
            timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host, port)),
            )
            .await??
        };
        let addrs: Vec<_> = addresses.collect();
        ensure!(
            !addrs.is_empty() && (policy.bypasses(Control::DataSampling) || addrs.len() <= 64),
            "invalid DNS response size"
        );
        for addr in &addrs {
            policy.check_ip(host, addr.ip())?;
        }
        Ok(addrs)
    }
    async fn perform(&self, actor: &str, action: &ToolAction) -> Result<(serde_json::Value, bool)> {
        ensure!(
            matches!(action, ToolAction::SourceRead { .. })
                || self.authorized
                || self.policy.bypasses(Control::Authorization),
            "active tool execution requires authorization or an explicit authorization override"
        );
        self.policy.check_action(action)?;
        match action {
            ToolAction::HttpGet { url } => self.http_get(url).await,
            ToolAction::WebDiscoveryFetch {
                url,
                allowed_origins,
                max_response_bytes,
                ..
            } => {
                self.web_discovery_fetch(url, allowed_origins, *max_response_bytes)
                    .await
            }
            ToolAction::OpenRedirectProbe {
                endpoint,
                parameter,
                canary,
            } => self.open_redirect_probe(endpoint, parameter, canary).await,
            ToolAction::ApiSchemaProbe {
                plan_hash,
                contract_hash,
                probe_id,
                method,
                url,
                allowed_origins,
                max_response_bytes,
                max_shape_nodes,
                max_shape_depth,
                max_properties,
                max_array_items,
            } => {
                self.api_schema_probe(
                    plan_hash,
                    contract_hash,
                    probe_id,
                    *method,
                    url,
                    allowed_origins,
                    *max_response_bytes,
                    *max_shape_nodes,
                    *max_shape_depth,
                    *max_properties,
                    *max_array_items,
                )
                .await
            }
            ToolAction::HttpRequest { url, method, body } => {
                self.http_request(url, method, body.as_ref(), false).await
            }
            ToolAction::AiPrompt { url, prompt } => {
                let body = json!({"messages":[{"role":"user","content":prompt}]});
                self.http_request(url, "POST", Some(&body), false).await
            }
            ToolAction::CreateAccount { url, username } => {
                ensure!(
                    !username.trim().is_empty() && username.len() <= 200,
                    "invalid test-account username"
                );
                let vault = self
                    .vault
                    .as_ref()
                    .context("account creation requires configured vault")?;
                let password = storage::random_id("Nrsplt-test")?;
                let reference = vault.put(&password)?;
                let audit_path = self
                    .journal
                    .as_ref()
                    .and_then(|p| p.parent())
                    .context("account creation requires audit directory")?
                    .join("account-attempts")
                    .join(format!("{}.json", reference.0));
                let pending = PendingAccountSecret {
                    vault: vault.clone(), reference: reference.clone(), audit_path,
                    audit: self.redactor.sanitize(&json!({"username":username,"target":url,"actor":actor,"secret_ref":reference,"outcome":"pending","secret_retained":true,"created_ms":domain::now_ms(),"expert_override":self.policy.overrides(),"disabled_controls":self.policy.overrides().disabled_controls()}))?,
                    armed: true,
                };
                storage::write_json(&pending.audit_path, &pending.audit)?;
                let body = json!({"username":username,"password":password});
                let result = self.http_request(url, "POST", Some(&body), true).await;
                match result {
                    Ok((mut data, truncated)) => {
                        let mut redact = self.redactor.clone();
                        redact.register(&password);
                        redact.value(&mut data);
                        let status = data["status"].as_u64();
                        let created = status.is_some_and(|s| (200..300).contains(&s));
                        pending.finish(
                            created,
                            if created { "created" } else { "rejected_http" },
                            status,
                        )?;
                        data["account_creation"] = json!({"created":created,"secret_retained":created,"local_cleanup":if created{"retained_for_account_cleanup"}else{"generated_secret_deleted"},"audit_id":reference.0});
                        if created {
                            data["test_identity"] =
                                json!({"username":username,"secret_ref":reference});
                        }
                        Ok((data, truncated))
                    }
                    Err(e) => {
                        pending.finish(false, "transport_failure", None)?;
                        Err(e)
                    }
                }
            }
            ToolAction::SourceRead {
                path,
                start_line,
                end_line,
            } => {
                self.slot().await?;
                let path = self.policy.check_path(path)?;
                ensure!(
                    self.policy.bypasses(Control::DataSampling)
                        || std::fs::metadata(&path)?.len()
                            <= self.policy.scope().max_response_bytes as u64,
                    "source file exceeds byte budget"
                );
                let raw = tokio::fs::read(&path).await?;
                let source_hash = hash(&raw);
                let text = std::str::from_utf8(&raw)?;
                let lines: Vec<_> = text.lines().collect();
                ensure!(
                    *start_line <= lines.len().max(1),
                    "source start line out of range"
                );
                let end = (*end_line).min(lines.len());
                let content = lines
                    .iter()
                    .skip(start_line - 1)
                    .take(end.saturating_sub(start_line - 1))
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok((
                    json!({"path":path,"start_line":start_line,"end_line":end,"total_lines":lines.len(),"source_hash":source_hash,"content":content}),
                    end < lines.len(),
                ))
            }
            ToolAction::DnsResolve { host } => {
                self.slot().await?;
                let port = self
                    .policy
                    .scope()
                    .network
                    .iter()
                    .find(|r| r.host == *host)
                    .and_then(|r| r.ports.first())
                    .copied()
                    .unwrap_or(443);
                let addrs = self.resolve(host, port).await?;
                Ok((
                    json!({"host":host,"addresses":addrs.iter().map(|a|a.ip().to_string()).collect::<Vec<_>>()}),
                    false,
                ))
            }
            ToolAction::TcpConnect { host, port } => {
                self.slot().await?;
                let addrs = self.resolve(host, *port).await?;
                let mut connected = None;
                for addr in addrs {
                    let connection = if self.policy.bypasses(Control::Timeouts) {
                        tokio::net::TcpStream::connect(addr).await
                    } else {
                        timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                            .await
                            .map_err(std::io::Error::other)
                            .and_then(|r| r)
                    };
                    if let Ok(stream) = connection {
                        connected = Some((stream, addr));
                        break;
                    }
                }
                let Some((stream, addr)) = connected else {
                    return Ok((json!({"host":host,"port":port,"open":false}), false));
                };
                let cap = if self.policy.bypasses(Control::DataSampling) {
                    usize::MAX
                } else {
                    1024
                };
                let mut bytes = Vec::new();
                let read_banner = async { stream.take(cap as u64).read_to_end(&mut bytes).await };
                if self.policy.bypasses(Control::Timeouts) {
                    let _ = read_banner.await;
                } else {
                    let _ = timeout(Duration::from_millis(250), read_banner).await;
                }
                Ok((
                    json!({"host":host,"port":port,"open":true,"address":addr.to_string(),"banner":String::from_utf8_lossy(&bytes)}),
                    bytes.len() == cap,
                ))
            }
            ToolAction::Shell {
                program,
                args,
                working_dir,
            } => {
                self.policy.reserve(true, false)?;
                self.persist_usage().await?;
                let mut command = tokio::process::Command::new(program);
                command
                    .args(args)
                    .current_dir(working_dir)
                    .kill_on_drop(true)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                if !self.policy.bypasses(Control::Environment) {
                    command
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
                }
                let mut child = command
                    .spawn()
                    .context("expert subprocess could not start")?;
                let stdout = child.stdout.take().context("stdout pipe")?;
                let stderr = child.stderr.take().context("stderr pipe")?;
                let cap = if self.policy.bypasses(Control::DataSampling) {
                    u64::MAX
                } else {
                    self.policy.scope().max_response_bytes as u64
                };
                let read_out = async move {
                    let mut out = Vec::new();
                    stdout
                        .take(cap + u64::from(cap != u64::MAX))
                        .read_to_end(&mut out)
                        .await
                        .map(|_| out)
                };
                let read_err = async move {
                    let mut out = Vec::new();
                    stderr
                        .take(cap + u64::from(cap != u64::MAX))
                        .read_to_end(&mut out)
                        .await
                        .map(|_| out)
                };
                let (out, err) = tokio::try_join!(read_out, read_err)?;
                let truncated = out.len() as u64 > cap || err.len() as u64 > cap;
                if truncated {
                    child.kill().await?;
                }
                let status = child.wait().await?;
                Ok((
                    json!({"expert_override":true,"exit_code":status.code(),"stdout":String::from_utf8_lossy(&out[..out.len().min(cap as usize)]),"stderr":String::from_utf8_lossy(&err[..err.len().min(cap as usize)])}),
                    truncated,
                ))
            }
            ToolAction::External { subsystem, .. } => {
                anyhow::bail!("{subsystem} actions require their dedicated typed runtime")
            }
        }
    }
    async fn http_get(&self, raw: &str) -> Result<(serde_json::Value, bool)> {
        self.http_request(raw, "GET", None, false).await
    }
    async fn web_discovery_fetch(
        &self,
        raw: &str,
        allowed_origins: &[String],
        max_response_bytes: u32,
    ) -> Result<(serde_json::Value, bool)> {
        // Policy validates both the central engagement scope and the exact
        // per-plan origins before this method is entered. This client observes
        // one response only; a Location value is data and is never contacted.
        let target = self.policy.check_url(raw)?;
        ensure!(
            allowed_origins.contains(&target.origin().ascii_serialization()),
            "web discovery target is outside the plan origins"
        );
        let host = target
            .host_str()
            .context("missing host")?
            .trim_matches(['[', ']']);
        let port = target.port_or_known_default().context("missing port")?;
        self.slot().await?;
        let addrs = self.resolve_with_policy(&self.policy, host, port).await?;
        ensure!(
            addrs.len() <= 64,
            "API schema DNS result exceeds the immutable typed-observation ceiling"
        );
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(host, &addrs);
        if !self.policy.bypasses(Control::Timeouts) {
            builder = builder
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(5));
        }
        let client = builder.build()?;
        let mut response = client
            .get(target.clone())
            .header(
                "user-agent",
                format!("MetisBLACK/{} authorized-assessment", domain::VERSION),
            )
            .send()
            .await
            .context("web discovery request failed")?;
        let status = response.status();
        let mut headers = BTreeMap::new();
        for (key, value) in response.headers() {
            if key == reqwest::header::SET_COOKIE && !self.policy.bypasses(Control::SecretRedaction)
            {
                continue;
            }
            headers.insert(
                key.to_string(),
                self.redactor
                    .text(value.to_str().unwrap_or("[non-text header]")),
            );
        }
        let limit = usize::try_from(max_response_bytes)?;
        let mut bytes = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = response.chunk().await? {
            self.check_cancelled()?;
            let remaining = limit.saturating_sub(bytes.len());
            if chunk.len() > remaining {
                bytes.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = std::str::from_utf8(&bytes)
            .context("web discovery response body is not valid UTF-8")?;
        Ok((
            json!({
                "url": target.as_str(),
                "status": status.as_u16(),
                "headers": headers,
                "body": body,
                "body_hash": hash(&bytes),
                "resolved_addresses": addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "request_count": 1,
                "redirect_followed": false
            }),
            truncated,
        ))
    }
    async fn open_redirect_probe(
        &self,
        endpoint: &str,
        parameter: &str,
        canary: &str,
    ) -> Result<(serde_json::Value, bool)> {
        let probe = self
            .policy
            .open_redirect_probe_url(endpoint, parameter, canary)?;
        let canary_url = domain::open_redirect_canary_url(canary)?;
        let host = probe
            .host_str()
            .context("missing host")?
            .trim_matches(['[', ']']);
        let port = probe.port_or_known_default().context("missing port")?;

        // This typed action is one observe-only request. In particular, it
        // never invokes redirect_policy and never resolves a Location host.
        self.slot().await?;
        let addrs = self.resolve_with_policy(&self.policy, host, port).await?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(host, &addrs);
        if !self.policy.bypasses(Control::Timeouts) {
            builder = builder
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(5));
        }
        let client = builder.build()?;
        let mut response = client
            .get(probe.clone())
            .header(
                "user-agent",
                format!("MetisBLACK/{} authorized-assessment", domain::VERSION),
            )
            .send()
            .await
            .context("open-redirect probe failed")?;
        let status = response.status().as_u16();
        let raw_location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|value| value.to_str().context("non-text Location header"))
            .transpose()?
            .map(str::to_owned);
        let location_matches_canary = raw_location.as_deref() == Some(canary_url.as_str());

        let mut headers = BTreeMap::new();
        for (key, value) in response.headers() {
            if key == reqwest::header::SET_COOKIE && !self.policy.bypasses(Control::SecretRedaction)
            {
                continue;
            }
            headers.insert(
                key.to_string(),
                self.redactor
                    .text(value.to_str().unwrap_or("[non-text header]")),
            );
        }
        let location = raw_location.map(|value| self.redactor.text(&value));
        let limit = if self.policy.bypasses(Control::DataSampling) {
            usize::MAX
        } else {
            self.policy.scope().max_response_bytes
        };
        let mut bytes = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = response.chunk().await? {
            self.check_cancelled()?;
            let remaining = limit.saturating_sub(bytes.len());
            if chunk.len() > remaining {
                bytes.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        let observation = OpenRedirectObservation {
            schema_version: OPEN_REDIRECT_OBSERVATION_SCHEMA_VERSION,
            kind: ObservationKind::OpenRedirect,
            endpoint: endpoint.to_owned(),
            parameter: parameter.to_owned(),
            canary: canary.to_owned(),
            probe_url: probe.into(),
            canary_url,
            status,
            location,
            location_matches_canary,
            headers,
            body_hash: hash(&bytes),
            resolved_addresses: addrs.iter().map(ToString::to_string).collect(),
            request_count: 1,
            redirect_followed: false,
            authorization_provenance: AuthorizationProvenance {
                authorized: self.authorized,
                explicit_override: self.policy.bypasses(Control::Authorization),
            },
        };
        observation.validate()?;
        Ok((serde_json::to_value(observation)?, truncated))
    }

    #[allow(clippy::too_many_arguments)]
    async fn api_schema_probe(
        &self,
        plan_hash: &str,
        contract_hash: &str,
        probe_id: &str,
        method: ApiProbeMethod,
        raw: &str,
        allowed_origins: &[String],
        max_response_bytes: u32,
        max_shape_nodes: u32,
        max_shape_depth: u16,
        max_properties: u32,
        max_array_items: u32,
    ) -> Result<(serde_json::Value, bool)> {
        // check_action has already enforced canonical identifiers, hard caps,
        // central scope and the immutable exact-origin acquisition boundary.
        let target = self.policy.check_url(raw)?;
        ensure!(
            target.as_str() == raw
                && target.username().is_empty()
                && target.password().is_none()
                && allowed_origins.contains(&target.origin().ascii_serialization()),
            "API schema target is not canonical, credential-free and inside the plan origins"
        );
        let host = target
            .host_str()
            .context("missing host")?
            .trim_matches(['[', ']']);
        let port = target.port_or_known_default().context("missing port")?;

        self.slot().await?;
        let addrs = self.resolve_with_policy(&self.policy, host, port).await?;
        // Every resolver result has already passed policy. Canonicalize only
        // after those checks, then enforce the typed receipt's non-bypassable
        // provenance ceiling before live HTTP I/O.
        let resolved_addresses = canonical_api_addresses(&addrs)?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(host, &addrs);
        if !self.policy.bypasses(Control::Timeouts) {
            builder = builder
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(5));
        }
        let client = builder.build()?;
        let request_method = match method {
            ApiProbeMethod::Get => reqwest::Method::GET,
            ApiProbeMethod::Head => reqwest::Method::HEAD,
            ApiProbeMethod::Options => reqwest::Method::OPTIONS,
        };
        let mut response = client
            .request(request_method, target.clone())
            .header(
                "user-agent",
                format!("MetisBLACK/{} authorized-assessment", domain::VERSION),
            )
            .send()
            .await
            .context("API schema probe failed")?;

        let status = response.status().as_u16();
        let set_cookie_present = response.headers().contains_key(reqwest::header::SET_COOKIE);
        let declared_content_length = response.content_length();
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(normalize_media_type);
        let mut headers_truncated = false;
        let mut header_names = Vec::new();
        for name in response.headers().keys() {
            let name = name.as_str().to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "set-cookie"
                    | "www-authenticate"
                    | "proxy-authenticate"
            ) {
                continue;
            }
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                headers_truncated = true;
                continue;
            }
            header_names.push(name);
        }
        header_names.sort();
        header_names.dedup();
        headers_truncated |= header_names.len() > 128;
        header_names.truncate(128);

        let limit = usize::try_from(max_response_bytes)?;
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut body_truncated = false;
        while let Some(chunk) = response.chunk().await? {
            self.check_cancelled()?;
            let remaining = limit.saturating_sub(bytes.len());
            if chunk.len() > remaining {
                bytes.extend_from_slice(&chunk[..remaining]);
                body_truncated = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
            if bytes.len() == limit {
                // A declared larger length proves truncation without reading
                // beyond the finite cap. Otherwise one more chunk is required
                // to distinguish an exact-bound body from a longer stream.
                if declared_content_length.is_some_and(|length| length > limit as u64) {
                    body_truncated = true;
                    break;
                }
            }
        }

        let (json_classification, json_shape, shape_node_count, shape_truncated) = if body_truncated
        {
            // A prefix can independently be valid JSON (for example `0`) or
            // look malformed even though the complete response is valid. Do
            // not turn either accident into conformance evidence.
            (JsonBodyClassification::Truncated, None, 0, false)
        } else {
            classify_json_shape(
                &bytes,
                max_shape_nodes,
                max_shape_depth,
                max_properties,
                max_array_items,
            )?
        };
        let observation = ApiSchemaObservation {
            schema_version: API_SCHEMA_OBSERVATION_SCHEMA_VERSION,
            kind: ObservationKind::ApiSchema,
            plan_hash: plan_hash.to_owned(),
            contract_hash: contract_hash.to_owned(),
            probe_id: probe_id.to_owned(),
            method,
            url: target.into(),
            status,
            media_type,
            header_names,
            headers_truncated,
            set_cookie_present,
            declared_content_length,
            body_hash: hash(&bytes),
            body_bytes: u32::try_from(bytes.len())?,
            body_truncated,
            json_classification,
            json_shape,
            shape_node_count,
            shape_truncated,
            max_response_bytes,
            max_shape_nodes,
            max_shape_depth,
            max_properties,
            max_array_items,
            request_provenance: ApiRequestProvenance {
                resolved_addresses,
                request_count: 1,
                redirect_followed: false,
                proxy_used: false,
                credentials_sent: false,
                authorization_provenance: AuthorizationProvenance {
                    authorized: self.authorized,
                    explicit_override: self.policy.bypasses(Control::Authorization),
                },
            },
        };
        observation.validate()?;
        Ok((serde_json::to_value(observation)?, body_truncated))
    }
    async fn http_request(
        &self,
        raw: &str,
        method: &str,
        body: Option<&serde_json::Value>,
        account: bool,
    ) -> Result<(serde_json::Value, bool)> {
        let method = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
        ensure!(
            [
                reqwest::Method::GET,
                reqwest::Method::HEAD,
                reqwest::Method::OPTIONS,
                reqwest::Method::POST,
                reqwest::Method::PUT,
                reqwest::Method::PATCH,
                reqwest::Method::DELETE
            ]
            .contains(&method)
                || self.policy.bypasses(Control::ToolCapabilities),
            "unsupported HTTP method"
        );
        if method == reqwest::Method::DELETE {
            ensure!(
                self.policy.bypasses(Control::DestructiveActions),
                "DELETE requires destructive_actions override"
            );
        }
        let state_change = ![
            reqwest::Method::GET,
            reqwest::Method::HEAD,
            reqwest::Method::OPTIONS,
        ]
        .contains(&method);
        let mut current = self.policy.check_url(raw)?;
        let mut redirects = vec![];
        let max_hops = if self.policy.bypasses(Control::Redirects) {
            usize::MAX
        } else {
            5
        };
        for hop in 0..=max_hops {
            self.check_cancelled()?;
            let hop_policy = if hop > 0 {
                self.policy.redirect_policy()
            } else {
                self.policy.clone()
            };
            hop_policy.check_url(current.as_str())?;
            let host = current
                .host_str()
                .context("missing host")?
                .trim_matches(['[', ']']);
            let port = current.port_or_known_default().context("missing port")?;
            self.slot_with_impact(state_change, account && hop == 0)
                .await?;
            let addrs = self.resolve_with_policy(&hop_policy, host, port).await?;
            let mut builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .resolve_to_addrs(host, &addrs);
            if !self.policy.bypasses(Control::Timeouts) {
                builder = builder
                    .timeout(Duration::from_secs(15))
                    .connect_timeout(Duration::from_secs(5));
            }
            let client = builder.build()?;
            let mut request = client.request(method.clone(), current.clone()).header(
                "user-agent",
                format!("MetisBLACK/{} authorized-assessment", domain::VERSION),
            );
            if let Some(body) = body {
                request = request.json(body);
            }
            let mut response = request.send().await.context("HTTP request failed")?;
            let status = response.status();
            if status.is_redirection() {
                if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                    ensure!(
                        !state_change || self.policy.bypasses(Control::Redirects),
                        "state-changing redirects require explicit redirects override"
                    );
                    ensure!(hop < max_hops, "redirect limit reached");
                    let next = current.join(location.to_str()?)?;
                    self.policy
                        .redirect_policy()
                        .check_url(next.as_str())
                        .context("redirect blocked")?;
                    redirects.push(json!({"from":current.as_str(),"status":status.as_u16(),"to":next.as_str()}));
                    current = next;
                    continue;
                }
            }
            let mut headers = BTreeMap::new();
            let mut cookies = vec![];
            for (key, value) in response.headers() {
                if key == reqwest::header::SET_COOKIE {
                    if self.policy.bypasses(Control::SecretRedaction) {
                        headers.insert(
                            key.to_string(),
                            value.to_str().unwrap_or_default().to_owned(),
                        );
                    }
                    let flags = value
                        .to_str()
                        .unwrap_or_default()
                        .split(';')
                        .skip(1)
                        .map(|s| s.trim().to_lowercase())
                        .collect::<Vec<_>>();
                    cookies.push(json!({"secure":flags.iter().any(|s|s=="secure"),"http_only":flags.iter().any(|s|s=="httponly"),"same_site":flags.iter().any(|s|s.starts_with("samesite="))}));
                } else {
                    headers.insert(
                        key.to_string(),
                        self.redactor
                            .text(value.to_str().unwrap_or("[non-text header]")),
                    );
                }
            }
            let limit = if self.policy.bypasses(Control::DataSampling) {
                usize::MAX
            } else {
                self.policy.scope().max_response_bytes
            };
            let mut bytes = Vec::new();
            let mut truncated = false;
            while let Some(chunk) = response.chunk().await? {
                self.check_cancelled()?;
                let remaining = limit.saturating_sub(bytes.len());
                if chunk.len() > remaining {
                    bytes.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok((
                json!({"url":current.as_str(),"status":status.as_u16(),"headers":headers,"cookie_security":cookies,"body":String::from_utf8_lossy(&bytes),"body_hash":hash(&bytes),"redirects":redirects,"resolved_addresses":addrs.iter().map(ToString::to_string).collect::<Vec<_>>()}),
                truncated,
            ));
        }
        Err(anyhow!("redirect limit reached"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::{scope_for_url, Policy};
    use tokio::{io::AsyncWriteExt, sync::oneshot};

    #[test]
    fn api_media_type_normalization_matches_the_bounded_contract_token_subset() {
        assert_eq!(
            normalize_media_type("Application/Vnd.foo_bar!#$&^+*-json; charset=utf-8"),
            Some("application/vnd.foo_bar!#$&^+*-json".into())
        );
        assert_eq!(normalize_media_type("application/vnd.foo%bar"), None);
    }

    #[test]
    fn api_resolved_address_provenance_is_canonical_and_hard_bounded() -> Result<()> {
        let addresses = vec![
            "192.0.2.2:443".parse()?,
            "192.0.2.1:443".parse()?,
            "192.0.2.2:443".parse()?,
        ];
        assert_eq!(
            canonical_api_addresses(&addresses)?,
            vec!["192.0.2.1:443", "192.0.2.2:443"]
        );
        let oversized = (1..=65)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
            .collect::<Vec<_>>();
        assert!(canonical_api_addresses(&oversized).is_err());
        Ok(())
    }
    async fn serve(response: &'static str) -> Result<(String, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let h = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(response.as_bytes()).await;
            }
        });
        Ok((url, h))
    }
    async fn serve_capture(
        response: String,
    ) -> Result<(
        String,
        oneshot::Receiver<String>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (sent, received) = oneshot::channel();
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = vec![0; 8192];
                let read = stream.read(&mut bytes).await.unwrap_or(0);
                bytes.truncate(read);
                let _ = sent.send(String::from_utf8_lossy(&bytes).into_owned());
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Ok((url, received, handle))
    }
    async fn serve_bytes_capture(
        response: Vec<u8>,
    ) -> Result<(
        String,
        oneshot::Receiver<String>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (sent, received) = oneshot::channel();
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = vec![0; 8192];
                let read = stream.read(&mut bytes).await.unwrap_or(0);
                bytes.truncate(read);
                let _ = sent.send(String::from_utf8_lossy(&bytes).into_owned());
                let _ = stream.write_all(&response).await;
            }
        });
        Ok((url, received, handle))
    }
    fn api_action(
        url: &str,
        method: ApiProbeMethod,
        max_response_bytes: u32,
        max_shape_nodes: u32,
    ) -> Result<ToolAction> {
        api_action_with_bounds(
            url,
            method,
            max_response_bytes,
            max_shape_nodes,
            domain::API_SCHEMA_DEFAULT_MAX_SHAPE_DEPTH,
            domain::API_SCHEMA_DEFAULT_MAX_PROPERTIES,
            domain::API_SCHEMA_DEFAULT_MAX_ARRAY_ITEMS,
        )
    }
    fn api_action_with_bounds(
        url: &str,
        method: ApiProbeMethod,
        max_response_bytes: u32,
        max_shape_nodes: u32,
        max_shape_depth: u16,
        max_properties: u32,
        max_array_items: u32,
    ) -> Result<ToolAction> {
        let parsed = url::Url::parse(url)?;
        Ok(ToolAction::ApiSchemaProbe {
            plan_hash: "a".repeat(64),
            contract_hash: "b".repeat(64),
            probe_id: format!("api-schema-{}", "c".repeat(64)),
            method,
            url: parsed.as_str().into(),
            allowed_origins: vec![parsed.origin().ascii_serialization()],
            max_response_bytes,
            max_shape_nodes,
            max_shape_depth,
            max_properties,
            max_array_items,
        })
    }
    fn runtime(url: &str, dir: &std::path::Path) -> Result<Runtime> {
        let mut scope = scope_for_url(url)?;
        scope.requests_per_second = 100;
        let mut runtime = Runtime::new(
            Policy::new(scope)?,
            EvidenceStore::new(dir, "run-test", Redactor::default())?,
            Redactor::default(),
        );
        runtime.authorize(true);
        Ok(runtime)
    }
    #[tokio::test]
    async fn captures_real_http_and_redacts_cookies() -> Result<()> {
        let d = tempfile::tempdir()?;
        let (url,h)=serve("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: session=private-value; HttpOnly\r\nConnection: close\r\n\r\nOK").await?;
        let r = runtime(&url, d.path())?
            .execute("probe", ToolAction::HttpGet { url })
            .await?;
        h.await?;
        assert!(r.output.successful);
        assert_eq!(r.output.data["status"], 200);
        assert!(!serde_json::to_string(&r)?.contains("private-value"));
        assert_eq!(r.output.data["cookie_security"][0]["secure"], false);
        Ok(())
    }
    #[tokio::test]
    async fn blocks_out_of_scope_redirect() -> Result<()> {
        let d = tempfile::tempdir()?;
        let (url,h)=serve("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        let r = runtime(&url, d.path())?
            .execute("probe", ToolAction::HttpGet { url })
            .await?;
        h.await?;
        assert!(!r.output.successful);
        assert!(r.output.data["error"]
            .as_str()
            .unwrap()
            .contains("redirect blocked"));
        Ok(())
    }
    #[tokio::test]
    async fn web_discovery_rejects_invalid_utf8_instead_of_hashing_lossy_text() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\n\xff\xfe";
                let _ = stream.write_all(response).await;
            }
        });
        let directory = tempfile::tempdir()?;
        let runtime = runtime(&url, directory.path())?;
        let origin = url::Url::parse(&url)?.origin().ascii_serialization();
        let receipt = runtime
            .execute(
                "web-discovery",
                ToolAction::WebDiscoveryFetch {
                    plan_hash: "a".repeat(64),
                    request_id: format!("discovery-{}", "b".repeat(64)),
                    url,
                    allowed_origins: vec![origin],
                    max_response_bytes: 1024,
                },
            )
            .await?;
        server.await?;
        assert!(!receipt.output.successful);
        assert!(receipt.output.data["error"]
            .as_str()
            .is_some_and(|error| error.contains("not valid UTF-8")));
        assert!(receipt.output.data.get("body").is_none());
        Ok(())
    }
    #[tokio::test]
    async fn open_redirect_probe_captures_exact_first_response_as_typed_data() -> Result<()> {
        let body = "observe-only";
        let canary = "redirect-canary-01";
        let canary_url = domain::open_redirect_canary_url(canary)?;
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {canary_url}\r\nX-Fixture: captured\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (base, request, server) = serve_capture(response).await?;
        let endpoint = format!("{base}/redirect?stable=value&next=old");
        let dir = tempfile::tempdir()?;
        let runtime = runtime(&endpoint, dir.path())?;
        let receipt = runtime
            .execute(
                "redirect-observer",
                ToolAction::OpenRedirectProbe {
                    endpoint: endpoint.clone(),
                    parameter: "next".into(),
                    canary: canary.into(),
                },
            )
            .await?;
        server.await?;

        assert!(
            receipt.output.successful,
            "unexpected probe failure: {}",
            receipt.output.data
        );
        assert_eq!(runtime.policy.usage().requests, 1);
        let observed: OpenRedirectObservation =
            serde_json::from_value(receipt.output.data.clone())?;
        observed.validate()?;
        assert_eq!(observed.schema_version, 1);
        assert_eq!(observed.kind, ObservationKind::OpenRedirect);
        assert_eq!(observed.status, 302);
        assert_eq!(observed.location.as_deref(), Some(canary_url.as_str()));
        assert!(observed.location_matches_canary);
        assert_eq!(observed.headers["x-fixture"], "captured");
        assert_eq!(observed.body_hash, hash(body.as_bytes()));
        assert!(!observed.resolved_addresses.is_empty());
        assert_eq!(observed.request_count, 1);
        assert!(!observed.redirect_followed);
        assert!(observed.authorization_provenance.authorized);
        assert!(!observed.authorization_provenance.explicit_override);

        let request = request.await?;
        assert!(request.starts_with("GET /redirect?stable=value&next=https%3A%2F%2Fmetisblack.invalid%2Fredirect-canary-01 HTTP/1.1\r\n"), "unexpected request: {request}");
        let mut untyped = receipt.output.data;
        untyped["finding"] = json!("confirmed");
        assert!(serde_json::from_value::<OpenRedirectObservation>(untyped).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn open_redirect_probe_records_negative_and_mismatch_without_following() -> Result<()> {
        let canary = "redirect-canary-02";
        for (status, location) in [(200, None), (302, Some("instrumented"))] {
            let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let destination_url = format!("http://{}/must-not-connect", destination.local_addr()?);
            let location_value = location.map(|_| destination_url.clone());
            let location_header = location_value
                .as_ref()
                .map(|value| format!("Location: {value}\r\n"))
                .unwrap_or_default();
            let response = format!(
                "HTTP/1.1 {status} Fixture\r\n{location_header}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let (endpoint, request, server) = serve_capture(response).await?;
            let dir = tempfile::tempdir()?;
            let runtime = runtime(&endpoint, dir.path())?;
            let receipt = runtime
                .execute(
                    "negative-observer",
                    ToolAction::OpenRedirectProbe {
                        endpoint,
                        parameter: "return_to".into(),
                        canary: canary.into(),
                    },
                )
                .await?;
            server.await?;
            let _ = request.await?;
            let observed: OpenRedirectObservation = serde_json::from_value(receipt.output.data)?;
            assert!(receipt.output.successful);
            assert_eq!(observed.status, status);
            assert_eq!(observed.location, location_value);
            assert!(!observed.location_matches_canary);
            assert_eq!(runtime.policy.usage().requests, 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), destination.accept())
                    .await
                    .is_err()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn open_redirect_probe_enforces_syntax_scope_authorization_and_budget() -> Result<()> {
        let cases = [
            ("bad&key", "redirect-canary-03", "invalid query parameter"),
            ("next", "UPPERCASE-CANARY", "invalid canary"),
        ];
        for (parameter, canary, label) in cases {
            let (endpoint, _request, server) = serve_capture(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            )
            .await?;
            let dir = tempfile::tempdir()?;
            let receipt = runtime(&endpoint, dir.path())?
                .execute(
                    label,
                    ToolAction::OpenRedirectProbe {
                        endpoint,
                        parameter: parameter.into(),
                        canary: canary.into(),
                    },
                )
                .await?;
            assert!(!receipt.output.successful, "{label}");
            server.abort();
        }

        let (base, _request, server) = serve_capture(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await?;
        let endpoint = format!("{base}/outside");
        let mut path_scope = scope_for_url(&base)?;
        path_scope.network[0].paths = vec!["/allowed".into()];
        let dir = tempfile::tempdir()?;
        let mut path_runtime = Runtime::new(
            Policy::new(path_scope)?,
            EvidenceStore::new(dir.path(), "run-scope", Redactor::default())?,
            Redactor::default(),
        );
        path_runtime.authorize(true);
        let receipt = path_runtime
            .execute(
                "scope-check",
                ToolAction::OpenRedirectProbe {
                    endpoint,
                    parameter: "next".into(),
                    canary: "redirect-canary-04".into(),
                },
            )
            .await?;
        assert!(!receipt.output.successful);
        assert_eq!(path_runtime.policy.usage().requests, 0);
        server.abort();

        for (authorized, max_requests, error) in [(false, 10, "authorization"), (true, 0, "budget")]
        {
            let (endpoint, _request, server) = serve_capture(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            )
            .await?;
            let dir = tempfile::tempdir()?;
            let mut scope = scope_for_url(&endpoint)?;
            scope.max_requests = max_requests;
            let mut runtime = Runtime::new(
                Policy::new(scope)?,
                EvidenceStore::new(dir.path(), "run-gate", Redactor::default())?,
                Redactor::default(),
            );
            runtime.authorize(authorized);
            let receipt = runtime
                .execute(
                    error,
                    ToolAction::OpenRedirectProbe {
                        endpoint,
                        parameter: "next".into(),
                        canary: "redirect-canary-05".into(),
                    },
                )
                .await?;
            assert!(!receipt.output.successful, "{error}");
            assert!(receipt.output.data["error"]
                .as_str()
                .is_some_and(|message| message.contains(error)));
            assert_eq!(runtime.policy.usage().requests, 0);
            server.abort();
        }

        let (endpoint, request, server) = serve_capture(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await?;
        let dir = tempfile::tempdir()?;
        let mut scope = scope_for_url(&endpoint)?;
        scope.max_requests = 0;
        let overrides = domain::ExpertOverrides {
            controls: vec![Control::Authorization, Control::RequestBudget],
            reason: "Explicit redirect regression bypass".into(),
            actor: "test-operator".into(),
            acknowledged: true,
            ..Default::default()
        };
        let mut runtime = Runtime::new(
            Policy::with_overrides(scope, overrides.clone())?,
            EvidenceStore::new(
                dir.path(),
                "run-override",
                Redactor::with_override(&overrides),
            )?,
            Redactor::with_override(&overrides),
        );
        runtime.authorize(false);
        let receipt = runtime
            .execute(
                "explicit-override",
                ToolAction::OpenRedirectProbe {
                    endpoint,
                    parameter: "next".into(),
                    canary: "redirect-canary-06".into(),
                },
            )
            .await?;
        server.await?;
        let _ = request.await?;
        assert!(receipt.output.successful);
        let observation: OpenRedirectObservation = serde_json::from_value(receipt.output.data)?;
        assert!(!observation.authorization_provenance.authorized);
        assert!(observation.authorization_provenance.explicit_override);
        assert_eq!(runtime.policy.usage().requests, 1);
        assert_eq!(
            receipt.expert_override.unwrap().controls,
            overrides.controls
        );
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_uses_exact_methods_and_retains_no_response_values() -> Result<()> {
        for method in [
            ApiProbeMethod::Get,
            ApiProbeMethod::Head,
            ApiProbeMethod::Options,
        ] {
            let body = r#"{"user":"fixture-secret","password":"fixture-secret","count":987654321,"nested":[true,null]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; private=fixture-secret\r\nSet-Cookie: session=fixture-secret\r\nWWW-Authenticate: Bearer fixture-secret\r\nX-Structural: present\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let (url, request, server) = serve_capture(response).await?;
            let directory = tempfile::tempdir()?;
            let runtime = runtime(&url, directory.path())?;
            let receipt = runtime
                .execute("api-schema", api_action(&url, method, 4096, 64)?)
                .await?;
            server.await?;
            assert!(receipt.output.successful);
            let observation: ApiSchemaObservation =
                serde_json::from_value(receipt.output.data.clone())?;
            observation.validate()?;
            assert_eq!(observation.method, method);
            assert_eq!(observation.request_provenance.request_count, 1);
            assert!(!observation.request_provenance.redirect_followed);
            assert!(!observation.request_provenance.proxy_used);
            assert!(!observation.request_provenance.credentials_sent);
            assert!(observation.set_cookie_present);
            assert!(!observation.header_names.contains(&"set-cookie".into()));
            assert!(!observation
                .header_names
                .contains(&"www-authenticate".into()));
            assert_eq!(observation.media_type.as_deref(), Some("application/json"));
            if method == ApiProbeMethod::Head {
                assert_eq!(
                    observation.json_classification,
                    JsonBodyClassification::Empty
                );
            } else {
                assert_eq!(
                    observation.json_classification,
                    JsonBodyClassification::ValidJson
                );
                assert!(matches!(
                    observation.json_shape,
                    Some(JsonShape::Object { .. })
                ));
            }
            let serialized = serde_json::to_string(&receipt.output.data)?;
            assert!(!serialized.contains("fixture-secret"));
            assert!(!serialized.contains("987654321"));
            let request = request.await?;
            assert!(
                request.starts_with(&format!("{} / HTTP/1.1\r\n", method.as_str())),
                "unexpected request: {request}"
            );
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            assert_eq!(runtime.policy.usage().requests, 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_classifies_invalid_utf8_invalid_json_and_shape_caps() -> Result<()> {
        let cases = [
            (
                vec![0xff, 0xfe],
                JsonBodyClassification::InvalidUtf8,
                16,
                false,
            ),
            (
                b"{not-json".to_vec(),
                JsonBodyClassification::InvalidJson,
                16,
                false,
            ),
            (
                b"[1,2,3,4]".to_vec(),
                JsonBodyClassification::ValidJson,
                3,
                true,
            ),
        ];
        for (body, expected, nodes, expected_shape_truncated) in cases {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            let (url, request, server) = serve_bytes_capture(response).await?;
            let directory = tempfile::tempdir()?;
            let runtime = runtime(&url, directory.path())?;
            let receipt = runtime
                .execute(
                    "api-classifier",
                    api_action(&url, ApiProbeMethod::Get, 4096, nodes)?,
                )
                .await?;
            server.await?;
            let _ = request.await?;
            assert!(receipt.output.successful);
            let observation: ApiSchemaObservation = serde_json::from_value(receipt.output.data)?;
            observation.validate()?;
            assert_eq!(observation.json_classification, expected);
            assert_eq!(observation.shape_truncated, expected_shape_truncated);
            if expected_shape_truncated {
                assert!(observation.json_shape.is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn api_json_shape_caps_fail_closed_without_retaining_partial_values() -> Result<()> {
        let cases = [
            (r#"{"a":{"b":{"c":1}}}"#, 8, 1, 16, 16),
            (r#"{"a":1,"b":2}"#, 8, 8, 1, 16),
            (r#"[1,2]"#, 8, 8, 16, 1),
        ];
        for (body, nodes, depth, properties, array_items) in cases {
            let (classification, shape, count, truncated) =
                classify_json_shape(body.as_bytes(), nodes, depth, properties, array_items)?;
            assert_eq!(classification, JsonBodyClassification::ValidJson);
            assert!(shape.is_none());
            assert_eq!(count, 0);
            assert!(truncated);
        }
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_turns_each_shape_overflow_into_value_free_evidence() -> Result<()> {
        let cases = [
            (r#"[1,2,3]"#, 3, 8, 16, 16),
            (r#"{"a":{"b":1}}"#, 16, 1, 16, 16),
            (r#"{"a":1,"b":2}"#, 16, 8, 1, 16),
            (r#"[1,2]"#, 16, 8, 16, 1),
        ];
        for (body, nodes, depth, properties, array_items) in cases {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let (url, request, server) = serve_capture(response).await?;
            let directory = tempfile::tempdir()?;
            let runtime = runtime(&url, directory.path())?;
            let receipt = runtime
                .execute(
                    "api-shape-bound",
                    api_action_with_bounds(
                        &url,
                        ApiProbeMethod::Get,
                        4096,
                        nodes,
                        depth,
                        properties,
                        array_items,
                    )?,
                )
                .await?;
            server.await?;
            let _ = request.await?;
            assert!(receipt.output.successful);
            let observation: ApiSchemaObservation = serde_json::from_value(receipt.output.data)?;
            observation.validate()?;
            assert_eq!(
                observation.json_classification,
                JsonBodyClassification::ValidJson
            );
            assert!(observation.json_shape.is_none());
            assert_eq!(observation.shape_node_count, 0);
            assert!(observation.shape_truncated);
        }
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_bounds_unsupported_header_names() -> Result<()> {
        let body = r#"{"ok":true}"#;
        let long_name = format!("x-{}", "a".repeat(127));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX_Bad: ignored\r\n{long_name}: ignored\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (url, request, server) = serve_capture(response).await?;
        let directory = tempfile::tempdir()?;
        let runtime = runtime(&url, directory.path())?;
        let receipt = runtime
            .execute(
                "api-hostile-header",
                api_action(&url, ApiProbeMethod::Get, 4096, 64)?,
            )
            .await?;
        server.await?;
        let _ = request.await?;
        assert!(
            receipt.output.successful,
            "unexpected hostile-header probe failure: {}",
            receipt.output.data
        );
        let observation: ApiSchemaObservation = serde_json::from_value(receipt.output.data)?;
        observation.validate()?;
        assert!(observation.headers_truncated);
        assert!(observation.header_names.len() <= 128);
        assert!(!observation.header_names.iter().any(|name| name == "x_bad"));
        assert!(!observation
            .header_names
            .iter()
            .any(|name| name == &long_name));
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_stops_at_byte_cap_and_never_contacts_redirect() -> Result<()> {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let destination_url = format!("http://{}/must-not-connect", destination.local_addr()?);
        let body = b"{\"long\":\"response-value\"}";
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {destination_url}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = response.into_bytes();
        response.extend_from_slice(body);
        let (url, request, server) = serve_bytes_capture(response).await?;
        let directory = tempfile::tempdir()?;
        let runtime = runtime(&url, directory.path())?;
        let receipt = runtime
            .execute(
                "api-truncation",
                api_action(&url, ApiProbeMethod::Get, 8, 16)?,
            )
            .await?;
        server.await?;
        let _ = request.await?;
        let observation: ApiSchemaObservation = serde_json::from_value(receipt.output.data)?;
        observation.validate()?;
        assert_eq!(observation.status, 302);
        assert_eq!(observation.body_bytes, 8);
        assert!(observation.body_truncated);
        assert_eq!(
            observation.json_classification,
            JsonBodyClassification::Truncated
        );
        assert!(observation.json_shape.is_none());
        assert_eq!(observation.shape_node_count, 0);
        assert!(!observation.shape_truncated);
        assert!(receipt.output.truncated);
        assert_eq!(observation.request_provenance.request_count, 1);
        assert!(!observation.request_provenance.redirect_followed);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), destination.accept())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_obeys_timeout_and_preflight_cancellation() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                sleep(Duration::from_millis(100)).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let mut scope = scope_for_url(&url)?;
        scope.requests_per_second = 100;
        scope.tool_timeout_ms = 10;
        let directory = tempfile::tempdir()?;
        let mut timeout_runtime = Runtime::new(
            Policy::new(scope)?,
            EvidenceStore::new(directory.path(), "run-timeout", Redactor::default())?,
            Redactor::default(),
        );
        timeout_runtime.authorize(true);
        let receipt = timeout_runtime
            .execute(
                "api-timeout",
                api_action(&url, ApiProbeMethod::Get, 1024, 16)?,
            )
            .await?;
        assert!(!receipt.output.successful);
        assert!(receipt.output.data["error"]
            .as_str()
            .is_some_and(|error| error.contains("timeout")));
        server.await?;

        let (cancel_url, _request, cancel_server) = serve_capture(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await?;
        let cancel_directory = tempfile::tempdir()?;
        let cancelled = runtime(&cancel_url, cancel_directory.path())?;
        cancelled.cancel();
        assert!(cancelled
            .execute(
                "api-cancelled",
                api_action(&cancel_url, ApiProbeMethod::Get, 1024, 16)?,
            )
            .await
            .is_err());
        cancel_server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_seals_post_contact_cancellation_as_failure() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return false;
            };
            let mut bytes = vec![0; 8192];
            let read = stream.read(&mut bytes).await.unwrap_or(0);
            bytes.truncate(read);
            let _ = accepted_tx.send(String::from_utf8_lossy(&bytes).into_owned());
            // Withhold the response until cancellation has completed so this
            // cannot collapse into the preflight-cancellation path.
            let _ = release_rx.await;
            drop(stream);
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok()
        });

        let directory = tempfile::tempdir()?;
        let runtime = Arc::new(runtime(&url, directory.path())?);
        let executing = Arc::clone(&runtime);
        let action = api_action(&url, ApiProbeMethod::Get, 1024, 16)?;
        let execution =
            tokio::spawn(async move { executing.execute("api-post-contact-cancel", action).await });

        let request = timeout(Duration::from_secs(2), accepted_rx)
            .await
            .context("API cancellation fixture was not contacted")??;
        assert_eq!(request.matches("GET / HTTP/1.1\r\n").count(), 1);
        assert_eq!(runtime.policy.usage().requests, 1);

        runtime.cancel();
        let joined = timeout(Duration::from_secs(2), execution)
            .await
            .context("post-contact cancellation did not stop execution")?;
        let receipt = joined??;
        let _ = release_tx.send(());
        assert!(!server.await?, "cancellation caused a second request");

        assert!(!receipt.output.successful);
        assert!(!receipt.output.truncated);
        assert!(matches!(
            receipt.output.action,
            ToolAction::ApiSchemaProbe { .. }
        ));
        assert!(receipt.output.data["error"]
            .as_str()
            .is_some_and(|error| error.contains("cancelled")));
        assert!(
            serde_json::from_value::<ApiSchemaObservation>(receipt.output.data.clone()).is_err()
        );
        let sealed = runtime.evidence.get(&receipt.id)?;
        assert_eq!(sealed.content_hash, receipt.content_hash);
        assert!(!sealed.output.successful);
        assert_eq!(runtime.policy.usage().requests, 1);
        Ok(())
    }

    #[tokio::test]
    async fn api_schema_probe_ignores_environment_proxies_in_child_process() -> Result<()> {
        const CHILD_MARKER: &str = "METISBLACK_API_PROXY_ISOLATION_CHILD";
        const TARGET_URL: &str = "METISBLACK_API_PROXY_ISOLATION_TARGET";

        if std::env::var_os(CHILD_MARKER).is_some() {
            let target = std::env::var(TARGET_URL).context("missing child target URL")?;
            let directory = tempfile::tempdir()?;
            let receipt = runtime(&target, directory.path())?
                .execute(
                    "api-proxy-isolation-child",
                    api_action(&target, ApiProbeMethod::Get, 1024, 16)?,
                )
                .await?;
            assert!(
                receipt.output.successful,
                "child probe failed: {}",
                receipt.output.data
            );
            let observation: ApiSchemaObservation = serde_json::from_value(receipt.output.data)?;
            observation.validate()?;
            return Ok(());
        }

        let (target, target_request, target_server) = serve_capture(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}"
                .into(),
        )
        .await?;
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_url = format!("http://{}", proxy_listener.local_addr()?);
        let proxy_trap = tokio::spawn(async move {
            let Ok((mut stream, _)) = proxy_listener.accept().await else {
                return false;
            };
            let _ = stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            true
        });

        let mut child = tokio::process::Command::new(std::env::current_exe()?);
        child
            .arg("tests::api_schema_probe_ignores_environment_proxies_in_child_process")
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env(TARGET_URL, &target)
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .kill_on_drop(true);
        let output = timeout(Duration::from_secs(10), child.output())
            .await
            .context("proxy-isolation child timed out")??;

        let target_request = timeout(Duration::from_secs(2), target_request).await;
        if target_server.is_finished() {
            target_server.await?;
        } else {
            target_server.abort();
        }
        let proxy_contacted = if proxy_trap.is_finished() {
            proxy_trap.await?
        } else {
            proxy_trap.abort();
            false
        };
        assert!(
            output.status.success(),
            "proxy-isolation child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let target_request =
            target_request.context("child did not contact the intended target")??;
        assert!(
            target_request.starts_with("GET / HTTP/1.1\r\n"),
            "unexpected direct target request: {target_request}"
        );
        assert!(
            !proxy_contacted,
            "API schema probe contacted environment proxy"
        );
        Ok(())
    }
}
