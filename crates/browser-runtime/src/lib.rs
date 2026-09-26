//! Typed W3C WebDriver runtime with policy checks and receipt-ready observations.
#![forbid(unsafe_code)]

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use domain::{now_ms, Control};
use futures::future::BoxFuture;
use policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use storage::{hash, Redactor};
use tokio::{sync::Mutex, time::Instant};
use url::Url;

mod plan;
pub use plan::*;

pub const W3C_ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";

/// HTTP methods required by the WebDriver protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverMethod {
    Get,
    Post,
    Delete,
}

/// An already-typed request to a WebDriver server. Paths are produced only by
/// this crate and never accept a full URL from a model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriverRequest {
    pub method: DriverMethod,
    pub path: String,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriverResponse {
    pub status: u16,
    pub body: Value,
    pub byte_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserErrorKind {
    InvalidInput,
    Transport,
    Protocol,
    Capability,
    Policy,
    ScopeEscape,
    Budget,
    Timeout,
    Cancelled,
    Closed,
    Artifact,
}

/// Error type at the transport boundary. Higher-level calls wrap this in an
/// observation so failed attempts remain auditable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserError {
    pub kind: BrowserErrorKind,
    pub message: String,
}

impl BrowserError {
    fn new(kind: BrowserErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for BrowserError {}

/// Injection seam for a live HTTP backend, deterministic tests, or a future
/// BiDi backend. It is object-safe without a proc-macro dependency.
pub trait BrowserTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: DriverRequest,
    ) -> BoxFuture<'a, std::result::Result<DriverResponse, BrowserError>>;
}

/// Live W3C WebDriver backend for chromedriver, geckodriver, safaridriver and
/// protocol-compatible remote grids.
#[derive(Clone)]
pub struct WebDriverHttpTransport {
    endpoint: Url,
    client: reqwest::Client,
    max_response_bytes: usize,
}

impl WebDriverHttpTransport {
    pub fn new(endpoint: &str, timeout: Duration, max_response_bytes: usize) -> Result<Self> {
        let mut endpoint = Url::parse(endpoint).context("invalid WebDriver endpoint")?;
        ensure!(
            ["http", "https"].contains(&endpoint.scheme()),
            "WebDriver endpoint must be HTTP(S)"
        );
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "WebDriver endpoint cannot contain credentials, query, or fragment"
        );
        ensure!(
            max_response_bytes > 0,
            "response byte limit must be positive"
        );
        if !endpoint.path().ends_with('/') {
            endpoint.set_path(&format!("{}/", endpoint.path()));
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            endpoint,
            client,
            max_response_bytes,
        })
    }
}

impl BrowserTransport for WebDriverHttpTransport {
    fn send<'a>(
        &'a self,
        request: DriverRequest,
    ) -> BoxFuture<'a, std::result::Result<DriverResponse, BrowserError>> {
        Box::pin(async move {
            let path = request.path.trim_start_matches('/');
            let url = self.endpoint.join(path).map_err(|error| {
                BrowserError::new(BrowserErrorKind::InvalidInput, error.to_string())
            })?;
            let builder = match request.method {
                DriverMethod::Get => self.client.get(url),
                DriverMethod::Post => self.client.post(url),
                DriverMethod::Delete => self.client.delete(url),
            };
            let response = if let Some(body) = request.body {
                builder.json(&body)
            } else {
                builder
            }
            .send()
            .await
            .map_err(|error| BrowserError::new(BrowserErrorKind::Transport, error.to_string()))?;
            let status = response.status().as_u16();
            let declared = response.content_length().unwrap_or_default();
            if declared > self.max_response_bytes as u64 {
                return Err(BrowserError::new(
                    BrowserErrorKind::Budget,
                    "WebDriver response exceeds byte budget",
                ));
            }
            let bytes = response.bytes().await.map_err(|error| {
                BrowserError::new(BrowserErrorKind::Transport, error.to_string())
            })?;
            if bytes.len() > self.max_response_bytes {
                return Err(BrowserError::new(
                    BrowserErrorKind::Budget,
                    "WebDriver response exceeds byte budget",
                ));
            }
            let body = serde_json::from_slice(&bytes).map_err(|error| {
                BrowserError::new(
                    BrowserErrorKind::Protocol,
                    format!("invalid WebDriver JSON: {error}"),
                )
            })?;
            Ok(DriverResponse {
                status,
                body,
                byte_count: bytes.len(),
            })
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserKind {
    Chrome,
    Firefox,
    Safari,
    Compatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub browser: BrowserKind,
    #[serde(default)]
    pub headless: bool,
    #[serde(default)]
    pub accept_insecure_certificates: bool,
    #[serde(default)]
    pub additional_capabilities: BTreeMap<String, Value>,
}

impl Default for SessionRequest {
    fn default() -> Self {
        Self {
            browser: BrowserKind::Chrome,
            headless: true,
            accept_insecure_certificates: false,
            additional_capabilities: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRuntimeConfig {
    /// Set only after the caller has verified the engagement authorization.
    /// Otherwise an explicit `authorization` expert override is required.
    pub authorized: bool,
    pub command_timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub max_steps: u64,
    pub max_total_bytes: usize,
    pub max_artifact_bytes: usize,
    pub allow_raw_javascript: bool,
    pub allow_downloads: bool,
    pub quarantine_on_scope_escape: bool,
    pub artifact_directory: Option<PathBuf>,
}

impl Default for BrowserRuntimeConfig {
    fn default() -> Self {
        Self {
            authorized: false,
            command_timeout_ms: 30_000,
            poll_interval_ms: 100,
            max_steps: 200,
            max_total_bytes: 16 * 1024 * 1024,
            max_artifact_bytes: 8 * 1024 * 1024,
            allow_raw_javascript: false,
            allow_downloads: false,
            quarantine_on_scope_escape: true,
            artifact_directory: None,
        }
    }
}

impl BrowserRuntimeConfig {
    fn validate(&self, policy: &Policy) -> Result<()> {
        ensure!(
            self.authorized || policy.bypasses(Control::Authorization),
            "browser execution requires verified authorization or an authorization override"
        );
        ensure!(
            self.command_timeout_ms > 0,
            "command timeout must be positive"
        );
        ensure!(self.poll_interval_ms > 0, "poll interval must be positive");
        ensure!(self.max_steps > 0, "step budget must be positive");
        ensure!(self.max_total_bytes > 0, "byte budget must be positive");
        ensure!(
            !self.allow_downloads || policy.bypasses(Control::ExternalDownloads),
            "downloads require the external_downloads expert override"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    pub browser_name: String,
    pub browser_version: Option<String>,
    pub platform_name: Option<String>,
    pub supports_javascript: bool,
    pub supports_console_logs: bool,
    pub supports_network_logs: bool,
    /// Classic WebDriver cannot guarantee this. Always false for this backend.
    pub supports_request_interception: bool,
    pub downloads_allowed: bool,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAction {
    CreateSession,
    DeleteSession,
    Navigate,
    CurrentUrl,
    FindElement,
    Click,
    Clear,
    SendKeys,
    SubmitForm,
    EvaluateScript,
    GetCookies,
    AddCookie,
    DeleteCookie,
    GetStorage,
    SetStorage,
    ClearStorage,
    Screenshot,
    ConsoleLogs,
    NetworkLogs,
    Wait,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub kind: String,
    pub path: Option<PathBuf>,
    pub media_type: String,
    pub byte_count: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserObservationRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub actor: String,
    pub session_id: Option<String>,
    pub action: BrowserAction,
    pub started_ms: u64,
    pub duration_ms: u64,
    pub successful: bool,
    pub current_url: Option<String>,
    pub redirect_chain: Vec<String>,
    pub data: Value,
    pub artifacts: Vec<Artifact>,
    pub warnings: Vec<String>,
    pub error_kind: Option<BrowserErrorKind>,
    pub error: Option<String>,
    pub truncated: bool,
}

/// Hash-addressed immutable command result. The digest is over the canonical
/// serialized record, so receipt adapters can detect post-capture mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserObservation {
    pub id: String,
    pub content_hash: String,
    pub record: BrowserObservationRecord,
}

impl BrowserObservation {
    fn from_record(record: BrowserObservationRecord) -> Self {
        let bytes = serde_json::to_vec(&record).expect("observation record serializes");
        let content_hash = hash(&bytes);
        Self {
            id: format!("browser-{}-{:.16}", record.sequence, content_hash),
            content_hash,
            record,
        }
    }

    pub fn verify(&self) -> bool {
        serde_json::to_vec(&self.record).is_ok_and(|bytes| hash(&bytes) == self.content_hash)
    }
}

#[derive(Debug, Clone)]
pub struct Observed<T> {
    pub value: T,
    pub observation: BrowserObservation,
}

#[derive(Debug, Clone)]
pub struct ObservedFailure {
    pub error: BrowserError,
    pub observation: BrowserObservation,
}
impl fmt::Display for ObservedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}
impl std::error::Error for ObservedFailure {}
pub type BrowserResult<T> = std::result::Result<Observed<T>, ObservedFailure>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElementRef {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "strategy", content = "value", rename_all = "snake_case")]
pub enum Locator {
    Css(String),
    XPath(String),
    Id(String),
    Name(String),
    TagName(String),
    LinkText(String),
}

impl Locator {
    fn wire(&self) -> Result<(&'static str, &str)> {
        let (using, value) = match self {
            Self::Css(value) => ("css selector", value.as_str()),
            Self::XPath(value) => ("xpath", value.as_str()),
            Self::Id(value) => ("css selector", value.as_str()),
            Self::Name(value) => ("css selector", value.as_str()),
            Self::TagName(value) => ("tag name", value.as_str()),
            Self::LinkText(value) => ("link text", value.as_str()),
        };
        ensure!(
            !value.is_empty() && value.len() <= 8_192 && !value.contains('\0'),
            "invalid locator"
        );
        Ok((using, value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(rename = "httpOnly", skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(rename = "sameSite", skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageArea {
    Local,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkEvent {
    pub method: Option<String>,
    pub url: String,
    pub timestamp: Option<f64>,
    pub in_scope: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Screenshot {
    pub bytes: Vec<u8>,
    pub artifact: Artifact,
}

#[derive(Default)]
struct Usage {
    steps: u64,
    bytes: usize,
}

struct RuntimeInner {
    transport: Arc<dyn BrowserTransport>,
    policy: Policy,
    redactor: Redactor,
    config: BrowserRuntimeConfig,
    cancelled: Arc<AtomicBool>,
    sequence: AtomicU64,
    usage: Mutex<Usage>,
}

#[derive(Clone)]
pub struct BrowserRuntime(Arc<RuntimeInner>);

impl BrowserRuntime {
    /// Construct a runtime with a private cancellation flag.
    ///
    /// Callers that already own a run-wide cancellation flag should use
    /// [`Self::new_with_cancellation`] so cancellation is propagated into an
    /// in-flight WebDriver command and the plan executor's cleanup path.
    pub fn new(
        transport: Arc<dyn BrowserTransport>,
        policy: Policy,
        redactor: Redactor,
        config: BrowserRuntimeConfig,
    ) -> Result<Self> {
        Self::new_with_cancellation(
            transport,
            policy,
            redactor,
            config,
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Construct a runtime attached to the caller's shared cancellation flag.
    ///
    /// The flag is deliberately supplied separately from
    /// [`BrowserRuntimeConfig`], keeping that serializable configuration
    /// backward-compatible and ensuring process-local control state is never
    /// persisted. Setting the flag to `true` interrupts in-flight transport,
    /// waits, and all subsequent commands.
    pub fn new_with_cancellation(
        transport: Arc<dyn BrowserTransport>,
        policy: Policy,
        redactor: Redactor,
        config: BrowserRuntimeConfig,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        config.validate(&policy)?;
        if let Some(directory) = &config.artifact_directory {
            storage::secure_dir(directory)?;
        }
        Ok(Self(Arc::new(RuntimeInner {
            transport,
            policy,
            redactor,
            config,
            cancelled,
            sequence: AtomicU64::new(0),
            usage: Mutex::new(Usage::default()),
        })))
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Return the exact process-local flag observed by this runtime.
    ///
    /// This is useful when a component created the runtime before constructing
    /// other workers that must participate in the same cancellation domain.
    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.0.cancelled.clone()
    }

    pub async fn start_session(
        &self,
        actor: &str,
        request: SessionRequest,
    ) -> BrowserResult<BrowserSession> {
        let capabilities = requested_capabilities(&request, &self.0.config);
        let response = self
            .command(
                actor,
                None,
                BrowserAction::CreateSession,
                DriverRequest {
                    method: DriverMethod::Post,
                    path: "/session".into(),
                    body: Some(json!({"capabilities":{"alwaysMatch":capabilities}})),
                },
                false,
            )
            .await?;
        let value = webdriver_value(&response.value).map_err(|error| {
            self.protocol_failure(actor, BrowserAction::CreateSession, &error.to_string())
        })?;
        let session_id = value
            .get("sessionId")
            .and_then(Value::as_str)
            .or_else(|| response.value.get("sessionId").and_then(Value::as_str))
            .ok_or_else(|| {
                self.protocol_failure(actor, BrowserAction::CreateSession, "session id missing")
            })?
            .to_owned();
        validate_wire_id(&session_id).map_err(|error| {
            self.protocol_failure(actor, BrowserAction::CreateSession, &error.to_string())
        })?;
        let raw_caps = value
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let negotiated = negotiate(&request, &self.0.config, raw_caps);
        let session = BrowserSession {
            runtime: self.clone(),
            id: session_id,
            capabilities: negotiated,
            closed: Arc::new(AtomicBool::new(false)),
            command_lock: Arc::new(Mutex::new(())),
            redirects: Arc::new(Mutex::new(Vec::new())),
        };
        Ok(Observed {
            value: session,
            observation: response.observation,
        })
    }

    fn protocol_failure(
        &self,
        actor: &str,
        action: BrowserAction,
        message: &str,
    ) -> ObservedFailure {
        let error = BrowserError::new(BrowserErrorKind::Protocol, message);
        let record = BrowserObservationRecord {
            schema_version: 1,
            sequence: self.0.sequence.fetch_add(1, Ordering::SeqCst) + 1,
            actor: actor.into(),
            session_id: None,
            action,
            started_ms: now_ms(),
            duration_ms: 0,
            successful: false,
            current_url: None,
            redirect_chain: vec![],
            data: json!({}),
            artifacts: vec![],
            warnings: vec![],
            error_kind: Some(error.kind.clone()),
            error: Some(self.0.redactor.text(message)),
            truncated: false,
        };
        ObservedFailure {
            error,
            observation: BrowserObservation::from_record(record),
        }
    }

    async fn command(
        &self,
        actor: &str,
        session_id: Option<&str>,
        action: BrowserAction,
        request: DriverRequest,
        state_change: bool,
    ) -> BrowserResult<Value> {
        let started_ms = now_ms();
        let started = Instant::now();
        let sequence = self.0.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut usage = self.0.usage.lock().await;
            if usage.steps >= self.0.config.max_steps
                && !self.0.policy.bypasses(Control::RequestBudget)
            {
                return Err(self.failure(
                    actor,
                    session_id,
                    action,
                    started_ms,
                    started,
                    sequence,
                    BrowserError::new(BrowserErrorKind::Budget, "browser step budget exhausted"),
                ));
            }
            usage.steps += 1;
        }
        if self.is_cancelled() {
            return Err(self.failure(
                actor,
                session_id,
                action,
                started_ms,
                started,
                sequence,
                BrowserError::new(BrowserErrorKind::Cancelled, "browser run cancelled"),
            ));
        }
        if let Err(error) = self.0.policy.reserve(state_change, false) {
            return Err(self.failure(
                actor,
                session_id,
                action,
                started_ms,
                started,
                sequence,
                BrowserError::new(BrowserErrorKind::Policy, error.to_string()),
            ));
        }
        let send = self.0.transport.send(request);
        let result = tokio::select! {
            _ = wait_cancelled(&self.0.cancelled) => Err(BrowserError::new(BrowserErrorKind::Cancelled, "browser run cancelled")),
            result = tokio::time::timeout(Duration::from_millis(self.0.config.command_timeout_ms), send) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(BrowserError::new(BrowserErrorKind::Timeout, "WebDriver command timed out")),
                }
            }
        };
        let response = result.map_err(|error| {
            self.failure(
                actor,
                session_id,
                action.clone(),
                started_ms,
                started,
                sequence,
                error,
            )
        })?;
        {
            let mut usage = self.0.usage.lock().await;
            let exceeds = usage
                .bytes
                .checked_add(response.byte_count)
                .is_none_or(|total| total > self.0.config.max_total_bytes);
            if exceeds && !self.0.policy.bypasses(Control::DataSampling) {
                return Err(self.failure(
                    actor,
                    session_id,
                    action,
                    started_ms,
                    started,
                    sequence,
                    BrowserError::new(BrowserErrorKind::Budget, "browser byte budget exhausted"),
                ));
            }
            usage.bytes = usage.bytes.saturating_add(response.byte_count);
        }
        if response.status >= 400 || webdriver_error(&response.body).is_some() {
            let message = webdriver_error(&response.body).unwrap_or("WebDriver command failed");
            return Err(self.failure(
                actor,
                session_id,
                action,
                started_ms,
                started,
                sequence,
                BrowserError::new(BrowserErrorKind::Protocol, message),
            ));
        }
        let mut body = response.body;
        self.0.redactor.value(&mut body);
        let record = BrowserObservationRecord {
            schema_version: 1,
            sequence,
            actor: actor.into(),
            session_id: session_id.map(str::to_owned),
            action,
            started_ms,
            duration_ms: started.elapsed().as_millis() as u64,
            successful: true,
            current_url: None,
            redirect_chain: vec![],
            data: body.clone(),
            artifacts: vec![],
            warnings: vec![],
            error_kind: None,
            error: None,
            truncated: false,
        };
        Ok(Observed {
            value: body,
            observation: BrowserObservation::from_record(record),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn failure(
        &self,
        actor: &str,
        session_id: Option<&str>,
        action: BrowserAction,
        started_ms: u64,
        started: Instant,
        sequence: u64,
        mut error: BrowserError,
    ) -> ObservedFailure {
        error.message = self.0.redactor.text(&error.message);
        let record = BrowserObservationRecord {
            schema_version: 1,
            sequence,
            actor: actor.into(),
            session_id: session_id.map(str::to_owned),
            action,
            started_ms,
            duration_ms: started.elapsed().as_millis() as u64,
            successful: false,
            current_url: None,
            redirect_chain: vec![],
            data: json!({}),
            artifacts: vec![],
            warnings: vec![],
            error_kind: Some(error.kind.clone()),
            error: Some(error.message.clone()),
            truncated: false,
        };
        ObservedFailure {
            error,
            observation: BrowserObservation::from_record(record),
        }
    }
}

#[derive(Clone)]
pub struct BrowserSession {
    runtime: BrowserRuntime,
    id: String,
    capabilities: NegotiatedCapabilities,
    closed: Arc<AtomicBool>,
    command_lock: Arc<Mutex<()>>,
    redirects: Arc<Mutex<Vec<String>>>,
}

impl BrowserSession {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn capabilities(&self) -> &NegotiatedCapabilities {
        &self.capabilities
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub async fn close(&self, actor: &str) -> BrowserResult<()> {
        let _guard = self.command_lock.lock().await;
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(self.closed_failure(actor, BrowserAction::DeleteSession));
        }
        let result = self
            .raw(
                actor,
                BrowserAction::DeleteSession,
                DriverMethod::Delete,
                "",
                None,
                false,
            )
            .await;
        match result {
            Ok(result) => Ok(Observed {
                value: (),
                observation: result.observation,
            }),
            Err(error) => Err(error),
        }
    }

    pub async fn navigate(&self, actor: &str, url: &str) -> BrowserResult<String> {
        let _guard = self.command_lock.lock().await;
        if self.is_closed() {
            return Err(self.closed_failure(actor, BrowserAction::Navigate));
        }
        if let Err(error) = self.runtime.0.policy.check_url(url) {
            return Err(self.local_failure(
                actor,
                BrowserAction::Navigate,
                BrowserErrorKind::Policy,
                error.to_string(),
            ));
        }
        let mut result = self
            .raw(
                actor,
                BrowserAction::Navigate,
                DriverMethod::Post,
                "/url",
                Some(json!({"url":url})),
                false,
            )
            .await?;
        let current = self.current_url_locked(actor).await.inspect_err(|_error| {
            let _ = self.closed.swap(true, Ordering::SeqCst);
        })?;
        let mut chain = self.redirects.lock().await;
        chain.clear();
        chain.push(url.to_owned());
        if current.value != url {
            chain.push(current.value.clone());
        }
        result.observation.record.current_url = Some(current.value.clone());
        result.observation.record.redirect_chain = chain.clone();
        result.observation = BrowserObservation::from_record(result.observation.record);
        drop(chain);
        if let Err(error) = self.runtime.0.policy.check_url(&current.value) {
            if self.runtime.0.config.quarantine_on_scope_escape {
                self.quarantine().await;
            }
            return Err(self.local_failure(
                actor,
                BrowserAction::Navigate,
                BrowserErrorKind::ScopeEscape,
                format!("redirect/current URL escaped scope: {error}"),
            ));
        }
        Ok(Observed {
            value: current.value,
            observation: result.observation,
        })
    }

    pub async fn current_url(&self, actor: &str) -> BrowserResult<String> {
        let _guard = self.command_lock.lock().await;
        self.current_url_locked(actor).await
    }

    async fn current_url_locked(&self, actor: &str) -> BrowserResult<String> {
        let result = self
            .raw(
                actor,
                BrowserAction::CurrentUrl,
                DriverMethod::Get,
                "/url",
                None,
                false,
            )
            .await?;
        let value = webdriver_value(&result.value).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::CurrentUrl,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        let url = value.as_str().ok_or_else(|| {
            self.local_failure(
                actor,
                BrowserAction::CurrentUrl,
                BrowserErrorKind::Protocol,
                "current URL missing",
            )
        })?;
        Ok(Observed {
            value: url.to_owned(),
            observation: result.observation,
        })
    }

    pub async fn find(&self, actor: &str, locator: Locator) -> BrowserResult<ElementRef> {
        let _guard = self.command_lock.lock().await;
        self.find_locked(actor, locator).await
    }

    async fn find_locked(&self, actor: &str, locator: Locator) -> BrowserResult<ElementRef> {
        let (using, value) = locator.wire().map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::FindElement,
                BrowserErrorKind::InvalidInput,
                error.to_string(),
            )
        })?;
        let value = match locator {
            Locator::Id(_) => format!("[id={}]", css_string(value)),
            Locator::Name(_) => format!("[name={}]", css_string(value)),
            _ => value.to_owned(),
        };
        let result = self
            .raw(
                actor,
                BrowserAction::FindElement,
                DriverMethod::Post,
                "/element",
                Some(json!({"using":using,"value":value})),
                false,
            )
            .await?;
        let body = webdriver_value(&result.value).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::FindElement,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        let id = body
            .get(W3C_ELEMENT_KEY)
            .or_else(|| body.get("ELEMENT"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.local_failure(
                    actor,
                    BrowserAction::FindElement,
                    BrowserErrorKind::Protocol,
                    "element reference missing",
                )
            })?;
        validate_wire_id(id).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::FindElement,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        Ok(Observed {
            value: ElementRef { id: id.into() },
            observation: result.observation,
        })
    }

    pub async fn click(&self, actor: &str, element: &ElementRef) -> BrowserResult<()> {
        self.element_command(
            actor,
            BrowserAction::Click,
            element,
            "/click",
            Some(json!({})),
            true,
        )
        .await
    }

    pub async fn clear(&self, actor: &str, element: &ElementRef) -> BrowserResult<()> {
        self.element_command(
            actor,
            BrowserAction::Clear,
            element,
            "/clear",
            Some(json!({})),
            true,
        )
        .await
    }

    pub async fn send_keys(
        &self,
        actor: &str,
        element: &ElementRef,
        text: &str,
    ) -> BrowserResult<()> {
        if text.len() > 65_536 || text.contains('\0') {
            return Err(self.local_failure(
                actor,
                BrowserAction::SendKeys,
                BrowserErrorKind::InvalidInput,
                "invalid form input",
            ));
        }
        self.element_command(actor, BrowserAction::SendKeys, element, "/value", Some(json!({"text":text,"value":text.chars().map(|c|c.to_string()).collect::<Vec<_>>() })), true).await
    }

    pub async fn fill(&self, actor: &str, locator: Locator, text: &str) -> BrowserResult<()> {
        let found = self.find(actor, locator).await?;
        self.clear(actor, &found.value).await?;
        self.send_keys(actor, &found.value, text).await
    }

    pub async fn submit(&self, actor: &str, element: &ElementRef) -> BrowserResult<()> {
        self.element_command(
            actor,
            BrowserAction::SubmitForm,
            element,
            "/submit",
            Some(json!({})),
            true,
        )
        .await
    }

    async fn element_command(
        &self,
        actor: &str,
        action: BrowserAction,
        element: &ElementRef,
        suffix: &str,
        body: Option<Value>,
        state_change: bool,
    ) -> BrowserResult<()> {
        validate_wire_id(&element.id).map_err(|error| {
            self.local_failure(
                actor,
                action.clone(),
                BrowserErrorKind::InvalidInput,
                error.to_string(),
            )
        })?;
        let _guard = self.command_lock.lock().await;
        let path = format!("/element/{}{}", element.id, suffix);
        let result = self
            .raw(
                actor,
                action.clone(),
                DriverMethod::Post,
                &path,
                body,
                state_change,
            )
            .await?;
        let result = if state_change {
            self.check_current_after(actor, action, result).await?
        } else {
            result
        };
        Ok(Observed {
            value: (),
            observation: result.observation,
        })
    }

    pub async fn evaluate_script(
        &self,
        actor: &str,
        script: &str,
        args: Vec<Value>,
    ) -> BrowserResult<Value> {
        if !self.runtime.0.config.allow_raw_javascript {
            return Err(self.local_failure(
                actor,
                BrowserAction::EvaluateScript,
                BrowserErrorKind::Capability,
                "raw JavaScript capability is disabled",
            ));
        }
        if !self.capabilities.supports_javascript {
            return Err(self.local_failure(
                actor,
                BrowserAction::EvaluateScript,
                BrowserErrorKind::Capability,
                "backend did not negotiate JavaScript",
            ));
        }
        if script.len() > 65_536 || script.contains('\0') {
            return Err(self.local_failure(
                actor,
                BrowserAction::EvaluateScript,
                BrowserErrorKind::InvalidInput,
                "invalid script",
            ));
        }
        let _guard = self.command_lock.lock().await;
        let result = self
            .raw(
                actor,
                BrowserAction::EvaluateScript,
                DriverMethod::Post,
                "/execute/sync",
                Some(json!({"script":script,"args":args})),
                true,
            )
            .await?;
        let result = self
            .check_current_after(actor, BrowserAction::EvaluateScript, result)
            .await?;
        let mut value = webdriver_value(&result.value)
            .map_err(|error| {
                self.local_failure(
                    actor,
                    BrowserAction::EvaluateScript,
                    BrowserErrorKind::Protocol,
                    error.to_string(),
                )
            })?
            .clone();
        self.runtime.0.redactor.value(&mut value);
        Ok(Observed {
            value,
            observation: result.observation,
        })
    }

    pub async fn cookies(&self, actor: &str) -> BrowserResult<Vec<Cookie>> {
        let _guard = self.command_lock.lock().await;
        let mut result = self
            .raw(
                actor,
                BrowserAction::GetCookies,
                DriverMethod::Get,
                "/cookie",
                None,
                false,
            )
            .await?;
        let value = webdriver_value(&result.value).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::GetCookies,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        let mut cookies: Vec<Cookie> = serde_json::from_value(value.clone()).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::GetCookies,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        for cookie in &mut cookies {
            cookie.value = self
                .runtime
                .0
                .redactor
                .text(&format!("cookie={}", cookie.value));
        }
        result.observation.record.data = json!({"value":cookies});
        result.observation = BrowserObservation::from_record(result.observation.record);
        Ok(Observed {
            value: cookies,
            observation: result.observation,
        })
    }

    pub async fn add_cookie(&self, actor: &str, cookie: Cookie) -> BrowserResult<()> {
        ensure_cookie(&cookie).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::AddCookie,
                BrowserErrorKind::InvalidInput,
                error.to_string(),
            )
        })?;
        let _guard = self.command_lock.lock().await;
        let result = self
            .raw(
                actor,
                BrowserAction::AddCookie,
                DriverMethod::Post,
                "/cookie",
                Some(json!({"cookie":cookie})),
                true,
            )
            .await?;
        Ok(Observed {
            value: (),
            observation: result.observation,
        })
    }

    pub async fn delete_cookie(&self, actor: &str, name: Option<&str>) -> BrowserResult<()> {
        let path = match name {
            Some(name) => {
                validate_cookie_name(name).map_err(|error| {
                    self.local_failure(
                        actor,
                        BrowserAction::DeleteCookie,
                        BrowserErrorKind::InvalidInput,
                        error.to_string(),
                    )
                })?;
                format!("/cookie/{name}")
            }
            None => "/cookie".into(),
        };
        let _guard = self.command_lock.lock().await;
        let result = self
            .raw(
                actor,
                BrowserAction::DeleteCookie,
                DriverMethod::Delete,
                &path,
                None,
                true,
            )
            .await?;
        Ok(Observed {
            value: (),
            observation: result.observation,
        })
    }

    pub async fn storage_get(
        &self,
        actor: &str,
        area: StorageArea,
        key: &str,
    ) -> BrowserResult<Option<String>> {
        validate_storage_key(key).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::GetStorage,
                BrowserErrorKind::InvalidInput,
                error.to_string(),
            )
        })?;
        let script = format!("return {}.getItem(arguments[0]);", storage_name(area));
        self.typed_script(
            actor,
            BrowserAction::GetStorage,
            &script,
            vec![json!(key)],
            false,
        )
        .await
        .map(|observed| Observed {
            value: observed.value.as_str().map(str::to_owned),
            observation: observed.observation,
        })
    }

    pub async fn storage_set(
        &self,
        actor: &str,
        area: StorageArea,
        key: &str,
        value: &str,
    ) -> BrowserResult<()> {
        validate_storage_key(key).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::SetStorage,
                BrowserErrorKind::InvalidInput,
                error.to_string(),
            )
        })?;
        if value.len() > 1_048_576 {
            return Err(self.local_failure(
                actor,
                BrowserAction::SetStorage,
                BrowserErrorKind::InvalidInput,
                "storage value too large",
            ));
        }
        let script = format!(
            "{}.setItem(arguments[0], arguments[1]);",
            storage_name(area)
        );
        let result = self
            .typed_script(
                actor,
                BrowserAction::SetStorage,
                &script,
                vec![json!(key), json!(value)],
                true,
            )
            .await?;
        Ok(Observed {
            value: (),
            observation: result.observation,
        })
    }

    pub async fn storage_clear(&self, actor: &str, area: StorageArea) -> BrowserResult<()> {
        let script = format!("{}.clear();", storage_name(area));
        let result = self
            .typed_script(actor, BrowserAction::ClearStorage, &script, vec![], true)
            .await?;
        Ok(Observed {
            value: (),
            observation: result.observation,
        })
    }

    async fn typed_script(
        &self,
        actor: &str,
        action: BrowserAction,
        script: &str,
        args: Vec<Value>,
        state_change: bool,
    ) -> BrowserResult<Value> {
        if !self.capabilities.supports_javascript {
            return Err(self.local_failure(
                actor,
                action,
                BrowserErrorKind::Capability,
                "backend did not negotiate JavaScript",
            ));
        }
        let _guard = self.command_lock.lock().await;
        let result = self
            .raw(
                actor,
                action.clone(),
                DriverMethod::Post,
                "/execute/sync",
                Some(json!({"script":script,"args":args})),
                state_change,
            )
            .await?;
        let value = webdriver_value(&result.value)
            .map_err(|error| {
                self.local_failure(actor, action, BrowserErrorKind::Protocol, error.to_string())
            })?
            .clone();
        Ok(Observed {
            value,
            observation: result.observation,
        })
    }

    pub async fn screenshot(&self, actor: &str) -> BrowserResult<Screenshot> {
        let _guard = self.command_lock.lock().await;
        let mut result = self
            .raw(
                actor,
                BrowserAction::Screenshot,
                DriverMethod::Get,
                "/screenshot",
                None,
                false,
            )
            .await?;
        let encoded = webdriver_value(&result.value)
            .map_err(|error| {
                self.local_failure(
                    actor,
                    BrowserAction::Screenshot,
                    BrowserErrorKind::Protocol,
                    error.to_string(),
                )
            })?
            .as_str()
            .ok_or_else(|| {
                self.local_failure(
                    actor,
                    BrowserAction::Screenshot,
                    BrowserErrorKind::Protocol,
                    "screenshot data missing",
                )
            })?;
        let bytes = BASE64.decode(encoded).map_err(|error| {
            self.local_failure(
                actor,
                BrowserAction::Screenshot,
                BrowserErrorKind::Protocol,
                error.to_string(),
            )
        })?;
        if bytes.len() > self.runtime.0.config.max_artifact_bytes
            && !self.runtime.0.policy.bypasses(Control::DataSampling)
        {
            return Err(self.local_failure(
                actor,
                BrowserAction::Screenshot,
                BrowserErrorKind::Budget,
                "screenshot exceeds artifact byte budget",
            ));
        }
        let sha256 = hash(&bytes);
        let path = if let Some(directory) = &self.runtime.0.config.artifact_directory {
            let path = directory.join(format!("screenshot-{sha256}.png"));
            if !path.exists() {
                storage::atomic_write(&path, &bytes).map_err(|error| {
                    self.local_failure(
                        actor,
                        BrowserAction::Screenshot,
                        BrowserErrorKind::Artifact,
                        error.to_string(),
                    )
                })?;
            }
            Some(path)
        } else {
            None
        };
        let artifact = Artifact {
            kind: "screenshot".into(),
            path,
            media_type: "image/png".into(),
            byte_count: bytes.len(),
            sha256,
        };
        result.observation.record.artifacts.push(artifact.clone());
        result.observation.record.data = json!({"artifact":artifact});
        result.observation = BrowserObservation::from_record(result.observation.record);
        Ok(Observed {
            value: Screenshot { bytes, artifact },
            observation: result.observation,
        })
    }

    pub async fn console_logs(&self, actor: &str) -> BrowserResult<Vec<Value>> {
        if !self.capabilities.supports_console_logs {
            return Err(self.local_failure(
                actor,
                BrowserAction::ConsoleLogs,
                BrowserErrorKind::Capability,
                "console logs were not negotiated",
            ));
        }
        self.logs(actor, BrowserAction::ConsoleLogs, "browser")
            .await
    }

    pub async fn network_logs(&self, actor: &str) -> BrowserResult<Vec<NetworkEvent>> {
        if !self.capabilities.supports_network_logs {
            return Err(self.local_failure(
                actor,
                BrowserAction::NetworkLogs,
                BrowserErrorKind::Capability,
                "network logs were not negotiated",
            ));
        }
        let logs = self
            .logs(actor, BrowserAction::NetworkLogs, "performance")
            .await?;
        let mut events = Vec::new();
        let mut escape = None;
        for log in logs.value {
            if let Some(event) = parse_network_event(&log) {
                let in_scope = self.runtime.0.policy.check_url(&event.url).is_ok();
                if !in_scope {
                    escape = Some(event.url.clone());
                }
                events.push(NetworkEvent { in_scope, ..event });
            }
        }
        if let Some(url) = escape {
            if self.runtime.0.config.quarantine_on_scope_escape {
                self.quarantine().await;
            }
            return Err(self.local_failure(
                actor,
                BrowserAction::NetworkLogs,
                BrowserErrorKind::ScopeEscape,
                format!("discovered request outside scope: {url}"),
            ));
        }
        Ok(Observed {
            value: events,
            observation: logs.observation,
        })
    }

    async fn logs(
        &self,
        actor: &str,
        action: BrowserAction,
        kind: &str,
    ) -> BrowserResult<Vec<Value>> {
        let _guard = self.command_lock.lock().await;
        let result = self
            .raw(
                actor,
                action.clone(),
                DriverMethod::Post,
                "/se/log",
                Some(json!({"type":kind})),
                false,
            )
            .await?;
        let value = webdriver_value(&result.value).map_err(|error| {
            self.local_failure(actor, action, BrowserErrorKind::Protocol, error.to_string())
        })?;
        let mut logs = value.as_array().cloned().ok_or_else(|| {
            self.local_failure(
                actor,
                BrowserAction::ConsoleLogs,
                BrowserErrorKind::Protocol,
                "log array missing",
            )
        })?;
        for value in &mut logs {
            self.runtime.0.redactor.value(value);
        }
        Ok(Observed {
            value: logs,
            observation: result.observation,
        })
    }

    pub async fn wait_for(
        &self,
        actor: &str,
        locator: Locator,
        timeout_ms: u64,
    ) -> BrowserResult<ElementRef> {
        if timeout_ms == 0 {
            return Err(self.local_failure(
                actor,
                BrowserAction::Wait,
                BrowserErrorKind::InvalidInput,
                "wait timeout must be positive",
            ));
        }
        let start = Instant::now();
        loop {
            if self.runtime.is_cancelled() {
                return Err(self.local_failure(
                    actor,
                    BrowserAction::Wait,
                    BrowserErrorKind::Cancelled,
                    "browser run cancelled",
                ));
            }
            match self.find(actor, locator.clone()).await {
                Ok(found) => return Ok(found),
                Err(error) if matches!(error.error.kind, BrowserErrorKind::Protocol) => {}
                Err(error) => return Err(error),
            }
            if start.elapsed() >= Duration::from_millis(timeout_ms) {
                return Err(self.local_failure(
                    actor,
                    BrowserAction::Wait,
                    BrowserErrorKind::Timeout,
                    "element wait timed out",
                ));
            }
            tokio::time::sleep(Duration::from_millis(
                self.runtime.0.config.poll_interval_ms,
            ))
            .await;
        }
    }

    async fn raw(
        &self,
        actor: &str,
        action: BrowserAction,
        method: DriverMethod,
        suffix: &str,
        body: Option<Value>,
        state_change: bool,
    ) -> BrowserResult<Value> {
        if self.is_closed() && action != BrowserAction::DeleteSession {
            return Err(self.closed_failure(actor, action));
        }
        let path = format!("/session/{}{}", self.id, suffix);
        self.runtime
            .command(
                actor,
                Some(&self.id),
                action,
                DriverRequest { method, path, body },
                state_change,
            )
            .await
    }

    async fn quarantine(&self) -> bool {
        self.closed.store(true, Ordering::SeqCst);
        let request = self.runtime.0.transport.send(DriverRequest {
            method: DriverMethod::Delete,
            path: format!("/session/{}", self.id),
            body: None,
        });
        // Cleanup must not inherit the already-triggered cancellation signal,
        // otherwise the DELETE would never be attempted. Bound the independent
        // best-effort request so a wedged driver cannot delay cancellation for
        // the full normal command timeout.
        let timeout = Duration::from_millis(self.runtime.0.config.command_timeout_ms.min(1_000));
        tokio::time::timeout(timeout, request)
            .await
            .is_ok_and(|result| result.is_ok())
    }

    async fn check_current_after(
        &self,
        actor: &str,
        action: BrowserAction,
        mut result: Observed<Value>,
    ) -> BrowserResult<Value> {
        let current = self.current_url_locked(actor).await?;
        if let Err(error) = self.runtime.0.policy.check_url(&current.value) {
            if self.runtime.0.config.quarantine_on_scope_escape {
                self.quarantine().await;
            }
            return Err(self.local_failure(
                actor,
                action,
                BrowserErrorKind::ScopeEscape,
                format!("browser interaction navigated outside scope: {error}"),
            ));
        }
        result.observation.record.current_url = Some(current.value);
        result.observation = BrowserObservation::from_record(result.observation.record);
        Ok(result)
    }

    fn closed_failure(&self, actor: &str, action: BrowserAction) -> ObservedFailure {
        self.local_failure(
            actor,
            action,
            BrowserErrorKind::Closed,
            "browser session is closed",
        )
    }

    fn local_failure(
        &self,
        actor: &str,
        action: BrowserAction,
        kind: BrowserErrorKind,
        message: impl Into<String>,
    ) -> ObservedFailure {
        let message = message.into();
        let error = BrowserError::new(kind, self.runtime.0.redactor.text(&message));
        let record = BrowserObservationRecord {
            schema_version: 1,
            sequence: self.runtime.0.sequence.fetch_add(1, Ordering::SeqCst) + 1,
            actor: actor.into(),
            session_id: Some(self.id.clone()),
            action,
            started_ms: now_ms(),
            duration_ms: 0,
            successful: false,
            current_url: None,
            redirect_chain: vec![],
            data: json!({}),
            artifacts: vec![],
            warnings: vec![],
            error_kind: Some(error.kind.clone()),
            error: Some(error.message.clone()),
            truncated: false,
        };
        ObservedFailure {
            error,
            observation: BrowserObservation::from_record(record),
        }
    }
}

fn requested_capabilities(request: &SessionRequest, config: &BrowserRuntimeConfig) -> Value {
    let browser_name = match request.browser {
        BrowserKind::Chrome => "chrome",
        BrowserKind::Firefox => "firefox",
        BrowserKind::Safari => "safari",
        BrowserKind::Compatible => "",
    };
    let mut caps = serde_json::Map::new();
    if !browser_name.is_empty() {
        caps.insert("browserName".into(), json!(browser_name));
    }
    caps.insert(
        "acceptInsecureCerts".into(),
        json!(request.accept_insecure_certificates),
    );
    for (key, value) in &request.additional_capabilities {
        caps.insert(key.clone(), value.clone());
    }
    match request.browser {
        BrowserKind::Chrome => {
            let args = if request.headless {
                vec!["--headless=new", "--disable-gpu"]
            } else {
                vec![]
            };
            caps.insert("goog:chromeOptions".into(), json!({"args":args,"prefs":{"download_restrictions":if config.allow_downloads {0} else {3},"download.prompt_for_download":!config.allow_downloads}}));
            caps.insert(
                "goog:loggingPrefs".into(),
                json!({"browser":"ALL","performance":"ALL"}),
            );
        }
        BrowserKind::Firefox => {
            let args = if request.headless {
                vec!["-headless"]
            } else {
                vec![]
            };
            caps.insert("moz:firefoxOptions".into(), json!({"args":args,"prefs":{"browser.download.useDownloadDir":config.allow_downloads,"browser.download.alwaysOpenPanel":false}}));
        }
        BrowserKind::Safari | BrowserKind::Compatible => {}
    }
    Value::Object(caps)
}

fn negotiate(
    request: &SessionRequest,
    config: &BrowserRuntimeConfig,
    raw: Value,
) -> NegotiatedCapabilities {
    let browser_name = raw
        .get("browserName")
        .and_then(Value::as_str)
        .unwrap_or(match request.browser {
            BrowserKind::Chrome => "chrome",
            BrowserKind::Firefox => "firefox",
            BrowserKind::Safari => "safari",
            BrowserKind::Compatible => "compatible",
        })
        .to_owned();
    let lower = browser_name.to_ascii_lowercase();
    let is_chromium =
        lower.contains("chrome") || lower.contains("chromium") || lower.contains("edge");
    NegotiatedCapabilities {
        browser_name,
        browser_version: raw
            .get("browserVersion")
            .and_then(Value::as_str)
            .map(str::to_owned),
        platform_name: raw
            .get("platformName")
            .and_then(Value::as_str)
            .map(str::to_owned),
        supports_javascript: true,
        supports_console_logs: is_chromium,
        supports_network_logs: is_chromium,
        supports_request_interception: false,
        downloads_allowed: config.allow_downloads,
        raw,
    }
}

fn webdriver_value(body: &Value) -> Result<&Value> {
    body.get("value").context("WebDriver value missing")
}

fn webdriver_error(body: &Value) -> Option<&str> {
    body.get("value")
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
        .or_else(|| body.get("error").and_then(Value::as_str))
}

fn validate_wire_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 512
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid WebDriver identifier"
    );
    Ok(())
}

fn css_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn validate_cookie_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 256
            && !name
                .chars()
                .any(|c| c.is_control() || matches!(c, ';' | ',' | '=')),
        "invalid cookie name"
    );
    Ok(())
}

fn ensure_cookie(cookie: &Cookie) -> Result<()> {
    validate_cookie_name(&cookie.name)?;
    ensure!(
        cookie.value.len() <= 16_384 && !cookie.value.contains(['\r', '\n']),
        "invalid cookie value"
    );
    Ok(())
}

fn validate_storage_key(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty() && key.len() <= 4_096 && !key.contains('\0'),
        "invalid storage key"
    );
    Ok(())
}

fn storage_name(area: StorageArea) -> &'static str {
    match area {
        StorageArea::Local => "window.localStorage",
        StorageArea::Session => "window.sessionStorage",
    }
}

fn parse_network_event(log: &Value) -> Option<NetworkEvent> {
    let message = log.get("message")?;
    let parsed = if let Some(text) = message.as_str() {
        serde_json::from_str::<Value>(text).ok()?
    } else {
        message.clone()
    };
    let inner = parsed.get("message").unwrap_or(&parsed);
    if inner.get("method")?.as_str()? != "Network.requestWillBeSent" {
        return None;
    }
    let request = inner.pointer("/params/request")?;
    Some(NetworkEvent {
        method: request
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned),
        url: request.get("url")?.as_str()?.to_owned(),
        timestamp: inner.pointer("/params/timestamp").and_then(Value::as_f64),
        in_scope: false,
    })
}

async fn wait_cancelled(cancelled: &AtomicBool) {
    while !cancelled.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Backend matrix is exported for UX/reporting; consumers should not imply
/// stronger guarantees than the selected backend provides.
pub fn backend_limitations() -> Value {
    json!({
        "backend":"w3c_webdriver_http",
        "portable":["session_lifecycle","navigation","dom","forms","cookies","web_storage","screenshots","timeouts","cancellation"],
        "conditional":["console_logs","performance_network_logs"],
        "not_supported":["portable_pre_request_interception","portable_response_body_capture","portable_download_observation"],
        "scope_model":"preflight top-level navigation; post-navigation redirect validation; post-hoc validation of requests exposed by negotiated performance logs"
    })
}
