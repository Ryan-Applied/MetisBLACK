use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use domain::{NetworkRule, Scope};
use futures::future::BoxFuture;
use metisblack_browser_runtime::{
    BrowserCheckpoint, BrowserError, BrowserErrorKind, BrowserPlan, BrowserPlanExecutor,
    BrowserPlanStatus, BrowserRuntime, BrowserRuntimeConfig, BrowserStep, BrowserStepAction,
    BrowserTransport, CleanupOutcome, DriverMethod, DriverRequest, DriverResponse, Locator,
    PlanValue, SecretResolver, SessionRequest, StorageArea, W3C_ELEMENT_KEY,
};
use policy::Policy;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use storage::Redactor;
use zeroize::Zeroizing;

#[derive(Default)]
struct MockState {
    current_url: String,
    redirect_to: Option<String>,
    deleted: bool,
    typed: Vec<String>,
    requests: Vec<DriverRequest>,
    performance_logs: Vec<Value>,
    fail_find: bool,
}

#[derive(Default)]
struct MockWebDriver {
    state: Mutex<MockState>,
    delay_ms: AtomicU64,
    delay_path: Mutex<Option<String>>,
    delayed_request_started: AtomicBool,
}

impl MockWebDriver {
    fn redirect_to(&self, url: &str) {
        self.state.lock().expect("state").redirect_to = Some(url.into());
    }

    fn delay(&self, delay_ms: u64) {
        *self.delay_path.lock().expect("delay path") = None;
        self.delay_ms.store(delay_ms, Ordering::SeqCst);
    }

    fn delay_path(&self, path: &str, delay_ms: u64) {
        *self.delay_path.lock().expect("delay path") = Some(path.into());
        self.delayed_request_started.store(false, Ordering::SeqCst);
        self.delay_ms.store(delay_ms, Ordering::SeqCst);
    }

    fn network_request(&self, url: &str) {
        self.state.lock().expect("state").performance_logs.push(
            json!({"message":serde_json::to_string(&json!({
                "message":{
                    "method":"Network.requestWillBeSent",
                    "params":{"timestamp":1.0,"request":{"method":"GET","url":url}}
                }
            })).expect("json")}),
        );
    }

    fn fail_find(&self) {
        self.state.lock().expect("state").fail_find = true;
    }

    fn response(value: Value) -> DriverResponse {
        let body = json!({"value":value});
        DriverResponse {
            status: 200,
            byte_count: serde_json::to_vec(&body).expect("json").len(),
            body,
        }
    }
}

impl BrowserTransport for MockWebDriver {
    fn send<'a>(
        &'a self,
        request: DriverRequest,
    ) -> BoxFuture<'a, std::result::Result<DriverResponse, BrowserError>> {
        Box::pin(async move {
            let delay = self.delay_ms.load(Ordering::SeqCst);
            let delay_path = self.delay_path.lock().expect("delay path").clone();
            let should_delay =
                delay > 0 && delay_path.as_ref().is_none_or(|path| path == &request.path);
            if should_delay {
                self.delayed_request_started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let mut state = self.state.lock().expect("state");
            state.requests.push(request.clone());
            let path = request.path.as_str();
            let response = match (request.method, path) {
                (DriverMethod::Post, "/session") => Self::response(json!({
                    "sessionId":"test-session",
                    "capabilities":{"browserName":"chrome","browserVersion":"130","platformName":"test"}
                })),
                (DriverMethod::Post, "/session/test-session/url") => {
                    let requested = request
                        .body
                        .as_ref()
                        .and_then(|body| body.get("url"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    state.current_url = state
                        .redirect_to
                        .clone()
                        .unwrap_or_else(|| requested.to_owned());
                    Self::response(Value::Null)
                }
                (DriverMethod::Get, "/session/test-session/url") => {
                    Self::response(json!(state.current_url))
                }
                (DriverMethod::Post, "/session/test-session/element") if state.fail_find => {
                    let body =
                        json!({"value":{"error":"no such element","message":"element missing"}});
                    DriverResponse {
                        status: 404,
                        byte_count: serde_json::to_vec(&body).expect("json").len(),
                        body,
                    }
                }
                (DriverMethod::Post, "/session/test-session/element") => {
                    Self::response(json!({W3C_ELEMENT_KEY:"element-1"}))
                }
                (DriverMethod::Post, "/session/test-session/element/element-1/value") => {
                    let text = request
                        .body
                        .as_ref()
                        .and_then(|body| body.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    state.typed.push(text.into());
                    Self::response(Value::Null)
                }
                (DriverMethod::Post, path)
                    if path.starts_with("/session/test-session/element/element-1/") =>
                {
                    Self::response(Value::Null)
                }
                (DriverMethod::Get, "/session/test-session/screenshot") => {
                    Self::response(json!(BASE64.encode(b"\x89PNG\r\nmock")))
                }
                (DriverMethod::Get, "/session/test-session/cookie") => Self::response(json!([{
                    "name":"session","value":"super-secret-cookie","path":"/","secure":true,
                    "httpOnly":true,"sameSite":"Strict","expiry":null,"domain":"app.test"
                }])),
                (DriverMethod::Post, "/session/test-session/se/log") => {
                    Self::response(json!(std::mem::take(&mut state.performance_logs)))
                }
                (DriverMethod::Delete, "/session/test-session") => {
                    state.deleted = true;
                    Self::response(Value::Null)
                }
                _ => Self::response(Value::Null),
            };
            Ok(response)
        })
    }
}

fn policy() -> Result<Policy> {
    Policy::new(Scope {
        network: vec![NetworkRule {
            host: "app.test".into(),
            subdomains: false,
            ports: vec![443],
            paths: vec!["/".into()],
        }],
        max_requests: 100,
        max_state_changes: 20,
        tool_timeout_ms: 2_000,
        ..Scope::default()
    })
}

fn runtime(driver: Arc<MockWebDriver>, mut config: BrowserRuntimeConfig) -> Result<BrowserRuntime> {
    config.authorized = true;
    BrowserRuntime::new(driver, policy()?, Redactor::default(), config)
}

#[derive(Default)]
struct MapSecretResolver(BTreeMap<String, String>);

impl SecretResolver for MapSecretResolver {
    fn resolve(&self, name: &str) -> std::result::Result<Zeroizing<String>, BrowserError> {
        self.0
            .get(name)
            .cloned()
            .map(Zeroizing::new)
            .ok_or_else(|| BrowserError {
                kind: BrowserErrorKind::InvalidInput,
                message: format!("missing test secret {name}"),
            })
    }
}

fn login_plan() -> BrowserPlan {
    BrowserPlan {
        schema_version: 1,
        name: "login-flow".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![
            BrowserStep {
                id: "navigate".into(),
                action: BrowserStepAction::Navigate {
                    url: "https://app.test/login".into(),
                },
            },
            BrowserStep {
                id: "username".into(),
                action: BrowserStepAction::Fill {
                    locator: Locator::Name("username".into()),
                    value: PlanValue::Public {
                        value: "test-user".into(),
                    },
                },
            },
            BrowserStep {
                id: "password".into(),
                action: BrowserStepAction::Fill {
                    locator: Locator::Name("password".into()),
                    value: PlanValue::Environment {
                        name: "LOGIN_PASSWORD".into(),
                    },
                },
            },
            BrowserStep {
                id: "find-submit".into(),
                action: BrowserStepAction::Find {
                    locator: Locator::Css("button[type=submit]".into()),
                    alias: "submit".into(),
                },
            },
            BrowserStep {
                id: "click-submit".into(),
                action: BrowserStepAction::Click {
                    alias: "submit".into(),
                },
            },
            BrowserStep {
                id: "save-session".into(),
                action: BrowserStepAction::SetStorage {
                    area: StorageArea::Session,
                    key: "test-token".into(),
                    value: PlanValue::Environment {
                        name: "LOGIN_PASSWORD".into(),
                    },
                },
            },
            BrowserStep {
                id: "evidence".into(),
                action: BrowserStepAction::Screenshot,
            },
        ],
    }
}

#[tokio::test]
async fn serializable_plan_executes_login_flow_without_serializing_secret() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let directory = tempfile::tempdir()?;
    let runtime = runtime(
        driver.clone(),
        BrowserRuntimeConfig {
            artifact_directory: Some(directory.path().into()),
            ..BrowserRuntimeConfig::default()
        },
    )?;
    let secrets = Arc::new(MapSecretResolver(BTreeMap::from([(
        "LOGIN_PASSWORD".into(),
        "correct-horse-battery-staple".into(),
    )])));
    let executor = BrowserPlanExecutor::with_secret_resolver(runtime, secrets);
    let plan = login_plan();
    let serialized_plan = serde_json::to_string(&plan)?;
    assert!(serialized_plan.contains("LOGIN_PASSWORD"));
    assert!(!serialized_plan.contains("correct-horse-battery-staple"));

    let result = executor.execute(&plan).await?;
    assert_eq!(result.status, BrowserPlanStatus::Completed);
    assert_eq!(result.cleanup, CleanupOutcome::Closed);
    assert_eq!(result.steps.len(), plan.steps.len());
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.final_url.as_deref(), Some("https://app.test/login"));
    assert!(result.observations.iter().all(|item| item.verify()));
    let serialized_result = serde_json::to_string(&result)?;
    assert!(!serialized_result.contains("correct-horse-battery-staple"));
    assert!(driver.state.lock().expect("state").deleted);
    assert_eq!(
        driver.state.lock().expect("state").typed,
        vec!["test-user", "correct-horse-battery-staple"]
    );
    Ok(())
}

#[tokio::test]
async fn plan_failure_quarantines_and_deletes_session() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    driver.fail_find();
    let runtime = runtime(driver.clone(), BrowserRuntimeConfig::default())?;
    let executor =
        BrowserPlanExecutor::with_secret_resolver(runtime, Arc::new(MapSecretResolver::default()));
    let plan = BrowserPlan {
        schema_version: 1,
        name: "failing-flow".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![
            BrowserStep {
                id: "navigate".into(),
                action: BrowserStepAction::Navigate {
                    url: "https://app.test/login".into(),
                },
            },
            BrowserStep {
                id: "missing".into(),
                action: BrowserStepAction::Find {
                    locator: Locator::Id("missing".into()),
                    alias: "missing".into(),
                },
            },
            BrowserStep {
                id: "never-run".into(),
                action: BrowserStepAction::Screenshot,
            },
        ],
    };
    let result = executor.execute(&plan).await?;
    assert_eq!(result.status, BrowserPlanStatus::Failed);
    assert_eq!(result.steps.len(), 2);
    assert!(!result.steps[1].successful);
    assert!(matches!(
        result.cleanup,
        CleanupOutcome::Quarantined {
            driver_acknowledged: true
        }
    ));
    assert!(driver.state.lock().expect("state").deleted);
    Ok(())
}

#[tokio::test]
async fn shared_cancellation_interrupts_plan_and_quarantines_session() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    driver.delay_path("/session/test-session/url", 5_000);
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut config = BrowserRuntimeConfig {
        command_timeout_ms: 2_000,
        ..BrowserRuntimeConfig::default()
    };
    config.authorized = true;
    let runtime = BrowserRuntime::new_with_cancellation(
        driver.clone(),
        policy()?,
        Redactor::default(),
        config,
        cancelled.clone(),
    )?;
    assert!(Arc::ptr_eq(&runtime.cancellation_flag(), &cancelled));
    let executor = BrowserPlanExecutor::new(runtime);
    let plan = BrowserPlan {
        schema_version: 1,
        name: "cancelled-flow".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![BrowserStep {
            id: "navigate".into(),
            action: BrowserStepAction::Navigate {
                url: "https://app.test/login".into(),
            },
        }],
    };
    let pending = tokio::spawn(async move { executor.execute(&plan).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !driver.delayed_request_started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    cancelled.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(Duration::from_millis(500), pending).await???;
    assert_eq!(result.status, BrowserPlanStatus::Cancelled);
    assert_eq!(result.steps.len(), 1);
    assert!(!result.steps[0].successful);
    assert!(matches!(
        result.cleanup,
        CleanupOutcome::Quarantined {
            driver_acknowledged: true
        }
    ));
    assert!(driver.state.lock().expect("state").deleted);
    Ok(())
}

#[tokio::test]
async fn checkpoint_is_deterministic_and_replays_verified_prefix() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let runtime = runtime(driver, BrowserRuntimeConfig::default())?;
    let executor = BrowserPlanExecutor::new(runtime);
    let plan = BrowserPlan {
        schema_version: 1,
        name: "resume-flow".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![BrowserStep {
            id: "navigate".into(),
            action: BrowserStepAction::Navigate {
                url: "https://app.test/login".into(),
            },
        }],
    };
    let checkpoint: BrowserCheckpoint = plan.checkpoint(vec!["navigate".into()])?;
    let roundtrip: BrowserPlan = serde_json::from_str(&serde_json::to_string(&plan)?)?;
    assert_eq!(roundtrip.fingerprint()?, plan.fingerprint()?);
    let result = executor
        .execute_with_checkpoint(&roundtrip, Some(&checkpoint))
        .await?;
    assert_eq!(result.status, BrowserPlanStatus::Completed);
    assert_eq!(result.replayed_prefix, vec!["navigate"]);
    Ok(())
}

#[test]
fn plan_validation_rejects_forward_aliases_and_embedded_credentials() {
    let forward = BrowserPlan {
        schema_version: 1,
        name: "bad-alias".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![BrowserStep {
            id: "click".into(),
            action: BrowserStepAction::Click {
                alias: "future".into(),
            },
        }],
    };
    assert!(forward.validate().is_err());
    let embedded = BrowserPlan {
        schema_version: 1,
        name: "bad-script".into(),
        actor: "browser-agent".into(),
        session: SessionRequest::default(),
        steps: vec![BrowserStep {
            id: "script".into(),
            action: BrowserStepAction::Javascript {
                script: "window.password = 'plain-text'".into(),
                arguments: vec![],
            },
        }],
    };
    assert!(embedded.validate().is_err());
}

#[tokio::test]
async fn session_lifecycle_and_capability_negotiation() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let runtime = runtime(driver.clone(), BrowserRuntimeConfig::default())?;
    let started = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?;
    assert!(started.observation.verify());
    assert_eq!(started.value.capabilities().browser_name, "chrome");
    assert!(started.value.capabilities().supports_console_logs);
    assert!(started.value.capabilities().supports_network_logs);
    assert!(!started.value.capabilities().supports_request_interception);
    assert!(!started.value.capabilities().downloads_allowed);

    let create = driver
        .state
        .lock()
        .expect("state")
        .requests
        .first()
        .cloned()
        .expect("create request");
    assert_eq!(
        create.body.as_ref().and_then(|v| v
            .pointer("/capabilities/alwaysMatch/goog:chromeOptions/prefs/download_restrictions")),
        Some(&json!(3))
    );
    started.value.close("browser-agent").await?;
    assert!(driver.state.lock().expect("state").deleted);
    Ok(())
}

#[tokio::test]
async fn redirect_scope_escape_is_blocked_and_quarantined() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    driver.redirect_to("https://evil.test/stolen");
    let runtime = runtime(driver.clone(), BrowserRuntimeConfig::default())?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    let failure = session
        .navigate("browser-agent", "https://app.test/login")
        .await
        .expect_err("escape blocked");
    assert_eq!(failure.error.kind, BrowserErrorKind::ScopeEscape);
    assert!(failure.observation.verify());
    assert!(session.is_closed());
    assert!(driver.state.lock().expect("state").deleted);
    Ok(())
}

#[tokio::test]
async fn discovered_network_scope_escape_is_blocked_and_quarantined() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    driver.network_request("https://third-party.test/pixel");
    let runtime = runtime(driver.clone(), BrowserRuntimeConfig::default())?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    let failure = session
        .network_logs("browser-agent")
        .await
        .expect_err("subresource escape blocked");
    assert_eq!(failure.error.kind, BrowserErrorKind::ScopeEscape);
    assert!(session.is_closed());
    assert!(driver.state.lock().expect("state").deleted);
    Ok(())
}

#[tokio::test]
async fn form_interaction_uses_typed_element_commands() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let runtime = runtime(driver.clone(), BrowserRuntimeConfig::default())?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    session
        .navigate("browser-agent", "https://app.test/form")
        .await?;
    session
        .fill(
            "browser-agent",
            Locator::Name("username".into()),
            "test-user",
        )
        .await?;
    assert_eq!(driver.state.lock().expect("state").typed, vec!["test-user"]);
    Ok(())
}

#[tokio::test]
async fn screenshot_bytes_are_hashed_and_written_as_private_artifact() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let driver = Arc::new(MockWebDriver::default());
    let config = BrowserRuntimeConfig {
        artifact_directory: Some(directory.path().into()),
        ..BrowserRuntimeConfig::default()
    };
    let runtime = runtime(driver, config)?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    let screenshot = session.screenshot("browser-agent").await?;
    assert_eq!(screenshot.value.bytes, b"\x89PNG\r\nmock");
    assert!(screenshot
        .value
        .artifact
        .path
        .as_ref()
        .is_some_and(|p| p.exists()));
    assert_eq!(screenshot.observation.record.artifacts.len(), 1);
    assert!(screenshot.observation.verify());
    Ok(())
}

#[tokio::test]
async fn cookie_values_are_redacted_from_value_and_observation() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let runtime = runtime(driver, BrowserRuntimeConfig::default())?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    let cookies = session.cookies("browser-agent").await?;
    assert_eq!(cookies.value[0].value, "[REDACTED]");
    let serialized = serde_json::to_string(&cookies.observation)?;
    assert!(!serialized.contains("super-secret-cookie"));
    assert!(cookies.observation.verify());
    Ok(())
}

#[tokio::test]
async fn timeout_and_cancellation_interrupt_transport() -> Result<()> {
    let timeout_driver = Arc::new(MockWebDriver::default());
    let timeout_runtime = runtime(
        timeout_driver.clone(),
        BrowserRuntimeConfig {
            command_timeout_ms: 20,
            ..BrowserRuntimeConfig::default()
        },
    )?;
    let timeout_session = timeout_runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    timeout_driver.delay(100);
    let timed_out = timeout_session
        .current_url("browser-agent")
        .await
        .expect_err("timeout");
    assert_eq!(timed_out.error.kind, BrowserErrorKind::Timeout);

    let cancel_driver = Arc::new(MockWebDriver::default());
    let cancel_runtime = runtime(cancel_driver.clone(), BrowserRuntimeConfig::default())?;
    let cancel_session = cancel_runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    cancel_driver.delay(500);
    let pending = tokio::spawn(async move { cancel_session.current_url("browser-agent").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel_runtime.cancel();
    let cancelled = pending.await?.expect_err("cancelled");
    assert_eq!(cancelled.error.kind, BrowserErrorKind::Cancelled);
    Ok(())
}

#[tokio::test]
async fn raw_javascript_requires_explicit_runtime_capability() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    let runtime = runtime(driver, BrowserRuntimeConfig::default())?;
    let session = runtime
        .start_session("browser-agent", SessionRequest::default())
        .await?
        .value;
    let failure = session
        .evaluate_script("browser-agent", "return document.title", vec![])
        .await
        .expect_err("capability denied");
    assert_eq!(failure.error.kind, BrowserErrorKind::Capability);
    Ok(())
}

#[test]
fn runtime_rejects_missing_authorization() -> Result<()> {
    let driver = Arc::new(MockWebDriver::default());
    assert!(BrowserRuntime::new(
        driver,
        policy()?,
        Redactor::default(),
        BrowserRuntimeConfig::default()
    )
    .is_err());
    Ok(())
}

#[test]
fn mock_protocol_does_not_accept_shell_commands() {
    // The contract exposes method/path/body only; this also guards accidental
    // expansion of the transport API into a command-string escape hatch.
    let request = DriverRequest {
        method: DriverMethod::Get,
        path: "/status".into(),
        body: None,
    };
    assert_eq!(request.path, "/status");
}
