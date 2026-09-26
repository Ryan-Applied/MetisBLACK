use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use domain::{NetworkRule, Scope};
use futures::future::BoxFuture;
use metisblack_browser_runtime::{
    AuthenticatedBrowserWorkflow, AuthenticatedBrowserWorkflowExecutor, AuthenticatedRolePlan,
    AuthenticatedWorkflowStatus, BrowserError, BrowserPlan, BrowserPlanStatus, BrowserRuntime,
    BrowserRuntimeConfig, BrowserStep, BrowserStepAction, BrowserTransport, CleanupOutcome,
    DriverMethod, DriverRequest, DriverResponse, Locator, PlanValue, RoleSecretBinding,
    SecretResolver, SessionRequest, W3C_ELEMENT_KEY,
};
use policy::Policy;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use storage::Redactor;
use zeroize::Zeroizing;

#[derive(Default)]
struct DriverState {
    next_session: u64,
    created: Vec<String>,
    deleted: BTreeSet<String>,
    current_urls: BTreeMap<String, String>,
    typed: BTreeMap<String, Vec<String>>,
    fail_find_session: Option<String>,
}

#[derive(Default)]
struct MultiRoleDriver {
    state: Mutex<DriverState>,
    delayed_path: Mutex<Option<String>>,
    delay_ms: AtomicU64,
    delayed_request_started: AtomicBool,
}

impl MultiRoleDriver {
    fn response(value: Value) -> DriverResponse {
        let body = json!({"value":value});
        DriverResponse {
            status: 200,
            byte_count: serde_json::to_vec(&body).expect("response JSON").len(),
            body,
        }
    }

    fn fail_find_for(&self, session: &str) {
        self.state.lock().expect("state").fail_find_session = Some(session.into());
    }

    fn delay_path(&self, path: &str, delay_ms: u64) {
        *self.delayed_path.lock().expect("delay path") = Some(path.into());
        self.delay_ms.store(delay_ms, Ordering::SeqCst);
        self.delayed_request_started.store(false, Ordering::SeqCst);
    }
}

impl BrowserTransport for MultiRoleDriver {
    fn send<'a>(
        &'a self,
        request: DriverRequest,
    ) -> BoxFuture<'a, std::result::Result<DriverResponse, BrowserError>> {
        Box::pin(async move {
            let delayed_path = self.delayed_path.lock().expect("delay path").clone();
            if delayed_path.as_deref() == Some(request.path.as_str()) {
                self.delayed_request_started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(self.delay_ms.load(Ordering::SeqCst)))
                    .await;
            }
            let mut state = self.state.lock().expect("state");
            if request.method == DriverMethod::Post && request.path == "/session" {
                state.next_session += 1;
                let session = format!("session-{}", state.next_session);
                state.created.push(session.clone());
                return Ok(Self::response(json!({
                    "sessionId":session,
                    "capabilities":{"browserName":"chrome","browserVersion":"130"}
                })));
            }
            let Some(relative) = request.path.strip_prefix("/session/") else {
                return Ok(Self::response(Value::Null));
            };
            let (session, suffix) = relative.split_once('/').unwrap_or((relative, ""));
            let suffix = format!("/{suffix}");
            let response = match (request.method, suffix.as_str()) {
                (DriverMethod::Post, "/url") => {
                    let url = request
                        .body
                        .as_ref()
                        .and_then(|body| body.get("url"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    state.current_urls.insert(session.into(), url);
                    Self::response(Value::Null)
                }
                (DriverMethod::Get, "/url") => Self::response(json!(state
                    .current_urls
                    .get(session)
                    .cloned()
                    .unwrap_or_default())),
                (DriverMethod::Post, "/element")
                    if state.fail_find_session.as_deref() == Some(session) =>
                {
                    let body = json!({"value":{
                        "error":"no such element",
                        "message":"role-specific test failure"
                    }});
                    DriverResponse {
                        status: 404,
                        byte_count: serde_json::to_vec(&body).expect("response JSON").len(),
                        body,
                    }
                }
                (DriverMethod::Post, "/element") => {
                    Self::response(json!({W3C_ELEMENT_KEY:"element-1"}))
                }
                (DriverMethod::Post, "/element/element-1/value") => {
                    let value = request
                        .body
                        .as_ref()
                        .and_then(|body| body.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    state.typed.entry(session.into()).or_default().push(value);
                    Self::response(Value::Null)
                }
                (DriverMethod::Post, "/element/element-1/clear") => Self::response(Value::Null),
                (DriverMethod::Get, "/screenshot") => {
                    Self::response(json!(BASE64.encode(format!("png-{session}"))))
                }
                (DriverMethod::Delete, "/") => {
                    state.deleted.insert(session.into());
                    Self::response(Value::Null)
                }
                _ => Self::response(Value::Null),
            };
            Ok(response)
        })
    }
}

#[derive(Default)]
struct MapSecrets(BTreeMap<String, String>);

impl SecretResolver for MapSecrets {
    fn resolve(&self, name: &str) -> std::result::Result<Zeroizing<String>, BrowserError> {
        self.0
            .get(name)
            .cloned()
            .map(Zeroizing::new)
            .ok_or_else(|| BrowserError {
                kind: metisblack_browser_runtime::BrowserErrorKind::InvalidInput,
                message: format!("missing test secret {name}"),
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
        max_requests: 500,
        max_state_changes: 100,
        tool_timeout_ms: 2_000,
        ..Scope::default()
    })
}

fn runtime(driver: Arc<MultiRoleDriver>, cancelled: Arc<AtomicBool>) -> Result<BrowserRuntime> {
    BrowserRuntime::new_with_cancellation(
        driver,
        policy()?,
        Redactor::default(),
        BrowserRuntimeConfig {
            authorized: true,
            command_timeout_ms: 2_000,
            ..BrowserRuntimeConfig::default()
        },
        cancelled,
    )
}

fn role(role: &str, resolver_key: &str) -> AuthenticatedRolePlan {
    AuthenticatedRolePlan {
        role: role.into(),
        plan: BrowserPlan {
            schema_version: 1,
            name: format!("{role}-authenticated-observation"),
            actor: format!("browser-{role}"),
            session: SessionRequest::default(),
            steps: vec![
                BrowserStep {
                    id: "navigate".into(),
                    action: BrowserStepAction::Navigate {
                        url: "https://app.test/account/42".into(),
                    },
                },
                BrowserStep {
                    id: "authenticate".into(),
                    action: BrowserStepAction::Fill {
                        locator: Locator::Name("password".into()),
                        value: PlanValue::Environment {
                            name: "ROLE_PASSWORD".into(),
                        },
                    },
                },
                BrowserStep {
                    id: "capture".into(),
                    action: BrowserStepAction::Screenshot,
                },
            ],
        },
        secret_bindings: BTreeMap::from([(
            "ROLE_PASSWORD".into(),
            RoleSecretBinding {
                resolver_key: resolver_key.into(),
            },
        )]),
    }
}

fn workflow() -> AuthenticatedBrowserWorkflow {
    AuthenticatedBrowserWorkflow {
        schema_version: 1,
        name: "account-role-comparison".into(),
        // Deliberately reverse lexical order to prove canonical execution.
        roles: vec![
            role("viewer", "VIEWER_PASSWORD"),
            role("admin", "ADMIN_PASSWORD"),
        ],
    }
}

#[test]
fn shipped_authenticated_workflow_example_is_valid() -> Result<()> {
    let workflow: AuthenticatedBrowserWorkflow = serde_json::from_str(include_str!(
        "../../../examples/browser-authenticated-workflow.json"
    ))?;
    workflow.validate()?;
    Ok(())
}

fn secrets() -> Arc<MapSecrets> {
    Arc::new(MapSecrets(BTreeMap::from([
        ("ADMIN_PASSWORD".into(), "admin-secret-value".into()),
        ("VIEWER_PASSWORD".into(), "viewer-secret-value".into()),
    ])))
}

#[test]
fn validation_rejects_duplicate_roles_shared_bindings_and_inline_credentials() {
    let mut duplicate = workflow();
    duplicate.roles[1].role = duplicate.roles[0].role.clone();
    assert!(duplicate.validate().is_err());

    let mut empty = workflow();
    empty.roles[0].role = " ".into();
    assert!(empty.validate().is_err());

    let mut shared = workflow();
    shared.roles[1]
        .secret_bindings
        .get_mut("ROLE_PASSWORD")
        .expect("binding")
        .resolver_key = "VIEWER_PASSWORD".into();
    assert!(shared.validate().is_err());

    let mut inline = workflow();
    inline.roles[0].plan.steps[1].action = BrowserStepAction::Fill {
        locator: Locator::Name("password".into()),
        value: PlanValue::Public {
            value: "serialized-password".into(),
        },
    };
    assert!(inline.validate().is_err());
}

#[tokio::test]
async fn roles_use_isolated_sessions_distinct_secrets_and_neutral_hashes() -> Result<()> {
    let driver = Arc::new(MultiRoleDriver::default());
    let executor = AuthenticatedBrowserWorkflowExecutor::with_secret_resolver(
        runtime(driver.clone(), Arc::new(AtomicBool::new(false)))?,
        secrets(),
    );
    let workflow = workflow();
    let serialized_workflow = serde_json::to_string(&workflow)?;
    assert!(serialized_workflow.contains("ADMIN_PASSWORD"));
    assert!(!serialized_workflow.contains("admin-secret-value"));

    let result = executor.execute(&workflow).await?;
    assert_eq!(result.status, AuthenticatedWorkflowStatus::Completed);
    assert_eq!(
        result
            .roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        vec!["admin", "viewer"]
    );
    assert!(result.comparison.verify());
    assert_eq!(
        result
            .comparison
            .roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        vec!["admin", "viewer"]
    );
    assert!(result
        .roles
        .iter()
        .all(|role| role.result.cleanup == CleanupOutcome::Closed));
    assert!(result
        .roles
        .iter()
        .flat_map(|role| &role.result.observations)
        .all(|observation| observation.verify()));

    let state = driver.state.lock().expect("state");
    assert_eq!(state.created, vec!["session-1", "session-2"]);
    assert_eq!(state.deleted.len(), 2);
    assert_eq!(
        state.typed.get("session-1"),
        Some(&vec!["admin-secret-value".into()])
    );
    assert_eq!(
        state.typed.get("session-2"),
        Some(&vec!["viewer-secret-value".into()])
    );
    drop(state);
    let serialized_result = serde_json::to_string(&result)?;
    assert!(!serialized_result.contains("admin-secret-value"));
    assert!(!serialized_result.contains("viewer-secret-value"));
    assert!(!serialized_result.contains("vulnerability"));
    Ok(())
}

#[tokio::test]
async fn role_failure_is_isolated_and_all_created_sessions_are_cleaned_up() -> Result<()> {
    let driver = Arc::new(MultiRoleDriver::default());
    driver.fail_find_for("session-1");
    let executor = AuthenticatedBrowserWorkflowExecutor::with_secret_resolver(
        runtime(driver.clone(), Arc::new(AtomicBool::new(false)))?,
        secrets(),
    );
    let result = executor.execute(&workflow()).await?;
    assert_eq!(result.status, AuthenticatedWorkflowStatus::PartiallyFailed);
    assert_eq!(result.roles[0].role, "admin");
    assert_eq!(result.roles[0].result.status, BrowserPlanStatus::Failed);
    assert!(matches!(
        result.roles[0].result.cleanup,
        CleanupOutcome::Quarantined {
            driver_acknowledged: true
        }
    ));
    assert_eq!(result.roles[1].role, "viewer");
    assert_eq!(result.roles[1].result.status, BrowserPlanStatus::Completed);
    assert_eq!(result.roles[1].result.cleanup, CleanupOutcome::Closed);
    let state = driver.state.lock().expect("state");
    assert_eq!(state.created.len(), 2);
    assert_eq!(state.deleted.len(), 2);
    Ok(())
}

#[tokio::test]
async fn shared_cancellation_returns_aggregate_and_cleans_active_role() -> Result<()> {
    let driver = Arc::new(MultiRoleDriver::default());
    driver.delay_path("/session/session-1/url", 5_000);
    let cancelled = Arc::new(AtomicBool::new(false));
    let executor = AuthenticatedBrowserWorkflowExecutor::with_secret_resolver(
        runtime(driver.clone(), cancelled.clone())?,
        secrets(),
    );
    let workflow = workflow();
    let pending = tokio::spawn(async move { executor.execute(&workflow).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !driver.delayed_request_started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    cancelled.store(true, Ordering::SeqCst);

    let result = tokio::time::timeout(Duration::from_millis(500), pending).await???;
    assert_eq!(result.status, AuthenticatedWorkflowStatus::Cancelled);
    assert_eq!(result.roles.len(), 2);
    assert_eq!(result.roles[0].result.status, BrowserPlanStatus::Cancelled);
    assert!(matches!(
        result.roles[0].result.cleanup,
        CleanupOutcome::Quarantined {
            driver_acknowledged: true
        }
    ));
    assert_eq!(result.roles[1].result.status, BrowserPlanStatus::Cancelled);
    assert_eq!(
        result.roles[1].result.cleanup,
        CleanupOutcome::SessionNotCreated
    );
    let state = driver.state.lock().expect("state");
    assert_eq!(state.created, vec!["session-1"]);
    assert_eq!(state.deleted, BTreeSet::from(["session-1".into()]));
    Ok(())
}
