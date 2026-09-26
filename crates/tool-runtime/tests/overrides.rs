use anyhow::Result;
use domain::{Control, ExpertOverrides, Scope, ToolAction};
use evidence::EvidenceStore;
use metisblack_tool_runtime::Runtime;
use policy::{scope_for_url, Policy};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use storage::Redactor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn expert(controls: Vec<Control>) -> ExpertOverrides {
    ExpertOverrides {
        controls,
        reason: "Local runtime regression fixture".into(),
        actor: "test-operator".into(),
        acknowledged: true,
        ..Default::default()
    }
}
fn runtime(root: &std::path::Path, scope: Scope, overrides: ExpertOverrides) -> Result<Runtime> {
    let redactor = Redactor::with_override(&overrides);
    let evidence = EvidenceStore::new(&root.join("receipts"), "run-test", redactor.clone())?;
    let mut runtime = Runtime::new(
        Policy::with_overrides(scope, overrides)?,
        evidence,
        redactor,
    );
    runtime.attach_vault(&root.join("vault"))?;
    runtime.authorize(true);
    Ok(runtime)
}
async fn fixture(
    delay_ms: u64,
    status: u16,
    headers: &str,
    body: &str,
) -> Result<(String, tokio::task::JoinHandle<()>)> {
    let (url, handle, _) = tracked_fixture(delay_ms, status, headers, body).await?;
    Ok((url, handle))
}

async fn tracked_fixture(
    delay_ms: u64,
    status: u16,
    headers: &str,
    body: &str,
) -> Result<(String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let response = format!(
        "HTTP/1.1 {status} OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let active = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let observed_max = max_in_flight.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let response = response.clone();
            let active = active.clone();
            let max_in_flight = max_in_flight.clone();
            tokio::spawn(async move {
                let mut bytes = [0u8; 4096];
                let _ = stream.read(&mut bytes).await;
                let in_flight = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let _ = stream.write_all(response.as_bytes()).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok((url, handle, observed_max))
}

#[tokio::test]
async fn response_sampling_and_secret_redaction_each_have_effective_overrides() -> Result<()> {
    let (url, server) = fixture(
        0,
        200,
        "Set-Cookie: session=fixture-secret; HttpOnly\r\n",
        "abcdefgh",
    )
    .await?;
    for (controls, truncated, secret) in [
        (vec![], true, false),
        (vec![Control::DataSampling], false, false),
        (vec![Control::SecretRedaction], true, true),
    ] {
        let root = tempfile::tempdir()?;
        let mut scope = scope_for_url(&url)?;
        scope.max_response_bytes = 3;
        let r = runtime(root.path(), scope, expert(controls))?
            .execute("test", ToolAction::HttpGet { url: url.clone() })
            .await?;
        assert!(r.output.successful);
        assert_eq!(r.output.truncated, truncated);
        assert_eq!(
            serde_json::to_string(&r)?.contains("fixture-secret"),
            secret
        );
    }
    server.abort();
    Ok(())
}
#[tokio::test]
async fn timeout_override_really_removes_tool_deadline() -> Result<()> {
    let (url, server) = fixture(40, 200, "", "OK").await?;
    for (controls, success) in [(vec![], false), (vec![Control::Timeouts], true)] {
        let root = tempfile::tempdir()?;
        let mut scope = scope_for_url(&url)?;
        scope.tool_timeout_ms = 5;
        let r = runtime(root.path(), scope, expert(controls))?
            .execute("test", ToolAction::HttpGet { url: url.clone() })
            .await?;
        assert_eq!(r.output.successful, success);
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn rate_and_concurrency_overrides_change_actual_execution_scheduling() -> Result<()> {
    for control in [Control::Concurrency, Control::RateLimit] {
        for enabled in [false, true] {
            let (url, server, max_in_flight) = tracked_fixture(90, 200, "", "OK").await?;
            let root = tempfile::tempdir()?;
            let mut scope = scope_for_url(&url)?;
            scope.max_concurrency = if control == Control::Concurrency {
                1
            } else {
                2
            };
            scope.requests_per_second = if control == Control::RateLimit {
                2
            } else {
                1000
            };
            let overrides = if enabled {
                expert(vec![control])
            } else {
                ExpertOverrides::default()
            };
            let r = runtime(root.path(), scope, overrides)?;
            let started = std::time::Instant::now();
            let (a, b) = tokio::join!(
                r.execute("a", ToolAction::HttpGet { url: url.clone() }),
                r.execute("b", ToolAction::HttpGet { url: url.clone() })
            );
            let elapsed = started.elapsed();
            assert!(a?.output.successful && b?.output.successful);
            if control == Control::RateLimit && !enabled {
                // Rate limiting guarantees a reservation/start delay, not
                // in-flight serialization. Under a loaded runner the first
                // response can legitimately remain active after that delay.
                assert!(
                    elapsed >= std::time::Duration::from_millis(450),
                    "rate-limited pair completed before the configured spacing: {elapsed:?}"
                );
            } else {
                let expected = if enabled { 2 } else { 1 };
                assert_eq!(
                    max_in_flight.load(Ordering::SeqCst),
                    expected,
                    "{control:?} scheduling with bypass={enabled}"
                );
            }
            server.abort();
        }
    }
    Ok(())
}
#[tokio::test]
async fn redirect_override_allows_only_explicitly_overridden_followup() -> Result<()> {
    let (target, target_server) = fixture(0, 200, "", "TARGET").await?;
    let (source, source_server) = fixture(0, 302, &format!("Location: {target}\r\n"), "").await?;
    for (controls, success) in [(vec![], false), (vec![Control::Redirects], true)] {
        let root = tempfile::tempdir()?;
        let r = runtime(root.path(), scope_for_url(&source)?, expert(controls))?
            .execute(
                "test",
                ToolAction::HttpGet {
                    url: source.clone(),
                },
            )
            .await?;
        assert_eq!(r.output.successful, success);
        if success {
            assert_eq!(r.output.data["body"], "TARGET");
            assert!(r
                .expert_override
                .as_ref()
                .unwrap()
                .controls
                .contains(&Control::Redirects));
        }
    }
    source_server.abort();
    target_server.abort();
    Ok(())
}
#[tokio::test]
async fn concurrent_account_attempts_share_one_budget_and_use_encrypted_vault() -> Result<()> {
    let (url, server) = fixture(
        0,
        201,
        "Content-Type: application/json\r\n",
        "{\"created\":true}",
    )
    .await?;
    let root = tempfile::tempdir()?;
    let mut scope = scope_for_url(&url)?;
    scope.max_accounts = 1;
    scope.max_state_changes = 1;
    scope.requests_per_second = 100;
    let r = runtime(root.path(), scope, ExpertOverrides::default())?;
    let a = r.execute(
        "agent-a",
        ToolAction::CreateAccount {
            url: url.clone(),
            username: "fixture-a".into(),
        },
    );
    let b = r.execute(
        "agent-b",
        ToolAction::CreateAccount {
            url: url.clone(),
            username: "fixture-b".into(),
        },
    );
    let (a, b) = tokio::join!(a, b);
    let results = [a?, b?];
    assert_eq!(results.iter().filter(|r| r.output.successful).count(), 1);
    assert_eq!(r.policy.usage().accounts, 1);
    let good = results.iter().find(|r| r.output.successful).unwrap();
    let reference: domain::SecretRef =
        serde_json::from_value(good.output.data["test_identity"]["secret_ref"].clone())?;
    let vault = storage::Vault::open(&root.path().join("vault"))?;
    let password = vault.resolve(&reference)?;
    assert!(!serde_json::to_string(good)?.contains(password.as_str()));
    assert_eq!(r.policy.usage().state_changes, 1);
    let journal: serde_json::Value = storage::read_json(&root.path().join("usage.json"))?;
    assert_eq!(journal["accounts"], 1);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn failed_and_timed_out_account_attempts_delete_generated_secrets_and_audit_cleanup(
) -> Result<()> {
    for (status, delay_ms) in [(400, 0), (409, 0), (503, 0), (201, 80)] {
        let (url, server) = fixture(delay_ms, status, "", "account attempt").await?;
        let root = tempfile::tempdir()?;
        let mut scope = scope_for_url(&url)?;
        scope.max_accounts = 1;
        scope.max_state_changes = 1;
        if delay_ms > 0 {
            scope.tool_timeout_ms = 5;
        }
        let runtime = runtime(root.path(), scope, ExpertOverrides::default())?;
        let receipt = runtime
            .execute(
                "account-regression",
                ToolAction::CreateAccount {
                    url,
                    username: "failed-fixture".into(),
                },
            )
            .await?;
        assert!(!receipt.output.successful);
        assert!(receipt.output.data.get("test_identity").is_none());
        assert_eq!(
            std::fs::read_dir(root.path().join("vault"))?
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|e| e == "vault"))
                .count(),
            0
        );
        let attempts = std::fs::read_dir(root.path().join("account-attempts"))?
            .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(attempts.len(), 1);
        let audit: serde_json::Value = storage::read_json(&attempts[0].path())?;
        assert_eq!(audit["secret_retained"], false);
        assert_eq!(audit["local_cleanup"], "generated_secret_deleted");
        assert_eq!(audit["actor"], "account-regression");
        assert_eq!(
            audit["outcome"],
            if delay_ms > 0 {
                "interrupted_remote_state_unknown"
            } else {
                "rejected_http"
            }
        );
        if delay_ms == 0 {
            assert_eq!(receipt.output.data["account_creation"]["created"], false);
        }
        server.abort();
    }
    Ok(())
}

#[tokio::test]
async fn runtime_checks_authorization_on_each_active_operation() -> Result<()> {
    let (url, server) = fixture(0, 200, "", "fixture").await?;
    for (controls, allowed) in [
        (vec![], false),
        (vec![Control::Network], false),
        (vec![Control::Authorization], true),
    ] {
        let root = tempfile::tempdir()?;
        let mut runtime = runtime(root.path(), scope_for_url(&url)?, expert(controls))?;
        runtime.authorize(false);
        let receipt = runtime
            .execute("fixture", ToolAction::HttpGet { url: url.clone() })
            .await?;
        assert_eq!(receipt.output.successful, allowed);
        assert_eq!(
            receipt.output.data["authorization_provenance"]["explicit_override"],
            allowed
        );
        assert_eq!(runtime.policy.usage().requests, u64::from(allowed));
    }
    server.abort();
    Ok(())
}
#[tokio::test]
async fn account_and_state_overrides_allow_a_deliberate_extra_account() -> Result<()> {
    let (url, server) = fixture(0, 201, "", "created").await?;
    let root = tempfile::tempdir()?;
    let mut scope = scope_for_url(&url)?;
    scope.max_accounts = 0;
    scope.max_state_changes = 0;
    let runtime = runtime(
        root.path(),
        scope,
        expert(vec![Control::AccountBudget, Control::StateChanges]),
    )?;
    let r = runtime
        .execute(
            "test",
            ToolAction::CreateAccount {
                url,
                username: "fixture-extra".into(),
            },
        )
        .await?;
    assert!(r.output.successful);
    assert_eq!(runtime.policy.usage().accounts, 1);
    server.abort();
    Ok(())
}
#[cfg(unix)]
#[tokio::test]
async fn environment_inheritance_is_an_explicit_separate_override() -> Result<()> {
    std::env::set_var("METISBLACK_OVERRIDE_FIXTURE", "fixture-present");
    for enabled in [false, true] {
        let root = tempfile::tempdir()?;
        let mut controls = vec![
            Control::Sandbox,
            Control::ToolCapabilities,
            Control::Network,
            Control::FilesystemRoots,
            Control::CommandRisk,
        ];
        if enabled {
            controls.push(Control::Environment);
        }
        let scope = Scope {
            roots: vec![root.path().into()],
            max_state_changes: 2,
            ..Default::default()
        };
        let runtime = runtime(root.path(), scope, expert(controls))?;
        let r = runtime
            .execute(
                "test",
                ToolAction::Shell {
                    program: "/bin/sh".into(),
                    args: vec![
                        "-c".into(),
                        "printf '%s' \"$METISBLACK_OVERRIDE_FIXTURE\"".into(),
                    ],
                    working_dir: root.path().into(),
                },
            )
            .await?;
        assert!(r.output.successful);
        assert_eq!(
            r.output.data["stdout"].as_str().unwrap(),
            if enabled { "fixture-present" } else { "" }
        );
    }
    std::env::remove_var("METISBLACK_OVERRIDE_FIXTURE");
    Ok(())
}
