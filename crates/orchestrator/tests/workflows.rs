use anyhow::Result;
use domain::{
    Control, ExpertOverrides, FindingState, Mode, Proof, RunSnapshot, RunStatus, Severity,
    ToolAction,
};
use metisblack_orchestrator::{default_config, Engine};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn expert(controls: Vec<Control>) -> ExpertOverrides {
    ExpertOverrides {
        controls,
        reason: "Authorized local regression fixture".into(),
        actor: "fixture-operator".into(),
        acknowledged: true,
        ..Default::default()
    }
}
async fn fixture() -> Result<(String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let records = requests.clone();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let records = records.clone();
            tokio::spawn(async move {
                let mut bytes = vec![0; 65536];
                let n = stream.read(&mut bytes).await.unwrap_or_default();
                records
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&bytes[..n]).into_owned());
                let body = "<html><p>Local fixture</p></html>";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok((url, requests, server))
}

#[tokio::test]
async fn ai_default_really_posts_two_prompts() -> Result<()> {
    let (url, requests, server) = fixture().await?;
    let root = tempfile::tempdir()?;
    let mut config = default_config(Mode::Ai, vec![url], root.path().into())?;
    config.authorized = true;
    config.scope.requests_per_second = 100;
    assert_eq!(config.scope.max_state_changes, 2);
    let run = Engine::new(config)?.run().await?;
    assert_eq!(run.status, RunStatus::Complete);
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        2
    );
    let audit: Value = storage::read_json(&root.path().join("ai-conversations.json"))?;
    assert_eq!(audit.as_array().unwrap().len(), 2);
    let usage: Value = storage::read_json(&root.path().join("usage.json"))?;
    assert_eq!(usage["state_changes"], 2);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn greybox_correlates_route_source_and_runtime_receipts() -> Result<()> {
    let (url, requests, server) = fixture().await?;
    let root = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    storage::atomic_write(
        &source.path().join("app.js"),
        b"app.get('/health', handler);\n",
    )?;
    let mut config = default_config(Mode::Greybox, vec![url], root.path().into())?;
    config.source_root = Some(source.path().into());
    config.authorized = true;
    config.scope.requests_per_second = 100;
    let run = Engine::new(config)?.run().await?;
    let links: Value = storage::read_json(&root.path().join("greybox-links.json"))?;
    assert_eq!(links.as_array().unwrap().len(), 1);
    assert!(run
        .receipt_ids
        .contains(&links[0]["source_receipt"].as_str().unwrap().to_owned()));
    assert!(run
        .receipt_ids
        .contains(&links[0]["http_receipt"].as_str().unwrap().to_owned()));
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.starts_with("GET /health ")));
    server.abort();
    Ok(())
}

#[tokio::test]
async fn source_targets_are_all_analyzed_and_skills_has_distinct_artifact() -> Result<()> {
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    for source in [&first, &second] {
        storage::atomic_write(
            &source.path().join("client.py"),
            b"requests.get(url, verify=False)\n",
        )?;
    }
    let config = default_config(
        Mode::Whitebox,
        vec![
            first.path().display().to_string(),
            second.path().display().to_string(),
        ],
        root.path().into(),
    )?;
    let run = Engine::new(config)?.run().await?;
    assert_eq!(
        run.findings.iter().filter(|f| f.state.confirmed()).count(),
        2
    );
    let skill_out = tempfile::tempdir()?;
    storage::atomic_write(&first.path().join("SKILL.md"), b"# Local review skill\n")?;
    let config = default_config(
        Mode::Skills,
        vec![first.path().display().to_string()],
        skill_out.path().into(),
    )?;
    Engine::new(config)?.run().await?;
    assert!(skill_out.path().join("skills-audit.json").exists());
    Ok(())
}

#[tokio::test]
async fn cloud_identity_and_authorization_have_deliberate_overrides() -> Result<()> {
    let source = tempfile::tempdir()?;
    storage::write_json(
        &source.path().join("cloud-identity.json"),
        &json!({"account_id":"actual-account"}),
    )?;
    for (controls, success) in [(vec![], false), (vec![Control::CloudIdentity], true)] {
        let root = tempfile::tempdir()?;
        let mut config = default_config(
            Mode::Cloud,
            vec![source.path().display().to_string()],
            root.path().into(),
        )?;
        config.scope.cloud_accounts = vec!["different-account".into()];
        config.overrides = expert(controls);
        assert_eq!(Engine::new(config)?.run().await.is_ok(), success);
    }
    let root = tempfile::tempdir()?;
    let mut config = default_config(
        Mode::Blackbox,
        vec!["http://127.0.0.1:1".into()],
        root.path().into(),
    )?;
    assert!(Engine::new(config.clone()).is_err());
    config.overrides = expert(vec![Control::Authorization]);
    assert!(Engine::new(config).is_ok());
    Ok(())
}

#[tokio::test]
async fn actual_specialist_schedule_has_isolated_review_and_refutation() -> Result<()> {
    let (url, _, server) = fixture().await?;
    let root = tempfile::tempdir()?;
    let mut config = default_config(Mode::Blackbox, vec![url], root.path().into())?;
    config.authorized = true;
    config.scope.requests_per_second = 100;
    let mut engine = Engine::new(config)?;
    engine.set_provider(providers::Provider::mock(vec![])?);
    engine.run().await?;
    let sessions: Vec<Value> = storage::read_json(&root.path().join("specialist-runs.json"))?;
    for id in [
        "recon/surface",
        "web/response-policy",
        "meta/evidence-review",
        "meta/refutation",
    ] {
        assert!(
            sessions
                .iter()
                .any(|s| s["playbook"] == id && s["independent_context"] == true),
            "missing {id}"
        );
    }
    let budget: Value = storage::read_json(&root.path().join("model-budget.json"))?;
    assert!(budget["reserved_steps"].as_u64().unwrap() >= 4);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn retest_persists_manifest_and_does_not_mistake_changed_hash_for_fix() -> Result<()> {
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = source.path().join("client.py");
    storage::atomic_write(&path, b"requests.get(url, verify=False)\n")?;
    let config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    let run = Engine::new(config)?.run().await?;
    let id = &run.findings[0].id;
    storage::atomic_write(
        &path,
        b"# unrelated edit\nrequests.get(url, verify=False)\n",
    )?;
    let present = metisblack_orchestrator::retest(root.path(), id, false).await?;
    assert_eq!(present.findings[0].state, FindingState::RetestedPresent);
    storage::atomic_write(&path, b"requests.get(url, verify=True)\n")?;
    let fixed = metisblack_orchestrator::retest(root.path(), id, false).await?;
    assert_eq!(fixed.findings[0].state, FindingState::RetestedFixed);
    let reload: RunSnapshot = storage::read_json(&root.path().join("run-manifest.json"))?;
    let manifest: Vec<Value> = storage::read_json(&root.path().join("receipts-manifest.json"))?;
    assert_eq!(reload.status, RunStatus::Complete);
    assert_eq!(manifest.len(), fixed.receipt_ids.len());
    assert_eq!(reload.findings[0].state, FindingState::RetestedFixed);
    Ok(())
}

#[tokio::test]
async fn operator_acceptance_is_explicit_receipted_and_excluded_from_default_gates() -> Result<()> {
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = source.path().join("README.md");
    storage::atomic_write(&path, b"Local evidence\n")?;
    let config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    let mut engine = Engine::new(config)?;
    let receipt = engine
        .runtime
        .execute(
            "fixture",
            ToolAction::SourceRead {
                path,
                start_line: 1,
                end_line: 1,
            },
        )
        .await?;
    let candidate: domain::Candidate = serde_json::from_value(
        json!({"title":"Review hypothesis","description":"Requires human validation","severity":"high","severity_justification":"Operator-provided risk hypothesis","location":"fixture","impact":"Potential impact needs validation","remediation":"Review manually","receipt_ids":[receipt.id],"proof":{"kind":"manual","procedure":"Review fixture"}}),
    )?;
    let id = engine
        .add_candidate(candidate, "fixture", Some(true))
        .await?;
    engine.run().await?;
    drop(engine);
    let run = metisblack_orchestrator::accept_finding(
        root.path(),
        &id,
        expert(vec![Control::Confirmation]),
    )?;
    let f = run.findings.iter().find(|f| f.id == id).unwrap();
    assert_eq!(f.state, FindingState::OperatorAccepted);
    assert!(!f.state.confirmed());
    assert!(!integrations::gate_trips(
        &run.findings,
        Severity::High,
        true
    ));
    assert!(integrations::gate_trips_with_operator(
        &run.findings,
        Severity::High,
        true,
        true
    ));
    let sarif = reporting::sarif(&run);
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["empiricallyConfirmed"],
        false
    );
    assert!(matches!(f.candidate.proof, Proof::Manual { .. }));
    Ok(())
}

#[tokio::test]
async fn explicit_integration_publication_is_audited_and_idempotent() -> Result<()> {
    let (url, requests, server) = fixture().await?;
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    let run = Engine::new(config)?.run().await?;
    std::env::set_var("METISBLACK_FIXTURE_INTEGRATION_TOKEN", "local-test-token");
    let integration = integrations::IntegrationConfig {
        kind: "github".into(),
        endpoint: url,
        token_env: "METISBLACK_FIXTURE_INTEGRATION_TOKEN".into(),
        project: "fixture/repository".into(),
        issue: "42".into(),
    };
    assert!(integrations::publish(&integration, &run).await.is_err());
    for _ in 0..2 {
        integrations::publish_with_overrides(
            &integration,
            &run,
            Some(expert(vec![Control::Network, Control::Authorization])),
        )
        .await?;
    }
    assert_eq!(requests.lock().unwrap().len(), 1);
    let path = std::fs::read_dir(root.path())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("publication-")
        })
        .unwrap();
    let audit: Value = storage::read_json(&path)?;
    assert_eq!(audit["status"], "published");
    assert_eq!(
        audit["disabled_controls"],
        json!(["network", "authorization"])
    );
    assert!(!audit.to_string().contains("local-test-token"));
    server.abort();
    Ok(())
}

async fn read_http_json(stream: &mut tokio::net::TcpStream) -> Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "fixture request ended early");
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(split) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..split]);
            let length = headers
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or_default();
            if bytes.len() >= split + 4 + length {
                return Ok(serde_json::from_slice(
                    &bytes[split + 4..split + 4 + length],
                )?);
            }
        }
    }
}

#[tokio::test]
async fn native_api_tool_loop_captures_real_receipts_and_canonicalizes_claims() -> Result<()> {
    let (target, _, target_server) = fixture().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let target_for_api = target.clone();
    let api = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let target = target_for_api.clone();
            tokio::spawn(async move {
                let body = read_http_json(&mut stream).await.unwrap();
                let messages = body["messages"].as_array().unwrap();
                let tool = messages
                    .iter()
                    .rev()
                    .find(|m| m["role"] == "tool")
                    .and_then(|m| m["content"].as_str())
                    .and_then(|s| serde_json::from_str::<Value>(s).ok());
                let (name, args) = if let Some(receipt) = tool {
                    if let Some(id) = receipt["id"].as_str() {
                        (
                            "submit_finding",
                            json!({"title":"Unjustified critical remote shell","description":"Unsupported dramatic claim","severity":"critical","severity_justification":"Model assertion","auth_context":"public fixture provider session","location":target,"impact":"Claimed shell","remediation":"Configure policy","receipt_ids":[id],"proof":{"kind":"missing_header","url":target,"header":"content-security-policy"}}),
                        )
                    } else {
                        ("finish", json!({"reason":"Local fixture completed"}))
                    }
                } else {
                    ("http_get", json!({"url":target}))
                };
                let response=json!({"choices":[{"message":{"tool_calls":[{"id":format!("call-{}",messages.len()),"type":"function","function":{"name":name,"arguments":args.to_string()}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":10}}).to_string();
                let http=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len());
                stream.write_all(http.as_bytes()).await.unwrap();
            });
        }
    });
    let root = tempfile::tempdir()?;
    let mut config = default_config(Mode::Blackbox, vec![target], root.path().into())?;
    config.authorized = true;
    config.scope.requests_per_second = 100;
    config.max_model_tokens = 4_000_000;
    config.provider = Some(domain::ProviderConfig {
        kind: "openai-compatible".into(),
        model: "local-fixture".into(),
        endpoint,
        key_env: None,
        timeout_seconds: 2,
        max_output_tokens: 512,
        subscription_cli: None,
    });
    let run = Engine::new(config)?.run().await?;
    let provider = run
        .findings
        .iter()
        .find(|f| f.finder.starts_with("provider:"))
        .expect("provider candidate persisted");
    assert!(provider.state.confirmed());
    assert_eq!(provider.candidate.severity, Severity::Low);
    assert!(!provider.candidate.title.contains("remote shell"));
    assert!(provider.validations.iter().any(|v| v.reproduced));
    target_server.abort();
    api.abort();
    Ok(())
}

#[tokio::test]
async fn pr_review_reports_only_changed_findings_as_introduced() -> Result<()> {
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let git = |args: &[&str]| -> Result<()> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(source.path())
            .args(args)
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.test")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.test")
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "git fixture failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    };
    git(&["init", "--quiet"])?;
    storage::atomic_write(
        &source.path().join("existing.py"),
        b"requests.get(url, verify=False)\n",
    )?;
    storage::atomic_write(
        &source.path().join("nested/new.py"),
        b"requests.get(url, verify=True)\n",
    )?;
    git(&["add", "."])?;
    git(&[
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "base",
    ])?;
    storage::atomic_write(
        &source.path().join("nested/new.py"),
        b"requests.get(url, verify=False)\n",
    )?;
    git(&["add", "."])?;
    git(&[
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "head",
    ])?;
    let mut config = default_config(
        Mode::Pr,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    config.base_ref = Some("HEAD^".into());
    config.head_ref = Some("HEAD".into());
    let run = Engine::new(config)?.run().await?;
    assert_eq!(run.findings.len(), 2);
    assert_eq!(
        run.findings
            .iter()
            .filter(|f| f.introduced == Some(true))
            .count(),
        1
    );
    assert_eq!(
        run.findings
            .iter()
            .filter(|f| f.introduced == Some(false))
            .count(),
        1
    );
    let changed_path = std::path::Path::new("nested")
        .join("new.py")
        .to_string_lossy()
        .into_owned();
    assert!(run
        .findings
        .iter()
        .find(|f| f.introduced == Some(true))
        .unwrap()
        .candidate
        .location
        .contains(&changed_path));
    assert!(integrations::gate_trips(
        &run.findings,
        Severity::Medium,
        true
    ));
    Ok(())
}

#[tokio::test]
async fn resume_preserves_typed_account_and_state_budgets_and_override_history() -> Result<()> {
    let (url, requests, server) = fixture().await?;
    let root = tempfile::tempdir()?;
    let mut config = default_config(Mode::Blackbox, vec![url.clone()], root.path().into())?;
    config.authorized = true;
    config.scope.max_accounts = 1;
    config.scope.max_state_changes = 1;
    let mut engine = Engine::new(config)?;
    let receipt = engine
        .runtime
        .execute(
            "fixture",
            ToolAction::CreateAccount {
                url: url.clone(),
                username: "fixture-one".into(),
            },
        )
        .await?;
    assert!(receipt.output.successful);
    engine.snapshot.receipt_ids.push(receipt.id);
    engine.snapshot.status = RunStatus::Paused;
    engine.checkpoint()?;
    drop(engine);
    let mut resumed = Engine::resume(root.path())?;
    assert_eq!(resumed.runtime.policy.usage().accounts, 1);
    assert_eq!(resumed.runtime.policy.usage().state_changes, 1);
    let denied = resumed
        .runtime
        .execute(
            "fixture",
            ToolAction::CreateAccount {
                url: url.clone(),
                username: "fixture-two".into(),
            },
        )
        .await?;
    assert!(!denied.output.successful);
    resumed.apply_overrides(expert(vec![Control::AccountBudget, Control::StateChanges]))?;
    let allowed = resumed
        .runtime
        .execute(
            "fixture",
            ToolAction::CreateAccount {
                url,
                username: "fixture-two".into(),
            },
        )
        .await?;
    assert!(allowed.output.successful);
    assert_eq!(resumed.snapshot.override_history.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 2);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn restricted_playbook_is_selected_only_by_explicit_selection_override() -> Result<()> {
    let source = tempfile::tempdir()?;
    let books = tempfile::tempdir()?;
    storage::atomic_write(&source.path().join("README.md"), b"Local fixture\n")?;
    let mut book = agent_library::Library::builtins().playbooks.remove(0);
    book.id = "fixture/restricted".into();
    book.risk_class = "restricted".into();
    book.modes = vec![Mode::Whitebox];
    book.required_observations = vec![];
    storage::write_json(&books.path().join("fixture.json"), &book)?;
    for enabled in [false, true] {
        let root = tempfile::tempdir()?;
        let mut config = default_config(
            Mode::Whitebox,
            vec![source.path().display().to_string()],
            root.path().into(),
        )?;
        config.playbooks = Some(books.path().into());
        if enabled {
            config.overrides = expert(vec![Control::PlaybookSelection]);
        }
        let mut engine = Engine::new(config)?;
        engine.set_provider(providers::Provider::mock(vec![])?);
        engine.run().await?;
        let sessions: Vec<Value> = storage::read_json(&root.path().join("specialist-runs.json"))?;
        assert_eq!(
            sessions
                .iter()
                .any(|s| s["playbook"] == "fixture/restricted"),
            enabled
        );
    }
    Ok(())
}

#[tokio::test]
async fn resumed_specialists_append_without_erasing_completed_session_audits() -> Result<()> {
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    storage::atomic_write(&source.path().join("README.md"), b"source fixture")?;
    let config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    let mut engine = Engine::new(config)?;
    engine.set_provider(providers::Provider::mock(vec![])?);
    let mut snapshot = engine.run().await?;
    drop(engine);
    let audit_path = root.path().join("specialist-runs.json");
    let mut prior: Vec<Value> = storage::read_json(&audit_path)?;
    let unfinished = prior.pop().unwrap()["playbook"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!prior.is_empty());
    snapshot.status = RunStatus::Paused;
    snapshot
        .completed_targets
        .retain(|s| s != &format!("agent:{unfinished}"));
    storage::write_json(&root.path().join("run-manifest.json"), &snapshot)?;
    storage::write_json(&audit_path, &prior)?;
    let mut resumed = Engine::resume(root.path())?;
    resumed.set_provider(providers::Provider::mock(vec![])?);
    resumed.run().await?;
    let after: Vec<Value> = storage::read_json(&audit_path)?;
    assert_eq!(&after[..prior.len()], prior.as_slice());
    assert_eq!(after.len(), prior.len() + 1);
    assert_eq!(after.last().unwrap()["playbook"], unfinished);
    Ok(())
}

#[tokio::test]
async fn provider_and_resume_authorization_cannot_be_bypassed_by_mode_or_replacement() -> Result<()>
{
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    config.provider = Some(domain::ProviderConfig {
        kind: "openai-compatible".into(),
        model: "fixture".into(),
        endpoint: "https://example.test".into(),
        key_env: None,
        timeout_seconds: 1,
        max_output_tokens: 32,
        subscription_cli: None,
    });
    assert!(Engine::new(config.clone()).is_err());
    config.overrides = expert(vec![Control::Network]);
    assert!(Engine::new(config.clone()).is_err());
    config.overrides = expert(vec![Control::Authorization]);
    let engine = Engine::new(config)?;
    drop(engine);
    let mut resumed = Engine::resume(root.path())?;
    assert!(resumed
        .apply_overrides(expert(vec![Control::Timeouts]))
        .is_err());
    assert!(resumed
        .snapshot
        .config
        .overrides
        .disables(Control::Authorization));
    resumed.authorize()?;
    resumed.apply_overrides(expert(vec![Control::Timeouts]))?;
    assert!(resumed.snapshot.config.authorized);
    assert!(!resumed
        .snapshot
        .config
        .overrides
        .disables(Control::Authorization));
    Ok(())
}

#[tokio::test]
async fn integration_requires_authorization_and_regenerates_coherent_history_reports() -> Result<()>
{
    let (url, requests, server) = fixture().await?;
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut config = default_config(
        Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    config.overrides = expert(vec![Control::DataSampling]);
    config.overrides.reason = "Earlier audited fixture policy".into();
    let run = Engine::new(config)?.run().await?;
    std::env::set_var("METISBLACK_HISTORY_FIXTURE_TOKEN", "fixture-token");
    let integration = integrations::IntegrationConfig {
        kind: "github".into(),
        endpoint: url,
        token_env: "METISBLACK_HISTORY_FIXTURE_TOKEN".into(),
        project: "fixture/repo".into(),
        issue: "1".into(),
    };
    assert!(integrations::publish_with_overrides(
        &integration,
        &run,
        Some(expert(vec![Control::Network]))
    )
    .await
    .is_err());
    assert_eq!(requests.lock().unwrap().len(), 0);
    let mut extra = expert(vec![Control::Network, Control::Authorization]);
    extra.reason = "Current publication fixture policy".into();
    integrations::publish_with_overrides(&integration, &run, Some(extra)).await?;
    let saved: RunSnapshot = storage::read_json(&root.path().join("run-manifest.json"))?;
    for name in ["report.md", "report.html", "report.json", "report.sarif"] {
        let content = std::fs::read_to_string(root.path().join(name))?;
        assert!(
            content.contains("Earlier audited fixture policy"),
            "missing history in {name}"
        );
        assert!(
            content.contains("Current publication fixture policy"),
            "missing current controls in {name}"
        );
    }
    let report: Value = storage::read_json(&root.path().join("report.json"))?;
    assert_eq!(
        report["run"]["override_history"],
        serde_json::to_value(&saved.override_history)?
    );
    assert_eq!(
        report["run"]["config"]["overrides"],
        serde_json::to_value(&saved.config.overrides)?
    );
    let sarif: Value = storage::read_json(&root.path().join("report.sarif"))?;
    assert_eq!(
        sarif["runs"][0]["properties"]["overrideHistory"],
        serde_json::to_value(&saved.override_history)?
    );
    server.abort();
    Ok(())
}
