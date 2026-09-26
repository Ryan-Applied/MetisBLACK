use domain::{
    Control, ExpertOverrides, SubscriptionCliAutonomy, SubscriptionCliConfig, SubscriptionCliKind,
};
use provider_cli_runtime::{CancellationToken, SubscriptionCliFailureKind, SubscriptionCliRuntime};
use serde_json::json;
use std::{path::PathBuf, sync::OnceLock, time::Duration};

fn fake_executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake-subscription-cli"))
}

fn config(kind: SubscriptionCliKind, autonomy: SubscriptionCliAutonomy) -> SubscriptionCliConfig {
    let mut config = SubscriptionCliConfig::new(kind);
    config.autonomy = autonomy;
    config.executable = Some(fake_executable());
    config.max_stdout_bytes = 256 * 1024;
    config.max_stderr_bytes = 64 * 1024;
    config.max_events = 100;
    config.max_turns = 16;
    config
}

fn overrides(autonomy: SubscriptionCliAutonomy) -> ExpertOverrides {
    let mut controls = vec![
        Control::ToolCapabilities,
        Control::Sandbox,
        Control::Network,
        Control::SecretExposure,
    ];
    if matches!(
        autonomy,
        SubscriptionCliAutonomy::WorkspaceWrite | SubscriptionCliAutonomy::Unrestricted
    ) {
        controls.extend([Control::FilesystemRoots, Control::StateChanges]);
    }
    if autonomy == SubscriptionCliAutonomy::Unrestricted {
        controls.extend([
            Control::Environment,
            Control::CommandRisk,
            Control::PackageInstallation,
            Control::ExternalDownloads,
            Control::DestructiveActions,
            Control::PrivilegeChanges,
        ]);
    }
    ExpertOverrides {
        controls,
        unsafe_all: false,
        reason: "subscription CLI integration test".into(),
        actor: "test-operator".into(),
        acknowledged: true,
        timestamp_ms: 1,
    }
}

fn runtime(kind: SubscriptionCliKind, autonomy: SubscriptionCliAutonomy) -> SubscriptionCliRuntime {
    SubscriptionCliRuntime::new(
        config(kind, autonomy),
        kind.provider_kind().into(),
        "fixture-model".into(),
        10,
        4_096,
        overrides(autonomy),
    )
    .expect("valid fixture runtime")
}

#[tokio::test]
async fn normalizes_machine_output_and_records_provenance() {
    let execution = runtime(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::ReadOnly,
    )
    .invoke(&json!({"fixture":"valid"}).to_string())
    .await
    .unwrap();
    assert_eq!(execution.text, "fixture complete");
    assert_eq!(execution.calls.len(), 1);
    assert_eq!(execution.calls[0].name, "finish");
    assert_eq!(execution.input_tokens, Some(11));
    assert_eq!(execution.output_tokens, Some(7));
    assert_eq!(execution.cost_microusd, Some(42));
    assert_eq!(
        execution.audit.cli_version,
        "fake-subscription-cli claude codex 1.2.3"
    );
    assert_eq!(execution.audit.executable_sha256.len(), 64);
    assert!(execution.audit.executable.is_absolute());
    assert!(!execution.audit.native_customizations);
    assert_eq!(
        execution.audit.customization_isolation,
        "user_config_and_execpolicy_rules_ignored"
    );
    assert!(!execution
        .audit
        .arguments
        .iter()
        .any(|arg| arg.contains("\"fixture\"")));
    assert!(execution.audit.events_is_not_exposed());
}

#[test]
fn descriptor_hashes_prompt_without_exposing_prompt_or_environment_values() {
    let runtime = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::ReadOnly,
    );
    let prompt = "descriptor-only-sensitive-prompt";
    let descriptor = runtime.descriptor(prompt).unwrap();
    let serialized = serde_json::to_string(&descriptor).unwrap();
    assert_eq!(descriptor.prompt_sha256.len(), 64);
    assert_eq!(descriptor.prompt_bytes, prompt.len() as u64);
    assert_eq!(descriptor.executable_sha256.len(), 64);
    assert!(descriptor.resolved_executable.is_some());
    assert!(descriptor.environment_names.contains(&"CI".into()));
    assert!(!serialized.contains(prompt));
    assert!(descriptor.arguments.contains(&"--permission-mode".into()));
    assert!(descriptor.cli_version.is_none());
}

#[tokio::test]
async fn prepared_invocation_binds_version_and_executes_the_same_snapshot() {
    let runtime = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::InferenceOnly,
    );
    let prepared = runtime
        .prepare(&json!({"fixture":"valid"}).to_string())
        .await
        .unwrap();
    assert_eq!(
        prepared.descriptor().cli_version.as_deref(),
        Some("fake-subscription-cli claude codex 1.2.3")
    );
    assert_eq!(prepared.descriptor().executable_sha256.len(), 64);
    let execution = runtime.invoke_prepared(prepared).await.unwrap();
    assert_eq!(execution.text, "fixture complete");
}

#[tokio::test]
async fn prepared_invocation_rejects_executable_replacement() {
    use std::io::Write;

    let directory = tempfile::tempdir().unwrap();
    let copied = directory.path().join("fake-subscription-cli");
    std::fs::copy(fake_executable(), &copied).unwrap();
    let mut cli_config = config(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::InferenceOnly,
    );
    cli_config.executable = Some(copied.clone());
    let runtime = SubscriptionCliRuntime::new(
        cli_config,
        "anthropic".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::InferenceOnly),
    )
    .unwrap();
    let prepared = runtime
        .prepare(&json!({"fixture":"valid"}).to_string())
        .await
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(copied)
        .unwrap()
        .write_all(b"changed-after-prepare")
        .unwrap();
    let failure = runtime.invoke_prepared(prepared).await.unwrap_err();
    assert_eq!(failure.kind, SubscriptionCliFailureKind::BindingMismatch);
}

trait AuditFixtureAssertion {
    fn events_is_not_exposed(&self) -> bool;
}

impl AuditFixtureAssertion for provider_cli_runtime::SubscriptionCliAudit {
    fn events_is_not_exposed(&self) -> bool {
        !self
            .arguments
            .iter()
            .any(|argument| argument.contains("fixture complete"))
    }
}

#[tokio::test]
async fn model_metacharacters_are_one_argv_value_and_never_execute() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = directory.path().join("shell-injection-sentinel");
    let model = format!("model; touch {}", sentinel.display());
    let runtime = SubscriptionCliRuntime::new(
        config(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::ReadOnly,
        ),
        "openai".into(),
        model.clone(),
        10,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .unwrap();
    let execution = runtime
        .invoke(&json!({"fixture":"arguments"}).to_string())
        .await
        .unwrap();
    assert!(execution
        .audit
        .arguments
        .iter()
        .any(|argument| argument == &model));
    assert!(!sentinel.exists());
}

#[tokio::test]
async fn native_autonomous_tools_are_audit_events_not_harness_calls() {
    for kind in [SubscriptionCliKind::Claude, SubscriptionCliKind::Codex] {
        let execution = runtime(kind, SubscriptionCliAutonomy::ReadOnly)
            .invoke(&json!({"fixture":"native_tool"}).to_string())
            .await
            .unwrap();
        assert!(execution.calls.is_empty());
        assert!(execution
            .events
            .iter()
            .any(|event| event.tool_name.as_deref() == Some("http_get")));
        assert_eq!(execution.text, "native operation observed");
    }
}

#[test]
fn every_mode_requires_its_exact_override_bundle() {
    for mode in [
        SubscriptionCliAutonomy::InferenceOnly,
        SubscriptionCliAutonomy::ReadOnly,
        SubscriptionCliAutonomy::WorkspaceWrite,
        SubscriptionCliAutonomy::Unrestricted,
    ] {
        assert!(SubscriptionCliRuntime::new(
            config(SubscriptionCliKind::Claude, mode),
            "anthropic".into(),
            "fixture-model".into(),
            5,
            4_096,
            ExpertOverrides::default(),
        )
        .is_err());
        assert!(SubscriptionCliRuntime::new(
            config(SubscriptionCliKind::Claude, mode),
            "anthropic".into(),
            "fixture-model".into(),
            5,
            4_096,
            overrides(mode),
        )
        .is_ok());
    }

    let baseline_only = overrides(SubscriptionCliAutonomy::ReadOnly);
    assert!(SubscriptionCliRuntime::new(
        config(
            SubscriptionCliKind::Claude,
            SubscriptionCliAutonomy::WorkspaceWrite
        ),
        "anthropic".into(),
        "fixture-model".into(),
        5,
        4_096,
        baseline_only,
    )
    .is_err());
    let workspace_only = overrides(SubscriptionCliAutonomy::WorkspaceWrite);
    assert!(SubscriptionCliRuntime::new(
        config(
            SubscriptionCliKind::Claude,
            SubscriptionCliAutonomy::Unrestricted
        ),
        "anthropic".into(),
        "fixture-model".into(),
        5,
        4_096,
        workspace_only,
    )
    .is_err());
}

#[test]
fn codex_inference_only_fails_closed_before_any_spawn() {
    let error = SubscriptionCliRuntime::new(
        config(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::InferenceOnly,
        ),
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::InferenceOnly),
    )
    .err()
    .expect("Codex inference-only must be unavailable");
    assert!(error.to_string().contains("verified"));
}

#[tokio::test]
async fn dangerous_flags_are_exact_and_unrestricted_only() {
    for kind in [SubscriptionCliKind::Claude, SubscriptionCliKind::Codex] {
        let dangerous = match kind {
            SubscriptionCliKind::Claude => "--dangerously-skip-permissions",
            SubscriptionCliKind::Codex => "--dangerously-bypass-approvals-and-sandbox",
        };
        let safe_modes = match kind {
            SubscriptionCliKind::Claude => vec![
                SubscriptionCliAutonomy::InferenceOnly,
                SubscriptionCliAutonomy::ReadOnly,
                SubscriptionCliAutonomy::WorkspaceWrite,
            ],
            SubscriptionCliKind::Codex => vec![
                SubscriptionCliAutonomy::ReadOnly,
                SubscriptionCliAutonomy::WorkspaceWrite,
            ],
        };
        for safe_mode in safe_modes {
            let execution = runtime(kind, safe_mode)
                .invoke(&json!({"fixture":"valid"}).to_string())
                .await
                .unwrap();
            assert!(!execution
                .audit
                .arguments
                .iter()
                .any(|argument| argument == dangerous));
        }
        let execution = runtime(kind, SubscriptionCliAutonomy::Unrestricted)
            .invoke(&json!({"fixture":"valid"}).to_string())
            .await
            .unwrap();
        assert_eq!(
            execution
                .audit
                .arguments
                .iter()
                .filter(|argument| argument.as_str() == dangerous)
                .count(),
            1
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn environment_is_allowlisted_and_known_values_are_redacted() {
    static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let _guard = ENV_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let old_proxy = std::env::var_os("HTTPS_PROXY");
    let old_canary = std::env::var_os("METISBLACK_ENV_CANARY");
    let old_anthropic_key = std::env::var_os("ANTHROPIC_API_KEY");
    let old_openai_key = std::env::var_os("OPENAI_API_KEY");
    let old_other_key = std::env::var_os("GEMINI_API_KEY");
    let secret = "https://fixture-user:fixture-password@proxy.invalid";
    std::env::set_var("HTTPS_PROXY", secret);
    std::env::set_var("METISBLACK_ENV_CANARY", "must-not-cross-boundary");
    std::env::set_var("ANTHROPIC_API_KEY", "must-never-inherit-anthropic");
    std::env::set_var("OPENAI_API_KEY", "must-never-inherit-openai");
    std::env::set_var("GEMINI_API_KEY", "must-never-inherit-other-provider");

    let mut cli_config = config(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::ReadOnly,
    );
    cli_config.inherit_environment = false;
    cli_config.profile_environment = vec!["HTTPS_PROXY".into()];
    let runtime = SubscriptionCliRuntime::new(
        cli_config,
        "anthropic".into(),
        "fixture-model".into(),
        15,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .unwrap();
    let environment = runtime
        .invoke(&json!({"fixture":"environment"}).to_string())
        .await
        .unwrap();
    assert!(!environment.text.contains("METISBLACK_ENV_CANARY"));
    assert!(environment
        .audit
        .environment_names
        .contains(&"HTTPS_PROXY".into()));
    let redacted = runtime
        .invoke(&json!({"fixture":"secret"}).to_string())
        .await
        .unwrap();
    assert!(!redacted.text.contains("fixture-password"));
    assert!(!redacted.audit.stderr_summary.contains("fixture-password"));
    assert!(redacted.text.contains("[REDACTED]"));

    let mut unrestricted_config = config(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::Unrestricted,
    );
    unrestricted_config.inherit_environment = true;
    let unrestricted = SubscriptionCliRuntime::new(
        unrestricted_config,
        "anthropic".into(),
        "fixture-model".into(),
        15,
        4_096,
        overrides(SubscriptionCliAutonomy::Unrestricted),
    )
    .unwrap();
    let inherited = unrestricted
        .invoke(&json!({"fixture":"environment"}).to_string())
        .await
        .unwrap();
    assert!(inherited.text.contains("METISBLACK_ENV_CANARY"));
    assert!(inherited.text.contains("must-not-cross-boundary"));
    assert!(!inherited.text.contains("ANTHROPIC_API_KEY"));
    assert!(!inherited.text.contains("OPENAI_API_KEY"));
    assert!(!inherited.text.contains("GEMINI_API_KEY"));
    assert!(!inherited
        .audit
        .environment_names
        .iter()
        .any(|name| name.contains("API_KEY")));
    assert_eq!(inherited.audit.assurance, "unrestricted_autonomous_expert");

    match old_proxy {
        Some(value) => std::env::set_var("HTTPS_PROXY", value),
        None => std::env::remove_var("HTTPS_PROXY"),
    }
    match old_canary {
        Some(value) => std::env::set_var("METISBLACK_ENV_CANARY", value),
        None => std::env::remove_var("METISBLACK_ENV_CANARY"),
    }
    for (name, old) in [
        ("ANTHROPIC_API_KEY", old_anthropic_key),
        ("OPENAI_API_KEY", old_openai_key),
        ("GEMINI_API_KEY", old_other_key),
    ] {
        match old {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}

#[test]
fn explicit_login_profile_is_copied_and_blanket_inheritance_requires_unrestricted_mode() {
    let mut explicit = config(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::ReadOnly,
    );
    explicit.profile_environment = vec!["HOME".into(), "PATH".into(), "CODEX_HOME".into()];
    assert!(SubscriptionCliRuntime::new(
        explicit,
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .is_ok());

    let mut blanket = config(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::ReadOnly,
    );
    blanket.inherit_environment = true;
    assert!(SubscriptionCliRuntime::new(
        blanket,
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .is_err());

    let mut unrestricted = config(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::Unrestricted,
    );
    unrestricted.inherit_environment = true;
    let unrestricted_runtime = SubscriptionCliRuntime::new(
        unrestricted,
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::Unrestricted),
    )
    .expect("unrestricted environment override");
    assert!(unrestricted_runtime
        .descriptor("fixture")
        .unwrap()
        .environment_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("PATH")));

    let safe_descriptor = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::Unrestricted,
    )
    .descriptor("fixture")
    .unwrap();
    assert!(safe_descriptor.arguments.contains(&"--safe-mode".into()));
    assert!(!safe_descriptor.native_customizations);

    let mut customized = config(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::Unrestricted,
    );
    customized.load_native_customizations = true;
    let customized = SubscriptionCliRuntime::new(
        customized,
        "anthropic".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::Unrestricted),
    )
    .unwrap()
    .descriptor("fixture")
    .unwrap();
    assert!(!customized.arguments.contains(&"--safe-mode".into()));
    assert!(customized.native_customizations);
}

#[tokio::test]
async fn rejects_non_machine_output_trailing_prose_and_caps() {
    let runtime = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::InferenceOnly,
    );
    for fixture in ["invalid", "trailing"] {
        assert!(runtime
            .invoke(&json!({"fixture":fixture}).to_string())
            .await
            .is_err());
    }

    let mut stdout_capped = config(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::InferenceOnly,
    );
    stdout_capped.max_stdout_bytes = 1_024;
    let runtime = SubscriptionCliRuntime::new(
        stdout_capped,
        "anthropic".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::InferenceOnly),
    )
    .unwrap();
    let overflow_failure = runtime
        .invoke(&json!({"fixture":"oversized"}).to_string())
        .await
        .unwrap_err();
    assert_eq!(
        overflow_failure.kind,
        SubscriptionCliFailureKind::OutputLimit
    );
    let overflow_audit = overflow_failure.audit.expect("overflow audit");
    assert!(overflow_audit.output_overflowed || overflow_audit.stdout_truncated);
    assert!(overflow_audit.direct_child_termination_attempted);

    let mut event_capped = config(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::ReadOnly,
    );
    event_capped.max_events = 2;
    let runtime = SubscriptionCliRuntime::new(
        event_capped,
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .unwrap();
    assert!(runtime
        .invoke(&json!({"fixture":"events","count":2}).to_string())
        .await
        .is_err());

    let mut turn_capped = config(
        SubscriptionCliKind::Codex,
        SubscriptionCliAutonomy::ReadOnly,
    );
    turn_capped.max_turns = 1;
    let runtime = SubscriptionCliRuntime::new(
        turn_capped,
        "openai".into(),
        "fixture-model".into(),
        5,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .unwrap();
    assert!(runtime
        .invoke(&json!({"fixture":"turns","count":2}).to_string())
        .await
        .is_err());
}

async fn live_unrestricted_probe(kind: SubscriptionCliKind, model: &str) {
    let directory = tempfile::tempdir().unwrap();
    let mut cli_config = config(kind, SubscriptionCliAutonomy::Unrestricted);
    cli_config.executable = None;
    cli_config.working_directory = Some(directory.path().to_path_buf());
    cli_config.profile_environment = match kind {
        SubscriptionCliKind::Claude => {
            vec![
                "HOME".into(),
                "PATH".into(),
                "USER".into(),
                "LOGNAME".into(),
                "CLAUDE_CONFIG_DIR".into(),
            ]
        }
        SubscriptionCliKind::Codex => {
            vec![
                "HOME".into(),
                "PATH".into(),
                "USER".into(),
                "LOGNAME".into(),
                "CODEX_HOME".into(),
            ]
        }
    };
    cli_config.max_turns = 1;
    let runtime = SubscriptionCliRuntime::new(
        cli_config,
        kind.provider_kind().into(),
        model.into(),
        180,
        512,
        overrides(SubscriptionCliAutonomy::Unrestricted),
    )
    .unwrap();
    let execution = runtime
        .invoke(
            "Do not use tools. Return exactly this JSON object and no Markdown or prose: {\"text\":\"live subscription probe ok\",\"calls\":[]}",
        )
        .await
        .unwrap();
    assert_eq!(execution.text, "live subscription probe ok");
    assert!(execution.calls.is_empty());
    assert_eq!(
        execution.audit.autonomy,
        SubscriptionCliAutonomy::Unrestricted
    );
}

#[tokio::test]
#[ignore = "requires an authenticated local Claude Code subscription and performs one live turn"]
async fn live_claude_unrestricted_subscription_probe() {
    let model = std::env::var("METISBLACK_LIVE_CLAUDE_MODEL").unwrap_or_else(|_| "sonnet".into());
    live_unrestricted_probe(SubscriptionCliKind::Claude, &model).await;
}

#[tokio::test]
#[ignore = "requires an authenticated local Codex subscription and performs one live turn"]
async fn live_codex_unrestricted_subscription_probe() {
    let model =
        std::env::var("METISBLACK_LIVE_CODEX_MODEL").unwrap_or_else(|_| "gpt-5.6-sol".into());
    live_unrestricted_probe(SubscriptionCliKind::Codex, &model).await;
}

#[tokio::test]
async fn timeout_and_cancellation_terminate_the_child() {
    let timeout_runtime = SubscriptionCliRuntime::new(
        config(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::ReadOnly,
        ),
        "openai".into(),
        "fixture-model".into(),
        1,
        4_096,
        overrides(SubscriptionCliAutonomy::ReadOnly),
    )
    .unwrap();
    let timeout_failure = timeout_runtime
        .invoke(&json!({"fixture":"sleep","milliseconds":2_000}).to_string())
        .await
        .unwrap_err();
    assert_eq!(timeout_failure.kind, SubscriptionCliFailureKind::TimedOut);
    let timeout_audit = timeout_failure.audit.expect("timeout audit");
    assert!(timeout_audit.timed_out);
    assert!(timeout_audit.direct_child_termination_attempted);
    assert!(timeout_audit.direct_child_reaped);

    let cancellation = CancellationToken::default();
    let trigger = cancellation.clone();
    let runtime = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::ReadOnly,
    );
    let task = tokio::spawn(async move {
        runtime
            .invoke_with_cancellation(
                &json!({"fixture":"sleep","milliseconds":5_000}).to_string(),
                cancellation,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    trigger.cancel();
    let cancellation_failure = task.await.unwrap().unwrap_err();
    assert_eq!(
        cancellation_failure.kind,
        SubscriptionCliFailureKind::Cancelled
    );
    let cancellation_audit = cancellation_failure.audit.expect("cancellation audit");
    assert!(cancellation_audit.cancelled);
    assert!(cancellation_audit.direct_child_termination_attempted);
}

#[tokio::test]
async fn nonzero_exit_returns_typed_failure_with_bounded_audit() {
    let failure = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::ReadOnly,
    )
    .invoke(&json!({"fixture":"failure"}).to_string())
    .await
    .unwrap_err();
    assert_eq!(failure.kind, SubscriptionCliFailureKind::ProcessFailure);
    let audit = failure.audit.expect("process failure audit");
    assert_eq!(audit.exit_code, Some(23));
    assert!(audit.stderr_summary.contains("fixture failure"));
    assert!(audit.direct_child_reaped);
}

#[tokio::test]
async fn descendant_held_pipes_are_aborted_after_a_bounded_drain() {
    let failure = runtime(
        SubscriptionCliKind::Claude,
        SubscriptionCliAutonomy::ReadOnly,
    )
    .invoke(&json!({"fixture":"descendant_pipe"}).to_string())
    .await
    .unwrap_err();
    assert_eq!(failure.kind, SubscriptionCliFailureKind::OutputDrain);
    let audit = failure.audit.expect("output drain audit");
    assert!(audit.pipe_drain_aborted);
    assert!(audit.direct_child_reaped);
    assert!(!audit.direct_child_termination_attempted);
}
