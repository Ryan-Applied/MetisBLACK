//! Exhaustive registry: adding a Control forces an enforcing probe here.
//! More detailed I/O and adjacency tests live with each subsystem.
use anyhow::Result;
use domain::{
    Control, ExpertOverrides, Finding, FindingState, Mode, NetworkRule, Scope, ToolAction,
};
use metisblack_orchestrator::{default_config, Engine};
use serde_json::json;
use storage::Redactor;

fn expert(controls: Vec<Control>, all: bool) -> ExpertOverrides {
    ExpertOverrides {
        controls,
        unsafe_all: all,
        actor: "matrix-operator".into(),
        reason: "Authorized isolated control matrix".into(),
        acknowledged: true,
        ..Default::default()
    }
}
fn scope() -> Scope {
    Scope {
        network: vec![NetworkRule {
            host: "example.test".into(),
            ports: vec![443],
            subdomains: false,
            paths: vec!["/allowed".into()],
        }],
        ..Default::default()
    }
}
async fn admitted(control: Control, mut overrides: ExpertOverrides) -> Result<bool> {
    // Dependency gates are deliberately acknowledged in shell probes; the
    // tested control remains absent in the default and adjacent cases.
    overrides.actor = "matrix-operator".into();
    overrides.reason = "Authorized isolated control matrix".into();
    overrides.acknowledged = true;
    let root = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    let mut scoped = scope();
    scoped.roots = vec![source.path().into()];
    let policy = |scope: Scope, o: ExpertOverrides| policy::Policy::with_overrides(scope, o);
    Ok(match control {
        Control::Scope | Control::Destinations | Control::ThirdParty => policy(scoped, overrides)?
            .check_url("https://other.test/allowed")
            .is_ok(),
        Control::Network => providers::Provider::with_overrides(
            domain::ProviderConfig {
                kind: "openai-compatible".into(),
                model: "fixture".into(),
                endpoint: "http://example.test".into(),
                key_env: None,
                timeout_seconds: 1,
                max_output_tokens: 1,
                subscription_cli: None,
            },
            overrides,
        )
        .is_ok(),
        Control::Redirects => policy(scoped, overrides)?
            .redirect_policy()
            .check_url("https://other.test/other")
            .is_ok(),
        Control::Subdomains => policy(scoped, overrides)?
            .check_url("https://sub.example.test/allowed")
            .is_ok(),
        Control::Paths => policy(scoped, overrides)?
            .check_url("https://example.test/other")
            .is_ok(),
        Control::Ports => policy(scoped, overrides)?
            .check_url("https://example.test:8443/allowed")
            .is_ok(),
        Control::Cidrs => policy(scoped, overrides)?
            .check_ip("example.test", "127.0.0.1".parse()?)
            .is_ok(),
        Control::FilesystemRoots => {
            let path = root.path().join("outside.rs");
            storage::atomic_write(&path, b"fixture")?;
            policy(scoped, overrides)?.check_path(&path).is_ok()
        }
        Control::SecretExposure => {
            let path = source.path().join(".env");
            storage::atomic_write(&path, b"fixture")?;
            policy(scoped, overrides)?.check_path(&path).is_ok()
        }
        Control::SecretRedaction => Redactor::with_override(&overrides)
            .text("password=matrix-fixture")
            .contains("matrix-fixture"),
        Control::RequestBudget => {
            scoped.max_requests = 0;
            policy(scoped, overrides)?.reserve(false, false).is_ok()
        }
        Control::StateChanges => {
            scoped.max_state_changes = 0;
            policy(scoped, overrides)?.reserve(true, false).is_ok()
        }
        Control::AccountBudget => {
            scoped.max_accounts = 0;
            scoped.max_state_changes = 1;
            policy(scoped, overrides)?.reserve(true, true).is_ok()
        }
        Control::RateLimit => {
            scoped.requests_per_second = 0;
            policy(scoped, overrides).is_ok()
        }
        Control::Concurrency | Control::DataSampling => {
            let mut c = default_config(
                Mode::Whitebox,
                vec![source.path().display().to_string()],
                root.path().into(),
            )?;
            c.overrides = overrides;
            if control == Control::Concurrency {
                c.scope.max_concurrency = 0;
            } else {
                c.scope.max_response_bytes = 20 * 1024 * 1024;
            }
            c.validate().is_ok()
        }
        Control::Authorization => {
            let mut c = default_config(
                Mode::Blackbox,
                vec!["http://127.0.0.1:1".into()],
                root.path().into(),
            )?;
            c.overrides = overrides;
            Engine::new(c).is_ok()
        }
        Control::CloudIdentity => {
            storage::write_json(
                &source.path().join("cloud-identity.json"),
                &json!({"account_id":"not-scoped"}),
            )?;
            let mut c = default_config(
                Mode::Cloud,
                vec![source.path().display().to_string()],
                root.path().into(),
            )?;
            c.scope.cloud_accounts = vec!["scoped-account".into()];
            c.overrides = overrides;
            Engine::new(c)?.run().await.is_ok()
        }
        Control::PlaybookSelection => {
            let mut lib = agent_library::Library::builtins();
            for b in &mut lib.playbooks {
                b.risk_class = "restricted".into();
            }
            !lib.select_with_overrides(Mode::Whitebox, &[], &[], &overrides)?
                .is_empty()
        }
        Control::ProviderCapabilities => providers::Provider::with_overrides(
            domain::ProviderConfig {
                kind: "custom".into(),
                model: "fixture".into(),
                endpoint: "https://example.test".into(),
                key_env: None,
                timeout_seconds: 1,
                max_output_tokens: 1,
                subscription_cli: None,
            },
            overrides,
        )
        .is_ok(),
        Control::Confirmation => {
            let candidate = serde_json::from_value(
                json!({"title":"Fixture","description":"Operator review","severity":"low","severity_justification":"Fixture risk","location":"local","impact":"Review","remediation":"Review","receipt_ids":["not-used-for-runtime-validation"],"proof":{"kind":"manual","procedure":"Review"}}),
            )?;
            let mut f = Finding {
                id: "fixture".into(),
                candidate,
                state: FindingState::NeedsReview,
                finder: "fixture".into(),
                validations: vec![],
                review_reason: String::new(),
                introduced: None,
                claim_receipts: Default::default(),
                confirmation_override: None,
            };
            f.confirm_by_operator(&overrides).is_ok()
        }
        Control::CommandRisk
        | Control::PackageInstallation
        | Control::ExternalDownloads
        | Control::DestructiveActions
        | Control::PrivilegeChanges
        | Control::Sandbox
        | Control::ToolCapabilities => {
            let prerequisites = [
                Control::ToolCapabilities,
                Control::Sandbox,
                Control::Network,
                Control::FilesystemRoots,
            ];
            overrides
                .controls
                .extend(prerequisites.into_iter().filter(|c| *c != control));
            let program = match control {
                Control::CommandRisk => "sh",
                Control::PackageInstallation => "pip",
                Control::ExternalDownloads => "curl",
                Control::DestructiveActions => "rm",
                Control::PrivilegeChanges => "sudo",
                _ => "true",
            };
            policy(scoped, overrides)?
                .check_action(&ToolAction::Shell {
                    program: program.into(),
                    args: vec![],
                    working_dir: source.path().into(),
                })
                .is_ok()
        }
        Control::Environment | Control::Timeouts => {
            overrides.controls.extend([
                Control::ToolCapabilities,
                Control::Sandbox,
                Control::Network,
                Control::FilesystemRoots,
                Control::CommandRisk,
                Control::StateChanges,
            ]);
            scoped.tool_timeout_ms = if control == Control::Timeouts {
                1
            } else {
                1000
            };
            let redactor = Redactor::with_override(&overrides);
            let store = evidence::EvidenceStore::new(
                &root.path().join("receipts"),
                "run-matrix",
                redactor.clone(),
            )?;
            let mut runtime =
                tool_runtime::Runtime::new(policy(scoped, overrides)?, store, redactor);
            runtime.authorize(true);
            #[cfg(unix)]
            let (program, args) = if control == Control::Timeouts {
                ("/bin/sleep", vec!["0.04".into()])
            } else {
                std::env::set_var("METISBLACK_MATRIX_MARKER", "matrix-only");
                (
                    "/bin/sh",
                    vec![
                        "-c".into(),
                        "printf %s \"$METISBLACK_MATRIX_MARKER\"".into(),
                    ],
                )
            };
            #[cfg(windows)]
            let (program, args) = if control == Control::Timeouts {
                ("cmd", vec!["/C".into(), "ping -n 2 127.0.0.1 >NUL".into()])
            } else {
                std::env::set_var("METISBLACK_MATRIX_MARKER", "matrix-only");
                (
                    "cmd",
                    vec!["/C".into(), "echo %METISBLACK_MATRIX_MARKER%".into()],
                )
            };
            let receipt = runtime
                .execute(
                    "matrix",
                    ToolAction::Shell {
                        program: program.into(),
                        args,
                        working_dir: source.path().into(),
                    },
                )
                .await?;
            if control == Control::Timeouts {
                receipt.output.successful
            } else {
                receipt.output.data["stdout"]
                    .as_str()
                    .is_some_and(|stdout| stdout.trim() == "matrix-only")
            }
        }
    })
}

#[tokio::test]
async fn all_registered_controls_enforce_exact_bypass_and_unsafe_all() -> Result<()> {
    for control in Control::ALL {
        let neighbor = match control {
            Control::Authorization => Control::Network,
            Control::CloudIdentity => Control::FilesystemRoots,
            Control::PlaybookSelection => Control::ToolCapabilities,
            Control::Scope | Control::Redirects | Control::Subdomains | Control::Cidrs => {
                Control::Ports
            }
            Control::Destinations | Control::Ports => Control::Paths,
            Control::ThirdParty | Control::Paths => Control::Subdomains,
            Control::FilesystemRoots | Control::SecretRedaction => Control::SecretExposure,
            Control::CommandRisk | Control::PrivilegeChanges => Control::DestructiveActions,
            Control::DestructiveActions => Control::PrivilegeChanges,
            Control::PackageInstallation => Control::ExternalDownloads,
            Control::ExternalDownloads => Control::PackageInstallation,
            Control::StateChanges => Control::AccountBudget,
            Control::AccountBudget => Control::StateChanges,
            Control::RateLimit => Control::RequestBudget,
            Control::RequestBudget | Control::Timeouts => Control::RateLimit,
            Control::Concurrency => Control::DataSampling,
            Control::DataSampling => Control::Concurrency,
            Control::Sandbox | Control::ProviderCapabilities => Control::ToolCapabilities,
            Control::ToolCapabilities => Control::Sandbox,
            Control::Network => Control::Destinations,
            Control::Environment | Control::SecretExposure => Control::SecretRedaction,
            Control::Confirmation => Control::Authorization,
        };
        for (overrides, expected, label) in [
            (ExpertOverrides::default(), false, "default"),
            (expert(vec![*control], false), true, "exact"),
            (expert(vec![neighbor], false), false, "adjacent"),
            (expert(vec![], true), true, "unsafe_all"),
        ] {
            assert_eq!(
                admitted(*control, overrides).await?,
                expected,
                "{control:?}: {label}"
            );
        }
    }
    Ok(())
}
