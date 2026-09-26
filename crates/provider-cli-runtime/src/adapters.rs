use crate::SubscriptionCliCapabilities;
use anyhow::{ensure, Result};
use domain::{SubscriptionCliAutonomy, SubscriptionCliConfig, SubscriptionCliKind};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) trait Adapter: Send + Sync {
    fn executable(&self) -> &'static str;
    fn version_arguments(&self) -> Vec<String>;
    fn capabilities(
        &self,
        provider: &str,
        model: &str,
        autonomy: SubscriptionCliAutonomy,
        native_customizations: bool,
    ) -> SubscriptionCliCapabilities;
}

struct ClaudeAdapter;
struct CodexAdapter;

static CLAUDE: ClaudeAdapter = ClaudeAdapter;
static CODEX: CodexAdapter = CodexAdapter;

pub(crate) fn adapter_for(kind: SubscriptionCliKind) -> &'static dyn Adapter {
    match kind {
        SubscriptionCliKind::Claude => &CLAUDE,
        SubscriptionCliKind::Codex => &CODEX,
    }
}

impl Adapter for ClaudeAdapter {
    fn executable(&self) -> &'static str {
        "claude"
    }

    fn version_arguments(&self) -> Vec<String> {
        vec!["--version".into()]
    }

    fn capabilities(
        &self,
        provider: &str,
        model: &str,
        autonomy: SubscriptionCliAutonomy,
        native_customizations: bool,
    ) -> SubscriptionCliCapabilities {
        capabilities(
            provider,
            model,
            SubscriptionCliKind::Claude,
            autonomy,
            "claude-stream-json-v1",
            true,
            native_customizations,
        )
    }
}

impl Adapter for CodexAdapter {
    fn executable(&self) -> &'static str {
        "codex"
    }

    fn version_arguments(&self) -> Vec<String> {
        vec!["--version".into()]
    }

    fn capabilities(
        &self,
        provider: &str,
        model: &str,
        autonomy: SubscriptionCliAutonomy,
        native_customizations: bool,
    ) -> SubscriptionCliCapabilities {
        capabilities(
            provider,
            model,
            SubscriptionCliKind::Codex,
            autonomy,
            "codex-exec-json-v1",
            false,
            native_customizations,
        )
    }
}

fn capabilities(
    provider: &str,
    model: &str,
    kind: SubscriptionCliKind,
    autonomy: SubscriptionCliAutonomy,
    protocol: &str,
    native_cost: bool,
    native_customizations: bool,
) -> SubscriptionCliCapabilities {
    SubscriptionCliCapabilities {
        provider: provider.into(),
        model: model.into(),
        kind,
        autonomy,
        protocol: protocol.into(),
        structured_output: true,
        typed_calls: true,
        token_telemetry: true,
        cost_telemetry: native_cost,
        cancellation: "direct_child_only_kill_on_drop_with_bounded_pipe_drain".into(),
        environment_isolation: "env_clear_with_named_profile".into(),
        native_customizations,
        customization_isolation: customization_isolation(kind, native_customizations).into(),
        assurance: match autonomy {
            SubscriptionCliAutonomy::InferenceOnly => "inference_only",
            SubscriptionCliAutonomy::ReadOnly => "read_only_autonomous",
            SubscriptionCliAutonomy::WorkspaceWrite => "workspace_write_autonomous",
            SubscriptionCliAutonomy::Unrestricted => "unrestricted_autonomous_expert",
        }
        .into(),
    }
}

pub(crate) fn customization_isolation(
    kind: SubscriptionCliKind,
    native_customizations: bool,
) -> &'static str {
    match kind {
        SubscriptionCliKind::Claude if native_customizations => "explicitly_enabled",
        SubscriptionCliKind::Claude => "safe_mode",
        SubscriptionCliKind::Codex if native_customizations => "explicitly_enabled",
        // These installed CLI switches prove only that $CODEX_HOME/config.toml
        // and user/project execpolicy `.rules` files are ignored. They do not
        // justify a broader claim about repository instructions.
        SubscriptionCliKind::Codex => "user_config_and_execpolicy_rules_ignored",
    }
}

pub(crate) fn command_for(
    kind: SubscriptionCliKind,
    autonomy: SubscriptionCliAutonomy,
    model: &str,
    max_turns: u32,
    load_native_customizations: bool,
) -> Result<Vec<String>> {
    let arguments = match kind {
        SubscriptionCliKind::Claude => {
            let mut args = vec![
                "--print".into(),
                "--verbose".into(),
                "--output-format".into(),
                "stream-json".into(),
                "--model".into(),
                model.into(),
                "--max-turns".into(),
                max_turns.to_string(),
                "--no-session-persistence".into(),
            ];
            if !load_native_customizations {
                args.push("--safe-mode".into());
            }
            match autonomy {
                SubscriptionCliAutonomy::InferenceOnly => {
                    args.extend([
                        "--tools".into(),
                        String::new(),
                        "--permission-mode".into(),
                        "plan".into(),
                    ]);
                }
                SubscriptionCliAutonomy::ReadOnly => {
                    args.extend(["--permission-mode".into(), "plan".into()]);
                }
                SubscriptionCliAutonomy::WorkspaceWrite => {
                    args.extend(["--permission-mode".into(), "acceptEdits".into()]);
                }
                SubscriptionCliAutonomy::Unrestricted => {
                    // Deliberately absent from every safer mode.
                    args.push("--dangerously-skip-permissions".into());
                }
            }
            args
        }
        SubscriptionCliKind::Codex => {
            ensure!(
                autonomy != SubscriptionCliAutonomy::InferenceOnly,
                "Codex inference-only mode is unavailable: the installed exec interface has no verified switch that disables all native tools"
            );
            let mut args = vec![
                "exec".into(),
                "--json".into(),
                "--model".into(),
                model.into(),
                "--ephemeral".into(),
            ];
            if !load_native_customizations {
                args.extend(["--ignore-user-config".into(), "--ignore-rules".into()]);
            }
            match autonomy {
                SubscriptionCliAutonomy::ReadOnly => {
                    args.extend(["--sandbox".into(), "read-only".into()]);
                }
                SubscriptionCliAutonomy::InferenceOnly => unreachable!("rejected above"),
                SubscriptionCliAutonomy::WorkspaceWrite => {
                    args.extend(["--sandbox".into(), "workspace-write".into()]);
                }
                SubscriptionCliAutonomy::Unrestricted => {
                    // Deliberately absent from every safer mode.
                    args.push("--dangerously-bypass-approvals-and-sandbox".into());
                }
            }
            // A single dash tells `codex exec` to read the prompt from stdin.
            args.push("-".into());
            args
        }
    };
    Ok(arguments)
}

pub(crate) fn profile_environment(
    config: &SubscriptionCliConfig,
) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    let common = BTreeSet::from([
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ]);
    let provider_specific = match config.kind {
        SubscriptionCliKind::Claude => "CLAUDE_CONFIG_DIR",
        SubscriptionCliKind::Codex => "CODEX_HOME",
    };
    if config.inherit_environment {
        for (name, value) in std::env::vars_os() {
            let name = name
                .into_string()
                .map_err(|_| anyhow::anyhow!("environment contains a non-UTF-8 variable name"))?;
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("environment variable {name} is not valid UTF-8"))?;
            environment.insert(name, value);
        }
    } else {
        let mut seen = BTreeSet::new();
        for name in &config.profile_environment {
            ensure!(
                seen.insert(name.as_str()),
                "duplicate subscription CLI profile environment name"
            );
            ensure!(
                common.contains(name.as_str()) || name == provider_specific,
                "environment variable {name} is not in the subscription CLI profile allowlist"
            );
            let Some(value) = std::env::var_os(name) else {
                continue;
            };
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("environment variable {name} is not valid UTF-8"))?;
            environment.insert(name.clone(), value);
        }
    }
    // These deterministic values win even under the explicitly unrestricted
    // inheritance route. The complete inherited name set is still recorded.
    environment.extend([
        ("CI".into(), "1".into()),
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("NO_COLOR".into(), "1".into()),
    ]);
    // Blanket inheritance never carries provider API keys or process injection
    // controls. Subscription CLIs authenticate through their named profile.
    environment.retain(|name, _| {
        !provider_api_key_name(name)
            && ![
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "DYLD_INSERT_LIBRARIES",
                "DYLD_LIBRARY_PATH",
                "NODE_OPTIONS",
                "PYTHONPATH",
                "PYTHONHOME",
                "RUBYOPT",
                "PERL5OPT",
                "BASH_ENV",
                "ENV",
            ]
            .contains(&name.as_str())
    });
    Ok(environment)
}

fn provider_api_key_name(name: &str) -> bool {
    let normalized = name.to_ascii_uppercase();
    normalized.contains("API_KEY")
        || normalized.contains("APIKEY")
        || [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ]
        .contains(&normalized.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_inference_only_is_rejected_without_a_verified_no_tools_switch() {
        let error = command_for(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::InferenceOnly,
            "fixture-model",
            1,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no verified switch"));
    }

    #[test]
    fn codex_default_customization_controls_match_installed_cli_semantics() {
        let arguments = command_for(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::ReadOnly,
            "fixture-model",
            1,
            false,
        )
        .unwrap();
        assert!(arguments
            .windows(1)
            .any(|item| item == ["--ignore-user-config"]));
        assert!(arguments.windows(1).any(|item| item == ["--ignore-rules"]));
        assert!(!arguments.iter().any(|item| item == "--no-tools"));

        let explicitly_enabled = command_for(
            SubscriptionCliKind::Codex,
            SubscriptionCliAutonomy::Unrestricted,
            "fixture-model",
            1,
            true,
        )
        .unwrap();
        assert!(!explicitly_enabled
            .iter()
            .any(|item| item == "--ignore-user-config" || item == "--ignore-rules"));
    }
}
