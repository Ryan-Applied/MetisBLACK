//! Direct-argv subscription CLI execution for MetisBLACK.
//!
//! This crate is deliberately not a general process runner. It supports only
//! versioned Claude and Codex command layouts, clears the child environment,
//! sends prompts over stdin, and accepts machine-readable output.

#![forbid(unsafe_code)]

mod adapters;
mod contract;
mod process;

pub use contract::{
    AutonomousEventSummary, CancellationToken, SubscriptionCliAudit, SubscriptionCliCapabilities,
    SubscriptionCliDescriptor, SubscriptionCliExecution, SubscriptionCliFailure,
    SubscriptionCliFailureKind, SubscriptionCliResult, SubscriptionCliToolCall,
};

use adapters::{adapter_for, command_for, profile_environment};
use anyhow::{ensure, Context, Result};
use contract::{normalize_output, Assurance};
use domain::{
    Control, ExpertOverrides, SubscriptionCliAutonomy, SubscriptionCliConfig,
    SUBSCRIPTION_CLI_SCHEMA_VERSION,
};
use process::{resolve_executable, run_process, sha256_hex, ProcessRequest};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use storage::Redactor;

const HARD_MAX_PROMPT_BYTES: usize = 2 * 1024 * 1024;

/// A fail-closed executor for one configured subscription CLI.
#[derive(Clone)]
pub struct SubscriptionCliRuntime {
    config: SubscriptionCliConfig,
    provider: String,
    model: String,
    timeout: Duration,
    max_output_tokens: u32,
    overrides: ExpertOverrides,
}

/// A single-use invocation whose prompt, executable identity, CLI version,
/// argv, environment values, working directory, and ceilings were frozen
/// before the provider process can be spawned.
pub struct PreparedSubscriptionCliInvocation {
    descriptor: SubscriptionCliDescriptor,
    executable: PathBuf,
    working_directory: Option<PathBuf>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    prompt: Vec<u8>,
    cli_version: String,
}

impl PreparedSubscriptionCliInvocation {
    pub fn descriptor(&self) -> &SubscriptionCliDescriptor {
        &self.descriptor
    }
}

struct InvocationBinding {
    descriptor: SubscriptionCliDescriptor,
    executable: PathBuf,
    working_directory: Option<PathBuf>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    prompt: Vec<u8>,
}

impl SubscriptionCliRuntime {
    pub fn new(
        config: SubscriptionCliConfig,
        provider: String,
        model: String,
        timeout_seconds: u64,
        max_output_tokens: u32,
        overrides: ExpertOverrides,
    ) -> Result<Self> {
        overrides.validate()?;
        config.validate()?;
        ensure!(
            config.schema_version == SUBSCRIPTION_CLI_SCHEMA_VERSION,
            "unsupported subscription CLI schema version"
        );
        ensure!(!provider.trim().is_empty(), "provider must not be empty");
        ensure!(!model.trim().is_empty(), "model must not be empty");
        ensure!(timeout_seconds > 0, "provider timeout must be positive");
        ensure!(
            timeout_seconds <= 300 || overrides.disables(Control::Timeouts),
            "provider timeout exceeds the five minute safety limit"
        );
        ensure!(
            max_output_tokens > 0,
            "maximum output tokens must be positive"
        );
        validate_mode_overrides(config.autonomy, &overrides)?;
        // The installed Codex exec surface has no verified flag that disables
        // every native tool. Treating read-only sandboxing as inference-only
        // would be a capability escalation, so construction fails closed.
        command_for(
            config.kind,
            config.autonomy,
            &model,
            config.max_turns,
            config.load_native_customizations,
        )?;
        // Validate the allowlist even when inheritance is disabled, so a
        // dormant unsafe profile cannot become active after a config toggle.
        profile_environment(&config)?;
        Ok(Self {
            config,
            provider,
            model,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_tokens,
            overrides,
        })
    }

    /// Static capabilities of the selected adapter. Per-execution provenance
    /// (resolved binary, hash, and CLI version) is returned in the audit.
    pub fn capabilities(&self) -> SubscriptionCliCapabilities {
        adapter_for(self.config.kind).capabilities(
            &self.provider,
            &self.model,
            self.config.autonomy,
            self.config.load_native_customizations,
        )
    }

    /// Build preview metadata without spawning or probing a CLI. This is not a
    /// prepared execution binding because `cli_version` is absent. Durable
    /// execution intents should use [`Self::prepare`] and persist its descriptor.
    pub fn descriptor(&self, prompt: &str) -> Result<SubscriptionCliDescriptor> {
        Ok(self.build_binding(prompt)?.descriptor)
    }

    /// Freeze and version-probe an invocation before its main provider process
    /// is spawned. The returned value is single-use and keeps environment
    /// values and prompt bytes private.
    pub async fn prepare(
        &self,
        prompt: &str,
    ) -> SubscriptionCliResult<PreparedSubscriptionCliInvocation> {
        self.prepare_with_cancellation(prompt, CancellationToken::default())
            .await
    }

    pub async fn prepare_with_cancellation(
        &self,
        prompt: &str,
        cancellation: CancellationToken,
    ) -> SubscriptionCliResult<PreparedSubscriptionCliInvocation> {
        if cancellation.is_cancelled() {
            return Err(failure(
                SubscriptionCliFailureKind::Cancelled,
                "prepare",
                "provider invocation cancelled",
                None,
            ));
        }
        let mut binding = self.build_binding(prompt).map_err(|error| {
            failure(
                SubscriptionCliFailureKind::Configuration,
                "prepare",
                error.to_string(),
                None,
            )
        })?;
        let redactor = self.redactor_for(&binding.environment);
        let adapter = adapter_for(self.config.kind);
        let version_arguments = adapter.version_arguments();
        let version_capture = run_process(ProcessRequest {
            executable: binding.executable.clone(),
            arguments: version_arguments.clone(),
            stdin: None,
            working_directory: binding.working_directory.clone(),
            environment: binding.environment.clone(),
            timeout: self.timeout.min(Duration::from_secs(10)),
            stdout_cap: usize::try_from(self.config.max_stdout_bytes.min(64 * 1024)).map_err(
                |error| {
                    failure(
                        SubscriptionCliFailureKind::Configuration,
                        "prepare",
                        error.to_string(),
                        None,
                    )
                },
            )?,
            stderr_cap: usize::try_from(self.config.max_stderr_bytes.min(64 * 1024)).map_err(
                |error| {
                    failure(
                        SubscriptionCliFailureKind::Configuration,
                        "prepare",
                        error.to_string(),
                        None,
                    )
                },
            )?,
            cancellation,
        })
        .await
        .map_err(|error| {
            failure(
                SubscriptionCliFailureKind::Spawn,
                "version_probe",
                error.to_string(),
                None,
            )
        })?;
        let candidate_version = first_nonempty_line(&version_capture.stdout_lossy())
            .or_else(|| first_nonempty_line(&version_capture.stderr_lossy()))
            .unwrap_or_default();
        let version_audit = contract::audit_from_capture(
            &self.config,
            &self.provider,
            &self.model,
            binding.executable.clone(),
            binding.descriptor.executable_sha256.clone(),
            redactor.text(&candidate_version),
            version_arguments,
            binding.environment.keys().cloned().collect(),
            &version_capture,
            Assurance::for_mode(self.config.autonomy),
            &redactor,
        );
        if let Some((kind, message)) = capture_failure(&version_capture, "version probe") {
            return Err(failure(kind, "version_probe", message, Some(version_audit)));
        }
        if let Err(error) = validate_cli_version(self.config.kind, &candidate_version) {
            return Err(failure(
                SubscriptionCliFailureKind::VersionProbe,
                "version_probe",
                error.to_string(),
                Some(version_audit),
            ));
        }
        if let Err(error) =
            verify_executable_hash(&binding.executable, &binding.descriptor.executable_sha256)
        {
            return Err(failure(
                SubscriptionCliFailureKind::BindingMismatch,
                "version_probe",
                error.to_string(),
                Some(version_audit),
            ));
        }
        let cli_version = redactor.text(&candidate_version);
        binding.descriptor.cli_version = Some(cli_version.clone());
        Ok(PreparedSubscriptionCliInvocation {
            descriptor: binding.descriptor,
            executable: binding.executable,
            working_directory: binding.working_directory,
            arguments: binding.arguments,
            environment: binding.environment,
            prompt: binding.prompt,
            cli_version,
        })
    }

    /// Invoke with a fresh cancellation token.
    pub async fn invoke(&self, prompt: &str) -> SubscriptionCliResult<SubscriptionCliExecution> {
        self.invoke_with_cancellation(prompt, CancellationToken::default())
            .await
    }

    /// Invoke while observing a run-level cancellation token.
    pub async fn invoke_with_cancellation(
        &self,
        prompt: &str,
        cancellation: CancellationToken,
    ) -> SubscriptionCliResult<SubscriptionCliExecution> {
        let prepared = self
            .prepare_with_cancellation(prompt, cancellation.clone())
            .await?;
        self.invoke_prepared_with_cancellation(prepared, cancellation)
            .await
    }

    pub async fn invoke_prepared(
        &self,
        prepared: PreparedSubscriptionCliInvocation,
    ) -> SubscriptionCliResult<SubscriptionCliExecution> {
        self.invoke_prepared_with_cancellation(prepared, CancellationToken::default())
            .await
    }

    pub async fn invoke_prepared_with_cancellation(
        &self,
        prepared: PreparedSubscriptionCliInvocation,
        cancellation: CancellationToken,
    ) -> SubscriptionCliResult<SubscriptionCliExecution> {
        if cancellation.is_cancelled() {
            return Err(failure(
                SubscriptionCliFailureKind::Cancelled,
                "invoke",
                "provider invocation cancelled",
                None,
            ));
        }
        let redactor = self.redactor_for(&prepared.environment);
        let preview = self
            .build_binding(std::str::from_utf8(&prepared.prompt).map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::BindingMismatch,
                    "invoke",
                    error.to_string(),
                    None,
                )
            })?)
            .map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::BindingMismatch,
                    "invoke",
                    error.to_string(),
                    None,
                )
            })?;
        let mut expected = prepared.descriptor.clone();
        expected.cli_version = None;
        if preview.descriptor != expected {
            return Err(failure(
                SubscriptionCliFailureKind::BindingMismatch,
                "invoke",
                "prepared invocation no longer matches the runtime configuration or executable identity",
                None,
            ));
        }
        verify_executable_hash(&prepared.executable, &prepared.descriptor.executable_sha256)
            .map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::BindingMismatch,
                    "invoke",
                    error.to_string(),
                    None,
                )
            })?;
        let capture = run_process(ProcessRequest {
            executable: prepared.executable.clone(),
            arguments: prepared.arguments.clone(),
            stdin: Some(prepared.prompt),
            working_directory: prepared.working_directory,
            environment: prepared.environment.clone(),
            timeout: self.timeout,
            stdout_cap: usize::try_from(self.config.max_stdout_bytes).map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::Configuration,
                    "invoke",
                    error.to_string(),
                    None,
                )
            })?,
            stderr_cap: usize::try_from(self.config.max_stderr_bytes).map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::Configuration,
                    "invoke",
                    error.to_string(),
                    None,
                )
            })?,
            cancellation,
        })
        .await
        .map_err(|error| {
            failure(
                SubscriptionCliFailureKind::Spawn,
                "invoke",
                error.to_string(),
                None,
            )
        })?;

        let audit = contract::audit_from_capture(
            &self.config,
            &self.provider,
            &self.model,
            prepared.executable,
            prepared.descriptor.executable_sha256,
            prepared.cli_version,
            prepared.arguments,
            prepared.environment.keys().cloned().collect(),
            &capture,
            Assurance::for_mode(self.config.autonomy),
            &redactor,
        );
        if let Some((kind, message)) = capture_failure(&capture, "invocation") {
            return Err(failure(kind, "invoke", message, Some(audit)));
        }

        let stdout = std::str::from_utf8(&capture.stdout).map_err(|error| {
            failure(
                SubscriptionCliFailureKind::InvalidOutput,
                "normalize",
                format!("subscription CLI stdout was not valid UTF-8: {error}"),
                Some(audit.clone()),
            )
        })?;
        let mut execution = normalize_output(
            self.config.kind,
            stdout,
            self.config.max_events,
            self.config.max_turns,
            &redactor,
        )
        .map_err(|error| {
            failure(
                SubscriptionCliFailureKind::InvalidOutput,
                "normalize",
                error.to_string(),
                Some(audit.clone()),
            )
        })?;
        let normalized_bytes = execution.text.len()
            + execution
                .calls
                .iter()
                .map(|call| call.id.len() + call.name.len() + call.arguments.to_string().len())
                .sum::<usize>();
        let estimated_output_tokens =
            u64::try_from(normalized_bytes.div_ceil(4)).map_err(|error| {
                failure(
                    SubscriptionCliFailureKind::InvalidOutput,
                    "normalize",
                    error.to_string(),
                    Some(audit.clone()),
                )
            })?;
        if estimated_output_tokens > u64::from(self.max_output_tokens)
            && !self.overrides.disables(Control::RequestBudget)
        {
            return Err(failure(
                SubscriptionCliFailureKind::BudgetExceeded,
                "normalize",
                "subscription CLI normalized output exceeds the token budget",
                Some(audit),
            ));
        }
        let output_tokens_estimated = execution.output_tokens.is_none();
        if output_tokens_estimated {
            execution.output_tokens = Some(estimated_output_tokens);
        }
        execution.audit = audit;
        execution.audit.output_tokens_estimated = output_tokens_estimated;
        Ok(execution)
    }

    fn build_binding(&self, prompt: &str) -> Result<InvocationBinding> {
        validate_mode_overrides(self.config.autonomy, &self.overrides)?;
        ensure!(
            prompt.len() <= HARD_MAX_PROMPT_BYTES || self.overrides.disables(Control::DataSampling),
            "subscription CLI prompt exceeds 2MiB"
        );
        let environment = profile_environment(&self.config)?;
        let adapter = adapter_for(self.config.kind);
        let executable =
            resolve_executable(self.config.executable.as_deref(), adapter.executable())?;
        let executable_sha256 = hash_executable(&executable)?;
        let working_directory =
            canonical_working_directory(self.config.working_directory.as_ref())?;
        let arguments = command_for(
            self.config.kind,
            self.config.autonomy,
            &self.model,
            self.config.max_turns,
            self.config.load_native_customizations,
        )?;
        let capabilities = self.capabilities();
        let descriptor = SubscriptionCliDescriptor {
            provider: self.provider.clone(),
            model: self.model.clone(),
            kind: self.config.kind,
            autonomy: self.config.autonomy,
            assurance: Assurance::for_mode(self.config.autonomy).label().into(),
            configured_executable: self.config.executable.clone(),
            resolved_executable: Some(executable.clone()),
            executable_sha256,
            cli_version: None,
            working_directory: working_directory.clone(),
            arguments: arguments.clone(),
            environment_names: environment.keys().cloned().collect(),
            native_customizations: self.config.load_native_customizations,
            customization_isolation: capabilities.customization_isolation,
            timeout_seconds: self.timeout.as_secs(),
            max_output_tokens: self.max_output_tokens,
            max_stdout_bytes: self.config.max_stdout_bytes,
            max_stderr_bytes: self.config.max_stderr_bytes,
            max_events: self.config.max_events,
            max_turns: self.config.max_turns,
            prompt_sha256: sha256_hex(prompt.as_bytes()),
            prompt_bytes: u64::try_from(prompt.len())?,
        };
        Ok(InvocationBinding {
            descriptor,
            executable,
            working_directory,
            arguments,
            environment,
            prompt: prompt.as_bytes().to_vec(),
        })
    }

    fn redactor_for(&self, environment: &BTreeMap<String, String>) -> Redactor {
        let mut redactor = Redactor::with_override(&self.overrides);
        for (name, value) in environment {
            if sensitive_environment_name(name) {
                redactor.register(value);
            }
        }
        redactor
    }
}

fn failure(
    kind: SubscriptionCliFailureKind,
    phase: &str,
    message: impl Into<String>,
    audit: Option<SubscriptionCliAudit>,
) -> SubscriptionCliFailure {
    SubscriptionCliFailure::new(kind, phase, message, audit)
}

fn capture_failure(
    capture: &process::ProcessCapture,
    label: &str,
) -> Option<(SubscriptionCliFailureKind, String)> {
    if capture.cancelled {
        return Some((
            SubscriptionCliFailureKind::Cancelled,
            format!("subscription CLI {label} cancelled"),
        ));
    }
    if capture.timed_out {
        return Some((
            SubscriptionCliFailureKind::TimedOut,
            format!("subscription CLI {label} timed out"),
        ));
    }
    if capture.output_overflowed || capture.stdout_truncated || capture.stderr_truncated {
        return Some((
            SubscriptionCliFailureKind::OutputLimit,
            format!("subscription CLI {label} exceeded a configured output cap"),
        ));
    }
    if capture.pipe_drain_aborted || capture.stdin_write_aborted || capture.io_error.is_some() {
        return Some((
            SubscriptionCliFailureKind::OutputDrain,
            format!("subscription CLI {label} I/O did not close within the bounded drain period"),
        ));
    }
    if !capture.direct_child_reaped {
        return Some((
            SubscriptionCliFailureKind::ProcessFailure,
            format!("subscription CLI {label} direct child could not be reaped"),
        ));
    }
    if capture.exit_code != Some(0) {
        return Some((
            SubscriptionCliFailureKind::ProcessFailure,
            format!("subscription CLI {label} exited unsuccessfully"),
        ));
    }
    None
}

fn hash_executable(executable: &PathBuf) -> Result<String> {
    Ok(sha256_hex(&std::fs::read(executable).with_context(
        || format!("failed to read subscription CLI {}", executable.display()),
    )?))
}

fn verify_executable_hash(executable: &PathBuf, expected: &str) -> Result<()> {
    let actual = hash_executable(executable)?;
    ensure!(
        actual == expected,
        "subscription CLI executable changed after invocation preparation"
    );
    Ok(())
}

fn sensitive_environment_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "CREDENTIAL",
        "COOKIE",
        "AUTH",
        "PROXY",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn canonical_working_directory(path: Option<&PathBuf>) -> Result<Option<PathBuf>> {
    let Some(path) = path else { return Ok(None) };
    ensure!(
        path.is_absolute(),
        "subscription CLI working directory must be absolute"
    );
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("invalid working directory {}", path.display()))?;
    ensure!(
        canonical.is_dir(),
        "subscription CLI working directory is not a directory"
    );
    Ok(Some(canonical))
}

fn first_nonempty_line(value: &str) -> Option<String> {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn validate_cli_version(kind: domain::SubscriptionCliKind, value: &str) -> Result<()> {
    let expected = match kind {
        domain::SubscriptionCliKind::Claude => "claude",
        domain::SubscriptionCliKind::Codex => "codex",
    };
    let normalized = value.to_ascii_lowercase();
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.is_ascii()
            && normalized.contains(expected)
            && value.bytes().any(|byte| byte.is_ascii_digit()),
        "subscription CLI version output does not identify the configured adapter"
    );
    Ok(())
}

fn validate_mode_overrides(
    mode: SubscriptionCliAutonomy,
    overrides: &ExpertOverrides,
) -> Result<()> {
    let mut required = vec![
        Control::ToolCapabilities,
        Control::Sandbox,
        Control::Network,
        Control::SecretExposure,
    ];
    if matches!(
        mode,
        SubscriptionCliAutonomy::WorkspaceWrite | SubscriptionCliAutonomy::Unrestricted
    ) {
        required.extend([Control::FilesystemRoots, Control::StateChanges]);
    }
    if mode == SubscriptionCliAutonomy::Unrestricted {
        required.extend([
            Control::Environment,
            Control::CommandRisk,
            Control::PackageInstallation,
            Control::ExternalDownloads,
            Control::DestructiveActions,
            Control::PrivilegeChanges,
        ]);
    }
    let missing = required
        .into_iter()
        .filter(|control| !overrides.disables(*control))
        .map(|control| {
            serde_json::to_value(control)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("unknown")
                .to_owned()
        })
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "subscription CLI autonomy requires explicit expert overrides: {}",
        missing.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::SubscriptionCliKind;

    #[test]
    fn version_probe_must_identify_the_selected_adapter() {
        assert!(validate_cli_version(SubscriptionCliKind::Claude, "2.1.283 (Claude Code)").is_ok());
        assert!(validate_cli_version(SubscriptionCliKind::Codex, "codex-cli 0.147.0").is_ok());
        assert!(validate_cli_version(SubscriptionCliKind::Claude, "codex-cli 0.147.0").is_err());
        assert!(validate_cli_version(SubscriptionCliKind::Codex, "unknown").is_err());
    }
}
