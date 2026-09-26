use crate::process::ProcessCapture;
use anyhow::{bail, ensure, Context, Result};
use domain::{SubscriptionCliAutonomy, SubscriptionCliConfig, SubscriptionCliKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fmt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use storage::Redactor;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AutonomousEventSummary {
    pub sequence: u32,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliCapabilities {
    pub provider: String,
    pub model: String,
    pub kind: SubscriptionCliKind,
    pub autonomy: SubscriptionCliAutonomy,
    pub protocol: String,
    pub structured_output: bool,
    pub typed_calls: bool,
    pub token_telemetry: bool,
    pub cost_telemetry: bool,
    pub cancellation: String,
    pub environment_isolation: String,
    pub native_customizations: bool,
    /// Exact adapter controls used to limit native customizations. This is not
    /// a claim that every repository-local instruction source is disabled.
    #[serde(default)]
    pub customization_isolation: String,
    pub assurance: String,
}

/// Deterministic metadata for a durable pre-spawn invocation intent. Prompt
/// and environment values are intentionally excluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliDescriptor {
    pub provider: String,
    pub model: String,
    pub kind: SubscriptionCliKind,
    pub autonomy: SubscriptionCliAutonomy,
    pub assurance: String,
    pub configured_executable: Option<PathBuf>,
    pub resolved_executable: Option<PathBuf>,
    pub executable_sha256: String,
    /// Present only for a prepared invocation whose version probe completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    pub working_directory: Option<PathBuf>,
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
    pub native_customizations: bool,
    #[serde(default)]
    pub customization_isolation: String,
    pub timeout_seconds: u64,
    pub max_output_tokens: u32,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_events: u32,
    pub max_turns: u32,
    pub prompt_sha256: String,
    pub prompt_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliAudit {
    pub provider: String,
    pub model: String,
    pub kind: SubscriptionCliKind,
    pub autonomy: SubscriptionCliAutonomy,
    pub assurance: String,
    #[serde(default)]
    pub native_customizations: bool,
    #[serde(default)]
    pub customization_isolation: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub cli_version: String,
    /// Fixed adapter argv only. The prompt is never placed in argv.
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
    pub started_unix_ms: u64,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    #[serde(default)]
    pub output_overflowed: bool,
    /// Only the directly spawned process is terminated. Descendants are not
    /// claimed to be contained or killed.
    #[serde(default)]
    pub direct_child_termination_attempted: bool,
    #[serde(default)]
    pub direct_child_reaped: bool,
    #[serde(default)]
    pub pipe_drain_aborted: bool,
    #[serde(default)]
    pub stdin_write_aborted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_error: Option<String>,
    pub stderr_summary: String,
    pub output_tokens_estimated: bool,
}

impl Default for SubscriptionCliAudit {
    fn default() -> Self {
        Self {
            provider: String::new(),
            model: String::new(),
            kind: SubscriptionCliKind::Codex,
            autonomy: SubscriptionCliAutonomy::InferenceOnly,
            assurance: String::new(),
            native_customizations: false,
            customization_isolation: String::new(),
            executable: PathBuf::new(),
            executable_sha256: String::new(),
            cli_version: String::new(),
            arguments: vec![],
            environment_names: vec![],
            started_unix_ms: 0,
            duration_ms: 0,
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_sha256: String::new(),
            stderr_sha256: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            cancelled: false,
            output_overflowed: false,
            direct_child_termination_attempted: false,
            direct_child_reaped: false,
            pipe_drain_aborted: false,
            stdin_write_aborted: false,
            io_error: None,
            stderr_summary: String::new(),
            output_tokens_estimated: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCliFailureKind {
    Configuration,
    BindingMismatch,
    VersionProbe,
    Spawn,
    Cancelled,
    TimedOut,
    OutputLimit,
    OutputDrain,
    ProcessFailure,
    InvalidOutput,
    BudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliFailure {
    pub kind: SubscriptionCliFailureKind,
    pub phase: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<SubscriptionCliAudit>,
}

impl SubscriptionCliFailure {
    pub(crate) fn new(
        kind: SubscriptionCliFailureKind,
        phase: impl Into<String>,
        message: impl Into<String>,
        audit: Option<SubscriptionCliAudit>,
    ) -> Self {
        Self {
            kind,
            phase: phase.into(),
            message: message.into(),
            audit,
        }
    }
}

impl fmt::Display for SubscriptionCliFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.phase, self.message)
    }
}

impl std::error::Error for SubscriptionCliFailure {}

pub type SubscriptionCliResult<T> = std::result::Result<T, SubscriptionCliFailure>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliExecution {
    pub text: String,
    pub calls: Vec<SubscriptionCliToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_microusd: Option<u64>,
    pub events: Vec<AutonomousEventSummary>,
    pub audit: SubscriptionCliAudit,
}

pub(crate) struct Assurance(&'static str);

impl Assurance {
    pub(crate) fn for_mode(mode: SubscriptionCliAutonomy) -> Self {
        match mode {
            SubscriptionCliAutonomy::InferenceOnly => Self("inference_only"),
            SubscriptionCliAutonomy::ReadOnly => Self("read_only_autonomous"),
            SubscriptionCliAutonomy::WorkspaceWrite => Self("workspace_write_autonomous"),
            SubscriptionCliAutonomy::Unrestricted => Self("unrestricted_autonomous_expert"),
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        self.0
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_from_capture(
    config: &SubscriptionCliConfig,
    provider: &str,
    model: &str,
    executable: PathBuf,
    executable_sha256: String,
    cli_version: String,
    arguments: Vec<String>,
    mut environment_names: Vec<String>,
    capture: &ProcessCapture,
    assurance: Assurance,
    redactor: &Redactor,
) -> SubscriptionCliAudit {
    environment_names.sort();
    SubscriptionCliAudit {
        provider: provider.into(),
        model: model.into(),
        kind: config.kind,
        autonomy: config.autonomy,
        assurance: assurance.0.into(),
        native_customizations: config.load_native_customizations,
        customization_isolation: crate::adapters::customization_isolation(
            config.kind,
            config.load_native_customizations,
        )
        .into(),
        executable,
        executable_sha256,
        cli_version,
        arguments,
        environment_names,
        started_unix_ms: capture.started_unix_ms,
        duration_ms: capture.duration_ms,
        exit_code: capture.exit_code,
        stdout_bytes: capture.stdout_bytes,
        stderr_bytes: capture.stderr_bytes,
        stdout_sha256: super::process::sha256_hex(&capture.stdout),
        stderr_sha256: super::process::sha256_hex(&capture.stderr),
        stdout_truncated: capture.stdout_truncated,
        stderr_truncated: capture.stderr_truncated,
        timed_out: capture.timed_out,
        cancelled: capture.cancelled,
        output_overflowed: capture.output_overflowed,
        direct_child_termination_attempted: capture.direct_child_termination_attempted,
        direct_child_reaped: capture.direct_child_reaped,
        pipe_drain_aborted: capture.pipe_drain_aborted,
        stdin_write_aborted: capture.stdin_write_aborted,
        io_error: capture.io_error.as_ref().map(|value| redactor.text(value)),
        stderr_summary: bounded(redactor.text(&capture.stderr_lossy()), 4_096),
        output_tokens_estimated: false,
    }
}

pub(crate) fn normalize_output(
    kind: SubscriptionCliKind,
    stdout: &str,
    max_events: u32,
    max_turns: u32,
    redactor: &Redactor,
) -> Result<SubscriptionCliExecution> {
    let values = parse_machine_stream(stdout)?;
    ensure!(
        values.len() <= usize::try_from(max_events)?,
        "subscription CLI event limit exceeded"
    );

    let mut execution = SubscriptionCliExecution {
        text: String::new(),
        calls: vec![],
        input_tokens: None,
        output_tokens: None,
        cost_microusd: None,
        events: vec![],
        audit: SubscriptionCliAudit::default(),
    };
    let mut turns = 0u64;
    for (index, value) in values.iter().enumerate() {
        let object = value
            .as_object()
            .context("subscription CLI events must be JSON objects")?;
        let event_type = object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("canonical");
        if event_type == "turn.started" {
            turns = turns.saturating_add(1);
        }
        if let Some(reported) = object.get("num_turns").and_then(Value::as_u64) {
            turns = turns.max(reported);
        }
        ensure!(
            turns <= u64::from(max_turns),
            "subscription CLI turn limit exceeded"
        );

        absorb_telemetry(value, &mut execution)?;
        absorb_canonical(value, &mut execution)?;
        if event_type == "result" {
            if let Some(text) = value.get("result").and_then(Value::as_str) {
                execution.text = text.into();
            }
        }
        match kind {
            SubscriptionCliKind::Claude => absorb_claude(value, &mut execution)?,
            SubscriptionCliKind::Codex => absorb_codex(value, &mut execution)?,
        }
        execution
            .events
            .push(summarize_event(index, value, redactor)?);
    }

    // Native CLIs wrap the requested canonical envelope in their final text.
    // Decode it once, strictly, without accepting prose around the document.
    if let Ok(value) = serde_json::from_str::<Value>(&execution.text) {
        if value.is_object() && (value.get("text").is_some() || value.get("calls").is_some()) {
            let mut canonical = SubscriptionCliExecution {
                text: String::new(),
                calls: vec![],
                input_tokens: execution.input_tokens,
                output_tokens: execution.output_tokens,
                cost_microusd: execution.cost_microusd,
                events: execution.events,
                audit: SubscriptionCliAudit::default(),
            };
            absorb_canonical(&value, &mut canonical)?;
            execution = canonical;
        }
    }

    ensure!(
        !execution.text.trim().is_empty() || !execution.calls.is_empty(),
        "subscription CLI returned no final text or typed calls"
    );
    ensure!(
        execution.calls.len() <= 64,
        "subscription CLI returned too many tool calls"
    );
    let mut ids = BTreeSet::new();
    for call in &mut execution.calls {
        ensure!(
            !call.id.trim().is_empty() && !call.name.trim().is_empty(),
            "subscription CLI returned an invalid tool call"
        );
        ensure!(
            call.arguments.is_object(),
            "tool call arguments must be an object"
        );
        ensure!(
            ids.insert(call.id.clone()),
            "duplicate subscription CLI tool call id"
        );
        call.id = redactor.text(&call.id);
        call.name = redactor.text(&call.name);
        redactor.value(&mut call.arguments);
    }
    execution.text = redactor.text(&execution.text);
    Ok(execution)
}

fn parse_machine_stream(stdout: &str) -> Result<Vec<Value>> {
    ensure!(
        !stdout.trim().is_empty(),
        "subscription CLI returned empty stdout"
    );
    if let Ok(value) = serde_json::from_str::<Value>(stdout) {
        return match value {
            Value::Array(values) => {
                ensure!(
                    !values.is_empty(),
                    "subscription CLI returned an empty event array"
                );
                Ok(values)
            }
            Value::Object(_) => Ok(vec![value]),
            _ => bail!("subscription CLI output must be a JSON object or object array"),
        };
    }
    let mut values = vec![];
    for (index, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("invalid subscription CLI JSONL at line {}", index + 1))?;
        ensure!(
            value.is_object(),
            "subscription CLI JSONL events must be objects"
        );
        values.push(value);
    }
    ensure!(
        !values.is_empty(),
        "subscription CLI returned no JSONL events"
    );
    Ok(values)
}

fn absorb_canonical(value: &Value, execution: &mut SubscriptionCliExecution) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if object.get("type").is_some() && object.get("text").is_none() && object.get("calls").is_none()
    {
        return Ok(());
    }
    if let Some(text) = object.get("text").and_then(Value::as_str) {
        execution.text = text.into();
    }
    if let Some(calls) = object.get("calls") {
        let calls = calls
            .as_array()
            .context("canonical calls must be an array")?;
        for call in calls {
            execution.calls.push(parse_call(call)?);
        }
    }
    Ok(())
}

fn absorb_claude(value: &Value, execution: &mut SubscriptionCliExecution) -> Result<()> {
    let event_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if event_type == "result" {
        if let Some(text) = value.get("result").and_then(Value::as_str) {
            execution.text = text.into();
        }
    }
    let content = value
        .pointer("/message/content")
        .or_else(|| value.get("content"))
        .and_then(Value::as_array);
    if let Some(content) = content {
        for item in content {
            match item.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        execution.text.push_str(text);
                    }
                }
                // Native autonomous operations are observations, not harness
                // tool requests. They remain in bounded event summaries and
                // can never cross into `execution.calls`.
                Some("tool_use") => {}
                _ => {}
            }
        }
    }
    Ok(())
}

fn absorb_codex(value: &Value, execution: &mut SubscriptionCliExecution) -> Result<()> {
    if value.get("type").and_then(Value::as_str) != Some("item.completed") {
        return Ok(());
    }
    let Some(item) = value.get("item") else {
        return Ok(());
    };
    match item.get("type").and_then(Value::as_str) {
        Some("agent_message") => {
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                execution.text = text.into();
            }
        }
        // Native autonomous operations are audit-only. Only a canonical final
        // envelope may request a harness tool.
        Some("tool_call" | "function_call") => {}
        _ => {}
    }
    Ok(())
}

fn absorb_telemetry(value: &Value, execution: &mut SubscriptionCliExecution) -> Result<()> {
    let usage = value
        .get("usage")
        .or_else(|| value.pointer("/message/usage"));
    if let Some(usage) = usage {
        if let Some(input) = usage.get("input_tokens").and_then(Value::as_u64) {
            execution.input_tokens = Some(input);
        }
        if let Some(output) = usage.get("output_tokens").and_then(Value::as_u64) {
            execution.output_tokens = Some(output);
        }
    }
    if let Some(input) = value.get("input_tokens").and_then(Value::as_u64) {
        execution.input_tokens = Some(input);
    }
    if let Some(output) = value.get("output_tokens").and_then(Value::as_u64) {
        execution.output_tokens = Some(output);
    }
    if let Some(cost) = value.get("cost_microusd").and_then(Value::as_u64) {
        execution.cost_microusd = Some(cost);
    } else if let Some(cost) = value.get("total_cost_usd").and_then(Value::as_f64) {
        ensure!(
            cost.is_finite() && cost >= 0.0,
            "invalid subscription CLI cost telemetry"
        );
        execution.cost_microusd = Some((cost * 1_000_000.0).round() as u64);
    }
    Ok(())
}

fn parse_call(value: &Value) -> Result<SubscriptionCliToolCall> {
    let arguments = value
        .get("arguments")
        .or_else(|| value.get("input"))
        .cloned()
        .unwrap_or_else(empty_object);
    let arguments = if let Some(encoded) = arguments.as_str() {
        serde_json::from_str(encoded).context("tool call arguments were not valid JSON")?
    } else {
        arguments
    };
    Ok(SubscriptionCliToolCall {
        id: required_string(value, "id")?,
        name: required_string(value, "name")?,
        arguments,
    })
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .with_context(|| format!("tool call requires {field}"))
}

fn summarize_event(
    index: usize,
    value: &Value,
    redactor: &Redactor,
) -> Result<AutonomousEventSummary> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("canonical")
        .to_owned();
    let tool_name = value
        .pointer("/item/name")
        .or_else(|| {
            value
                .pointer("/message/content")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| item.get("type").and_then(Value::as_str) == Some("tool_use"))
                })
                .and_then(|item| item.get("name"))
        })
        .or_else(|| value.get("name"))
        .and_then(Value::as_str)
        .map(|name| redactor.text(name));
    Ok(AutonomousEventSummary {
        sequence: u32::try_from(index)?,
        kind,
        tool_name,
        summary: bounded(redactor.text(&value.to_string()), 2_048),
    })
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

fn bounded(mut value: String, max: usize) -> String {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str("...[truncated]");
    value
}
