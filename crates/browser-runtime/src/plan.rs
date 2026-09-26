//! Serializable browser workflows. Secret values are resolved only at execution time.

use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, env, sync::Arc};
use zeroize::Zeroizing;

pub const BROWSER_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPlan {
    pub schema_version: u32,
    pub name: String,
    pub actor: String,
    pub session: SessionRequest,
    pub steps: Vec<BrowserStep>,
}

impl BrowserPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == BROWSER_PLAN_SCHEMA_VERSION,
            "unsupported browser plan schema"
        );
        validate_name(&self.name, "plan name")?;
        validate_name(&self.actor, "plan actor")?;
        ensure!(
            !self.steps.is_empty() && self.steps.len() <= 1_000,
            "browser plan must contain 1..=1000 steps"
        );
        let mut ids = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        for step in &self.steps {
            validate_name(&step.id, "step id")?;
            ensure!(ids.insert(step.id.clone()), "duplicate browser step id");
            step.action.validate(&aliases)?;
            if let Some(alias) = step.action.created_alias() {
                validate_name(alias, "element alias")?;
                ensure!(aliases.insert(alias.to_owned()), "duplicate element alias");
            }
        }
        Ok(())
    }

    /// Stable because plans contain environment variable names, never their values.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }

    pub fn checkpoint(&self, completed_step_ids: Vec<String>) -> Result<BrowserCheckpoint> {
        self.validate()?;
        ensure!(
            completed_step_ids.len() <= self.steps.len(),
            "checkpoint exceeds plan"
        );
        for (completed, expected) in completed_step_ids.iter().zip(&self.steps) {
            ensure!(
                completed == &expected.id,
                "checkpoint must be a plan prefix"
            );
        }
        Ok(BrowserCheckpoint {
            plan_fingerprint: self.fingerprint()?,
            completed_step_ids,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserStep {
    pub id: String,
    pub action: BrowserStepAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserStepAction {
    Navigate {
        url: String,
    },
    Find {
        locator: Locator,
        alias: String,
    },
    Wait {
        locator: Locator,
        alias: String,
        timeout_ms: u64,
    },
    Click {
        alias: String,
    },
    Clear {
        alias: String,
    },
    SendKeys {
        alias: String,
        value: PlanValue,
    },
    Fill {
        locator: Locator,
        value: PlanValue,
    },
    Submit {
        alias: String,
    },
    GetCookies,
    AddCookie {
        cookie: PlannedCookie,
    },
    DeleteCookie {
        name: Option<String>,
    },
    GetStorage {
        area: StorageArea,
        key: String,
    },
    SetStorage {
        area: StorageArea,
        key: String,
        value: PlanValue,
    },
    ClearStorage {
        area: StorageArea,
    },
    Screenshot,
    ConsoleLogs,
    NetworkLogs,
    Javascript {
        script: String,
        #[serde(default)]
        arguments: Vec<PlanArgument>,
    },
}

impl BrowserStepAction {
    fn created_alias(&self) -> Option<&str> {
        match self {
            Self::Find { alias, .. } | Self::Wait { alias, .. } => Some(alias),
            _ => None,
        }
    }

    fn validate(&self, aliases: &BTreeSet<String>) -> Result<()> {
        let required = match self {
            Self::Click { alias }
            | Self::Clear { alias }
            | Self::SendKeys { alias, .. }
            | Self::Submit { alias } => Some(alias),
            _ => None,
        };
        if let Some(alias) = required {
            ensure!(
                aliases.contains(alias),
                "element alias must be defined by an earlier step"
            );
        }
        if let Self::Wait { timeout_ms, .. } = self {
            ensure!(*timeout_ms > 0, "wait timeout must be positive");
        }
        if let Self::SendKeys { value, .. }
        | Self::Fill { value, .. }
        | Self::SetStorage { value, .. } = self
        {
            value.validate()?;
        }
        if let Self::GetStorage { key, .. } | Self::SetStorage { key, .. } = self {
            validate_storage_key(key)?;
        }
        match self {
            Self::Navigate { url } => {
                let parsed = Url::parse(url).context("invalid plan navigation URL")?;
                ensure!(
                    ["http", "https"].contains(&parsed.scheme()),
                    "plan navigation must be HTTP(S)"
                );
            }
            Self::Find { locator, .. }
            | Self::Wait { locator, .. }
            | Self::Fill { locator, .. } => {
                locator.wire()?;
            }
            Self::AddCookie { cookie } => cookie.validate()?,
            Self::DeleteCookie { name: Some(name) } => validate_cookie_name(name)?,
            Self::Javascript { script, arguments } => {
                ensure!(
                    !script.trim().is_empty() && script.len() <= 65_536 && !script.contains('\0'),
                    "invalid JavaScript plan step"
                );
                ensure!(arguments.len() <= 128, "too many JavaScript arguments");
                let normalized = script.to_ascii_lowercase().replace(' ', "");
                ensure!(
                    !["password=", "secret=", "token=", "api_key=", "apikey=",]
                        .iter()
                        .any(|needle| normalized.contains(needle)),
                    "embed credentials through environment arguments, not script text"
                );
                for argument in arguments {
                    argument.validate()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Plans never contain credential values. `Public` is deliberately named to
/// make callers attest that serialization is safe; secrets use `Environment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanValue {
    Public { value: String },
    Environment { name: String },
}

impl PlanValue {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Public { value } => ensure!(
                value.len() <= 1_048_576 && !value.contains('\0'),
                "invalid public plan value"
            ),
            Self::Environment { name } => validate_environment_name(name)?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanArgument {
    Public { value: Value },
    Environment { name: String },
}

impl PlanArgument {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Public { value } => ensure!(
                serde_json::to_vec(value)?.len() <= 1_048_576,
                "JavaScript argument is too large"
            ),
            Self::Environment { name } => validate_environment_name(name)?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedCookie {
    pub name: String,
    pub value: PlanValue,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub secure: Option<bool>,
    #[serde(rename = "httpOnly")]
    pub http_only: Option<bool>,
    #[serde(rename = "sameSite")]
    pub same_site: Option<String>,
    pub expiry: Option<u64>,
}

impl PlannedCookie {
    fn validate(&self) -> Result<()> {
        validate_cookie_name(&self.name)?;
        self.value.validate()
    }
}

/// A checkpoint authenticates a completed prefix. Resuming deliberately
/// replays that prefix in a new isolated session to reconstruct browser state;
/// it never trusts stale element handles or cookies from a previous process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCheckpoint {
    pub plan_fingerprint: String,
    pub completed_step_ids: Vec<String>,
}

pub trait SecretResolver: Send + Sync {
    fn resolve(&self, name: &str) -> std::result::Result<Zeroizing<String>, BrowserError>;
}

#[derive(Debug, Default)]
pub struct EnvironmentSecretResolver;

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, name: &str) -> std::result::Result<Zeroizing<String>, BrowserError> {
        validate_environment_name(name).map_err(|error| {
            BrowserError::new(BrowserErrorKind::InvalidInput, error.to_string())
        })?;
        env::var(name).map(Zeroizing::new).map_err(|_| {
            BrowserError::new(
                BrowserErrorKind::InvalidInput,
                format!("required environment variable {name} is unavailable"),
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPlanStatus {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CleanupOutcome {
    Closed,
    Quarantined { driver_acknowledged: bool },
    SessionNotCreated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserStepOutcome {
    pub step_id: String,
    pub successful: bool,
    pub observation_ids: Vec<String>,
    pub output: Value,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserPlanResult {
    pub schema_version: u32,
    pub plan_name: String,
    pub plan_fingerprint: String,
    pub status: BrowserPlanStatus,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub observations: Vec<BrowserObservation>,
    pub steps: Vec<BrowserStepOutcome>,
    pub artifacts: Vec<Artifact>,
    pub final_url: Option<String>,
    pub capabilities: Option<NegotiatedCapabilities>,
    pub cleanup: CleanupOutcome,
    /// A verified checkpoint prefix that was deterministically replayed.
    pub replayed_prefix: Vec<String>,
}

pub struct BrowserPlanExecutor {
    runtime: BrowserRuntime,
    secrets: Arc<dyn SecretResolver>,
}

impl BrowserPlanExecutor {
    pub fn new(runtime: BrowserRuntime) -> Self {
        Self {
            runtime,
            secrets: Arc::new(EnvironmentSecretResolver),
        }
    }

    pub fn with_secret_resolver(runtime: BrowserRuntime, secrets: Arc<dyn SecretResolver>) -> Self {
        Self { runtime, secrets }
    }

    pub async fn execute(&self, plan: &BrowserPlan) -> Result<BrowserPlanResult> {
        self.execute_with_checkpoint(plan, None).await
    }

    pub async fn execute_with_checkpoint(
        &self,
        plan: &BrowserPlan,
        checkpoint: Option<&BrowserCheckpoint>,
    ) -> Result<BrowserPlanResult> {
        plan.validate()?;
        let fingerprint = plan.fingerprint()?;
        let replayed_prefix = if let Some(checkpoint) = checkpoint {
            ensure!(
                checkpoint.plan_fingerprint == fingerprint,
                "checkpoint belongs to a different browser plan"
            );
            let verified = plan.checkpoint(checkpoint.completed_step_ids.clone())?;
            ensure!(&verified == checkpoint, "invalid browser checkpoint");
            checkpoint.completed_step_ids.clone()
        } else {
            vec![]
        };
        let started_ms = now_ms();
        let mut observations = Vec::new();
        let mut steps = Vec::new();
        let mut artifacts = Vec::new();
        let mut redactor = Redactor::with_override(self.runtime.0.policy.overrides());
        let started = match self
            .runtime
            .start_session(&plan.actor, plan.session.clone())
            .await
        {
            Ok(started) => started,
            Err(failure) => {
                observations.push(sanitize_observation(failure.observation, &redactor, false));
                return Ok(BrowserPlanResult {
                    schema_version: BROWSER_PLAN_SCHEMA_VERSION,
                    plan_name: plan.name.clone(),
                    plan_fingerprint: fingerprint,
                    status: status_for_error(&failure.error),
                    started_ms,
                    finished_ms: now_ms(),
                    observations,
                    steps,
                    artifacts,
                    final_url: None,
                    capabilities: None,
                    cleanup: CleanupOutcome::SessionNotCreated,
                    replayed_prefix,
                });
            }
        };
        observations.push(sanitize_observation(started.observation, &redactor, false));
        let session = started.value;
        let capabilities = Some(session.capabilities().clone());
        let mut aliases = BTreeMap::new();
        let mut status = BrowserPlanStatus::Completed;
        let mut final_url = None;
        for step in &plan.steps {
            let run = self
                .run_step(&session, &plan.actor, step, &mut aliases, &mut redactor)
                .await;
            match run {
                Ok(mut run) => {
                    if let Some(url) = run.final_url.take() {
                        final_url = Some(url);
                    }
                    let observation_ids = run
                        .observations
                        .iter()
                        .map(|observation| observation.id.clone())
                        .collect();
                    artifacts.extend(run.artifacts.clone());
                    observations.extend(run.observations);
                    steps.push(BrowserStepOutcome {
                        step_id: step.id.clone(),
                        successful: true,
                        observation_ids,
                        output: run.output,
                        error: None,
                    });
                }
                Err(failure) => {
                    let observation = sanitize_observation(failure.observation, &redactor, false);
                    let observation_id = observation.id.clone();
                    observations.push(observation);
                    let message = redactor.text(&failure.error.message);
                    status = status_for_error(&failure.error);
                    steps.push(BrowserStepOutcome {
                        step_id: step.id.clone(),
                        successful: false,
                        observation_ids: vec![observation_id],
                        output: json!({}),
                        error: Some(message),
                    });
                    break;
                }
            }
        }
        let cleanup = if status == BrowserPlanStatus::Completed {
            match session.close(&plan.actor).await {
                Ok(closed) => {
                    observations.push(sanitize_observation(closed.observation, &redactor, false));
                    CleanupOutcome::Closed
                }
                Err(failure) => {
                    observations.push(sanitize_observation(failure.observation, &redactor, false));
                    status = status_for_error(&failure.error);
                    CleanupOutcome::Quarantined {
                        driver_acknowledged: session.quarantine().await,
                    }
                }
            }
        } else {
            CleanupOutcome::Quarantined {
                driver_acknowledged: session.quarantine().await,
            }
        };
        Ok(BrowserPlanResult {
            schema_version: BROWSER_PLAN_SCHEMA_VERSION,
            plan_name: plan.name.clone(),
            plan_fingerprint: fingerprint,
            status,
            started_ms,
            finished_ms: now_ms(),
            observations,
            steps,
            artifacts,
            final_url,
            capabilities,
            cleanup,
            replayed_prefix,
        })
    }

    async fn run_step(
        &self,
        session: &BrowserSession,
        actor: &str,
        step: &BrowserStep,
        aliases: &mut BTreeMap<String, ElementRef>,
        redactor: &mut Redactor,
    ) -> std::result::Result<StepRun, ObservedFailure> {
        match &step.action {
            BrowserStepAction::Navigate { url } => {
                let observed = session.navigate(actor, url).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"url":observed.value}),
                    Some(observed.value),
                ))
            }
            BrowserStepAction::Find { locator, alias } => {
                let observed = session.find(actor, locator.clone()).await?;
                aliases.insert(alias.clone(), observed.value);
                Ok(StepRun::one(
                    observed.observation,
                    json!({"alias":alias}),
                    None,
                ))
            }
            BrowserStepAction::Wait {
                locator,
                alias,
                timeout_ms,
            } => {
                let observed = session
                    .wait_for(actor, locator.clone(), *timeout_ms)
                    .await?;
                aliases.insert(alias.clone(), observed.value);
                Ok(StepRun::one(
                    observed.observation,
                    json!({"alias":alias}),
                    None,
                ))
            }
            BrowserStepAction::Click { alias } => {
                let observed = session
                    .click(actor, alias_element(session, actor, aliases, alias)?)
                    .await?;
                Ok(StepRun::one(observed.observation, json!({}), None))
            }
            BrowserStepAction::Clear { alias } => {
                let observed = session
                    .clear(actor, alias_element(session, actor, aliases, alias)?)
                    .await?;
                Ok(StepRun::one(observed.observation, json!({}), None))
            }
            BrowserStepAction::SendKeys { alias, value } => {
                let resolved =
                    resolve_value(value, self.secrets.as_ref(), redactor).map_err(|error| {
                        session.local_failure(
                            actor,
                            BrowserAction::SendKeys,
                            error.kind,
                            error.message,
                        )
                    })?;
                let observed = session
                    .send_keys(
                        actor,
                        alias_element(session, actor, aliases, alias)?,
                        &resolved,
                    )
                    .await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"sent":true}),
                    None,
                ))
            }
            BrowserStepAction::Fill { locator, value } => {
                let resolved =
                    resolve_value(value, self.secrets.as_ref(), redactor).map_err(|error| {
                        session.local_failure(
                            actor,
                            BrowserAction::SendKeys,
                            error.kind,
                            error.message,
                        )
                    })?;
                let observed = session.fill(actor, locator.clone(), &resolved).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"filled":true}),
                    None,
                ))
            }
            BrowserStepAction::Submit { alias } => {
                let observed = session
                    .submit(actor, alias_element(session, actor, aliases, alias)?)
                    .await?;
                Ok(StepRun::one(observed.observation, json!({}), None))
            }
            BrowserStepAction::GetCookies => {
                let observed = session.cookies(actor).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"cookie_count":observed.value.len()}),
                    None,
                ))
            }
            BrowserStepAction::AddCookie { cookie } => {
                let value = resolve_value(&cookie.value, self.secrets.as_ref(), redactor).map_err(
                    |error| {
                        session.local_failure(
                            actor,
                            BrowserAction::AddCookie,
                            error.kind,
                            error.message,
                        )
                    },
                )?;
                let observed = session
                    .add_cookie(
                        actor,
                        Cookie {
                            name: cookie.name.clone(),
                            value: value.to_string(),
                            path: cookie.path.clone(),
                            domain: cookie.domain.clone(),
                            secure: cookie.secure,
                            http_only: cookie.http_only,
                            same_site: cookie.same_site.clone(),
                            expiry: cookie.expiry,
                        },
                    )
                    .await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"added":true}),
                    None,
                ))
            }
            BrowserStepAction::DeleteCookie { name } => {
                let observed = session.delete_cookie(actor, name.as_deref()).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"deleted":true}),
                    None,
                ))
            }
            BrowserStepAction::GetStorage { area, key } => {
                let observed = session.storage_get(actor, *area, key).await?;
                let present = observed.value.is_some();
                Ok(StepRun::one_sensitive(
                    observed.observation,
                    json!({"present":present,"value":"[REDACTED]"}),
                ))
            }
            BrowserStepAction::SetStorage { area, key, value } => {
                let resolved =
                    resolve_value(value, self.secrets.as_ref(), redactor).map_err(|error| {
                        session.local_failure(
                            actor,
                            BrowserAction::SetStorage,
                            error.kind,
                            error.message,
                        )
                    })?;
                let observed = session.storage_set(actor, *area, key, &resolved).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"set":true}),
                    None,
                ))
            }
            BrowserStepAction::ClearStorage { area } => {
                let observed = session.storage_clear(actor, *area).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"cleared":true}),
                    None,
                ))
            }
            BrowserStepAction::Screenshot => {
                let observed = session.screenshot(actor).await?;
                let artifact = observed.value.artifact.clone();
                Ok(StepRun {
                    observations: vec![observed.observation],
                    output: json!({"artifact_sha256":artifact.sha256}),
                    artifacts: vec![artifact],
                    final_url: None,
                    sensitive_observation: false,
                })
            }
            BrowserStepAction::ConsoleLogs => {
                let observed = session.console_logs(actor).await?;
                let mut output = json!({"entries":observed.value});
                redactor.value(&mut output);
                Ok(StepRun::one(observed.observation, output, None))
            }
            BrowserStepAction::NetworkLogs => {
                let observed = session.network_logs(actor).await?;
                Ok(StepRun::one(
                    observed.observation,
                    json!({"requests":observed.value}),
                    None,
                ))
            }
            BrowserStepAction::Javascript { script, arguments } => {
                let arguments = resolve_arguments(arguments, self.secrets.as_ref(), redactor)
                    .map_err(|error| {
                        session.local_failure(
                            actor,
                            BrowserAction::EvaluateScript,
                            error.kind,
                            error.message,
                        )
                    })?;
                let observed = session.evaluate_script(actor, script, arguments).await?;
                let mut output = json!({"value":observed.value});
                redactor.value(&mut output);
                Ok(StepRun::one(observed.observation, output, None))
            }
        }
        .map(|mut run| {
            for observation in &mut run.observations {
                *observation =
                    sanitize_observation(observation.clone(), redactor, run.sensitive_observation);
            }
            redactor.value(&mut run.output);
            run
        })
    }
}

struct StepRun {
    observations: Vec<BrowserObservation>,
    output: Value,
    artifacts: Vec<Artifact>,
    final_url: Option<String>,
    sensitive_observation: bool,
}

impl StepRun {
    fn one(observation: BrowserObservation, output: Value, final_url: Option<String>) -> Self {
        Self {
            observations: vec![observation],
            output,
            artifacts: vec![],
            final_url,
            sensitive_observation: false,
        }
    }

    fn one_sensitive(observation: BrowserObservation, output: Value) -> Self {
        Self {
            observations: vec![observation],
            output,
            artifacts: vec![],
            final_url: None,
            sensitive_observation: true,
        }
    }
}

#[allow(clippy::result_large_err)]
fn alias_element<'a>(
    session: &BrowserSession,
    actor: &str,
    aliases: &'a BTreeMap<String, ElementRef>,
    alias: &str,
) -> std::result::Result<&'a ElementRef, ObservedFailure> {
    aliases.get(alias).ok_or_else(|| {
        session.local_failure(
            actor,
            BrowserAction::FindElement,
            BrowserErrorKind::InvalidInput,
            format!("unknown element alias {alias}"),
        )
    })
}

fn resolve_value(
    value: &PlanValue,
    secrets: &dyn SecretResolver,
    redactor: &mut Redactor,
) -> std::result::Result<Zeroizing<String>, BrowserError> {
    match value {
        PlanValue::Public { value } => Ok(Zeroizing::new(value.clone())),
        PlanValue::Environment { name } => {
            let secret = secrets.resolve(name)?;
            redactor.register(&secret);
            Ok(secret)
        }
    }
}

fn resolve_arguments(
    arguments: &[PlanArgument],
    secrets: &dyn SecretResolver,
    redactor: &mut Redactor,
) -> std::result::Result<Vec<Value>, BrowserError> {
    arguments
        .iter()
        .map(|argument| match argument {
            PlanArgument::Public { value } => Ok(value.clone()),
            PlanArgument::Environment { name } => {
                let secret = secrets.resolve(name)?;
                redactor.register(&secret);
                Ok(json!(secret.as_str()))
            }
        })
        .collect()
}

fn sanitize_observation(
    mut observation: BrowserObservation,
    redactor: &Redactor,
    force_secret: bool,
) -> BrowserObservation {
    if force_secret {
        observation.record.data = json!({"value":"[REDACTED]"});
    } else {
        redactor.value(&mut observation.record.data);
    }
    if let Some(error) = &mut observation.record.error {
        *error = redactor.text(error);
    }
    BrowserObservation::from_record(observation.record)
}

fn status_for_error(error: &BrowserError) -> BrowserPlanStatus {
    if error.kind == BrowserErrorKind::Cancelled {
        BrowserPlanStatus::Cancelled
    } else {
        BrowserPlanStatus::Failed
    }
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:@".contains(character)),
        "invalid {label}"
    );
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<()> {
    let mut characters = name.chars();
    ensure!(
        name.len() <= 160
            && characters
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
            && characters.all(|character| character == '_' || character.is_ascii_alphanumeric()),
        "invalid environment variable name"
    );
    Ok(())
}
