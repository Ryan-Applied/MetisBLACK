use anyhow::{ensure, Context, Result};
use domain::{
    now_ms, ArtifactKind, ArtifactLineage, ArtifactRef, Control, CoverageManifest, CoverageReason,
    CoverageState, CoverageSummary, EngagementConfig, EngagementExecutionState, EngagementSnapshot,
    LimitUsage, OverrideEpoch, ProviderWork, Receipt, StageAttempt, StageConfig, StageCoverage,
    StageExecutionState, StageId, StageKind, StageRecord, StageRetryAuthorization, StageSpec,
    ToolAction, TypedTarget, ENGAGEMENT_SCHEMA_VERSION,
};
use evidence::EvidenceStore;
use policy::Policy;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use storage::{hash, random_id, read_json, secure_dir, write_json, Redactor, RunLock};
use tool_runtime::{ExecutionBudget, Runtime};

use crate::RunControl;

const CONFIG_FILE: &str = "engagement-config.json";
const SNAPSHOT_FILE: &str = "engagement-snapshot.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageAttemptToken {
    engagement_id: String,
    config_fingerprint: String,
    stage_id: StageId,
    stage_spec_fingerprint: String,
    attempt: u32,
    started_ms: u64,
    capability_id: String,
}

impl StageAttemptToken {
    pub fn stage_id(&self) -> &StageId {
        &self.stage_id
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[derive(Debug, Clone)]
pub struct StageTerminalOutcome {
    pub state: StageExecutionState,
    pub coverage_state: CoverageState,
    pub coverage_reasons: Vec<CoverageReason>,
    pub receipt_ids: Vec<String>,
    pub artifacts: Vec<ArtifactRef>,
    pub model_tokens: u64,
    pub cost_microusd: u64,
    pub reason: Option<CoverageReason>,
}

struct ActiveAttempt {
    capability_id: String,
    actor: String,
    budget: ExecutionBudget,
}

/// An attempt-scoped runtime capability. It fixes the receipt actor, applies
/// stage capability/target checks and shares a live stage budget across every
/// clone. Terminalizing the attempt invalidates all outstanding clones.
#[derive(Clone)]
pub struct StageRuntime {
    runtime: Runtime,
    actor: String,
    spec: StageSpec,
    targets: Vec<TypedTarget>,
    output_dir: PathBuf,
    overrides: domain::ExpertOverrides,
}

impl StageRuntime {
    pub async fn execute(&self, action: ToolAction) -> Result<Receipt> {
        validate_stage_action(
            &self.spec,
            &self.targets,
            &self.output_dir,
            &self.overrides,
            &action,
        )?;
        self.runtime.execute(&self.actor, action).await
    }
}

/// Durable boundary for a composed assessment. Stage adapters are deliberately
/// not child [`crate::Engine`] instances: they share this lock, policy ledger,
/// evidence store, cancellation state and engagement identity.
pub struct EngagementEngine {
    config: EngagementConfig,
    snapshot: EngagementSnapshot,
    runtime: Runtime,
    control: RunControl,
    active_attempts: BTreeMap<StageId, ActiveAttempt>,
    _lock: RunLock,
}

impl EngagementEngine {
    pub fn config(&self) -> &EngagementConfig {
        &self.config
    }

    pub fn snapshot(&self) -> &EngagementSnapshot {
        &self.snapshot
    }

    pub fn control(&self) -> RunControl {
        self.control.clone()
    }

    pub fn new(mut config: EngagementConfig) -> Result<Self> {
        config.validate()?;
        secure_dir(&config.output_dir)?;
        config.output_dir = config
            .output_dir
            .canonicalize()
            .context("engagement output directory could not be canonicalized")?;
        if config.overrides.active() {
            config.overrides.timestamp_ms = now_ms();
            config.overrides.controls = config.overrides.disabled_controls();
        }
        config.validate()?;
        let config_redactor = Redactor::with_override(&config.overrides);
        ensure!(
            config_redactor.sanitize(&config)? == config,
            "engagement configuration contains secret-like material; use environment/vault references or an explicit secret_redaction override"
        );
        preflight_targets(&config, &config.overrides)?;
        let lock = RunLock::acquire(&config.output_dir)?;
        ensure!(
            !config.output_dir.join(CONFIG_FILE).exists()
                && !config.output_dir.join(SNAPSHOT_FILE).exists(),
            "engagement directory already contains durable state; use resume or a new directory"
        );
        verify_input_artifacts(&config)?;
        let config_fingerprint = hash(&config.canonical_fingerprint_input()?);
        let created_ms = now_ms();
        let override_history = if config.overrides.active() {
            vec![OverrideEpoch {
                epoch: 1,
                recorded_ms: created_ms,
                overrides: config.overrides.clone(),
            }]
        } else {
            vec![]
        };
        let snapshot = EngagementSnapshot {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: config.engagement_id.clone(),
            config_fingerprint,
            sequence: 1,
            created_ms,
            updated_ms: created_ms,
            execution_state: EngagementExecutionState::Planned,
            stages: config
                .stages
                .iter()
                .map(|stage| StageRecord {
                    stage_id: stage.id.clone(),
                    execution_state: StageExecutionState::Planned,
                    coverage_state: CoverageState::NotStarted,
                    coverage_reasons: vec![],
                    attempts: vec![],
                    usage: LimitUsage::default(),
                    artifacts: vec![],
                    reason: None,
                })
                .collect(),
            usage: LimitUsage::default(),
            receipt_ids: vec![],
            override_epoch: u64::try_from(override_history.len())?,
            override_history,
            coverage_manifest: None,
        };
        snapshot.validate(&config)?;
        let control = RunControl::default();
        let runtime = runtime(&config, &snapshot, &control)?;
        let engine = Self {
            config,
            snapshot,
            runtime,
            control,
            active_attempts: BTreeMap::new(),
            _lock: lock,
        };
        engine.persist()?;
        Ok(engine)
    }

    pub fn resume(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .context("engagement output directory could not be canonicalized")?;
        let lock = RunLock::acquire(&root)?;
        let config: EngagementConfig = read_json(&root.join(CONFIG_FILE))?;
        ensure!(
            config.output_dir.canonicalize()? == root,
            "engagement resume directory mismatch"
        );
        config.validate()?;
        let config_redactor = Redactor::with_override(&config.overrides);
        ensure!(
            config_redactor.sanitize(&config)? == config,
            "persisted engagement configuration contains unapproved secret-like material"
        );
        verify_input_artifacts(&config)?;
        let mut snapshot: EngagementSnapshot = read_json(&root.join(SNAPSHOT_FILE))?;
        ensure!(
            snapshot.config_fingerprint == hash(&config.canonical_fingerprint_input()?),
            "engagement configuration fingerprint changed"
        );
        snapshot.validate(&config)?;
        preflight_targets(&config, effective_overrides(&config, &snapshot))?;
        let resume_evidence = EvidenceStore::new(
            &config.output_dir.join("receipts"),
            &config.engagement_id,
            Redactor::with_override(effective_overrides(&config, &snapshot)),
        )?;
        verify_snapshot_evidence(&config, &snapshot, &resume_evidence)?;
        let interrupted = reconcile_interrupted_attempts(&config, &mut snapshot, &resume_evidence)?;
        if interrupted {
            reconcile_dependencies(&config, &mut snapshot)?;
            snapshot.sequence = snapshot
                .sequence
                .checked_add(1)
                .context("engagement snapshot sequence overflow")?;
            snapshot.updated_ms = now_ms().max(snapshot.created_ms);
            snapshot.validate(&config)?;
        }
        let control = RunControl::default();
        let runtime = runtime(&config, &snapshot, &control)?;
        let engine = Self {
            config,
            snapshot,
            runtime,
            control,
            active_attempts: BTreeMap::new(),
            _lock: lock,
        };
        if interrupted {
            engine.persist()?;
        }
        Ok(engine)
    }

    /// Enter the scheduler lifecycle without performing external I/O. Every
    /// later adapter transition must checkpoint its attempt before dispatch.
    pub fn start(&mut self) -> Result<()> {
        ensure!(
            self.snapshot.execution_state == EngagementExecutionState::Planned,
            "only a planned engagement can start"
        );
        let previous = self.snapshot.clone();
        self.snapshot.execution_state = EngagementExecutionState::Running;
        if let Err(error) = reconcile_dependencies(&self.config, &mut self.snapshot) {
            self.snapshot = previous;
            return Err(error);
        }
        if let Err(error) = self.checkpoint() {
            self.snapshot = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn ready_stage_ids(&self) -> Vec<StageId> {
        self.snapshot
            .stages
            .iter()
            .filter(|record| record.execution_state == StageExecutionState::Ready)
            .map(|record| record.stage_id.clone())
            .collect()
    }

    /// Adapters receive the shared typed runtime only after proving they hold
    /// the exact persisted stage attempt token returned by [`Self::begin_stage`].
    pub fn runtime_for_attempt(&self, token: &StageAttemptToken) -> Result<StageRuntime> {
        ensure!(
            token.engagement_id == self.config.engagement_id
                && token.config_fingerprint == self.snapshot.config_fingerprint,
            "stage attempt token belongs to another engagement"
        );
        let spec = self
            .config
            .stage(&token.stage_id)
            .context("stage attempt token references a missing stage")?;
        ensure!(
            token.stage_spec_fingerprint == hash(&spec.canonical_fingerprint_input()?),
            "stage attempt token does not bind the immutable stage specification"
        );
        let record = self
            .snapshot
            .stages
            .iter()
            .find(|record| record.stage_id == token.stage_id)
            .context("stage attempt record is missing")?;
        ensure!(
            record.execution_state == StageExecutionState::Running
                && record.attempts.last().is_some_and(|attempt| {
                    attempt.state == StageExecutionState::Running
                        && attempt.attempt == token.attempt
                        && attempt.started_ms == token.started_ms
                }),
            "stage attempt token is stale or not running"
        );
        let active = self
            .active_attempts
            .get(&token.stage_id)
            .context("stage attempt execution authority is absent or was invalidated")?;
        ensure!(
            active.capability_id == token.capability_id,
            "stage attempt capability is stale or forged"
        );
        let targets = spec
            .target_ids
            .iter()
            .map(|id| {
                self.config
                    .targets
                    .iter()
                    .find(|target| target.id() == id)
                    .cloned()
                    .with_context(|| format!("stage target {id} is missing"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(StageRuntime {
            runtime: self.runtime.with_execution_budget(active.budget.clone()),
            actor: active.actor.clone(),
            spec: spec.clone(),
            targets,
            output_dir: self.config.output_dir.clone(),
            overrides: effective_overrides(&self.config, &self.snapshot).clone(),
        })
    }

    /// Persist a stage-scoped running intent before returning authority to an
    /// adapter. A crash after this call leaves an outcome-unknown running
    /// attempt; the scheduler must reconcile evidence or require exact retry
    /// authority rather than dispatching the operation again.
    pub fn begin_stage(&mut self, stage_id: &StageId) -> Result<StageAttemptToken> {
        ensure!(
            self.snapshot.execution_state == EngagementExecutionState::Running,
            "engagement must be running before a stage can start"
        );
        let spec = self
            .config
            .stage(stage_id)
            .context("stage does not exist in the immutable engagement")?;
        let spec_fingerprint = hash(&spec.canonical_fingerprint_input()?);
        let previous = self.snapshot.clone();
        let record = self
            .snapshot
            .stages
            .iter_mut()
            .find(|record| record.stage_id == *stage_id)
            .context("stage record is missing")?;
        ensure!(
            record.execution_state == StageExecutionState::Ready && record.attempts.is_empty(),
            "stage is not ready for its first attempt"
        );
        let started_ms = now_ms().max(self.snapshot.created_ms);
        let attempt = 1;
        record.execution_state = StageExecutionState::Running;
        record.coverage_state = CoverageState::Running;
        record.attempts.push(StageAttempt {
            attempt,
            state: StageExecutionState::Running,
            started_ms,
            finished_ms: None,
            usage: LimitUsage::default(),
            receipt_ids: vec![],
            artifacts: vec![],
            reason: None,
        });
        let token = match self.issue_attempt_token(stage_id, spec_fingerprint, attempt, started_ms)
        {
            Ok(token) => token,
            Err(error) => {
                self.snapshot = previous;
                return Err(error);
            }
        };
        if let Err(error) = self.checkpoint() {
            self.snapshot = previous;
            if let Some(active) = self.active_attempts.remove(stage_id) {
                active.budget.deactivate();
            }
            return Err(error);
        }
        Ok(token)
    }

    pub fn retry_stage(
        &mut self,
        authorization: &StageRetryAuthorization,
    ) -> Result<StageAttemptToken> {
        ensure!(
            self.snapshot.execution_state == EngagementExecutionState::Running,
            "engagement must be running before a stage can retry"
        );
        let spec = self
            .config
            .stage(&authorization.stage_id)
            .context("retry stage does not exist")?;
        let spec_fingerprint = hash(&spec.canonical_fingerprint_input()?);
        authorization.validate(&self.config, &self.snapshot, &spec_fingerprint)?;
        ensure!(
            !self.active_attempts.contains_key(&authorization.stage_id),
            "stage already has live execution authority"
        );
        let retry_dir = self.config.output_dir.join("retry-authorizations");
        secure_dir(&retry_dir)?;
        let retry_path = retry_dir.join(format!(
            "{}-{}-{}.json",
            authorization.stage_id.as_str(),
            authorization.prior_attempt,
            authorization.next_attempt
        ));
        ensure!(
            !retry_path.exists(),
            "this exact stage retry authorization was already consumed"
        );
        write_json(&retry_path, authorization)?;
        let previous = self.snapshot.clone();
        let started_ms = now_ms().max(self.snapshot.updated_ms);
        let record = self
            .snapshot
            .stages
            .iter_mut()
            .find(|record| record.stage_id == authorization.stage_id)
            .context("retry stage record is missing")?;
        record.execution_state = StageExecutionState::Running;
        record.coverage_state = CoverageState::Running;
        record.coverage_reasons.clear();
        record.reason = None;
        record.attempts.push(StageAttempt {
            attempt: authorization.next_attempt,
            state: StageExecutionState::Running,
            started_ms,
            finished_ms: None,
            usage: LimitUsage::default(),
            receipt_ids: vec![],
            artifacts: vec![],
            reason: None,
        });
        let token = match self.issue_attempt_token(
            &authorization.stage_id,
            spec_fingerprint,
            authorization.next_attempt,
            started_ms,
        ) {
            Ok(token) => token,
            Err(error) => {
                self.snapshot = previous;
                return Err(error);
            }
        };
        if let Err(error) = self.checkpoint() {
            self.snapshot = previous;
            if let Some(active) = self.active_attempts.remove(&authorization.stage_id) {
                active.budget.deactivate();
            }
            return Err(error);
        }
        Ok(token)
    }

    pub fn finish_stage(
        &mut self,
        token: &StageAttemptToken,
        outcome: StageTerminalOutcome,
    ) -> Result<()> {
        self.apply_terminal_outcome(token, outcome, false)
    }

    fn apply_terminal_outcome(
        &mut self,
        token: &StageAttemptToken,
        outcome: StageTerminalOutcome,
        allow_reporting: bool,
    ) -> Result<()> {
        ensure!(
            outcome.state.is_terminal()
                && !matches!(
                    outcome.state,
                    StageExecutionState::Blocked
                        | StageExecutionState::Planned
                        | StageExecutionState::Ready
                        | StageExecutionState::Running
                ),
            "adapter outcome must be an adapter-terminal state"
        );
        self.validate_token(token)?;
        let spec = self
            .config
            .stage(&token.stage_id)
            .context("stage specification is missing")?
            .clone();
        ensure!(
            spec.kind != StageKind::Reporting || allow_reporting,
            "reporting finalizer must use atomic coverage finalization"
        );
        let active = self
            .active_attempts
            .get(&token.stage_id)
            .context("stage attempt execution authority is absent")?;
        let live = active.budget.usage()?;
        for receipt_id in &outcome.receipt_ids {
            let receipt = self.runtime.evidence.get(receipt_id)?;
            ensure!(
                receipt.actor == active.actor,
                "receipt actor is not bound to this stage attempt"
            );
        }
        let mut actor_receipts = self
            .runtime
            .evidence
            .manifest()?
            .into_iter()
            .filter(|receipt| receipt.actor == active.actor)
            .map(|receipt| receipt.id)
            .collect::<Vec<_>>();
        actor_receipts.sort();
        ensure!(
            actor_receipts == outcome.receipt_ids,
            "terminal outcome must account for every receipt captured by this stage attempt"
        );
        for artifact in &outcome.artifacts {
            verify_output_artifact(&self.config.output_dir, artifact)?;
        }
        let finished_ms = now_ms().max(token.started_ms);
        let artifact_bytes = outcome
            .artifacts
            .iter()
            .try_fold(0_u64, |total, artifact| {
                total
                    .checked_add(artifact.size_bytes)
                    .context("stage artifact byte usage overflow")
            })?;
        let usage = LimitUsage {
            requests: live.requests,
            state_changes: live.state_changes,
            accounts: live.accounts,
            model_tokens: outcome.model_tokens,
            cost_microusd: outcome.cost_microusd,
            duration_ms: finished_ms.saturating_sub(token.started_ms).max(1),
            artifact_bytes,
            peak_concurrency: live.peak_concurrency,
        };
        let previous = self.snapshot.clone();
        let record = self
            .snapshot
            .stages
            .iter_mut()
            .find(|record| record.stage_id == token.stage_id)
            .context("stage record is missing")?;
        let attempt = record
            .attempts
            .last_mut()
            .context("stage attempt is missing")?;
        attempt.state = outcome.state;
        attempt.finished_ms = Some(finished_ms);
        attempt.usage = usage;
        attempt.receipt_ids = outcome.receipt_ids;
        attempt.artifacts = outcome.artifacts;
        attempt.reason = outcome.reason.clone();
        record.execution_state = outcome.state;
        record.coverage_state = outcome.coverage_state;
        record.coverage_reasons = outcome.coverage_reasons;
        record.reason = outcome.reason;
        rebuild_snapshot_aggregates(&mut self.snapshot)?;
        reconcile_dependencies(&self.config, &mut self.snapshot)?;
        if allow_reporting {
            return Ok(());
        }
        if let Err(error) = self.checkpoint() {
            self.snapshot = previous;
            return Err(error);
        }
        if let Some(active) = self.active_attempts.remove(&token.stage_id) {
            active.budget.deactivate();
        }
        Ok(())
    }

    /// Atomically terminalize the reporting stage, seal the canonical coverage
    /// manifest and transition the engagement lifecycle. Report renderers run
    /// before this call and provide immutable report artifacts plus lineage;
    /// the coverage manifest itself is written here so its snapshot binding
    /// cannot race another scheduler transition.
    pub fn finalize_engagement(
        &mut self,
        token: &StageAttemptToken,
        outcome: StageTerminalOutcome,
        mut provider_work: Vec<ProviderWork>,
        mut artifact_lineage: Vec<ArtifactLineage>,
    ) -> Result<CoverageManifest> {
        let spec = self
            .config
            .stage(token.stage_id())
            .context("finalizer stage does not exist")?;
        ensure!(
            spec.kind == StageKind::Reporting,
            "only the reporting stage can finalize engagement coverage"
        );
        let previous = self.snapshot.clone();
        if let Err(error) = self.apply_terminal_outcome(token, outcome, true) {
            self.snapshot = previous;
            return Err(error);
        }
        ensure!(
            self.snapshot
                .stages
                .iter()
                .all(|record| record.execution_state.is_terminal()),
            "coverage cannot finalize while a stage is non-terminal"
        );
        self.snapshot.execution_state = if self
            .snapshot
            .stages
            .iter()
            .any(|record| record.execution_state == StageExecutionState::Cancelled)
        {
            EngagementExecutionState::Cancelled
        } else if self
            .snapshot
            .stages
            .iter()
            .zip(&self.config.stages)
            .any(|(record, spec)| {
                spec.required && record.execution_state != StageExecutionState::Succeeded
            })
        {
            EngagementExecutionState::Failed
        } else {
            EngagementExecutionState::Complete
        };
        self.snapshot.sequence = self
            .snapshot
            .sequence
            .checked_add(1)
            .context("engagement snapshot sequence overflow")?;
        self.snapshot.updated_ms = now_ms().max(self.snapshot.created_ms);

        let manifest_path = "coverage/manifest.json";
        self.snapshot.coverage_manifest = Some(ArtifactRef {
            id: "coverage-manifest".into(),
            kind: ArtifactKind::CoverageManifest,
            path: manifest_path.into(),
            sha256: "0".repeat(64),
            size_bytes: 0,
            media_type: "application/json".into(),
        });
        provider_work.sort_by(|left, right| left.id.cmp(&right.id));
        artifact_lineage.sort_by(|left, right| left.artifact.id.cmp(&right.artifact.id));
        let stages = self
            .snapshot
            .stages
            .iter()
            .zip(&self.config.stages)
            .map(|(record, spec)| StageCoverage {
                stage_id: record.stage_id.clone(),
                kind: spec.kind,
                execution_state: record.execution_state,
                coverage_state: record.coverage_state,
                reasons: record.coverage_reasons.clone(),
                usage: record.usage.clone(),
                artifact_ids: record
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.id.clone())
                    .collect(),
                provider_work_ids: provider_work
                    .iter()
                    .filter(|work| work.stage_id == record.stage_id)
                    .map(|work| work.id.clone())
                    .collect(),
            })
            .collect::<Vec<_>>();
        let summary = coverage_summary(&stages, provider_work.len(), artifact_lineage.len())?;
        let manifest = CoverageManifest {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: self.config.engagement_id.clone(),
            config_fingerprint: self.snapshot.config_fingerprint.clone(),
            snapshot_sequence: self.snapshot.sequence,
            generated_ms: self.snapshot.updated_ms,
            execution_state: self.snapshot.execution_state,
            stages,
            provider_work,
            artifact_lineage,
            summary,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        self.snapshot.coverage_manifest = Some(ArtifactRef {
            id: "coverage-manifest".into(),
            kind: ArtifactKind::CoverageManifest,
            path: manifest_path.into(),
            sha256: hash(&bytes),
            size_bytes: u64::try_from(bytes.len())?,
            media_type: "application/json".into(),
        });
        if let Err(error) = manifest
            .validate(&self.config, &self.snapshot)
            .and_then(|()| {
                let coverage_dir = self.config.output_dir.join("coverage");
                secure_dir(&coverage_dir)?;
                storage::atomic_write(&coverage_dir.join("manifest.json"), &bytes)?;
                verify_output_artifact(
                    &self.config.output_dir,
                    self.snapshot
                        .coverage_manifest
                        .as_ref()
                        .context("coverage artifact missing")?,
                )?;
                self.persist()
            })
        {
            self.snapshot = previous;
            return Err(error);
        }
        if let Some(active) = self.active_attempts.remove(token.stage_id()) {
            active.budget.deactivate();
        }
        Ok(manifest)
    }

    fn issue_attempt_token(
        &mut self,
        stage_id: &StageId,
        stage_spec_fingerprint: String,
        attempt: u32,
        started_ms: u64,
    ) -> Result<StageAttemptToken> {
        let spec = self
            .config
            .stage(stage_id)
            .context("stage specification is missing")?;
        let prior_usage = self
            .snapshot
            .stages
            .iter()
            .find(|record| record.stage_id == *stage_id)
            .context("stage record is missing")?
            .attempts
            .iter()
            .take(usize::try_from(attempt.saturating_sub(1))?)
            .try_fold(LimitUsage::default(), |mut total, prior| {
                checked_add_usage(&mut total, &prior.usage)?;
                Ok::<_, anyhow::Error>(total)
            })?;
        let capability_id = random_id("stage-capability")?;
        let actor = format!(
            "engagement:{}:stage:{}:attempt:{}",
            self.config.engagement_id,
            stage_id.as_str(),
            attempt
        );
        let budget = ExecutionBudget::new(
            spec.budget
                .max_requests
                .saturating_sub(prior_usage.requests),
            spec.budget
                .max_state_changes
                .saturating_sub(prior_usage.state_changes),
            spec.budget
                .max_accounts
                .saturating_sub(prior_usage.accounts),
            spec.budget.max_concurrency,
        )?;
        ensure!(
            self.active_attempts
                .insert(
                    stage_id.clone(),
                    ActiveAttempt {
                        capability_id: capability_id.clone(),
                        actor,
                        budget,
                    },
                )
                .is_none(),
            "stage already has live execution authority"
        );
        Ok(StageAttemptToken {
            engagement_id: self.config.engagement_id.clone(),
            config_fingerprint: self.snapshot.config_fingerprint.clone(),
            stage_id: stage_id.clone(),
            stage_spec_fingerprint,
            attempt,
            started_ms,
            capability_id,
        })
    }

    fn validate_token(&self, token: &StageAttemptToken) -> Result<()> {
        self.runtime_for_attempt(token).map(|_| ())
    }

    pub fn checkpoint(&mut self) -> Result<()> {
        self.snapshot.sequence = self
            .snapshot
            .sequence
            .checked_add(1)
            .context("engagement snapshot sequence overflow")?;
        self.snapshot.updated_ms = now_ms().max(self.snapshot.created_ms);
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        self.snapshot.validate(&self.config)?;
        let root = &self.config.output_dir;
        write_json(&root.join(CONFIG_FILE), &self.config)?;
        let redactor = Redactor::with_override(effective_overrides(&self.config, &self.snapshot));
        write_json(
            &root.join(SNAPSHOT_FILE),
            &redactor.sanitize(&self.snapshot)?,
        )
    }
}

fn reconcile_interrupted_attempts(
    config: &EngagementConfig,
    snapshot: &mut EngagementSnapshot,
    evidence: &EvidenceStore,
) -> Result<bool> {
    let mut changed = false;
    let finished_ms = now_ms().max(snapshot.updated_ms);
    let receipts = evidence.manifest()?;
    let already_claimed = snapshot
        .receipt_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let overrides = effective_overrides(config, snapshot).clone();
    for record in &mut snapshot.stages {
        if record.execution_state != StageExecutionState::Running {
            continue;
        }
        let attempt = record
            .attempts
            .last_mut()
            .context("running stage is missing its running attempt")?;
        ensure!(
            attempt.state == StageExecutionState::Running,
            "running stage latest attempt is not running"
        );
        let reason = CoverageReason::OutcomeUnknown {
            operation: format!(
                "stage {} attempt {} interrupted before a durable terminal outcome",
                record.stage_id.as_str(),
                attempt.attempt
            ),
        };
        let actor = format!(
            "engagement:{}:stage:{}:attempt:{}",
            config.engagement_id,
            record.stage_id.as_str(),
            attempt.attempt
        );
        let spec = config
            .stage(&record.stage_id)
            .context("interrupted stage specification is missing")?;
        let targets = spec
            .target_ids
            .iter()
            .map(|id| {
                config
                    .targets
                    .iter()
                    .find(|target| target.id() == id)
                    .cloned()
                    .with_context(|| format!("stage target {id} is missing"))
            })
            .collect::<Result<Vec<_>>>()?;
        let recovered = receipts
            .iter()
            .filter(|receipt| {
                receipt.actor == actor && !already_claimed.contains(receipt.id.as_str())
            })
            .collect::<Vec<_>>();
        for receipt in &recovered {
            validate_stage_action(
                spec,
                &targets,
                &config.output_dir,
                &overrides,
                &receipt.output.action,
            )?;
        }
        attempt.receipt_ids = recovered
            .into_iter()
            .map(|receipt| receipt.id.clone())
            .collect();
        attempt.receipt_ids.sort();
        attempt.state = StageExecutionState::Indeterminate;
        attempt.finished_ms = Some(finished_ms.max(attempt.started_ms));
        attempt.reason = Some(reason.clone());
        record.execution_state = StageExecutionState::Indeterminate;
        record.coverage_state = CoverageState::Indeterminate;
        record.coverage_reasons = vec![reason.clone()];
        record.reason = Some(reason);
        changed = true;
    }
    if changed {
        rebuild_snapshot_aggregates(snapshot)?;
    }
    Ok(changed)
}

fn checked_add_usage(total: &mut LimitUsage, usage: &LimitUsage) -> Result<()> {
    total.requests = total
        .requests
        .checked_add(usage.requests)
        .context("request usage overflow")?;
    total.state_changes = total
        .state_changes
        .checked_add(usage.state_changes)
        .context("state-change usage overflow")?;
    total.accounts = total
        .accounts
        .checked_add(usage.accounts)
        .context("account usage overflow")?;
    total.model_tokens = total
        .model_tokens
        .checked_add(usage.model_tokens)
        .context("model token usage overflow")?;
    total.cost_microusd = total
        .cost_microusd
        .checked_add(usage.cost_microusd)
        .context("cost usage overflow")?;
    total.duration_ms = total
        .duration_ms
        .checked_add(usage.duration_ms)
        .context("duration usage overflow")?;
    total.artifact_bytes = total
        .artifact_bytes
        .checked_add(usage.artifact_bytes)
        .context("artifact byte usage overflow")?;
    total.peak_concurrency = total.peak_concurrency.max(usage.peak_concurrency);
    Ok(())
}

fn coverage_summary(
    stages: &[StageCoverage],
    provider_work_items: usize,
    artifacts: usize,
) -> Result<CoverageSummary> {
    let mut summary = CoverageSummary {
        total_stages: u32::try_from(stages.len())?,
        complete: 0,
        partial: 0,
        omitted: 0,
        indeterminate: 0,
        running: 0,
        not_started: 0,
        provider_work_items: u32::try_from(provider_work_items)?,
        artifacts: u32::try_from(artifacts)?,
        usage: LimitUsage::default(),
    };
    for stage in stages {
        match stage.coverage_state {
            CoverageState::Complete => summary.complete += 1,
            CoverageState::Partial => summary.partial += 1,
            CoverageState::Omitted => summary.omitted += 1,
            CoverageState::Indeterminate => summary.indeterminate += 1,
            CoverageState::Running => summary.running += 1,
            CoverageState::NotStarted => summary.not_started += 1,
        }
        checked_add_usage(&mut summary.usage, &stage.usage)?;
    }
    Ok(summary)
}

fn rebuild_snapshot_aggregates(snapshot: &mut EngagementSnapshot) -> Result<()> {
    let mut engagement_usage = LimitUsage::default();
    let mut receipt_ids = BTreeSet::new();
    for record in &mut snapshot.stages {
        let mut stage_usage = LimitUsage::default();
        let mut artifacts = BTreeMap::new();
        for attempt in &record.attempts {
            checked_add_usage(&mut stage_usage, &attempt.usage)?;
            for receipt_id in &attempt.receipt_ids {
                ensure!(
                    receipt_ids.insert(receipt_id.clone()),
                    "receipt cannot belong to multiple stage attempts"
                );
            }
            for artifact in &attempt.artifacts {
                if let Some(existing) = artifacts.insert(artifact.id.clone(), artifact.clone()) {
                    ensure!(
                        existing == *artifact,
                        "attempts disagree about an immutable artifact"
                    );
                }
            }
        }
        record.usage = stage_usage;
        record.artifacts = artifacts.into_values().collect();
        checked_add_usage(&mut engagement_usage, &record.usage)?;
    }
    snapshot.usage = engagement_usage;
    snapshot.receipt_ids = receipt_ids.into_iter().collect();
    Ok(())
}

fn validate_stage_action(
    spec: &StageSpec,
    targets: &[TypedTarget],
    output_dir: &Path,
    overrides: &domain::ExpertOverrides,
    action: &ToolAction,
) -> Result<()> {
    if !overrides.disables(Control::ToolCapabilities) {
        let permitted = match spec.kind {
            StageKind::Web => matches!(
                action,
                ToolAction::HttpGet { .. }
                    | ToolAction::WebDiscoveryFetch { .. }
                    | ToolAction::OpenRedirectProbe { .. }
                    | ToolAction::ApiSchemaProbe { .. }
                    | ToolAction::HttpRequest { .. }
                    | ToolAction::CreateAccount { .. }
                    | ToolAction::DnsResolve { .. }
            ),
            StageKind::Browser => {
                matches!(
                    action,
                    ToolAction::HttpGet { .. }
                        | ToolAction::HttpRequest { .. }
                        | ToolAction::CreateAccount { .. }
                ) || matches!(
                    action,
                    ToolAction::External { subsystem, .. } if subsystem == "browser"
                )
            }
            StageKind::Source => matches!(action, ToolAction::SourceRead { .. }),
            StageKind::Host => matches!(
                action,
                ToolAction::DnsResolve { .. } | ToolAction::TcpConnect { .. }
            ),
            StageKind::CloudSnapshot => matches!(action, ToolAction::SourceRead { .. }),
            StageKind::CloudLive => matches!(
                action,
                ToolAction::External { subsystem, .. } if subsystem == "cloud"
            ),
            StageKind::Ai => {
                matches!(
                    action,
                    ToolAction::AiPrompt { .. }
                        | ToolAction::HttpGet { .. }
                        | ToolAction::HttpRequest { .. }
                ) || matches!(
                    action,
                    ToolAction::External { subsystem, .. } if subsystem == "ai" || subsystem == "mcp"
                )
            }
            StageKind::Skills => matches!(action, ToolAction::SourceRead { .. }),
            StageKind::Provider => matches!(
                action,
                ToolAction::External { subsystem, .. } if subsystem == "provider"
            ),
            StageKind::ModelPanel => matches!(
                action,
                ToolAction::External { subsystem, .. } if subsystem == "provider" || subsystem == "model_panel"
            ),
            StageKind::Chains | StageKind::Cleanup => true,
            StageKind::Reporting => false,
        };
        ensure!(
            permitted,
            "tool action is not permitted for this stage kind"
        );
    }

    if overrides.disables(Control::Scope)
        || matches!(spec.kind, StageKind::Chains | StageKind::Cleanup)
    {
        return Ok(());
    }
    ensure!(
        targets
            .iter()
            .any(|target| action_matches_target(action, target, output_dir)),
        "tool action does not match a typed target assigned to this stage"
    );
    Ok(())
}

fn action_matches_target(action: &ToolAction, target: &TypedTarget, output_dir: &Path) -> bool {
    match (action, target) {
        (
            ToolAction::HttpGet { url }
            | ToolAction::WebDiscoveryFetch { url, .. }
            | ToolAction::ApiSchemaProbe { url, .. }
            | ToolAction::HttpRequest { url, .. }
            | ToolAction::CreateAccount { url, .. },
            TypedTarget::Web { url: target, .. },
        ) => same_origin_and_path(target, url),
        (ToolAction::OpenRedirectProbe { endpoint, .. }, TypedTarget::Web { url, .. }) => {
            same_origin_and_path(url, endpoint)
        }
        (
            ToolAction::AiPrompt { url, .. }
            | ToolAction::HttpGet { url }
            | ToolAction::HttpRequest { url, .. },
            TypedTarget::Ai { endpoint, .. },
        ) => same_origin_and_path(endpoint, url),
        (
            ToolAction::DnsResolve { host } | ToolAction::TcpConnect { host, .. },
            TypedTarget::Host { host: target, .. },
        ) => host.eq_ignore_ascii_case(target),
        (ToolAction::DnsResolve { host }, TypedTarget::Web { url, .. }) => url::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
            .is_some_and(|target| host.eq_ignore_ascii_case(&target)),
        (ToolAction::SourceRead { path, .. }, TypedTarget::Source { root, .. })
        | (ToolAction::SourceRead { path, .. }, TypedTarget::Workspace { root, .. }) => {
            path_within(Path::new(root), path)
        }
        (ToolAction::SourceRead { path, .. }, TypedTarget::Cloud { .. }) => {
            path_within(output_dir, path)
        }
        (ToolAction::External { target, .. }, TypedTarget::Cloud { account_id, .. }) => {
            target == account_id
        }
        (ToolAction::External { target, .. }, TypedTarget::Provider { provider_id, .. }) => {
            target == provider_id
        }
        (ToolAction::External { target, .. }, TypedTarget::ModelPanel { panel_id, .. }) => {
            target == panel_id
        }
        (ToolAction::External { target, .. }, TypedTarget::Chain { chain_id, .. }) => {
            target == chain_id
        }
        (ToolAction::External { target, .. }, TypedTarget::Web { url, .. }) => {
            same_origin_and_path(url, target)
        }
        (ToolAction::External { target, .. }, TypedTarget::Ai { endpoint, .. }) => {
            same_origin_and_path(endpoint, target)
        }
        (ToolAction::Shell { working_dir, .. }, _) => path_within(output_dir, working_dir),
        _ => false,
    }
}

fn same_origin_and_path(base: &str, candidate: &str) -> bool {
    let (Ok(base), Ok(candidate)) = (url::Url::parse(base), url::Url::parse(candidate)) else {
        return false;
    };
    base.origin() == candidate.origin() && candidate.path().starts_with(base.path())
}

fn path_within(root: &Path, candidate: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    candidate
        .canonicalize()
        .is_ok_and(|candidate| candidate.starts_with(root))
}

fn reconcile_dependencies(
    config: &EngagementConfig,
    snapshot: &mut EngagementSnapshot,
) -> Result<()> {
    loop {
        let mut changed = false;
        for (index, spec) in config.stages.iter().enumerate() {
            if !matches!(
                snapshot.stages[index].execution_state,
                StageExecutionState::Planned | StageExecutionState::Ready
            ) {
                continue;
            }
            let dependencies = spec
                .depends_on
                .iter()
                .map(|dependency| {
                    snapshot
                        .stages
                        .iter()
                        .find(|record| record.stage_id == *dependency)
                        .map(|record| (dependency, record.execution_state))
                        .context("stage dependency record is missing")
                })
                .collect::<Result<Vec<_>>>()?;
            if dependencies.iter().any(|(_, state)| !state.is_terminal()) {
                continue;
            }
            let failed_dependency = dependencies
                .iter()
                .find(|(_, state)| *state != StageExecutionState::Succeeded)
                .map(|(id, _)| (*id).clone());
            if spec.dependency_policy == domain::DependencyPolicy::AllSucceeded {
                if let Some(failed_dependency) = failed_dependency {
                    let reason = domain::CoverageReason::DependencyFailed {
                        stage_id: failed_dependency,
                    };
                    let finished_ms = now_ms().max(snapshot.created_ms);
                    let record = &mut snapshot.stages[index];
                    record.execution_state = StageExecutionState::Blocked;
                    record.coverage_state = CoverageState::Omitted;
                    record.coverage_reasons = vec![reason.clone()];
                    record.reason = Some(reason.clone());
                    record.attempts.push(StageAttempt {
                        attempt: u32::try_from(record.attempts.len() + 1)?,
                        state: StageExecutionState::Blocked,
                        started_ms: finished_ms,
                        finished_ms: Some(finished_ms),
                        usage: LimitUsage::default(),
                        receipt_ids: vec![],
                        artifacts: vec![],
                        reason: Some(reason),
                    });
                    changed = true;
                    continue;
                }
            }
            if snapshot.stages[index].execution_state != StageExecutionState::Ready {
                snapshot.stages[index].execution_state = StageExecutionState::Ready;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }
}

fn effective_overrides<'a>(
    config: &'a EngagementConfig,
    snapshot: &'a EngagementSnapshot,
) -> &'a domain::ExpertOverrides {
    snapshot
        .override_history
        .last()
        .map(|entry| &entry.overrides)
        .unwrap_or(&config.overrides)
}

fn runtime(
    config: &EngagementConfig,
    snapshot: &EngagementSnapshot,
    control: &RunControl,
) -> Result<Runtime> {
    let overrides = effective_overrides(config, snapshot);
    let redactor = Redactor::with_override(overrides);
    let evidence = EvidenceStore::new(
        &config.output_dir.join("receipts"),
        &config.engagement_id,
        redactor.clone(),
    )?;
    let policy = Policy::with_overrides(config.scope.clone(), overrides.clone())?;
    policy.restore_budgets(
        snapshot.usage.requests,
        snapshot.usage.state_changes,
        snapshot.usage.accounts,
    )?;
    let usage_path = config.output_dir.join("usage.json");
    if usage_path.exists() {
        let durable: serde_json::Value = read_json(&usage_path)?;
        let requests = durable["requests"]
            .as_u64()
            .context("durable request usage is invalid")?;
        let state_changes = durable["state_changes"]
            .as_u64()
            .context("durable state-change usage is invalid")?;
        let accounts = durable["accounts"]
            .as_u64()
            .context("durable account usage is invalid")?;
        ensure!(
            requests >= snapshot.usage.requests
                && state_changes >= snapshot.usage.state_changes
                && accounts >= snapshot.usage.accounts,
            "durable runtime usage regressed below the engagement snapshot"
        );
        policy.restore_budgets(requests, state_changes, accounts)?;
    }
    let mut runtime = Runtime::new(policy, evidence, redactor);
    runtime.attach_vault(&config.output_dir.join("vault"))?;
    runtime.authorize(config.authorized);
    runtime.cancelled = control.cancel.clone();
    Ok(runtime)
}

fn verify_snapshot_evidence(
    config: &EngagementConfig,
    snapshot: &EngagementSnapshot,
    evidence: &EvidenceStore,
) -> Result<()> {
    let overrides = effective_overrides(config, snapshot);
    for record in &snapshot.stages {
        let spec = config
            .stage(&record.stage_id)
            .context("snapshot stage specification is missing")?;
        let targets = spec
            .target_ids
            .iter()
            .map(|id| {
                config
                    .targets
                    .iter()
                    .find(|target| target.id() == id)
                    .with_context(|| format!("stage target {id} is missing"))
            })
            .collect::<Result<Vec<_>>>()?;
        let targets = targets.into_iter().cloned().collect::<Vec<_>>();
        for attempt in &record.attempts {
            let actor = format!(
                "engagement:{}:stage:{}:attempt:{}",
                config.engagement_id,
                record.stage_id.as_str(),
                attempt.attempt
            );
            for receipt_id in &attempt.receipt_ids {
                let receipt = evidence
                    .get(receipt_id)
                    .with_context(|| format!("verify persisted receipt {receipt_id}"))?;
                ensure!(
                    receipt.actor == actor,
                    "persisted receipt actor does not match its stage attempt"
                );
                validate_stage_action(
                    spec,
                    &targets,
                    &config.output_dir,
                    overrides,
                    &receipt.output.action,
                )?;
            }
        }
        for artifact in &record.artifacts {
            verify_output_artifact(&config.output_dir, artifact).with_context(|| {
                format!(
                    "verify output artifact {} from stage {}",
                    artifact.id,
                    record.stage_id.as_str()
                )
            })?;
        }
    }
    if let Some(coverage) = &snapshot.coverage_manifest {
        verify_output_artifact(&config.output_dir, coverage)
            .context("verify persisted coverage manifest artifact")?;
        let manifest: CoverageManifest = read_json(&config.output_dir.join(&coverage.path))?;
        manifest
            .validate(config, snapshot)
            .context("validate persisted coverage manifest")?;
    }
    Ok(())
}

fn preflight_targets(config: &EngagementConfig, overrides: &domain::ExpertOverrides) -> Result<()> {
    let policy = Policy::with_overrides(config.scope.clone(), overrides.clone())?;
    for target in &config.targets {
        let action = match target {
            TypedTarget::Web { url, .. } | TypedTarget::Ai { endpoint: url, .. } => {
                Some(ToolAction::HttpGet { url: url.clone() })
            }
            TypedTarget::Host { host, .. } => Some(ToolAction::DnsResolve { host: host.clone() }),
            TypedTarget::Source { root, .. } | TypedTarget::Workspace { root, .. } => {
                Some(ToolAction::SourceRead {
                    path: root.into(),
                    start_line: 1,
                    end_line: 1,
                })
            }
            TypedTarget::Cloud { account_id, .. } => Some(ToolAction::External {
                subsystem: "cloud".into(),
                operation: "engagement_scope_preflight".into(),
                target: account_id.clone(),
                parameters: serde_json::json!({}),
            }),
            TypedTarget::Provider { .. }
            | TypedTarget::ModelPanel { .. }
            | TypedTarget::Chain { .. } => None,
        };
        if let Some(action) = action {
            policy.check_action(&action)?;
        }
    }
    Ok(())
}

fn verify_input_artifacts(config: &EngagementConfig) -> Result<()> {
    for stage in &config.stages {
        for artifact in stage_input_artifacts(&stage.config) {
            verify_input_artifact(&config.output_dir, artifact).with_context(|| {
                format!(
                    "verify immutable input artifact {} for stage {}",
                    artifact.id,
                    stage.id.as_str()
                )
            })?;
        }
    }
    Ok(())
}

fn stage_input_artifacts(config: &StageConfig) -> Vec<&ArtifactRef> {
    match config {
        StageConfig::Web { plan, .. }
        | StageConfig::CloudLive { plan, .. }
        | StageConfig::Ai { plan, .. } => vec![plan],
        StageConfig::Browser { workflow, .. } => vec![workflow],
        StageConfig::Host { profile } => vec![profile],
        StageConfig::CloudSnapshot { snapshot } => vec![snapshot],
        StageConfig::Provider { request, .. } => vec![request],
        StageConfig::Chains { templates, .. } => vec![templates],
        StageConfig::Source { .. }
        | StageConfig::Skills { .. }
        | StageConfig::ModelPanel { .. }
        | StageConfig::Cleanup { .. }
        | StageConfig::Reporting { .. } => vec![],
    }
}

fn verify_input_artifact(root: &Path, artifact: &ArtifactRef) -> Result<()> {
    artifact.validate()?;
    ensure!(
        matches!(artifact.kind, ArtifactKind::Plan | ArtifactKind::Snapshot),
        "stage input artifact has a non-input type"
    );
    let bytes = verified_artifact_bytes(root, artifact)?;
    ensure!(
        artifact.size_bytes == u64::try_from(bytes.len())? && artifact.sha256 == hash(&bytes),
        "stage input artifact size or hash changed"
    );
    Ok(())
}

fn verify_output_artifact(root: &Path, artifact: &ArtifactRef) -> Result<()> {
    artifact.validate()?;
    let bytes = verified_artifact_bytes(root, artifact)?;
    ensure!(
        artifact.size_bytes == u64::try_from(bytes.len())? && artifact.sha256 == hash(&bytes),
        "stage output artifact size or hash changed"
    );
    Ok(())
}

fn verified_artifact_bytes(root: &Path, artifact: &ArtifactRef) -> Result<Vec<u8>> {
    let canonical_root = root
        .canonicalize()
        .context("engagement artifact root could not be canonicalized")?;
    let mut cursor = canonical_root.clone();
    for component in Path::new(&artifact.path).components() {
        let std::path::Component::Normal(segment) = component else {
            anyhow::bail!("artifact path is not normalized")
        };
        cursor.push(segment);
        ensure!(
            !fs::symlink_metadata(&cursor)?.file_type().is_symlink(),
            "artifact path cannot traverse a symlink"
        );
    }
    let canonical = cursor
        .canonicalize()
        .context("artifact path could not be canonicalized")?;
    ensure!(
        canonical.starts_with(&canonical_root),
        "artifact path escapes the engagement root"
    );
    fs::read(canonical).context("read immutable engagement artifact")
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{
        DependencyPolicy, EngagementBudgets, NetworkRule, ReportFormat, Scope, StageBudgetCaps,
        StageId, StageKind, StageSpec, TypedTarget,
    };
    fn fixture(root: &Path) -> Result<EngagementConfig> {
        let plan = b"{}";
        let plan_path = root.join("plans/web.json");
        secure_dir(plan_path.parent().context("plan parent")?)?;
        storage::atomic_write(&plan_path, plan)?;
        let plan = ArtifactRef {
            id: "web-plan".into(),
            kind: ArtifactKind::Plan,
            path: "plans/web.json".into(),
            sha256: hash(plan),
            size_bytes: 2,
            media_type: "application/json".into(),
        };
        Ok(EngagementConfig {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: "fixture-engagement".into(),
            output_dir: root.to_path_buf(),
            scope: Scope {
                network: vec![NetworkRule {
                    host: "example.test".into(),
                    subdomains: false,
                    ports: vec![443],
                    paths: vec!["/".into()],
                }],
                max_requests: 10,
                max_concurrency: 2,
                ..Scope::default()
            },
            authorized: true,
            overrides: domain::ExpertOverrides::default(),
            targets: vec![TypedTarget::Web {
                id: "web-main".into(),
                url: "https://example.test/".into(),
            }],
            budgets: EngagementBudgets {
                max_requests: 10,
                max_state_changes: 0,
                max_accounts: 0,
                max_model_tokens: 0,
                max_cost_microusd: 0,
                max_duration_ms: 10_000,
                max_artifact_bytes: 10_000,
                max_concurrency: 2,
            },
            stages: vec![
                StageSpec {
                    id: StageId("report-final".into()),
                    kind: StageKind::Reporting,
                    target_ids: vec![],
                    depends_on: vec![StageId("web-discovery".into())],
                    dependency_policy: DependencyPolicy::AllTerminal,
                    required: true,
                    budget: StageBudgetCaps {
                        max_duration_ms: 1_000,
                        max_artifact_bytes: 1_000,
                        max_concurrency: 1,
                        ..StageBudgetCaps::default()
                    },
                    config: StageConfig::Reporting {
                        formats: vec![ReportFormat::Json],
                        finalizer: true,
                    },
                },
                StageSpec {
                    id: StageId("web-discovery".into()),
                    kind: StageKind::Web,
                    target_ids: vec!["web-main".into()],
                    depends_on: vec![],
                    dependency_policy: DependencyPolicy::AllSucceeded,
                    required: true,
                    budget: StageBudgetCaps {
                        max_requests: 10,
                        max_duration_ms: 1_000,
                        max_artifact_bytes: 1_000,
                        max_concurrency: 1,
                        ..StageBudgetCaps::default()
                    },
                    config: StageConfig::Web {
                        plan,
                        authenticated: false,
                    },
                },
            ],
        })
    }

    fn source_fixture(root: &Path) -> Result<EngagementConfig> {
        let source_path = root.join("source/example.rs");
        secure_dir(source_path.parent().context("source parent")?)?;
        storage::atomic_write(&source_path, b"fn main() {}\n")?;
        Ok(EngagementConfig {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: "source-engagement".into(),
            output_dir: root.to_path_buf(),
            scope: Scope {
                roots: vec![root.to_path_buf()],
                max_requests: 10,
                max_concurrency: 2,
                ..Scope::default()
            },
            authorized: true,
            overrides: domain::ExpertOverrides::default(),
            targets: vec![TypedTarget::Source {
                id: "source-main".into(),
                root: root.display().to_string(),
            }],
            budgets: EngagementBudgets {
                max_requests: 1,
                max_state_changes: 0,
                max_accounts: 0,
                max_model_tokens: 0,
                max_cost_microusd: 0,
                max_duration_ms: 10_000,
                max_artifact_bytes: 10_000,
                max_concurrency: 2,
            },
            stages: vec![
                StageSpec {
                    id: StageId("report-final".into()),
                    kind: StageKind::Reporting,
                    target_ids: vec![],
                    depends_on: vec![StageId("source-analysis".into())],
                    dependency_policy: DependencyPolicy::AllTerminal,
                    required: true,
                    budget: StageBudgetCaps {
                        max_duration_ms: 1_000,
                        max_artifact_bytes: 1_000,
                        max_concurrency: 1,
                        ..StageBudgetCaps::default()
                    },
                    config: StageConfig::Reporting {
                        formats: vec![ReportFormat::Json],
                        finalizer: true,
                    },
                },
                StageSpec {
                    id: StageId("source-analysis".into()),
                    kind: StageKind::Source,
                    target_ids: vec!["source-main".into()],
                    depends_on: vec![],
                    dependency_policy: DependencyPolicy::AllSucceeded,
                    required: true,
                    budget: StageBudgetCaps {
                        max_requests: 1,
                        max_duration_ms: 1_000,
                        max_artifact_bytes: 1_000,
                        max_concurrency: 1,
                        ..StageBudgetCaps::default()
                    },
                    config: StageConfig::Source {
                        languages: vec!["rust".into()],
                        base_ref: None,
                        head_ref: None,
                    },
                },
            ],
        })
    }

    #[test]
    fn initializes_one_durable_planned_engagement_and_resumes_it() -> Result<()> {
        let output = tempfile::tempdir()?;
        let config = fixture(output.path())?;
        let engine = EngagementEngine::new(config)?;
        assert_eq!(engine.snapshot().sequence, 1);
        assert_eq!(
            engine.snapshot().execution_state,
            EngagementExecutionState::Planned
        );
        assert!(output.path().join(CONFIG_FILE).is_file());
        assert!(output.path().join(SNAPSHOT_FILE).is_file());
        assert!(output.path().join("receipts").is_dir());
        assert!(output.path().join("vault").is_dir());
        drop(engine);

        let mut resumed = EngagementEngine::resume(output.path())?;
        resumed.start()?;
        assert_eq!(resumed.snapshot().sequence, 2);
        assert_eq!(
            resumed.snapshot().execution_state,
            EngagementExecutionState::Running
        );
        assert_eq!(
            resumed.ready_stage_ids(),
            vec![StageId("web-discovery".into())]
        );
        Ok(())
    }

    #[test]
    fn stage_attempt_is_durable_before_adapter_io_and_never_implicitly_repeated() -> Result<()> {
        let output = tempfile::tempdir()?;
        let mut engine = EngagementEngine::new(fixture(output.path())?)?;
        engine.start()?;
        let stage_id = StageId("web-discovery".into());
        let token = engine.begin_stage(&stage_id)?;
        assert_eq!(token.attempt(), 1);
        assert_eq!(token.stage_id(), &stage_id);
        engine.runtime_for_attempt(&token)?;
        let mut wrong = token.clone();
        wrong.stage_spec_fingerprint = "f".repeat(64);
        assert!(engine.runtime_for_attempt(&wrong).is_err());
        assert_eq!(engine.snapshot().sequence, 3);
        assert_eq!(
            engine.snapshot().stages[1].execution_state,
            StageExecutionState::Running
        );
        drop(engine);

        let mut resumed = EngagementEngine::resume(output.path())?;
        assert_eq!(
            resumed.snapshot().stages[1].execution_state,
            StageExecutionState::Indeterminate
        );
        assert_eq!(
            resumed.snapshot().stages[1].coverage_state,
            CoverageState::Indeterminate
        );
        assert!(matches!(
            resumed.snapshot().stages[1].reason,
            Some(CoverageReason::OutcomeUnknown { .. })
        ));
        assert!(resumed.runtime_for_attempt(&token).is_err());
        assert!(resumed.begin_stage(&stage_id).is_err());

        let spec = resumed.config().stage(&stage_id).context("stage spec")?;
        let authorization = StageRetryAuthorization {
            engagement_id: resumed.config().engagement_id.clone(),
            config_fingerprint: resumed.snapshot().config_fingerprint.clone(),
            stage_id: stage_id.clone(),
            stage_spec_fingerprint: hash(&spec.canonical_fingerprint_input()?),
            prior_attempt: 1,
            next_attempt: 2,
            actor: "fixture-operator".into(),
            reason: "retry interrupted fixture stage".into(),
            authorized_ms: now_ms().max(resumed.snapshot().updated_ms),
        };
        let retry = resumed.retry_stage(&authorization)?;
        assert_eq!(retry.attempt(), 2);
        assert!(output
            .path()
            .join("retry-authorizations/web-discovery-1-2.json")
            .is_file());
        resumed.runtime_for_attempt(&retry)?;
        Ok(())
    }

    #[test]
    fn terminal_stage_outcome_is_durable_and_unlocks_reporting() -> Result<()> {
        let output = tempfile::tempdir()?;
        let mut engine = EngagementEngine::new(fixture(output.path())?)?;
        engine.start()?;
        let stage_id = StageId("web-discovery".into());
        let token = engine.begin_stage(&stage_id)?;
        let bytes = b"{\"resources\":[]}";
        let path = output.path().join("artifacts/web-observation.json");
        secure_dir(path.parent().context("artifact parent")?)?;
        storage::atomic_write(&path, bytes)?;
        let artifact = ArtifactRef {
            id: "web-observation".into(),
            kind: ArtifactKind::Observation,
            path: "artifacts/web-observation.json".into(),
            sha256: hash(bytes),
            size_bytes: u64::try_from(bytes.len())?,
            media_type: "application/json".into(),
        };
        engine.finish_stage(
            &token,
            StageTerminalOutcome {
                state: StageExecutionState::Succeeded,
                coverage_state: CoverageState::Complete,
                coverage_reasons: vec![],
                receipt_ids: vec![],
                artifacts: vec![artifact.clone()],
                model_tokens: 0,
                cost_microusd: 0,
                reason: None,
            },
        )?;
        assert!(engine.runtime_for_attempt(&token).is_err());
        assert_eq!(
            engine.snapshot().stages[1].execution_state,
            StageExecutionState::Succeeded
        );
        assert_eq!(engine.snapshot().stages[1].artifacts, vec![artifact]);
        assert_eq!(
            engine.ready_stage_ids(),
            vec![StageId("report-final".into())]
        );
        drop(engine);

        let resumed = EngagementEngine::resume(output.path())?;
        assert_eq!(
            resumed.snapshot().stages[1].execution_state,
            StageExecutionState::Succeeded
        );
        assert_eq!(
            resumed.ready_stage_ids(),
            vec![StageId("report-final".into())]
        );
        Ok(())
    }

    #[test]
    fn reporting_atomically_seals_coverage_and_terminal_lifecycle() -> Result<()> {
        let output = tempfile::tempdir()?;
        let mut engine = EngagementEngine::new(fixture(output.path())?)?;
        engine.start()?;
        let web_id = StageId("web-discovery".into());
        let web_token = engine.begin_stage(&web_id)?;
        let web_bytes = b"{\"resources\":[]}";
        let web_path = output.path().join("artifacts/web-observation.json");
        secure_dir(web_path.parent().context("web artifact parent")?)?;
        storage::atomic_write(&web_path, web_bytes)?;
        let web_artifact = ArtifactRef {
            id: "web-observation".into(),
            kind: ArtifactKind::Observation,
            path: "artifacts/web-observation.json".into(),
            sha256: hash(web_bytes),
            size_bytes: u64::try_from(web_bytes.len())?,
            media_type: "application/json".into(),
        };
        engine.finish_stage(
            &web_token,
            StageTerminalOutcome {
                state: StageExecutionState::Succeeded,
                coverage_state: CoverageState::Complete,
                coverage_reasons: vec![],
                receipt_ids: vec![],
                artifacts: vec![web_artifact.clone()],
                model_tokens: 0,
                cost_microusd: 0,
                reason: None,
            },
        )?;

        let report_id = StageId("report-final".into());
        let report_token = engine.begin_stage(&report_id)?;
        let report_bytes = b"{\"coverage_manifest\":\"coverage/manifest.json\"}";
        let report_path = output.path().join("reports/report.json");
        secure_dir(report_path.parent().context("report artifact parent")?)?;
        storage::atomic_write(&report_path, report_bytes)?;
        let report_artifact = ArtifactRef {
            id: "report-json".into(),
            kind: ArtifactKind::Report,
            path: "reports/report.json".into(),
            sha256: hash(report_bytes),
            size_bytes: u64::try_from(report_bytes.len())?,
            media_type: "application/json".into(),
        };
        let manifest = engine.finalize_engagement(
            &report_token,
            StageTerminalOutcome {
                state: StageExecutionState::Succeeded,
                coverage_state: CoverageState::Complete,
                coverage_reasons: vec![],
                receipt_ids: vec![],
                artifacts: vec![report_artifact.clone()],
                model_tokens: 0,
                cost_microusd: 0,
                reason: None,
            },
            vec![],
            vec![
                ArtifactLineage {
                    artifact: report_artifact,
                    stage_id: report_id,
                    attempt: 1,
                    parent_artifact_ids: vec![web_artifact.id.clone()],
                    receipt_ids: vec![],
                },
                ArtifactLineage {
                    artifact: web_artifact,
                    stage_id: web_id,
                    attempt: 1,
                    parent_artifact_ids: vec![],
                    receipt_ids: vec![],
                },
            ],
        )?;
        assert_eq!(
            engine.snapshot().execution_state,
            EngagementExecutionState::Complete
        );
        assert_eq!(manifest.summary.complete, 2);
        assert!(output.path().join("coverage/manifest.json").is_file());
        assert!(engine.runtime_for_attempt(&report_token).is_err());
        drop(engine);

        let resumed = EngagementEngine::resume(output.path())?;
        assert_eq!(
            resumed.snapshot().execution_state,
            EngagementExecutionState::Complete
        );
        Ok(())
    }

    #[tokio::test]
    async fn stage_runtime_enforces_exact_tool_target_budget_and_receipt_binding() -> Result<()> {
        let output = tempfile::tempdir()?;
        let mut engine = EngagementEngine::new(source_fixture(output.path())?)?;
        engine.start()?;
        let stage_id = StageId("source-analysis".into());
        let token = engine.begin_stage(&stage_id)?;
        let runtime = engine.runtime_for_attempt(&token)?;
        let action = ToolAction::SourceRead {
            path: output.path().join("source/example.rs"),
            start_line: 1,
            end_line: 1,
        };
        let first = runtime.execute(action.clone()).await?;
        assert!(first.output.successful);
        let denied = runtime.execute(action).await?;
        assert!(!denied.output.successful);
        assert!(denied.output.data["error"]
            .as_str()
            .is_some_and(|error| error.contains("stage request budget exhausted")));

        let forbidden_runtime = engine.runtime_for_attempt(&token)?;
        let forbidden = forbidden_runtime.execute(ToolAction::HttpGet {
            url: "https://example.test/".into(),
        });
        assert!(forbidden.await.is_err());

        let mut receipt_ids = vec![first.id, denied.id];
        receipt_ids.sort();
        let reason = CoverageReason::BudgetExhausted {
            dimension: domain::BudgetDimension::Requests,
        };
        engine.finish_stage(
            &token,
            StageTerminalOutcome {
                state: StageExecutionState::Succeeded,
                coverage_state: CoverageState::Partial,
                coverage_reasons: vec![reason],
                receipt_ids,
                artifacts: vec![],
                model_tokens: 0,
                cost_microusd: 0,
                reason: None,
            },
        )?;
        assert_eq!(engine.snapshot().stages[1].usage.requests, 1);
        assert_eq!(engine.snapshot().stages[1].usage.peak_concurrency, 1);
        Ok(())
    }

    #[test]
    fn resume_rejects_tampered_bound_input_artifact() -> Result<()> {
        let output = tempfile::tempdir()?;
        let engine = EngagementEngine::new(fixture(output.path())?)?;
        drop(engine);
        storage::atomic_write(&output.path().join("plans/web.json"), b"{\"changed\":true}")?;
        assert!(EngagementEngine::resume(output.path()).is_err());
        Ok(())
    }

    #[test]
    fn active_engine_holds_the_single_writer_lock() -> Result<()> {
        let output = tempfile::tempdir()?;
        let engine = EngagementEngine::new(fixture(output.path())?)?;
        assert!(EngagementEngine::resume(output.path()).is_err());
        drop(engine);
        EngagementEngine::resume(output.path())?;
        Ok(())
    }

    #[test]
    fn persisted_configuration_fingerprint_is_verified() -> Result<()> {
        let output = tempfile::tempdir()?;
        let engine = EngagementEngine::new(fixture(output.path())?)?;
        drop(engine);
        let path = output.path().join(CONFIG_FILE);
        let mut config: EngagementConfig = read_json(&path)?;
        config.scope.max_requests = 9;
        write_json(&path, &config)?;
        assert!(EngagementEngine::resume(output.path()).is_err());
        Ok(())
    }

    #[test]
    fn target_scope_and_secret_query_are_checked_before_state_persistence() -> Result<()> {
        let output = tempfile::tempdir()?;
        let mut config = fixture(output.path())?;
        config.targets[0] = TypedTarget::Web {
            id: "web-main".into(),
            url: "https://example.test/?token=fixture-secret".into(),
        };
        assert!(EngagementEngine::new(config.clone()).is_err());
        assert!(!output.path().join(CONFIG_FILE).exists());

        config.overrides = domain::ExpertOverrides {
            controls: vec![
                domain::Control::SecretExposure,
                domain::Control::SecretRedaction,
            ],
            reason: "authorized secret-bearing fixture target".into(),
            actor: "fixture-operator".into(),
            acknowledged: true,
            ..domain::ExpertOverrides::default()
        };
        EngagementEngine::new(config)?;
        Ok(())
    }
}
