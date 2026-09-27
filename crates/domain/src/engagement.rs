//! Storage-independent contracts for a complete, multi-stage assessment.
//!
//! This schema intentionally does not extend [`crate::RunConfig`]. An
//! engagement is a durable orchestration contract, while a run remains one
//! backwards-compatible engine invocation.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use crate::{Control, ExpertOverrides, Scope};

pub const ENGAGEMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct StageId(pub String);

impl StageId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_stable_id("stage", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<()> {
        validate_stable_id("stage", &self.0)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    Web,
    Browser,
    Source,
    Host,
    CloudSnapshot,
    CloudLive,
    Ai,
    Skills,
    Provider,
    ModelPanel,
    Chains,
    Cleanup,
    Reporting,
}

impl StageKind {
    /// Stages that can cause network or provider-side activity and therefore
    /// require engagement authorization before the scheduler may start them.
    pub fn requires_authorization(self) -> bool {
        matches!(
            self,
            Self::Web
                | Self::Browser
                | Self::Host
                | Self::CloudLive
                | Self::Ai
                | Self::Provider
                | Self::ModelPanel
                | Self::Chains
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedTarget {
    Web {
        id: String,
        url: String,
    },
    Source {
        id: String,
        root: String,
    },
    Host {
        id: String,
        host: String,
    },
    Cloud {
        id: String,
        provider: CloudProvider,
        account_id: String,
    },
    Ai {
        id: String,
        endpoint: String,
    },
    Workspace {
        id: String,
        root: String,
    },
    Provider {
        id: String,
        provider_id: String,
    },
    ModelPanel {
        id: String,
        panel_id: String,
    },
    Chain {
        id: String,
        chain_id: String,
    },
}

impl TypedTarget {
    pub fn id(&self) -> &str {
        match self {
            Self::Web { id, .. }
            | Self::Source { id, .. }
            | Self::Host { id, .. }
            | Self::Cloud { id, .. }
            | Self::Ai { id, .. }
            | Self::Workspace { id, .. }
            | Self::Provider { id, .. }
            | Self::ModelPanel { id, .. }
            | Self::Chain { id, .. } => id,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_stable_id("target", self.id())?;
        match self {
            Self::Web { url, .. } => validate_http_url("web target", url),
            Self::Ai { endpoint, .. } => validate_http_url("AI target", endpoint),
            Self::Source { root, .. } | Self::Workspace { root, .. } => {
                ensure!(!root.trim().is_empty(), "target root cannot be empty");
                Ok(())
            }
            Self::Host { host, .. } => {
                ensure!(
                    !host.trim().is_empty()
                        && host.len() <= 253
                        && !host.chars().any(char::is_whitespace),
                    "invalid host target"
                );
                Ok(())
            }
            Self::Cloud { account_id, .. } => {
                ensure!(
                    !account_id.trim().is_empty() && account_id.len() <= 256,
                    "invalid cloud account target"
                );
                Ok(())
            }
            Self::Provider { provider_id, .. } => validate_stable_id("provider", provider_id),
            Self::ModelPanel { panel_id, .. } => validate_stable_id("panel", panel_id),
            Self::Chain { chain_id, .. } => validate_stable_id("chain", chain_id),
        }
    }

    fn supports(&self, kind: StageKind) -> bool {
        matches!(
            (self, kind),
            (Self::Web { .. }, StageKind::Web | StageKind::Browser)
                | (Self::Source { .. }, StageKind::Source)
                | (Self::Host { .. }, StageKind::Host)
                | (
                    Self::Cloud { .. },
                    StageKind::CloudSnapshot | StageKind::CloudLive
                )
                | (Self::Ai { .. }, StageKind::Ai)
                | (Self::Workspace { .. }, StageKind::Skills)
                | (Self::Provider { .. }, StageKind::Provider)
                | (Self::ModelPanel { .. }, StageKind::ModelPanel)
                | (Self::Chain { .. }, StageKind::Chains)
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Plan,
    Observation,
    Receipt,
    Finding,
    Screenshot,
    SourceMap,
    Snapshot,
    CleanupRecord,
    CoverageManifest,
    Report,
    Log,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub id: String,
    pub kind: ArtifactKind,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

impl ArtifactRef {
    pub fn validate(&self) -> Result<()> {
        validate_stable_id("artifact", &self.id)?;
        ensure!(
            crate::is_canonical_sha256(&self.sha256),
            "artifact hash must be canonical SHA-256"
        );
        validate_relative_artifact_path(&self.path)?;
        ensure!(
            !self.media_type.is_empty()
                && self.media_type.len() <= 255
                && self.media_type.is_ascii()
                && !self.media_type.chars().any(char::is_whitespace),
            "invalid artifact media type"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngagementBudgets {
    pub max_requests: u64,
    pub max_state_changes: u64,
    pub max_accounts: u64,
    pub max_model_tokens: u64,
    pub max_cost_microusd: u64,
    pub max_duration_ms: u64,
    pub max_artifact_bytes: u64,
    pub max_concurrency: u32,
}

impl EngagementBudgets {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.max_duration_ms > 0 && self.max_artifact_bytes > 0 && self.max_concurrency > 0,
            "engagement duration, artifact and concurrency budgets must be positive"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct StageBudgetCaps {
    pub max_requests: u64,
    pub max_state_changes: u64,
    pub max_accounts: u64,
    pub max_model_tokens: u64,
    pub max_cost_microusd: u64,
    pub max_duration_ms: u64,
    pub max_artifact_bytes: u64,
    pub max_concurrency: u32,
}

impl StageBudgetCaps {
    fn validate(&self, global: &EngagementBudgets, overrides: &ExpertOverrides) -> Result<()> {
        ensure!(
            self.max_duration_ms > 0 && self.max_artifact_bytes > 0 && self.max_concurrency > 0,
            "stage duration, artifact and concurrency caps must be positive"
        );
        ensure!(
            (overrides.disables(Control::RequestBudget)
                || (self.max_requests <= global.max_requests
                    && self.max_model_tokens <= global.max_model_tokens
                    && self.max_cost_microusd <= global.max_cost_microusd))
                && (overrides.disables(Control::StateChanges)
                    || self.max_state_changes <= global.max_state_changes)
                && (overrides.disables(Control::AccountBudget)
                    || self.max_accounts <= global.max_accounts)
                && (overrides.disables(Control::Timeouts)
                    || self.max_duration_ms <= global.max_duration_ms)
                && (overrides.disables(Control::DataSampling)
                    || self.max_artifact_bytes <= global.max_artifact_bytes)
                && (overrides.disables(Control::Concurrency)
                    || self.max_concurrency <= global.max_concurrency),
            "stage cap exceeds the engagement ceiling"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Sarif,
    Html,
    Markdown,
    Pdf,
}

impl ReportFormat {
    fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Sarif => "application/sarif+json",
            Self::Html => "text/html",
            Self::Markdown => "text/markdown",
            Self::Pdf => "application/pdf",
        }
    }
}

/// Dependency semantics are explicit so the reporting finalizer and cleanup
/// cannot be accidentally blocked by a failed assessment stage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencyPolicy {
    AllSucceeded,
    AllTerminal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StageConfig {
    Web {
        plan: ArtifactRef,
        authenticated: bool,
    },
    Browser {
        workflow: ArtifactRef,
        roles: Vec<String>,
    },
    Source {
        languages: Vec<String>,
        base_ref: Option<String>,
        head_ref: Option<String>,
    },
    Host {
        profile: ArtifactRef,
    },
    CloudSnapshot {
        snapshot: ArtifactRef,
    },
    CloudLive {
        plan: ArtifactRef,
        read_only: bool,
    },
    Ai {
        plan: ArtifactRef,
        max_turns: u32,
    },
    Skills {
        skill_ids: Vec<String>,
    },
    Provider {
        provider_id: String,
        deployment: String,
        request: ArtifactRef,
        requested_sessions: u32,
    },
    ModelPanel {
        panel_id: String,
        member_stage_ids: Vec<StageId>,
        quorum: u32,
    },
    Chains {
        chain_id: String,
        templates: ArtifactRef,
        cleanup_required: bool,
    },
    Cleanup {
        stage_ids: Vec<StageId>,
    },
    Reporting {
        formats: Vec<ReportFormat>,
        finalizer: bool,
    },
}

impl StageConfig {
    pub fn kind(&self) -> StageKind {
        match self {
            Self::Web { .. } => StageKind::Web,
            Self::Browser { .. } => StageKind::Browser,
            Self::Source { .. } => StageKind::Source,
            Self::Host { .. } => StageKind::Host,
            Self::CloudSnapshot { .. } => StageKind::CloudSnapshot,
            Self::CloudLive { .. } => StageKind::CloudLive,
            Self::Ai { .. } => StageKind::Ai,
            Self::Skills { .. } => StageKind::Skills,
            Self::Provider { .. } => StageKind::Provider,
            Self::ModelPanel { .. } => StageKind::ModelPanel,
            Self::Chains { .. } => StageKind::Chains,
            Self::Cleanup { .. } => StageKind::Cleanup,
            Self::Reporting { .. } => StageKind::Reporting,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Web { plan, .. } => {
                plan.validate()?;
                ensure!(plan.kind == ArtifactKind::Plan, "web plan has wrong type");
                Ok(())
            }
            Self::Browser { workflow, roles } => {
                workflow.validate()?;
                ensure!(
                    workflow.kind == ArtifactKind::Plan,
                    "browser workflow has wrong type"
                );
                validate_sorted_stable_ids("browser role", roles)
            }
            Self::Source {
                languages,
                base_ref,
                head_ref,
            } => {
                ensure!(
                    !languages.is_empty()
                        && languages.windows(2).all(|pair| pair[0] < pair[1])
                        && languages.iter().all(|language| {
                            !language.is_empty()
                                && language.len() <= 32
                                && language.bytes().all(|byte| {
                                    byte.is_ascii_lowercase()
                                        || byte.is_ascii_digit()
                                        || matches!(byte, b'+' | b'#' | b'-')
                                })
                        }),
                    "source languages must be sorted, unique and canonical"
                );
                ensure!(
                    base_ref
                        .as_ref()
                        .is_none_or(|value| !value.trim().is_empty())
                        && head_ref
                            .as_ref()
                            .is_none_or(|value| !value.trim().is_empty()),
                    "source refs cannot be empty"
                );
                Ok(())
            }
            Self::Host { profile } => {
                profile.validate()?;
                ensure!(
                    profile.kind == ArtifactKind::Plan,
                    "host profile has wrong type"
                );
                Ok(())
            }
            Self::CloudSnapshot { snapshot } => {
                snapshot.validate()?;
                ensure!(
                    snapshot.kind == ArtifactKind::Snapshot,
                    "cloud snapshot has wrong type"
                );
                Ok(())
            }
            Self::CloudLive { plan, .. } => {
                plan.validate()?;
                ensure!(
                    plan.kind == ArtifactKind::Plan,
                    "cloud-live plan has wrong type"
                );
                Ok(())
            }
            Self::Ai { plan, max_turns } => {
                plan.validate()?;
                ensure!(plan.kind == ArtifactKind::Plan, "AI plan has wrong type");
                ensure!(*max_turns > 0, "AI stage max_turns must be positive");
                Ok(())
            }
            Self::Skills { skill_ids } => validate_sorted_stable_ids("skill", skill_ids),
            Self::Provider {
                provider_id,
                deployment,
                request,
                requested_sessions,
            } => {
                validate_stable_id("provider", provider_id)?;
                ensure!(
                    !deployment.trim().is_empty(),
                    "provider deployment is required"
                );
                request.validate()?;
                ensure!(
                    request.kind == ArtifactKind::Plan,
                    "provider request artifact must be a plan"
                );
                ensure!(
                    *requested_sessions > 0,
                    "provider stage must request at least one session"
                );
                Ok(())
            }
            Self::ModelPanel {
                panel_id,
                member_stage_ids,
                quorum,
            } => {
                validate_stable_id("panel", panel_id)?;
                validate_sorted_stage_ids("model-panel members", member_stage_ids)?;
                ensure!(
                    *quorum >= 2 && usize::try_from(*quorum)? <= member_stage_ids.len(),
                    "model-panel quorum must be at least two and no larger than membership"
                );
                Ok(())
            }
            Self::Chains {
                chain_id,
                templates,
                ..
            } => {
                validate_stable_id("chain", chain_id)?;
                templates.validate()?;
                ensure!(
                    templates.kind == ArtifactKind::Plan,
                    "chain template bundle has wrong type"
                );
                Ok(())
            }
            Self::Cleanup { stage_ids } => {
                validate_sorted_stage_ids("cleanup stage references", stage_ids)
            }
            Self::Reporting { formats, finalizer } => {
                ensure!(*finalizer, "reporting stage must be the finalizer");
                ensure!(
                    !formats.is_empty() && formats.windows(2).all(|pair| pair[0] < pair[1]),
                    "report formats must be sorted and unique"
                );
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageSpec {
    pub id: StageId,
    pub kind: StageKind,
    pub target_ids: Vec<String>,
    pub depends_on: Vec<StageId>,
    pub dependency_policy: DependencyPolicy,
    pub required: bool,
    pub budget: StageBudgetCaps,
    pub config: StageConfig,
}

impl StageSpec {
    /// Canonical bytes used by storage to bind one-stage retry authority.
    pub fn canonical_fingerprint_input(&self) -> Result<Vec<u8>> {
        self.id.validate()?;
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&value).context("serialize canonical stage fingerprint input")
    }

    fn validate_local(
        &self,
        targets: &BTreeMap<&str, &TypedTarget>,
        global: &EngagementBudgets,
        overrides: &ExpertOverrides,
    ) -> Result<()> {
        self.id.validate()?;
        ensure!(
            self.kind == self.config.kind(),
            "stage kind and typed configuration disagree"
        );
        self.config.validate()?;
        self.budget.validate(global, overrides)?;
        validate_sorted_stable_ids("stage target", &self.target_ids)?;
        validate_sorted_stage_ids("stage dependencies", &self.depends_on)?;
        ensure!(
            !self.depends_on.contains(&self.id),
            "stage cannot depend on itself"
        );
        if self.dependency_policy == DependencyPolicy::AllTerminal {
            ensure!(
                matches!(self.kind, StageKind::Cleanup | StageKind::Reporting),
                "all-terminal dependencies are reserved for cleanup and reporting"
            );
        }
        if self.kind == StageKind::Cleanup {
            ensure!(
                self.dependency_policy == DependencyPolicy::AllTerminal,
                "cleanup must run after terminal dependencies, including failures"
            );
        }

        if matches!(self.kind, StageKind::Cleanup | StageKind::Reporting) {
            ensure!(
                self.target_ids.is_empty(),
                "cleanup and reporting stages cannot declare assessment targets"
            );
        } else {
            ensure!(
                !self.target_ids.is_empty(),
                "assessment stage requires at least one typed target"
            );
        }
        for target_id in &self.target_ids {
            let target = targets
                .get(target_id.as_str())
                .with_context(|| format!("stage references missing target {target_id}"))?;
            ensure!(
                target.supports(self.kind),
                "stage target is incompatible with its typed configuration"
            );
            match (target, &self.config) {
                (
                    TypedTarget::Provider { provider_id, .. },
                    StageConfig::Provider {
                        provider_id: configured,
                        ..
                    },
                ) => ensure!(
                    provider_id == configured,
                    "provider stage target and configuration disagree"
                ),
                (
                    TypedTarget::ModelPanel { panel_id, .. },
                    StageConfig::ModelPanel {
                        panel_id: configured,
                        ..
                    },
                ) => ensure!(
                    panel_id == configured,
                    "model-panel stage target and configuration disagree"
                ),
                (
                    TypedTarget::Chain { chain_id, .. },
                    StageConfig::Chains {
                        chain_id: configured,
                        ..
                    },
                ) => ensure!(
                    chain_id == configured,
                    "chain stage target and configuration disagree"
                ),
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngagementConfig {
    pub schema_version: u32,
    pub engagement_id: String,
    pub output_dir: PathBuf,
    pub scope: Scope,
    pub authorized: bool,
    #[serde(default)]
    pub overrides: ExpertOverrides,
    pub targets: Vec<TypedTarget>,
    pub budgets: EngagementBudgets,
    pub stages: Vec<StageSpec>,
}

impl EngagementConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == ENGAGEMENT_SCHEMA_VERSION,
            "unsupported engagement schema"
        );
        validate_stable_id("engagement", &self.engagement_id)?;
        ensure!(
            !self.output_dir.as_os_str().is_empty(),
            "engagement output directory is required"
        );
        self.overrides.validate()?;
        self.budgets.validate()?;
        ensure!(
            self.overrides.disables(Control::RequestBudget)
                || self.budgets.max_requests <= self.scope.max_requests,
            "engagement request budget exceeds central scope"
        );
        ensure!(
            self.overrides.disables(Control::StateChanges)
                || self.budgets.max_state_changes <= self.scope.max_state_changes,
            "engagement state-change budget exceeds central scope"
        );
        ensure!(
            self.overrides.disables(Control::AccountBudget)
                || self.budgets.max_accounts <= self.scope.max_accounts,
            "engagement account budget exceeds central scope"
        );
        ensure!(
            self.overrides.disables(Control::Concurrency)
                || usize::try_from(self.budgets.max_concurrency)? <= self.scope.max_concurrency,
            "engagement concurrency exceeds central scope"
        );
        ensure!(
            !self.targets.is_empty(),
            "engagement requires typed targets"
        );
        ensure!(!self.stages.is_empty(), "engagement requires stages");
        ensure!(
            self.targets
                .windows(2)
                .all(|pair| pair[0].id() < pair[1].id()),
            "engagement targets must be sorted by unique stable id"
        );
        ensure!(
            self.stages.windows(2).all(|pair| pair[0].id < pair[1].id),
            "engagement stages must be sorted by unique stable id"
        );

        let mut targets = BTreeMap::new();
        for target in &self.targets {
            target.validate()?;
            ensure!(
                targets.insert(target.id(), target).is_none(),
                "duplicate target id"
            );
        }
        let stage_ids: BTreeSet<_> = self.stages.iter().map(|stage| &stage.id).collect();
        ensure!(stage_ids.len() == self.stages.len(), "duplicate stage id");
        for stage in &self.stages {
            stage.validate_local(&targets, &self.budgets, &self.overrides)?;
            ensure!(
                stage
                    .depends_on
                    .iter()
                    .all(|dependency| stage_ids.contains(dependency)),
                "stage dependency does not exist"
            );
        }
        ensure!(
            !self
                .stages
                .iter()
                .any(|stage| stage.kind.requires_authorization())
                || self.authorized
                || self.overrides.disables(Control::Authorization),
            "active engagement stages require authorization or an audited authorization override"
        );
        validate_acyclic(&self.stages)?;
        self.validate_cross_stage_references(&stage_ids)?;
        self.validate_finalizer()?;
        self.validate_budget_allocation()?;
        Ok(())
    }

    /// Canonical, storage-independent bytes for a caller-owned fingerprint.
    /// Validation requires canonical ordering, so these bytes are stable across
    /// serde round trips without coupling the domain crate to a hash provider.
    pub fn canonical_fingerprint_input(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&value).context("serialize canonical engagement fingerprint input")
    }

    fn validate_cross_stage_references(&self, stage_ids: &BTreeSet<&StageId>) -> Result<()> {
        for stage in &self.stages {
            match &stage.config {
                StageConfig::ModelPanel {
                    member_stage_ids, ..
                } => {
                    for member in member_stage_ids {
                        let member_stage = self
                            .stage(member)
                            .context("model panel references missing provider stage")?;
                        ensure!(
                            member_stage.kind == StageKind::Provider
                                && stage.depends_on.contains(member),
                            "model-panel members must be provider dependencies"
                        );
                    }
                }
                StageConfig::Cleanup {
                    stage_ids: cleanup_ids,
                } => {
                    ensure!(!cleanup_ids.is_empty(), "cleanup stage cannot be empty");
                    for cleaned in cleanup_ids {
                        ensure!(
                            stage_ids.contains(cleaned)
                                && stage.depends_on.contains(cleaned)
                                && self
                                    .stage(cleaned)
                                    .is_some_and(|value| value.kind != StageKind::Reporting),
                            "cleanup references must be direct non-reporting dependencies"
                        );
                    }
                }
                _ => {}
            }
        }
        for chain in self.stages.iter().filter(|stage| {
            matches!(
                stage.config,
                StageConfig::Chains {
                    cleanup_required: true,
                    ..
                }
            )
        }) {
            ensure!(
                self.stages.iter().any(|cleanup| {
                    matches!(
                        &cleanup.config,
                        StageConfig::Cleanup { stage_ids }
                            if cleanup.depends_on.contains(&chain.id)
                                && stage_ids.contains(&chain.id)
                    )
                }),
                "chain stage requiring cleanup must be named by a directly dependent cleanup stage"
            );
        }
        Ok(())
    }

    fn validate_finalizer(&self) -> Result<()> {
        let finalizers: Vec<_> = self
            .stages
            .iter()
            .filter(|stage| {
                matches!(
                    stage.config,
                    StageConfig::Reporting {
                        finalizer: true,
                        ..
                    }
                )
            })
            .collect();
        ensure!(
            finalizers.len() == 1,
            "engagement requires exactly one reporting finalizer"
        );
        let finalizer = finalizers[0];
        ensure!(finalizer.required, "reporting finalizer must be required");
        ensure!(
            finalizer.dependency_policy == DependencyPolicy::AllTerminal,
            "reporting finalizer must run after terminal dependencies, including failures"
        );
        ensure!(
            !self
                .stages
                .iter()
                .any(|stage| stage.depends_on.contains(&finalizer.id)),
            "no stage can depend on the reporting finalizer"
        );
        for stage in &self.stages {
            if stage.id != finalizer.id {
                ensure!(
                    dependency_reachable(&finalizer.id, &stage.id, &self.stages),
                    "reporting finalizer must transitively depend on every stage"
                );
            }
        }
        Ok(())
    }

    fn validate_budget_allocation(&self) -> Result<()> {
        let mut allocated = StageBudgetCaps::default();
        for stage in &self.stages {
            checked_accumulate(&mut allocated, &stage.budget)?;
        }
        ensure!(
            (self.overrides.disables(Control::RequestBudget)
                || (allocated.max_requests <= self.budgets.max_requests
                    && allocated.max_model_tokens <= self.budgets.max_model_tokens
                    && allocated.max_cost_microusd <= self.budgets.max_cost_microusd))
                && (self.overrides.disables(Control::StateChanges)
                    || allocated.max_state_changes <= self.budgets.max_state_changes)
                && (self.overrides.disables(Control::AccountBudget)
                    || allocated.max_accounts <= self.budgets.max_accounts)
                && (self.overrides.disables(Control::Timeouts)
                    || allocated.max_duration_ms <= self.budgets.max_duration_ms)
                && (self.overrides.disables(Control::DataSampling)
                    || allocated.max_artifact_bytes <= self.budgets.max_artifact_bytes)
                && (self.overrides.disables(Control::Concurrency)
                    || allocated.max_concurrency <= self.budgets.max_concurrency),
            "sum of per-stage allocations exceeds an engagement ceiling"
        );
        Ok(())
    }

    pub fn stage(&self, id: &StageId) -> Option<&StageSpec> {
        self.stages.iter().find(|stage| stage.id == *id)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngagementExecutionState {
    Planned,
    Running,
    Paused,
    Complete,
    Failed,
    Cancelled,
}

impl EngagementExecutionState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageExecutionState {
    Planned,
    Ready,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Blocked,
    Cancelled,
    Indeterminate,
}

impl StageExecutionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Skipped
                | Self::Blocked
                | Self::Cancelled
                | Self::Indeterminate
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    NotStarted,
    Running,
    Complete,
    Partial,
    Omitted,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    Requests,
    StateChanges,
    Accounts,
    ModelTokens,
    Cost,
    Duration,
    ArtifactBytes,
    Concurrency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageReason {
    DependencyFailed {
        stage_id: StageId,
    },
    BudgetExhausted {
        dimension: BudgetDimension,
    },
    ResourceLimit {
        resource: String,
        observed: u64,
        limit: u64,
    },
    CrawlLimitReached {
        dimension: String,
        observed: u64,
        limit: u64,
    },
    CredentialUnavailable {
        credential: String,
    },
    CapabilityUnavailable {
        capability: String,
    },
    ConfigurationMissing {
        field: String,
    },
    Unsupported {
        capability: String,
    },
    Unavailable {
        component: String,
    },
    PolicyDenied {
        control: String,
    },
    Cancelled {
        actor: String,
    },
    ExecutionError {
        code: String,
    },
    TimedOut {
        operation: String,
        timeout_ms: u64,
    },
    OutcomeUnknown {
        operation: String,
    },
    ValidationInconclusive {
        validator: String,
    },
    AcquisitionFailure {
        code: String,
    },
    ProviderNoReply {
        work_id: String,
    },
    ProviderTelemetryUnavailable {
        work_id: String,
    },
    NoApplicableWork {
        explanation: String,
    },
    OperatorExcluded {
        actor: String,
        reason: String,
    },
}

impl CoverageReason {
    fn validate(&self) -> Result<()> {
        let value = match self {
            Self::DependencyFailed { stage_id } => return stage_id.validate(),
            Self::BudgetExhausted { .. } => return Ok(()),
            Self::ResourceLimit {
                resource,
                observed,
                limit,
            }
            | Self::CrawlLimitReached {
                dimension: resource,
                observed,
                limit,
            } => {
                ensure!(
                    !resource.trim().is_empty() && *limit > 0 && observed >= limit,
                    "coverage resource limit is invalid"
                );
                return Ok(());
            }
            Self::CredentialUnavailable { credential } => credential,
            Self::CapabilityUnavailable { capability } => capability,
            Self::ConfigurationMissing { field } => field,
            Self::Unsupported { capability } => capability,
            Self::Unavailable { component } => component,
            Self::PolicyDenied { control } => control,
            Self::Cancelled { actor } => actor,
            Self::ExecutionError { code } => code,
            Self::TimedOut {
                operation,
                timeout_ms,
            } => {
                ensure!(
                    !operation.trim().is_empty() && *timeout_ms > 0,
                    "coverage timeout is invalid"
                );
                return Ok(());
            }
            Self::OutcomeUnknown { operation } => operation,
            Self::ValidationInconclusive { validator } => validator,
            Self::AcquisitionFailure { code } => code,
            Self::ProviderNoReply { work_id } | Self::ProviderTelemetryUnavailable { work_id } => {
                validate_stable_id("provider work", work_id)?;
                return Ok(());
            }
            Self::NoApplicableWork { explanation } => explanation,
            Self::OperatorExcluded { actor, reason } => {
                ensure!(
                    !actor.trim().is_empty() && !reason.trim().is_empty(),
                    "operator exclusion requires actor and reason"
                );
                return Ok(());
            }
        };
        ensure!(!value.trim().is_empty(), "coverage reason cannot be empty");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct LimitUsage {
    pub requests: u64,
    pub state_changes: u64,
    pub accounts: u64,
    pub model_tokens: u64,
    pub cost_microusd: u64,
    pub duration_ms: u64,
    pub artifact_bytes: u64,
    pub peak_concurrency: u32,
}

impl LimitUsage {
    fn validate(&self, cap: &StageBudgetCaps, overrides: &ExpertOverrides) -> Result<()> {
        ensure!(
            (overrides.disables(Control::RequestBudget)
                || (self.requests <= cap.max_requests
                    && self.model_tokens <= cap.max_model_tokens
                    && self.cost_microusd <= cap.max_cost_microusd))
                && (overrides.disables(Control::StateChanges)
                    || self.state_changes <= cap.max_state_changes)
                && (overrides.disables(Control::AccountBudget)
                    || self.accounts <= cap.max_accounts)
                && (overrides.disables(Control::Timeouts)
                    || self.duration_ms <= cap.max_duration_ms)
                && (overrides.disables(Control::DataSampling)
                    || self.artifact_bytes <= cap.max_artifact_bytes)
                && (overrides.disables(Control::Concurrency)
                    || self.peak_concurrency <= cap.max_concurrency),
            "stage usage exceeds its immutable budget cap"
        );
        Ok(())
    }

    fn validate_global(
        &self,
        budget: &EngagementBudgets,
        overrides: &ExpertOverrides,
    ) -> Result<()> {
        ensure!(
            (overrides.disables(Control::RequestBudget)
                || (self.requests <= budget.max_requests
                    && self.model_tokens <= budget.max_model_tokens
                    && self.cost_microusd <= budget.max_cost_microusd))
                && (overrides.disables(Control::StateChanges)
                    || self.state_changes <= budget.max_state_changes)
                && (overrides.disables(Control::AccountBudget)
                    || self.accounts <= budget.max_accounts)
                && (overrides.disables(Control::Timeouts)
                    || self.duration_ms <= budget.max_duration_ms)
                && (overrides.disables(Control::DataSampling)
                    || self.artifact_bytes <= budget.max_artifact_bytes)
                && (overrides.disables(Control::Concurrency)
                    || self.peak_concurrency <= budget.max_concurrency),
            "engagement usage exceeds its immutable global budget"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageAttempt {
    pub attempt: u32,
    pub state: StageExecutionState,
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    pub usage: LimitUsage,
    pub receipt_ids: Vec<String>,
    pub artifacts: Vec<ArtifactRef>,
    pub reason: Option<CoverageReason>,
}

impl StageAttempt {
    fn validate(
        &self,
        expected: u32,
        cap: &StageBudgetCaps,
        overrides: &ExpertOverrides,
    ) -> Result<()> {
        ensure!(
            self.attempt == expected && self.attempt > 0,
            "stage attempt numbers must be contiguous and one-based"
        );
        ensure!(
            !matches!(
                self.state,
                StageExecutionState::Planned | StageExecutionState::Ready
            ),
            "planned or ready work is not an attempt"
        );
        self.usage.validate(cap, overrides)?;
        validate_receipt_ids(&self.receipt_ids)?;
        validate_artifact_set(&self.artifacts)?;
        if self.state == StageExecutionState::Running {
            ensure!(
                self.finished_ms.is_none() && self.reason.is_none(),
                "running attempt cannot have terminal fields"
            );
        } else {
            let finished = self
                .finished_ms
                .context("terminal attempt requires a finish timestamp")?;
            ensure!(
                finished >= self.started_ms,
                "attempt timestamps are reversed"
            );
            if self.state == StageExecutionState::Succeeded {
                ensure!(
                    self.reason.is_none()
                        && (!self.receipt_ids.is_empty() || !self.artifacts.is_empty()),
                    "successful attempt requires evidence and no failure reason"
                );
            } else {
                let reason = self
                    .reason
                    .as_ref()
                    .context("non-successful attempt requires a typed reason")?;
                reason.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageRecord {
    pub stage_id: StageId,
    pub execution_state: StageExecutionState,
    pub coverage_state: CoverageState,
    pub coverage_reasons: Vec<CoverageReason>,
    pub attempts: Vec<StageAttempt>,
    pub usage: LimitUsage,
    pub artifacts: Vec<ArtifactRef>,
    pub reason: Option<CoverageReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OverrideEpoch {
    pub epoch: u64,
    pub recorded_ms: u64,
    pub overrides: ExpertOverrides,
}

impl OverrideEpoch {
    fn validate(&self, expected: u64) -> Result<()> {
        ensure!(
            self.epoch == expected && self.epoch > 0,
            "override epochs must be contiguous and one-based"
        );
        ensure!(self.recorded_ms > 0, "override epoch needs a timestamp");
        self.overrides.validate()?;
        ensure!(
            self.overrides.active(),
            "override history cannot contain an inactive entry"
        );
        Ok(())
    }
}

/// Explicit authorization to repeat exactly one failed or indeterminate stage
/// attempt. The scheduler hashes the canonical StageSpec bytes and must reject
/// this authorization if either the engagement or stage specification changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageRetryAuthorization {
    pub engagement_id: String,
    pub config_fingerprint: String,
    pub stage_id: StageId,
    pub stage_spec_fingerprint: String,
    pub prior_attempt: u32,
    pub next_attempt: u32,
    pub actor: String,
    pub reason: String,
    pub authorized_ms: u64,
}

impl StageRetryAuthorization {
    pub fn validate(
        &self,
        config: &EngagementConfig,
        snapshot: &EngagementSnapshot,
        expected_stage_spec_fingerprint: &str,
    ) -> Result<()> {
        snapshot.validate(config)?;
        ensure!(
            self.engagement_id == config.engagement_id
                && self.config_fingerprint == snapshot.config_fingerprint,
            "retry authorization is not bound to this engagement"
        );
        ensure!(
            crate::is_canonical_sha256(expected_stage_spec_fingerprint)
                && self.stage_spec_fingerprint == expected_stage_spec_fingerprint,
            "retry authorization is not bound to the exact current stage specification"
        );
        let record = snapshot
            .stages
            .iter()
            .find(|record| record.stage_id == self.stage_id)
            .context("retry authorization references missing stage")?;
        ensure!(
            matches!(
                record.execution_state,
                StageExecutionState::Failed | StageExecutionState::Indeterminate
            ) && self.prior_attempt > 0
                && self.prior_attempt == u32::try_from(record.attempts.len())?
                && self.next_attempt == self.prior_attempt.saturating_add(1),
            "retry authorization is not for the exact latest failed attempt"
        );
        ensure!(
            !self.actor.trim().is_empty()
                && self.reason.trim().len() >= 8
                && self.authorized_ms >= snapshot.updated_ms,
            "retry authorization requires actor, meaningful reason and a current timestamp"
        );
        Ok(())
    }
}

impl StageRecord {
    fn validate(&self, spec: &StageSpec, overrides: &ExpertOverrides) -> Result<()> {
        ensure!(self.stage_id == spec.id, "stage record identity mismatch");
        self.usage.validate(&spec.budget, overrides)?;
        validate_artifact_set(&self.artifacts)?;
        for reason in &self.coverage_reasons {
            reason.validate()?;
        }
        match self.coverage_state {
            CoverageState::Partial | CoverageState::Omitted | CoverageState::Indeterminate => {
                ensure!(
                    !self.coverage_reasons.is_empty(),
                    "non-complete terminal coverage requires typed reasons"
                );
            }
            CoverageState::NotStarted | CoverageState::Running | CoverageState::Complete => {
                ensure!(
                    self.coverage_reasons.is_empty(),
                    "complete or active coverage cannot carry omission reasons"
                );
            }
        }
        let mut aggregate_usage = LimitUsage::default();
        let mut aggregate_artifacts = BTreeMap::new();
        for (index, attempt) in self.attempts.iter().enumerate() {
            attempt.validate(u32::try_from(index + 1)?, &spec.budget, overrides)?;
            checked_accumulate_usage(&mut aggregate_usage, &attempt.usage)?;
            for artifact in &attempt.artifacts {
                if let Some(existing) = aggregate_artifacts.insert(artifact.id.as_str(), artifact) {
                    ensure!(
                        existing == artifact,
                        "attempts disagree about an immutable artifact"
                    );
                }
            }
        }
        ensure!(
            self.usage == aggregate_usage,
            "stage usage must equal the aggregate of its attempts"
        );
        ensure!(
            aggregate_artifacts
                .values()
                .copied()
                .eq(self.artifacts.iter()),
            "stage artifacts must equal the artifacts produced by its attempts"
        );
        if matches!(
            self.execution_state,
            StageExecutionState::Failed | StageExecutionState::Cancelled
        ) && self.coverage_state == CoverageState::Partial
        {
            ensure!(
                self.usage != LimitUsage::default()
                    || !self.artifacts.is_empty()
                    || self
                        .attempts
                        .iter()
                        .any(|attempt| !attempt.receipt_ids.is_empty()),
                "failed or cancelled zero-work cannot claim partial coverage"
            );
        }
        match self.execution_state {
            StageExecutionState::Planned | StageExecutionState::Ready => ensure!(
                self.attempts.is_empty()
                    && self.coverage_state == CoverageState::NotStarted
                    && self.coverage_reasons.is_empty()
                    && self.reason.is_none(),
                "unstarted stage has execution or coverage evidence"
            ),
            state => {
                ensure!(
                    self.attempts
                        .last()
                        .is_some_and(|attempt| attempt.state == state),
                    "stage state must equal its latest attempt"
                );
                validate_execution_coverage(state, self.coverage_state)?;
                if state == StageExecutionState::Succeeded {
                    ensure!(
                        self.reason.is_none(),
                        "successful stage has a failure reason"
                    );
                    if let StageConfig::Reporting { formats, .. } = &spec.config {
                        let report_media_types: Vec<_> = self
                            .artifacts
                            .iter()
                            .filter(|artifact| artifact.kind == ArtifactKind::Report)
                            .map(|artifact| artifact.media_type.as_str())
                            .collect();
                        ensure!(
                            report_media_types.len() == formats.len()
                                && formats.iter().all(|format| {
                                    report_media_types
                                        .iter()
                                        .filter(|media_type| {
                                            **media_type == format.media_type()
                                        })
                                        .count()
                                        == 1
                                }),
                            "successful reporting must produce exactly one requested report artifact per format"
                        );
                    }
                } else if state != StageExecutionState::Running {
                    let reason = self
                        .reason
                        .as_ref()
                        .context("non-successful stage requires a typed reason")?;
                    reason.validate()?;
                    ensure!(
                        self.attempts
                            .last()
                            .and_then(|attempt| attempt.reason.as_ref())
                            == Some(reason),
                        "stage reason must equal the latest attempt reason"
                    );
                    ensure!(
                        self.coverage_reasons.contains(reason),
                        "stage failure reason must be represented in coverage"
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngagementSnapshot {
    pub schema_version: u32,
    pub engagement_id: String,
    pub config_fingerprint: String,
    pub sequence: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub execution_state: EngagementExecutionState,
    pub stages: Vec<StageRecord>,
    pub usage: LimitUsage,
    pub receipt_ids: Vec<String>,
    pub override_epoch: u64,
    pub override_history: Vec<OverrideEpoch>,
    pub coverage_manifest: Option<ArtifactRef>,
}

impl EngagementSnapshot {
    pub fn validate(&self, config: &EngagementConfig) -> Result<()> {
        config.validate()?;
        ensure!(
            self.schema_version == ENGAGEMENT_SCHEMA_VERSION
                && self.engagement_id == config.engagement_id,
            "snapshot does not match engagement contract"
        );
        ensure!(
            crate::is_canonical_sha256(&self.config_fingerprint),
            "snapshot config fingerprint must be canonical SHA-256"
        );
        ensure!(self.sequence > 0, "snapshot sequence must be positive");
        ensure!(
            self.created_ms > 0 && self.updated_ms >= self.created_ms,
            "snapshot timestamps are invalid"
        );
        ensure!(
            self.stages.len() == config.stages.len()
                && self
                    .stages
                    .iter()
                    .map(|record| &record.stage_id)
                    .eq(config.stages.iter().map(|spec| &spec.id)),
            "snapshot must contain exactly one ordered record per configured stage"
        );
        for (index, epoch) in self.override_history.iter().enumerate() {
            epoch.validate(u64::try_from(index + 1)?)?;
        }
        ensure!(
            self.override_epoch == u64::try_from(self.override_history.len())?,
            "active override epoch contradicts history"
        );
        if config.overrides.active() {
            ensure!(
                self.override_history
                    .first()
                    .is_some_and(|entry| entry.overrides == config.overrides),
                "snapshot omitted configured expert overrides"
            );
        }
        let effective_overrides = self
            .override_history
            .last()
            .map(|entry| &entry.overrides)
            .unwrap_or(&config.overrides);
        for (record, spec) in self.stages.iter().zip(&config.stages) {
            record.validate(spec, effective_overrides)?;
        }
        let mut aggregate_usage = LimitUsage::default();
        let mut aggregate_receipts = BTreeSet::new();
        for record in &self.stages {
            checked_accumulate_usage(&mut aggregate_usage, &record.usage)?;
            for attempt in &record.attempts {
                for receipt_id in &attempt.receipt_ids {
                    ensure!(
                        aggregate_receipts.insert(receipt_id.as_str()),
                        "receipt cannot belong to multiple stage attempts"
                    );
                }
            }
        }
        ensure!(
            self.usage == aggregate_usage,
            "engagement usage must equal aggregate stage usage"
        );
        self.usage
            .validate_global(&config.budgets, effective_overrides)?;
        validate_receipt_ids(&self.receipt_ids)?;
        ensure!(
            self.receipt_ids
                .iter()
                .map(String::as_str)
                .eq(aggregate_receipts.into_iter()),
            "engagement receipts must equal exact stage-attempt receipts"
        );
        if let Some(manifest) = &self.coverage_manifest {
            manifest.validate()?;
            ensure!(
                manifest.kind == ArtifactKind::CoverageManifest,
                "snapshot coverage artifact has wrong type"
            );
        }
        self.validate_overall_state(config)
    }

    fn validate_overall_state(&self, config: &EngagementConfig) -> Result<()> {
        let all_terminal = self
            .stages
            .iter()
            .all(|record| record.execution_state.is_terminal());
        let any_running = self
            .stages
            .iter()
            .any(|record| record.execution_state == StageExecutionState::Running);
        let any_cancelled = self
            .stages
            .iter()
            .any(|record| record.execution_state == StageExecutionState::Cancelled);
        let required_failed = self
            .stages
            .iter()
            .zip(&config.stages)
            .any(|(record, spec)| {
                spec.required && record.execution_state != StageExecutionState::Succeeded
            });
        let report_succeeded = self
            .stages
            .iter()
            .zip(&config.stages)
            .any(|(record, spec)| {
                spec.kind == StageKind::Reporting
                    && record.execution_state == StageExecutionState::Succeeded
            });

        match self.execution_state {
            EngagementExecutionState::Planned => ensure!(
                self.stages.iter().all(|record| {
                    record.execution_state == StageExecutionState::Planned
                        && record.coverage_state == CoverageState::NotStarted
                }) && self.coverage_manifest.is_none(),
                "planned snapshot contains execution evidence"
            ),
            EngagementExecutionState::Running => ensure!(
                !all_terminal && self.coverage_manifest.is_none(),
                "running engagement cannot be terminal or finalized"
            ),
            EngagementExecutionState::Paused => ensure!(
                !all_terminal && !any_running && self.coverage_manifest.is_none(),
                "paused engagement has running work or is terminal"
            ),
            EngagementExecutionState::Complete => ensure!(
                all_terminal
                    && !required_failed
                    && report_succeeded
                    && self.coverage_manifest.is_some(),
                "complete engagement lacks successful required work or final coverage"
            ),
            EngagementExecutionState::Failed => ensure!(
                all_terminal && required_failed && self.coverage_manifest.is_some(),
                "failed engagement must be terminal, finalized and have required failure"
            ),
            EngagementExecutionState::Cancelled => ensure!(
                all_terminal && any_cancelled && self.coverage_manifest.is_some(),
                "cancelled engagement must be terminal, finalized and record cancellation"
            ),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderWorkState {
    Planned,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Unavailable,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTelemetryState {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderWork {
    pub id: String,
    pub stage_id: StageId,
    pub provider_id: String,
    pub model: String,
    pub state: ProviderWorkState,
    pub started_ms: Option<u64>,
    pub finished_ms: Option<u64>,
    pub normalized_reply_count: u32,
    pub tool_call_count: u32,
    pub candidate_count: u32,
    pub telemetry_state: ProviderTelemetryState,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    pub receipt_ids: Vec<String>,
    pub reason: Option<CoverageReason>,
}

impl ProviderWork {
    fn validate(&self, config: &EngagementConfig) -> Result<()> {
        validate_stable_id("provider work", &self.id)?;
        self.stage_id.validate()?;
        validate_stable_id("provider", &self.provider_id)?;
        ensure!(
            !self.model.trim().is_empty(),
            "provider work model is required"
        );
        validate_receipt_ids(&self.receipt_ids)?;
        let stage = config
            .stage(&self.stage_id)
            .context("provider work references missing stage")?;
        ensure!(
            matches!(
                stage.kind,
                StageKind::Ai | StageKind::Provider | StageKind::ModelPanel
            ),
            "provider work belongs to a non-provider stage"
        );
        if let StageConfig::Provider {
            provider_id,
            deployment,
            ..
        } = &stage.config
        {
            ensure!(
                self.provider_id == *provider_id && self.model == *deployment,
                "provider work does not match the configured provider and deployment"
            );
        }
        match (self.started_ms, self.finished_ms) {
            (None, None) => ensure!(
                matches!(
                    self.state,
                    ProviderWorkState::Planned
                        | ProviderWorkState::Skipped
                        | ProviderWorkState::Unavailable
                ),
                "provider work without an attempt has an invalid state"
            ),
            (Some(started), None) => ensure!(
                self.state == ProviderWorkState::Running && started > 0,
                "running provider work has invalid timestamps"
            ),
            (Some(started), Some(finished)) => ensure!(
                !matches!(
                    self.state,
                    ProviderWorkState::Planned | ProviderWorkState::Running
                ) && started > 0
                    && finished >= started,
                "terminal provider work has invalid timestamps"
            ),
            (None, Some(_)) => anyhow::bail!("provider work cannot finish before it starts"),
        }
        match self.telemetry_state {
            ProviderTelemetryState::Complete => ensure!(
                self.input_tokens > 0 || self.output_tokens > 0,
                "complete provider telemetry cannot report zero tokens"
            ),
            ProviderTelemetryState::Partial => ensure!(
                self.input_tokens > 0 || self.output_tokens > 0 || self.cost_microusd > 0,
                "partial provider telemetry contains no telemetry"
            ),
            ProviderTelemetryState::Unavailable => ensure!(
                self.input_tokens == 0 && self.output_tokens == 0 && self.cost_microusd == 0,
                "unavailable provider telemetry must not invent usage"
            ),
        }
        match self.state {
            ProviderWorkState::Succeeded => ensure!(
                self.reason.is_none()
                    && self.normalized_reply_count > 0
                    && !self.receipt_ids.is_empty(),
                "successful provider work needs a normalized reply, receipts and no failure reason"
            ),
            ProviderWorkState::Planned => ensure!(
                self.reason.is_none()
                    && self.normalized_reply_count == 0
                    && self.tool_call_count == 0
                    && self.candidate_count == 0,
                "planned provider work cannot contain execution output"
            ),
            ProviderWorkState::Running => ensure!(
                self.reason.is_none(),
                "running provider work cannot carry a terminal reason"
            ),
            _ => self
                .reason
                .as_ref()
                .context("non-successful provider work requires a reason")?
                .validate()?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLineage {
    pub artifact: ArtifactRef,
    pub stage_id: StageId,
    pub attempt: u32,
    pub parent_artifact_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
}

impl ArtifactLineage {
    fn validate(&self, config: &EngagementConfig) -> Result<()> {
        self.artifact.validate()?;
        ensure!(
            config.stage(&self.stage_id).is_some() && self.attempt > 0,
            "artifact lineage references invalid stage attempt"
        );
        validate_sorted_stable_ids("parent artifact", &self.parent_artifact_ids)?;
        validate_receipt_ids(&self.receipt_ids)?;
        ensure!(
            !self.parent_artifact_ids.contains(&self.artifact.id),
            "artifact cannot derive from itself"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageCoverage {
    pub stage_id: StageId,
    pub kind: StageKind,
    pub execution_state: StageExecutionState,
    pub coverage_state: CoverageState,
    pub reasons: Vec<CoverageReason>,
    pub usage: LimitUsage,
    pub artifact_ids: Vec<String>,
    pub provider_work_ids: Vec<String>,
}

impl StageCoverage {
    fn validate(
        &self,
        spec: &StageSpec,
        record: &StageRecord,
        artifacts: &BTreeMap<&str, &ArtifactLineage>,
        provider_work: &BTreeMap<&str, &ProviderWork>,
        overrides: &ExpertOverrides,
    ) -> Result<()> {
        ensure!(
            self.stage_id == spec.id
                && self.kind == spec.kind
                && self.execution_state == record.execution_state
                && self.coverage_state == record.coverage_state,
            "coverage stage contradicts execution snapshot"
        );
        ensure!(
            self.reasons == record.coverage_reasons,
            "coverage reasons contradict the durable stage record"
        );
        validate_execution_coverage(self.execution_state, self.coverage_state)?;
        self.usage.validate(&spec.budget, overrides)?;
        ensure!(
            self.usage == record.usage,
            "coverage usage contradicts execution snapshot"
        );
        for reason in &self.reasons {
            reason.validate()?;
        }
        if matches!(
            self.coverage_state,
            CoverageState::Partial | CoverageState::Omitted | CoverageState::Indeterminate
        ) {
            ensure!(
                !self.reasons.is_empty(),
                "non-complete terminal coverage requires a typed reason"
            );
        } else {
            ensure!(
                self.reasons.is_empty(),
                "complete or active coverage cannot carry omission reasons"
            );
        }
        validate_sorted_stable_ids("stage artifact", &self.artifact_ids)?;
        validate_sorted_stable_ids("provider work", &self.provider_work_ids)?;
        ensure!(
            self.artifact_ids
                .iter()
                .zip(&record.artifacts)
                .all(|(id, artifact)| id == &artifact.id
                    && artifacts
                        .get(id.as_str())
                        .is_some_and(|lineage| lineage.artifact == *artifact)),
            "coverage artifacts contradict execution or lineage"
        );
        ensure!(
            self.artifact_ids.len() == record.artifacts.len(),
            "coverage omits execution artifacts"
        );
        let mut provider_tokens = 0_u64;
        let mut provider_cost = 0_u64;
        for id in &self.provider_work_ids {
            let work = provider_work
                .get(id.as_str())
                .context("coverage references missing provider work")?;
            ensure!(
                work.stage_id == self.stage_id,
                "coverage references provider work from another stage"
            );
            provider_tokens = provider_tokens
                .checked_add(work.input_tokens)
                .and_then(|value| value.checked_add(work.output_tokens))
                .context("provider token usage overflow")?;
            provider_cost = provider_cost
                .checked_add(work.cost_microusd)
                .context("provider cost usage overflow")?;
            if work.state != ProviderWorkState::Succeeded {
                ensure!(
                    self.coverage_state != CoverageState::Complete
                        && work
                            .reason
                            .as_ref()
                            .is_some_and(|reason| self.reasons.contains(reason)),
                    "incomplete provider work must reduce stage coverage with the same typed reason"
                );
            }
            if work.normalized_reply_count == 0
                && !matches!(
                    work.state,
                    ProviderWorkState::Planned | ProviderWorkState::Running
                )
            {
                ensure!(
                    self.coverage_state != CoverageState::Complete
                        && self.reasons.contains(&CoverageReason::ProviderNoReply {
                            work_id: work.id.clone(),
                        }),
                    "provider zero-work must be explicit and reduce coverage"
                );
            }
            if work.telemetry_state != ProviderTelemetryState::Complete
                && work.state == ProviderWorkState::Succeeded
            {
                ensure!(
                    self.coverage_state != CoverageState::Complete
                        && self
                            .reasons
                            .contains(&CoverageReason::ProviderTelemetryUnavailable {
                                work_id: work.id.clone(),
                            },),
                    "successful provider work without complete telemetry must reduce coverage"
                );
            }
        }
        if let StageConfig::Provider {
            requested_sessions, ..
        } = &spec.config
        {
            ensure!(
                self.provider_work_ids.len() == usize::try_from(*requested_sessions)?,
                "provider coverage must account for every requested session"
            );
        }
        ensure!(
            provider_tokens == self.usage.model_tokens && provider_cost == self.usage.cost_microusd,
            "provider work totals contradict stage usage"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub total_stages: u32,
    pub complete: u32,
    pub partial: u32,
    pub omitted: u32,
    pub indeterminate: u32,
    pub running: u32,
    pub not_started: u32,
    pub provider_work_items: u32,
    pub artifacts: u32,
    pub usage: LimitUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageManifest {
    pub schema_version: u32,
    pub engagement_id: String,
    pub config_fingerprint: String,
    pub snapshot_sequence: u64,
    pub generated_ms: u64,
    pub execution_state: EngagementExecutionState,
    pub stages: Vec<StageCoverage>,
    pub provider_work: Vec<ProviderWork>,
    pub artifact_lineage: Vec<ArtifactLineage>,
    pub summary: CoverageSummary,
}

impl CoverageManifest {
    pub fn validate(&self, config: &EngagementConfig, snapshot: &EngagementSnapshot) -> Result<()> {
        snapshot.validate(config)?;
        ensure!(
            self.schema_version == ENGAGEMENT_SCHEMA_VERSION
                && self.engagement_id == config.engagement_id
                && self.config_fingerprint == snapshot.config_fingerprint
                && self.snapshot_sequence == snapshot.sequence
                && self.execution_state == snapshot.execution_state,
            "coverage manifest is not bound to its engagement snapshot"
        );
        ensure!(
            crate::is_canonical_sha256(&self.config_fingerprint),
            "coverage config fingerprint must be canonical SHA-256"
        );
        ensure!(
            self.stages.len() == config.stages.len()
                && self
                    .stages
                    .iter()
                    .map(|coverage| &coverage.stage_id)
                    .eq(config.stages.iter().map(|spec| &spec.id)),
            "coverage must contain exactly one ordered entry per stage"
        );

        let mut work_by_id = BTreeMap::new();
        let mut provider_receipt_owner = BTreeMap::new();
        ensure!(
            self.provider_work
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
            "provider work must be sorted by unique id"
        );
        for work in &self.provider_work {
            work.validate(config)?;
            let stage_record = snapshot
                .stages
                .iter()
                .find(|record| record.stage_id == work.stage_id)
                .context("provider work stage is missing from snapshot")?;
            ensure!(
                work.receipt_ids.iter().all(|receipt_id| {
                    stage_record
                        .attempts
                        .iter()
                        .any(|attempt| attempt.receipt_ids.contains(receipt_id))
                }),
                "provider work references a receipt outside its stage attempts"
            );
            for receipt_id in &work.receipt_ids {
                ensure!(
                    provider_receipt_owner
                        .insert(receipt_id.as_str(), work.id.as_str())
                        .is_none(),
                    "one provider receipt cannot prove multiple requested work items"
                );
            }
            ensure!(
                work_by_id.insert(work.id.as_str(), work).is_none(),
                "duplicate provider work id"
            );
        }
        let mut lineage_by_id = BTreeMap::new();
        ensure!(
            self.artifact_lineage
                .windows(2)
                .all(|pair| pair[0].artifact.id < pair[1].artifact.id),
            "artifact lineage must be sorted by unique artifact id"
        );
        for lineage in &self.artifact_lineage {
            lineage.validate(config)?;
            ensure!(
                lineage_by_id
                    .insert(lineage.artifact.id.as_str(), lineage)
                    .is_none(),
                "duplicate artifact lineage id"
            );
        }
        for lineage in &self.artifact_lineage {
            ensure!(
                lineage
                    .parent_artifact_ids
                    .iter()
                    .all(|id| lineage_by_id.contains_key(id.as_str())),
                "artifact lineage references missing parent"
            );
            for parent_id in &lineage.parent_artifact_ids {
                let parent = lineage_by_id[parent_id.as_str()];
                ensure!(
                    (parent.stage_id == lineage.stage_id && parent.attempt < lineage.attempt)
                        || dependency_reachable(
                            &lineage.stage_id,
                            &parent.stage_id,
                            &config.stages,
                        ),
                    "artifact parent must come from an earlier attempt of the same stage or a transitive dependency"
                );
            }
        }
        validate_lineage_acyclic(&self.artifact_lineage)?;
        let mut referenced_artifacts = BTreeSet::new();
        let mut referenced_work = BTreeSet::new();
        let effective_overrides = snapshot
            .override_history
            .last()
            .map(|entry| &entry.overrides)
            .unwrap_or(&config.overrides);
        for ((coverage, spec), record) in
            self.stages.iter().zip(&config.stages).zip(&snapshot.stages)
        {
            coverage.validate(
                spec,
                record,
                &lineage_by_id,
                &work_by_id,
                effective_overrides,
            )?;
            referenced_artifacts.extend(coverage.artifact_ids.iter().map(String::as_str));
            referenced_work.extend(coverage.provider_work_ids.iter().map(String::as_str));
        }
        ensure!(
            referenced_artifacts.len() == lineage_by_id.len()
                && referenced_artifacts
                    .iter()
                    .all(|id| lineage_by_id.contains_key(id)),
            "coverage manifest contains orphaned artifact lineage"
        );
        ensure!(
            referenced_work.len() == work_by_id.len()
                && referenced_work.iter().all(|id| work_by_id.contains_key(id)),
            "coverage manifest contains orphaned provider work"
        );
        for lineage in &self.artifact_lineage {
            let record = snapshot
                .stages
                .iter()
                .find(|record| record.stage_id == lineage.stage_id)
                .context("artifact lineage stage is missing from snapshot")?;
            let attempt_index = usize::try_from(lineage.attempt - 1)?;
            let attempt = record
                .attempts
                .get(attempt_index)
                .context("artifact lineage attempt is missing")?;
            ensure!(
                attempt.artifacts.contains(&lineage.artifact)
                    && lineage
                        .receipt_ids
                        .iter()
                        .all(|receipt_id| attempt.receipt_ids.contains(receipt_id)),
                "artifact lineage does not match its producing attempt and receipts"
            );
        }
        self.validate_summary()?;
        ensure!(
            self.summary.usage == snapshot.usage,
            "coverage usage contradicts the engagement ledger"
        );
        self.summary
            .usage
            .validate_global(&config.budgets, effective_overrides)
    }

    fn validate_summary(&self) -> Result<()> {
        let mut expected = CoverageSummary {
            total_stages: u32::try_from(self.stages.len())?,
            complete: 0,
            partial: 0,
            omitted: 0,
            indeterminate: 0,
            running: 0,
            not_started: 0,
            provider_work_items: u32::try_from(self.provider_work.len())?,
            artifacts: u32::try_from(self.artifact_lineage.len())?,
            usage: LimitUsage::default(),
        };
        for stage in &self.stages {
            match stage.coverage_state {
                CoverageState::Complete => expected.complete += 1,
                CoverageState::Partial => expected.partial += 1,
                CoverageState::Omitted => expected.omitted += 1,
                CoverageState::Indeterminate => expected.indeterminate += 1,
                CoverageState::Running => expected.running += 1,
                CoverageState::NotStarted => expected.not_started += 1,
            }
            checked_accumulate_usage(&mut expected.usage, &stage.usage)?;
        }
        ensure!(self.summary == expected, "coverage summary is inconsistent");
        Ok(())
    }
}

fn validate_execution_coverage(
    execution: StageExecutionState,
    coverage: CoverageState,
) -> Result<()> {
    let valid = match execution {
        StageExecutionState::Planned | StageExecutionState::Ready => {
            coverage == CoverageState::NotStarted
        }
        StageExecutionState::Running => coverage == CoverageState::Running,
        StageExecutionState::Succeeded => {
            matches!(coverage, CoverageState::Complete | CoverageState::Partial)
        }
        StageExecutionState::Failed => {
            matches!(
                coverage,
                CoverageState::Partial | CoverageState::Indeterminate
            )
        }
        StageExecutionState::Skipped | StageExecutionState::Blocked => {
            coverage == CoverageState::Omitted
        }
        StageExecutionState::Cancelled => {
            matches!(coverage, CoverageState::Partial | CoverageState::Omitted)
        }
        StageExecutionState::Indeterminate => coverage == CoverageState::Indeterminate,
    };
    ensure!(valid, "execution and coverage states contradict each other");
    Ok(())
}

fn validate_stable_id(label: &str, value: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            }),
        "{label} id must be a stable lower-case identifier"
    );
    Ok(())
}

fn validate_sorted_stable_ids(label: &str, values: &[String]) -> Result<()> {
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "{label} ids must be sorted and unique"
    );
    for value in values {
        validate_stable_id(label, value)?;
    }
    Ok(())
}

fn validate_sorted_stage_ids(label: &str, values: &[StageId]) -> Result<()> {
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "{label} must be sorted and unique"
    );
    for value in values {
        value.validate()?;
    }
    Ok(())
}

fn validate_http_url(label: &str, value: &str) -> Result<()> {
    let parsed = url::Url::parse(value).with_context(|| format!("invalid {label} URL"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https")
            && parsed.as_str() == value
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.fragment().is_none(),
        "{label} must be canonical credential-free HTTP(S) without a fragment"
    );
    Ok(())
}

fn validate_relative_artifact_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        !value.is_empty()
            && !value.contains('\\')
            && !path.is_absolute()
            && path.components().all(|component| {
                matches!(component, Component::Normal(segment) if !segment.is_empty())
            }),
        "artifact path must be a normalized relative path"
    );
    Ok(())
}

fn validate_receipt_ids(values: &[String]) -> Result<()> {
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1])
            && values
                .iter()
                .all(|value| !value.trim().is_empty() && value.len() <= 256),
        "receipt ids must be sorted, unique and bounded"
    );
    Ok(())
}

fn validate_artifact_set(values: &[ArtifactRef]) -> Result<()> {
    ensure!(
        values.windows(2).all(|pair| pair[0].id < pair[1].id),
        "artifacts must be sorted by unique id"
    );
    for value in values {
        value.validate()?;
    }
    Ok(())
}

fn checked_accumulate(total: &mut StageBudgetCaps, value: &StageBudgetCaps) -> Result<()> {
    total.max_requests = total
        .max_requests
        .checked_add(value.max_requests)
        .context("request allocation overflow")?;
    total.max_state_changes = total
        .max_state_changes
        .checked_add(value.max_state_changes)
        .context("state-change allocation overflow")?;
    total.max_accounts = total
        .max_accounts
        .checked_add(value.max_accounts)
        .context("account allocation overflow")?;
    total.max_model_tokens = total
        .max_model_tokens
        .checked_add(value.max_model_tokens)
        .context("model-token allocation overflow")?;
    total.max_cost_microusd = total
        .max_cost_microusd
        .checked_add(value.max_cost_microusd)
        .context("cost allocation overflow")?;
    total.max_duration_ms = total
        .max_duration_ms
        .checked_add(value.max_duration_ms)
        .context("duration allocation overflow")?;
    total.max_artifact_bytes = total
        .max_artifact_bytes
        .checked_add(value.max_artifact_bytes)
        .context("artifact allocation overflow")?;
    total.max_concurrency = total.max_concurrency.max(value.max_concurrency);
    Ok(())
}

fn checked_accumulate_usage(total: &mut LimitUsage, value: &LimitUsage) -> Result<()> {
    total.requests = total
        .requests
        .checked_add(value.requests)
        .context("request usage overflow")?;
    total.state_changes = total
        .state_changes
        .checked_add(value.state_changes)
        .context("state-change usage overflow")?;
    total.accounts = total
        .accounts
        .checked_add(value.accounts)
        .context("account usage overflow")?;
    total.model_tokens = total
        .model_tokens
        .checked_add(value.model_tokens)
        .context("model-token usage overflow")?;
    total.cost_microusd = total
        .cost_microusd
        .checked_add(value.cost_microusd)
        .context("cost usage overflow")?;
    total.duration_ms = total
        .duration_ms
        .checked_add(value.duration_ms)
        .context("duration usage overflow")?;
    total.artifact_bytes = total
        .artifact_bytes
        .checked_add(value.artifact_bytes)
        .context("artifact usage overflow")?;
    total.peak_concurrency = total.peak_concurrency.max(value.peak_concurrency);
    Ok(())
}

fn validate_acyclic(stages: &[StageSpec]) -> Result<()> {
    fn visit<'a>(
        id: &'a StageId,
        by_id: &BTreeMap<&'a StageId, &'a StageSpec>,
        visiting: &mut BTreeSet<&'a StageId>,
        visited: &mut BTreeSet<&'a StageId>,
    ) -> Result<()> {
        if visited.contains(id) {
            return Ok(());
        }
        ensure!(
            visiting.insert(id),
            "engagement stage graph contains a cycle"
        );
        for dependency in &by_id[id].depends_on {
            visit(dependency, by_id, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id);
        Ok(())
    }

    let by_id: BTreeMap<_, _> = stages.iter().map(|stage| (&stage.id, stage)).collect();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in by_id.keys() {
        visit(id, &by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn dependency_reachable(from: &StageId, wanted: &StageId, stages: &[StageSpec]) -> bool {
    let by_id: BTreeMap<_, _> = stages.iter().map(|stage| (&stage.id, stage)).collect();
    let mut pending = vec![from];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        for dependency in &by_id[current].depends_on {
            if dependency == wanted {
                return true;
            }
            pending.push(dependency);
        }
    }
    false
}

fn validate_lineage_acyclic(lineage: &[ArtifactLineage]) -> Result<()> {
    fn visit<'a>(
        id: &'a str,
        by_id: &BTreeMap<&'a str, &'a ArtifactLineage>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<()> {
        if visited.contains(id) {
            return Ok(());
        }
        ensure!(visiting.insert(id), "artifact lineage contains a cycle");
        for parent in &by_id[id].parent_artifact_ids {
            visit(parent, by_id, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id);
        Ok(())
    }

    let by_id: BTreeMap<_, _> = lineage
        .iter()
        .map(|entry| (entry.artifact.id.as_str(), entry))
        .collect();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in by_id.keys() {
        visit(id, &by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(id: &str) -> ArtifactRef {
        ArtifactRef {
            id: id.into(),
            kind: ArtifactKind::Plan,
            path: format!("plans/{id}.json"),
            sha256: "a".repeat(64),
            size_bytes: 100,
            media_type: "application/json".into(),
        }
    }

    fn budget(requests: u64, tokens: u64) -> StageBudgetCaps {
        StageBudgetCaps {
            max_requests: requests,
            max_state_changes: 0,
            max_accounts: 0,
            max_model_tokens: tokens,
            max_cost_microusd: tokens,
            max_duration_ms: 1_000,
            max_artifact_bytes: 10_000,
            max_concurrency: 1,
        }
    }

    fn audited_overrides(controls: Vec<Control>) -> ExpertOverrides {
        ExpertOverrides {
            controls,
            reason: "audited fixture budget bypass".into(),
            actor: "fixture-operator".into(),
            acknowledged: true,
            timestamp_ms: 1,
            ..ExpertOverrides::default()
        }
    }

    fn valid_config() -> EngagementConfig {
        EngagementConfig {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: "mixed-assessment".into(),
            output_dir: PathBuf::from("runs/mixed-assessment"),
            scope: Scope::default(),
            authorized: true,
            overrides: ExpertOverrides::default(),
            targets: vec![
                TypedTarget::Provider {
                    id: "provider-main".into(),
                    provider_id: "openai".into(),
                },
                TypedTarget::Web {
                    id: "web-main".into(),
                    url: "https://example.test/".into(),
                },
            ],
            budgets: EngagementBudgets {
                max_requests: 20,
                max_state_changes: 0,
                max_accounts: 0,
                max_model_tokens: 1_000,
                max_cost_microusd: 1_000,
                max_duration_ms: 10_000,
                max_artifact_bytes: 100_000,
                max_concurrency: 2,
            },
            stages: vec![
                StageSpec {
                    id: StageId("provider-openai".into()),
                    kind: StageKind::Provider,
                    target_ids: vec!["provider-main".into()],
                    depends_on: vec![],
                    dependency_policy: DependencyPolicy::AllSucceeded,
                    required: false,
                    budget: budget(0, 1_000),
                    config: StageConfig::Provider {
                        provider_id: "openai".into(),
                        deployment: "gpt-fixture".into(),
                        request: artifact("provider-request"),
                        requested_sessions: 1,
                    },
                },
                StageSpec {
                    id: StageId("report-final".into()),
                    kind: StageKind::Reporting,
                    target_ids: vec![],
                    depends_on: vec![
                        StageId("provider-openai".into()),
                        StageId("web-discovery".into()),
                    ],
                    dependency_policy: DependencyPolicy::AllTerminal,
                    required: true,
                    budget: budget(0, 0),
                    config: StageConfig::Reporting {
                        formats: vec![ReportFormat::Json, ReportFormat::Sarif],
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
                    budget: budget(20, 0),
                    config: StageConfig::Web {
                        plan: artifact("web-plan"),
                        authenticated: false,
                    },
                },
            ],
        }
    }

    fn valid_chain_cleanup_config() -> EngagementConfig {
        let mut config = valid_config();
        config.targets.insert(
            0,
            TypedTarget::Chain {
                id: "chain-main".into(),
                chain_id: "validated-chain".into(),
            },
        );
        config.stages.insert(
            0,
            StageSpec {
                id: StageId("chain-execute".into()),
                kind: StageKind::Chains,
                target_ids: vec!["chain-main".into()],
                depends_on: vec![],
                dependency_policy: DependencyPolicy::AllSucceeded,
                required: true,
                budget: budget(0, 0),
                config: StageConfig::Chains {
                    chain_id: "validated-chain".into(),
                    templates: artifact("chain-templates"),
                    cleanup_required: true,
                },
            },
        );
        config.stages.insert(
            1,
            StageSpec {
                id: StageId("cleanup-chains".into()),
                kind: StageKind::Cleanup,
                target_ids: vec![],
                depends_on: vec![StageId("chain-execute".into())],
                dependency_policy: DependencyPolicy::AllTerminal,
                required: true,
                budget: budget(0, 0),
                config: StageConfig::Cleanup {
                    stage_ids: vec![StageId("chain-execute".into())],
                },
            },
        );
        config.stages[3]
            .depends_on
            .insert(0, StageId("cleanup-chains".into()));
        config
    }

    fn output_artifact(id: &str, kind: ArtifactKind) -> ArtifactRef {
        ArtifactRef {
            id: id.into(),
            kind,
            path: format!("artifacts/{id}.json"),
            sha256: "b".repeat(64),
            size_bytes: 100,
            media_type: "application/json".into(),
        }
    }

    fn successful_record(
        stage_id: &str,
        receipt_id: &str,
        artifact: ArtifactRef,
        usage: LimitUsage,
    ) -> StageRecord {
        StageRecord {
            stage_id: StageId(stage_id.into()),
            execution_state: StageExecutionState::Succeeded,
            coverage_state: CoverageState::Complete,
            coverage_reasons: vec![],
            attempts: vec![StageAttempt {
                attempt: 1,
                state: StageExecutionState::Succeeded,
                started_ms: 10,
                finished_ms: Some(20),
                usage: usage.clone(),
                receipt_ids: vec![receipt_id.into()],
                artifacts: vec![artifact.clone()],
                reason: None,
            }],
            usage,
            artifacts: vec![artifact],
            reason: None,
        }
    }

    fn valid_snapshot(config: &EngagementConfig) -> EngagementSnapshot {
        let provider_artifact = output_artifact("provider-output", ArtifactKind::Observation);
        let report_artifact = output_artifact("report-output", ArtifactKind::Report);
        let mut sarif_artifact = output_artifact("report-sarif", ArtifactKind::Report);
        sarif_artifact.media_type = "application/sarif+json".into();
        let web_artifact = output_artifact("web-output", ArtifactKind::Observation);
        let mut report_record = successful_record(
            "report-final",
            "receipt-report",
            report_artifact,
            LimitUsage {
                duration_ms: 100,
                artifact_bytes: 200,
                peak_concurrency: 1,
                ..LimitUsage::default()
            },
        );
        report_record.attempts[0]
            .artifacts
            .push(sarif_artifact.clone());
        report_record.artifacts.push(sarif_artifact);
        EngagementSnapshot {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: config.engagement_id.clone(),
            config_fingerprint: "c".repeat(64),
            sequence: 4,
            created_ms: 1,
            updated_ms: 30,
            execution_state: EngagementExecutionState::Complete,
            stages: vec![
                successful_record(
                    "provider-openai",
                    "receipt-provider",
                    provider_artifact,
                    LimitUsage {
                        model_tokens: 12,
                        cost_microusd: 10,
                        duration_ms: 100,
                        artifact_bytes: 100,
                        peak_concurrency: 1,
                        ..LimitUsage::default()
                    },
                ),
                report_record,
                successful_record(
                    "web-discovery",
                    "receipt-web",
                    web_artifact,
                    LimitUsage {
                        requests: 1,
                        duration_ms: 100,
                        artifact_bytes: 100,
                        peak_concurrency: 1,
                        ..LimitUsage::default()
                    },
                ),
            ],
            usage: LimitUsage {
                requests: 1,
                model_tokens: 12,
                cost_microusd: 10,
                duration_ms: 300,
                artifact_bytes: 400,
                peak_concurrency: 1,
                ..LimitUsage::default()
            },
            receipt_ids: vec![
                "receipt-provider".into(),
                "receipt-report".into(),
                "receipt-web".into(),
            ],
            override_epoch: 0,
            override_history: vec![],
            coverage_manifest: Some(ArtifactRef {
                id: "coverage-manifest".into(),
                kind: ArtifactKind::CoverageManifest,
                path: "coverage/manifest.json".into(),
                sha256: "d".repeat(64),
                size_bytes: 100,
                media_type: "application/json".into(),
            }),
        }
    }

    fn valid_manifest(
        config: &EngagementConfig,
        snapshot: &EngagementSnapshot,
    ) -> CoverageManifest {
        let provider_work = ProviderWork {
            id: "provider-work".into(),
            stage_id: StageId("provider-openai".into()),
            provider_id: "openai".into(),
            model: "gpt-fixture".into(),
            state: ProviderWorkState::Succeeded,
            started_ms: Some(10),
            finished_ms: Some(20),
            normalized_reply_count: 1,
            tool_call_count: 1,
            candidate_count: 1,
            telemetry_state: ProviderTelemetryState::Complete,
            input_tokens: 5,
            output_tokens: 7,
            cost_microusd: 10,
            receipt_ids: vec!["receipt-provider".into()],
            reason: None,
        };
        let lineage = vec![
            ArtifactLineage {
                artifact: snapshot.stages[0].artifacts[0].clone(),
                stage_id: StageId("provider-openai".into()),
                attempt: 1,
                parent_artifact_ids: vec![],
                receipt_ids: vec!["receipt-provider".into()],
            },
            ArtifactLineage {
                artifact: snapshot.stages[1].artifacts[0].clone(),
                stage_id: StageId("report-final".into()),
                attempt: 1,
                parent_artifact_ids: vec!["provider-output".into(), "web-output".into()],
                receipt_ids: vec!["receipt-report".into()],
            },
            ArtifactLineage {
                artifact: snapshot.stages[1].artifacts[1].clone(),
                stage_id: StageId("report-final".into()),
                attempt: 1,
                parent_artifact_ids: vec!["provider-output".into(), "web-output".into()],
                receipt_ids: vec!["receipt-report".into()],
            },
            ArtifactLineage {
                artifact: snapshot.stages[2].artifacts[0].clone(),
                stage_id: StageId("web-discovery".into()),
                attempt: 1,
                parent_artifact_ids: vec![],
                receipt_ids: vec!["receipt-web".into()],
            },
        ];
        let stages = snapshot
            .stages
            .iter()
            .zip(&config.stages)
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
                provider_work_ids: if spec.kind == StageKind::Provider {
                    vec!["provider-work".into()]
                } else {
                    vec![]
                },
            })
            .collect();
        CoverageManifest {
            schema_version: ENGAGEMENT_SCHEMA_VERSION,
            engagement_id: config.engagement_id.clone(),
            config_fingerprint: snapshot.config_fingerprint.clone(),
            snapshot_sequence: snapshot.sequence,
            generated_ms: 40,
            execution_state: snapshot.execution_state,
            stages,
            provider_work: vec![provider_work],
            artifact_lineage: lineage,
            summary: CoverageSummary {
                total_stages: 3,
                complete: 3,
                partial: 0,
                omitted: 0,
                indeterminate: 0,
                running: 0,
                not_started: 0,
                provider_work_items: 1,
                artifacts: 4,
                usage: LimitUsage {
                    requests: 1,
                    model_tokens: 12,
                    cost_microusd: 10,
                    duration_ms: 300,
                    artifact_bytes: 400,
                    peak_concurrency: 1,
                    ..LimitUsage::default()
                },
            },
        }
    }

    #[test]
    fn valid_mixed_stage_fixture_and_fingerprint_are_stable() -> Result<()> {
        let config = valid_config();
        config.validate()?;
        let first = config.canonical_fingerprint_input()?;
        let decoded: EngagementConfig = serde_json::from_slice(&first)?;
        let second = decoded.canonical_fingerprint_input()?;
        assert_eq!(first, second);
        assert_eq!(config, decoded);
        Ok(())
    }

    #[test]
    fn strict_contracts_reject_unknown_fields() -> Result<()> {
        let mut value = serde_json::to_value(valid_config())?;
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EngagementConfig>(value).is_err());

        let mut stage = serde_json::to_value(&valid_config().stages[2])?;
        stage["config"]["arbitrary"] = serde_json::json!("not allowed");
        assert!(serde_json::from_value::<StageSpec>(stage).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_and_cyclic_stages_are_rejected() {
        let mut duplicate = valid_config();
        duplicate.stages.insert(1, duplicate.stages[0].clone());
        assert!(duplicate.validate().is_err());

        let mut cyclic = valid_config();
        cyclic.stages[0].depends_on = vec![StageId("web-discovery".into())];
        cyclic.stages[2].depends_on = vec![StageId("provider-openai".into())];
        assert!(cyclic.validate().is_err());
    }

    #[test]
    fn budget_overallocation_is_rejected() {
        let mut config = valid_config();
        config.stages[1].budget.max_requests = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn operational_limit_overrides_map_to_exact_usage_dimensions() -> Result<()> {
        let cap = StageBudgetCaps {
            max_requests: 1,
            max_state_changes: 1,
            max_accounts: 1,
            max_model_tokens: 1,
            max_cost_microusd: 1,
            max_duration_ms: 1,
            max_artifact_bytes: 1,
            max_concurrency: 1,
        };
        let global = EngagementBudgets {
            max_requests: 1,
            max_state_changes: 1,
            max_accounts: 1,
            max_model_tokens: 1,
            max_cost_microusd: 1,
            max_duration_ms: 1,
            max_artifact_bytes: 1,
            max_concurrency: 1,
        };
        let cases = [
            (
                LimitUsage {
                    requests: 2,
                    model_tokens: 2,
                    cost_microusd: 2,
                    ..LimitUsage::default()
                },
                Control::RequestBudget,
            ),
            (
                LimitUsage {
                    state_changes: 2,
                    ..LimitUsage::default()
                },
                Control::StateChanges,
            ),
            (
                LimitUsage {
                    accounts: 2,
                    ..LimitUsage::default()
                },
                Control::AccountBudget,
            ),
            (
                LimitUsage {
                    duration_ms: 2,
                    ..LimitUsage::default()
                },
                Control::Timeouts,
            ),
            (
                LimitUsage {
                    artifact_bytes: 2,
                    ..LimitUsage::default()
                },
                Control::DataSampling,
            ),
            (
                LimitUsage {
                    peak_concurrency: 2,
                    ..LimitUsage::default()
                },
                Control::Concurrency,
            ),
        ];
        for (usage, control) in cases {
            assert!(usage.validate(&cap, &ExpertOverrides::default()).is_err());
            assert!(usage
                .validate_global(&global, &ExpertOverrides::default())
                .is_err());
            let overrides = audited_overrides(vec![control]);
            usage.validate(&cap, &overrides)?;
            usage.validate_global(&global, &overrides)?;
        }

        let unsafe_overrides = ExpertOverrides {
            unsafe_all: true,
            reason: "audited fixture unsafe bypass".into(),
            actor: "fixture-operator".into(),
            acknowledged: true,
            timestamp_ms: 1,
            ..ExpertOverrides::default()
        };
        let all_over = LimitUsage {
            requests: 2,
            state_changes: 2,
            accounts: 2,
            model_tokens: 2,
            cost_microusd: 2,
            duration_ms: 2,
            artifact_bytes: 2,
            peak_concurrency: 2,
        };
        all_over.validate(&cap, &unsafe_overrides)?;
        all_over.validate_global(&global, &unsafe_overrides)
    }

    #[test]
    fn allocation_overages_require_explicit_or_unsafe_bypass() -> Result<()> {
        let mut explicit = valid_config();
        explicit.stages[0].budget.max_model_tokens = 1_001;
        explicit.stages[0].budget.max_cost_microusd = 1_001;
        explicit.stages[2].budget.max_requests = 21;
        assert!(explicit.validate().is_err());
        explicit.overrides = audited_overrides(vec![Control::RequestBudget]);
        explicit.validate()?;

        let mut unsafe_config = valid_config();
        unsafe_config.stages[0].budget = StageBudgetCaps {
            max_requests: 21,
            max_state_changes: 1,
            max_accounts: 1,
            max_model_tokens: 1_001,
            max_cost_microusd: 1_001,
            max_duration_ms: 10_001,
            max_artifact_bytes: 100_001,
            max_concurrency: 3,
        };
        assert!(unsafe_config.validate().is_err());
        unsafe_config.overrides = ExpertOverrides {
            unsafe_all: true,
            reason: "audited fixture unsafe bypass".into(),
            actor: "fixture-operator".into(),
            acknowledged: true,
            timestamp_ms: 1,
            ..ExpertOverrides::default()
        };
        unsafe_config.validate()
    }

    #[test]
    fn snapshot_overage_bypass_preserves_exact_usage_aggregation() -> Result<()> {
        let mut config = valid_config();
        let mut snapshot = valid_snapshot(&config);
        snapshot.stages[0].attempts[0].usage.model_tokens = 1_001;
        snapshot.stages[0].attempts[0].usage.cost_microusd = 1_001;
        snapshot.stages[0].usage.model_tokens = 1_001;
        snapshot.stages[0].usage.cost_microusd = 1_001;
        snapshot.stages[2].attempts[0].usage.requests = 21;
        snapshot.stages[2].usage.requests = 21;
        snapshot.usage.requests = 21;
        snapshot.usage.model_tokens = 1_001;
        snapshot.usage.cost_microusd = 1_001;
        assert!(snapshot.validate(&config).is_err());

        config.overrides = audited_overrides(vec![Control::RequestBudget]);
        snapshot.override_epoch = 1;
        snapshot.override_history = vec![OverrideEpoch {
            epoch: 1,
            recorded_ms: 1,
            overrides: config.overrides.clone(),
        }];
        snapshot.validate(&config)?;

        snapshot.usage.requests += 1;
        assert!(snapshot.validate(&config).is_err());
        Ok(())
    }

    #[test]
    fn incompatible_target_config_and_missing_finalizer_are_rejected() {
        let mut config = valid_config();
        config.stages[2].target_ids = vec!["provider-main".into()];
        assert!(config.validate().is_err());

        let mut config = valid_config();
        if let StageConfig::Provider { provider_id, .. } = &mut config.stages[0].config {
            *provider_id = "anthropic".into();
        }
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.stages[1].config = StageConfig::Reporting {
            formats: vec![ReportFormat::Json],
            finalizer: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn execution_and_coverage_state_contradictions_are_rejected() -> Result<()> {
        assert!(
            validate_execution_coverage(StageExecutionState::Skipped, CoverageState::Complete)
                .is_err()
        );
        assert!(validate_execution_coverage(
            StageExecutionState::Succeeded,
            CoverageState::Omitted
        )
        .is_err());
        validate_execution_coverage(
            StageExecutionState::Indeterminate,
            CoverageState::Indeterminate,
        )?;
        Ok(())
    }

    #[test]
    fn artifact_hash_and_path_are_fail_closed() {
        let mut value = artifact("evidence");
        value.path = "../evidence.json".into();
        assert!(value.validate().is_err());
        value.path = "evidence.json".into();
        value.sha256 = "A".repeat(64);
        assert!(value.validate().is_err());
    }

    #[test]
    fn snapshot_and_coverage_manifest_enforce_truthful_aggregates() -> Result<()> {
        let config = valid_config();
        let snapshot = valid_snapshot(&config);
        snapshot.validate(&config)?;
        let manifest = valid_manifest(&config, &snapshot);
        manifest.validate(&config, &snapshot)?;

        let mut invalid_summary = manifest.clone();
        invalid_summary.summary.complete -= 1;
        assert!(invalid_summary.validate(&config, &snapshot).is_err());

        let mut orphaned_work = manifest.clone();
        orphaned_work.provider_work[0].id = "unreported-work".into();
        assert!(orphaned_work.validate(&config, &snapshot).is_err());

        let mut cross_stage_provider_receipt = manifest.clone();
        cross_stage_provider_receipt.provider_work[0].receipt_ids = vec!["receipt-web".into()];
        assert!(cross_stage_provider_receipt
            .validate(&config, &snapshot)
            .is_err());

        let mut cross_attempt_lineage = manifest.clone();
        cross_attempt_lineage.artifact_lineage[2].receipt_ids = vec!["receipt-provider".into()];
        assert!(cross_attempt_lineage.validate(&config, &snapshot).is_err());

        let mut invalid_snapshot = snapshot;
        invalid_snapshot.stages[2].coverage_state = CoverageState::Omitted;
        assert!(invalid_snapshot.validate(&config).is_err());
        Ok(())
    }

    #[test]
    fn active_stages_bind_authorization_and_central_scope_budgets() -> Result<()> {
        let mut config = valid_config();
        config.authorized = false;
        assert!(config.validate().is_err());

        config.overrides = ExpertOverrides {
            controls: vec![Control::Authorization],
            reason: "authorized fixture bypass".into(),
            actor: "fixture-operator".into(),
            acknowledged: true,
            ..ExpertOverrides::default()
        };
        config.validate()?;

        config.scope.max_requests = 1;
        assert!(config.validate().is_err());
        config.overrides.controls.push(Control::RequestBudget);
        config.validate()?;
        Ok(())
    }

    #[test]
    fn reporting_finalizer_is_always_run_after_terminal_dependencies() {
        let mut config = valid_config();
        config.stages[1].dependency_policy = DependencyPolicy::AllSucceeded;
        assert!(config.validate().is_err());
    }

    #[test]
    fn cleanup_is_all_terminal_and_covers_stateful_chains() -> Result<()> {
        let config = valid_chain_cleanup_config();
        config.validate()?;

        let mut all_succeeded = config.clone();
        all_succeeded.stages[1].dependency_policy = DependencyPolicy::AllSucceeded;
        assert!(all_succeeded.validate().is_err());

        let mut missing_cleanup = config;
        missing_cleanup.stages.remove(1);
        missing_cleanup.stages[2].depends_on[0] = StageId("chain-execute".into());
        assert!(missing_cleanup.validate().is_err());
        Ok(())
    }

    #[test]
    fn provider_work_matches_configured_provider_and_deployment() -> Result<()> {
        let config = valid_config();
        let snapshot = valid_snapshot(&config);
        let manifest = valid_manifest(&config, &snapshot);
        manifest.validate(&config, &snapshot)?;

        let mut wrong_provider = manifest.clone();
        wrong_provider.provider_work[0].provider_id = "anthropic".into();
        assert!(wrong_provider.validate(&config, &snapshot).is_err());

        let mut wrong_deployment = manifest;
        wrong_deployment.provider_work[0].model = "gpt-other".into();
        assert!(wrong_deployment.validate(&config, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn successful_reporting_exactly_matches_requested_formats() -> Result<()> {
        let config = valid_config();
        let snapshot = valid_snapshot(&config);
        snapshot.validate(&config)?;

        let mut missing = snapshot.clone();
        missing.stages[1].attempts[0].artifacts.pop();
        missing.stages[1].artifacts.pop();
        missing.stages[1].attempts[0].usage.artifact_bytes = 100;
        missing.stages[1].usage.artifact_bytes = 100;
        missing.usage.artifact_bytes = 300;
        assert!(missing.validate(&config).is_err());

        let mut duplicate = snapshot.clone();
        duplicate.stages[1].attempts[0].artifacts[1].media_type = "application/json".into();
        duplicate.stages[1].artifacts[1].media_type = "application/json".into();
        assert!(duplicate.validate(&config).is_err());

        let mut unrequested = snapshot;
        unrequested.stages[1].attempts[0].artifacts[1].media_type = "text/html".into();
        unrequested.stages[1].artifacts[1].media_type = "text/html".into();
        assert!(unrequested.validate(&config).is_err());
        Ok(())
    }

    #[test]
    fn lineage_parents_require_causal_stage_dependencies() -> Result<()> {
        let config = valid_config();
        let snapshot = valid_snapshot(&config);
        let manifest = valid_manifest(&config, &snapshot);
        manifest.validate(&config, &snapshot)?;

        let mut unrelated = manifest.clone();
        unrelated.artifact_lineage[0].parent_artifact_ids = vec!["web-output".into()];
        assert!(unrelated.validate(&config, &snapshot).is_err());

        let mut same_attempt = manifest;
        same_attempt.artifact_lineage[2]
            .parent_artifact_ids
            .insert(1, "report-output".into());
        assert!(same_attempt.validate(&config, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn failed_or_cancelled_zero_work_cannot_claim_partial_coverage() -> Result<()> {
        let config = valid_config();
        let spec = &config.stages[2];
        for state in [StageExecutionState::Failed, StageExecutionState::Cancelled] {
            let reason = CoverageReason::ExecutionError {
                code: "zero-work".into(),
            };
            let mut record = StageRecord {
                stage_id: spec.id.clone(),
                execution_state: state,
                coverage_state: CoverageState::Partial,
                coverage_reasons: vec![reason.clone()],
                attempts: vec![StageAttempt {
                    attempt: 1,
                    state,
                    started_ms: 10,
                    finished_ms: Some(20),
                    usage: LimitUsage::default(),
                    receipt_ids: vec![],
                    artifacts: vec![],
                    reason: Some(reason.clone()),
                }],
                usage: LimitUsage::default(),
                artifacts: vec![],
                reason: Some(reason),
            };
            assert!(record.validate(spec, &ExpertOverrides::default()).is_err());
            record.attempts[0].receipt_ids = vec!["receipt-zero-work".into()];
            record.validate(spec, &ExpertOverrides::default())?;
        }
        Ok(())
    }

    #[test]
    fn provider_zero_work_cannot_be_successful_or_hidden() -> Result<()> {
        let config = valid_config();
        let snapshot = valid_snapshot(&config);
        let mut manifest = valid_manifest(&config, &snapshot);
        manifest.provider_work[0].normalized_reply_count = 0;
        assert!(manifest.validate(&config, &snapshot).is_err());
        manifest.provider_work[0].normalized_reply_count = 1;

        let mut snapshot = snapshot;
        let unavailable = CoverageReason::CredentialUnavailable {
            credential: "openai-login".into(),
        };
        snapshot.stages[0] = StageRecord {
            stage_id: StageId("provider-openai".into()),
            execution_state: StageExecutionState::Skipped,
            coverage_state: CoverageState::Omitted,
            coverage_reasons: vec![
                unavailable.clone(),
                CoverageReason::ProviderNoReply {
                    work_id: "provider-work".into(),
                },
            ],
            attempts: vec![StageAttempt {
                attempt: 1,
                state: StageExecutionState::Skipped,
                started_ms: 10,
                finished_ms: Some(10),
                usage: LimitUsage::default(),
                receipt_ids: vec![],
                artifacts: vec![],
                reason: Some(unavailable.clone()),
            }],
            usage: LimitUsage::default(),
            artifacts: vec![],
            reason: Some(unavailable.clone()),
        };
        snapshot.usage.model_tokens = 0;
        snapshot.usage.cost_microusd = 0;
        snapshot.usage.duration_ms = 200;
        snapshot.usage.artifact_bytes = 300;
        snapshot.receipt_ids = vec!["receipt-report".into(), "receipt-web".into()];
        snapshot.validate(&config)?;

        manifest.provider_work[0] = ProviderWork {
            id: "provider-work".into(),
            stage_id: StageId("provider-openai".into()),
            provider_id: "openai".into(),
            model: "gpt-fixture".into(),
            state: ProviderWorkState::Unavailable,
            started_ms: None,
            finished_ms: None,
            normalized_reply_count: 0,
            tool_call_count: 0,
            candidate_count: 0,
            telemetry_state: ProviderTelemetryState::Unavailable,
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: 0,
            receipt_ids: vec![],
            reason: Some(unavailable.clone()),
        };
        manifest.artifact_lineage.remove(0);
        manifest.artifact_lineage[0].parent_artifact_ids = vec!["web-output".into()];
        manifest.artifact_lineage[1].parent_artifact_ids = vec!["web-output".into()];
        manifest.stages[0] = StageCoverage {
            stage_id: StageId("provider-openai".into()),
            kind: StageKind::Provider,
            execution_state: StageExecutionState::Skipped,
            coverage_state: CoverageState::Omitted,
            reasons: vec![
                unavailable,
                CoverageReason::ProviderNoReply {
                    work_id: "provider-work".into(),
                },
            ],
            usage: LimitUsage::default(),
            artifact_ids: vec![],
            provider_work_ids: vec!["provider-work".into()],
        };
        manifest.summary.complete = 2;
        manifest.summary.omitted = 1;
        manifest.summary.artifacts = 3;
        manifest.summary.usage = snapshot.usage.clone();
        manifest.validate(&config, &snapshot)?;

        manifest.stages[0]
            .reasons
            .retain(|reason| !matches!(reason, CoverageReason::ProviderNoReply { .. }));
        assert!(manifest.validate(&config, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn provider_telemetry_gaps_reduce_successful_stage_coverage() -> Result<()> {
        let config = valid_config();
        let mut snapshot = valid_snapshot(&config);
        snapshot.stages[0].coverage_state = CoverageState::Partial;
        snapshot.stages[0].coverage_reasons = vec![CoverageReason::ProviderTelemetryUnavailable {
            work_id: "provider-work".into(),
        }];
        snapshot.stages[0].usage.model_tokens = 0;
        snapshot.stages[0].usage.cost_microusd = 0;
        snapshot.stages[0].attempts[0].usage.model_tokens = 0;
        snapshot.stages[0].attempts[0].usage.cost_microusd = 0;
        snapshot.usage.model_tokens = 0;
        snapshot.usage.cost_microusd = 0;
        snapshot.validate(&config)?;

        let mut manifest = valid_manifest(&config, &snapshot);
        manifest.provider_work[0].telemetry_state = ProviderTelemetryState::Unavailable;
        manifest.provider_work[0].input_tokens = 0;
        manifest.provider_work[0].output_tokens = 0;
        manifest.provider_work[0].cost_microusd = 0;
        manifest.stages[0].coverage_state = CoverageState::Partial;
        manifest.stages[0].usage.model_tokens = 0;
        manifest.stages[0].usage.cost_microusd = 0;
        manifest.stages[0].reasons = vec![CoverageReason::ProviderTelemetryUnavailable {
            work_id: "provider-work".into(),
        }];
        manifest.summary.complete = 2;
        manifest.summary.partial = 1;
        manifest.summary.usage = snapshot.usage.clone();
        manifest.validate(&config, &snapshot)?;

        manifest.stages[0].reasons = vec![CoverageReason::NoApplicableWork {
            explanation: "wrong reason".into(),
        }];
        assert!(manifest.validate(&config, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn snapshot_receipts_and_one_attempt_retry_authority_are_exact() -> Result<()> {
        let config = valid_config();
        let mut snapshot = valid_snapshot(&config);
        snapshot.receipt_ids.push("receipt-unbound".into());
        assert!(snapshot.validate(&config).is_err());

        snapshot.receipt_ids.pop();
        let failed = CoverageReason::ExecutionError {
            code: "fixture-failure".into(),
        };
        snapshot.stages[2] = StageRecord {
            stage_id: StageId("web-discovery".into()),
            execution_state: StageExecutionState::Failed,
            coverage_state: CoverageState::Partial,
            coverage_reasons: vec![failed.clone()],
            attempts: vec![StageAttempt {
                attempt: 1,
                state: StageExecutionState::Failed,
                started_ms: 10,
                finished_ms: Some(20),
                usage: LimitUsage {
                    requests: 1,
                    duration_ms: 100,
                    peak_concurrency: 1,
                    ..LimitUsage::default()
                },
                receipt_ids: vec!["receipt-web".into()],
                artifacts: vec![],
                reason: Some(failed.clone()),
            }],
            usage: LimitUsage {
                requests: 1,
                duration_ms: 100,
                peak_concurrency: 1,
                ..LimitUsage::default()
            },
            artifacts: vec![],
            reason: Some(failed),
        };
        snapshot.execution_state = EngagementExecutionState::Failed;
        snapshot.usage.artifact_bytes = 300;
        snapshot.validate(&config)?;

        let authorization = StageRetryAuthorization {
            engagement_id: config.engagement_id.clone(),
            config_fingerprint: snapshot.config_fingerprint.clone(),
            stage_id: StageId("web-discovery".into()),
            stage_spec_fingerprint: "e".repeat(64),
            prior_attempt: 1,
            next_attempt: 2,
            actor: "fixture-operator".into(),
            reason: "retry after fixture repair".into(),
            authorized_ms: snapshot.updated_ms,
        };
        authorization.validate(&config, &snapshot, &"e".repeat(64))?;
        assert!(authorization
            .validate(&config, &snapshot, &"f".repeat(64))
            .is_err());
        Ok(())
    }
}
