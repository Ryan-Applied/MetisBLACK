//! Versioned contracts. Model candidates deliberately cannot set finding state.
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: u32 = 1;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Operator-only controls. These values never come from provider tool arguments.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    Authorization,
    CloudIdentity,
    PlaybookSelection,
    Scope,
    Destinations,
    Redirects,
    Subdomains,
    ThirdParty,
    Paths,
    Ports,
    Cidrs,
    FilesystemRoots,
    CommandRisk,
    PackageInstallation,
    ExternalDownloads,
    StateChanges,
    DestructiveActions,
    PrivilegeChanges,
    AccountBudget,
    RateLimit,
    RequestBudget,
    Concurrency,
    DataSampling,
    Sandbox,
    Network,
    Environment,
    SecretRedaction,
    SecretExposure,
    ProviderCapabilities,
    ToolCapabilities,
    Confirmation,
    Timeouts,
}
impl Control {
    pub const ALL: &'static [Self] = &[
        Self::Authorization,
        Self::CloudIdentity,
        Self::PlaybookSelection,
        Self::Scope,
        Self::Destinations,
        Self::Redirects,
        Self::Subdomains,
        Self::ThirdParty,
        Self::Paths,
        Self::Ports,
        Self::Cidrs,
        Self::FilesystemRoots,
        Self::CommandRisk,
        Self::PackageInstallation,
        Self::ExternalDownloads,
        Self::StateChanges,
        Self::DestructiveActions,
        Self::PrivilegeChanges,
        Self::AccountBudget,
        Self::RateLimit,
        Self::RequestBudget,
        Self::Concurrency,
        Self::DataSampling,
        Self::Sandbox,
        Self::Network,
        Self::Environment,
        Self::SecretRedaction,
        Self::SecretExposure,
        Self::ProviderCapabilities,
        Self::ToolCapabilities,
        Self::Confirmation,
        Self::Timeouts,
    ];
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExpertOverrides {
    #[serde(default)]
    pub controls: Vec<Control>,
    #[serde(default)]
    pub unsafe_all: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub acknowledged: bool,
    #[serde(default)]
    pub timestamp_ms: u64,
}
impl ExpertOverrides {
    pub fn active(&self) -> bool {
        self.unsafe_all || !self.controls.is_empty()
    }
    pub fn disables(&self, control: Control) -> bool {
        self.acknowledged && (self.unsafe_all || self.controls.contains(&control))
    }
    pub fn disabled_controls(&self) -> Vec<Control> {
        if self.unsafe_all {
            Control::ALL.to_vec()
        } else {
            self.controls.clone()
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.active() {
            ensure!(
                self.acknowledged,
                "expert overrides require explicit acknowledgement"
            );
            ensure!(
                self.reason.trim().len() >= 8,
                "expert overrides require a meaningful reason (8+ characters)"
            );
            ensure!(
                !self.actor.trim().is_empty(),
                "expert overrides require an actor"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Blackbox,
    Browser,
    Whitebox,
    Greybox,
    Host,
    Cloud,
    CloudLive,
    Ai,
    Skills,
    Pr,
}
impl Mode {
    pub fn has_network(self) -> bool {
        matches!(
            self,
            Self::Blackbox
                | Self::Browser
                | Self::Greybox
                | Self::Host
                | Self::CloudLive
                | Self::Ai
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub host: String,
    #[serde(default)]
    pub subdomains: bool,
    pub ports: Vec<u16>,
    #[serde(default = "root_paths")]
    pub paths: Vec<String>,
}
fn root_paths() -> Vec<String> {
    vec!["/".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub network: Vec<NetworkRule>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub cidr_ports: Vec<u16>,
    #[serde(default)]
    pub excluded_hosts: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    #[serde(default)]
    pub cloud_accounts: Vec<String>,
    #[serde(default)]
    pub allow_private: bool,
    #[serde(default = "default_requests")]
    pub max_requests: u64,
    #[serde(default = "default_rate")]
    pub requests_per_second: u32,
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_ms: u64,
    #[serde(default = "default_bytes")]
    pub max_response_bytes: usize,
    #[serde(default)]
    pub max_state_changes: u64,
    #[serde(default)]
    pub max_accounts: u64,
}
fn default_requests() -> u64 {
    100
}
fn default_rate() -> u32 {
    2
}
fn default_concurrency() -> usize {
    4
}
fn default_tool_timeout() -> u64 {
    35_000
}
fn default_bytes() -> usize {
    1_048_576
}
impl Default for Scope {
    fn default() -> Self {
        Self {
            network: vec![],
            cidrs: vec![],
            cidr_ports: vec![],
            excluded_hosts: vec![],
            excluded_paths: vec![],
            roots: vec![],
            cloud_accounts: vec![],
            allow_private: false,
            max_requests: default_requests(),
            requests_per_second: default_rate(),
            max_concurrency: default_concurrency(),
            tool_timeout_ms: default_tool_timeout(),
            max_response_bytes: default_bytes(),
            max_state_changes: 0,
            max_accounts: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretRef(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "tool", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolAction {
    HttpGet {
        url: String,
    },
    HttpRequest {
        url: String,
        method: String,
        body: Option<serde_json::Value>,
    },
    CreateAccount {
        url: String,
        username: String,
    },
    AiPrompt {
        url: String,
        prompt: String,
    },
    SourceRead {
        path: PathBuf,
        start_line: usize,
        end_line: usize,
    },
    DnsResolve {
        host: String,
    },
    TcpConnect {
        host: String,
        port: u16,
    },
    Shell {
        program: String,
        args: Vec<String>,
        working_dir: PathBuf,
    },
    /// An operation executed by a dedicated typed runtime (browser, cloud, or
    /// another registered adapter). The dedicated runtime performs the live
    /// operation; this value binds its immutable observation into the common
    /// receipt format.
    External {
        subsystem: String,
        operation: String,
        target: String,
        #[serde(default)]
        parameters: serde_json::Value,
    },
}
impl ToolAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::HttpGet { .. } => "http_get",
            Self::HttpRequest { .. } => "http_request",
            Self::CreateAccount { .. } => "create_account",
            Self::AiPrompt { .. } => "ai_prompt",
            Self::SourceRead { .. } => "source_read",
            Self::DnsResolve { .. } => "dns_resolve",
            Self::TcpConnect { .. } => "tcp_connect",
            Self::Shell { .. } => "shell",
            Self::External { .. } => "external",
        }
    }
    pub fn target(&self) -> String {
        match self {
            Self::HttpGet { url } => url.clone(),
            Self::HttpRequest { url, .. }
            | Self::CreateAccount { url, .. }
            | Self::AiPrompt { url, .. } => url.clone(),
            Self::SourceRead { path, .. } => path.display().to_string(),
            Self::DnsResolve { host } | Self::TcpConnect { host, .. } => host.clone(),
            Self::Shell { working_dir, .. } => working_dir.display().to_string(),
            Self::External { target, .. } => target.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOutput {
    pub action: ToolAction,
    pub successful: bool,
    pub data: serde_json::Value,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub id: String,
    pub run_id: String,
    pub actor: String,
    pub captured_ms: u64,
    pub content_hash: String,
    pub output: ToolOutput,
    #[serde(default)]
    pub expert_override: Option<ExpertOverrides>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Hypothesis,
    Candidate,
    Reproduced,
    Confirmed,
    NeedsReview,
    Rejected,
    RetestedFixed,
    RetestedPresent,
    OperatorAccepted,
}
impl FindingState {
    pub fn confirmed(self) -> bool {
        matches!(self, Self::Confirmed | Self::RetestedPresent)
    }
    pub fn can_transition(self, next: Self) -> bool {
        use FindingState::*;
        matches!(
            (self, next),
            (Hypothesis, Candidate | Rejected | NeedsReview)
                | (Candidate, Reproduced | NeedsReview | Rejected)
                | (Reproduced, Confirmed | NeedsReview | Rejected)
                | (NeedsReview, Candidate | Rejected)
                | (
                    Confirmed | RetestedPresent | RetestedFixed | OperatorAccepted,
                    RetestedFixed | RetestedPresent | NeedsReview
                )
        )
    }
}

/// Narrow, harness-verifiable predicates. Unsupported vulnerability narratives
/// cannot use a generic substring proof to become a confirmed exploit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Proof {
    MissingHeader {
        url: String,
        header: String,
    },
    InsecureCookie {
        url: String,
        flag: String,
    },
    SourceRule {
        path: PathBuf,
        line: usize,
        rule: String,
        source_hash: String,
    },
    OpenPort {
        host: String,
        port: u16,
    },
    Manual {
        procedure: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub severity_justification: String,
    #[serde(default)]
    pub cvss: Option<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub owasp: Vec<String>,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub location: String,
    #[serde(default)]
    pub payload: String,
    pub impact: String,
    pub remediation: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub auth_context: String,
    #[serde(default)]
    pub test_identity: Option<SecretRef>,
    pub receipt_ids: Vec<String>,
    #[serde(default)]
    pub screenshots: Vec<String>,
    #[serde(default)]
    pub chains_from: Vec<String>,
    pub proof: Proof,
}

impl Candidate {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_overrides(&ExpertOverrides::default())
    }
    pub fn validate_with_overrides(&self, overrides: &ExpertOverrides) -> Result<()> {
        ensure!(
            !self.title.trim().is_empty()
                && (self.title.len() <= 300 || overrides.disables(Control::DataSampling)),
            "invalid finding title"
        );
        ensure!(
            !self.severity_justification.trim().is_empty(),
            "severity requires justification"
        );
        ensure!(
            (0.0..=1.0).contains(&self.confidence),
            "confidence must be 0..1"
        );
        ensure!(
            self.receipt_ids.len() <= 100 || overrides.disables(Control::DataSampling),
            "too many receipts"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validation {
    pub actor: String,
    pub receipt_ids: Vec<String>,
    pub reproduced: bool,
    pub reason: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub candidate: Candidate,
    pub state: FindingState,
    pub finder: String,
    pub validations: Vec<Validation>,
    pub review_reason: String,
    pub introduced: Option<bool>,
    pub claim_receipts: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub confirmation_override: Option<ExpertOverrides>,
}
impl Finding {
    pub fn confirm_by_operator(&mut self, overrides: &ExpertOverrides) -> Result<()> {
        overrides.validate()?;
        ensure!(
            overrides.disables(Control::Confirmation),
            "confirmation override required"
        );
        ensure!(
            self.state != FindingState::Rejected && !self.candidate.receipt_ids.is_empty(),
            "operator acceptance cannot authenticate missing or rejected evidence"
        );
        self.confirmation_override = Some(overrides.clone());
        self.review_reason = format!("Operator override: {}", overrides.reason);
        self.state = FindingState::OperatorAccepted;
        Ok(())
    }
    pub fn transition(&mut self, next: FindingState) -> Result<()> {
        if !self.state.can_transition(next) {
            bail!("invalid finding transition {:?} → {:?}", self.state, next);
        }
        if matches!(
            next,
            FindingState::Confirmed | FindingState::RetestedPresent
        ) {
            ensure!(
                self.validations
                    .iter()
                    .any(|v| v.reproduced && v.actor != self.finder && !v.receipt_ids.is_empty()),
                "independent reproduction required"
            );
            ensure!(!self.candidate.receipt_ids.is_empty(), "receipt required");
            ensure!(
                !self.claim_receipts.is_empty(),
                "claim-to-receipt mapping required"
            );
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: String,
    pub to: String,
    pub receipt_ids: Vec<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: String,
    pub created_by_run: bool,
    pub secret_ref: Option<SecretRef>,
    pub target: String,
    pub cleanup_status: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Planned,
    Recon,
    Assessing,
    Validating,
    Paused,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    pub schema_version: u32,
    pub mode: Mode,
    pub targets: Vec<String>,
    pub scope: Scope,
    pub output_dir: PathBuf,
    #[serde(default)]
    pub source_root: Option<PathBuf>,
    #[serde(default)]
    pub base_ref: Option<String>,
    #[serde(default)]
    pub head_ref: Option<String>,
    #[serde(default)]
    pub provider: Option<ProviderConfig>,
    /// A genuine heterogeneous validation panel. The legacy `provider` field
    /// remains the primary assessment model for backwards compatibility.
    #[serde(default)]
    pub model_panel: Option<ModelPanelConfig>,
    #[serde(default)]
    pub browser: Option<BrowserRunConfig>,
    /// Path to a live cloud plan. The plan contains environment-variable names,
    /// never credential values.
    #[serde(default)]
    pub cloud_plan: Option<PathBuf>,
    #[serde(default)]
    pub chains: Option<ChainRunConfig>,
    #[serde(default)]
    pub playbooks: Option<PathBuf>,
    #[serde(default = "default_steps")]
    pub max_steps: usize,
    #[serde(default = "default_model_tokens")]
    pub max_model_tokens: u64,
    #[serde(default)]
    pub authorized: bool,
    #[serde(default)]
    pub overrides: ExpertOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRunConfig {
    pub webdriver_endpoint: String,
    #[serde(default = "default_browser_kind")]
    pub browser: String,
    #[serde(default = "default_true")]
    pub headless: bool,
    #[serde(default)]
    pub accept_insecure_certificates: bool,
    #[serde(default)]
    pub allow_raw_javascript: bool,
    #[serde(default)]
    pub allow_downloads: bool,
    #[serde(default)]
    pub plan: Option<PathBuf>,
    /// Authenticated multi-role workflow. Mutually exclusive with `plan`.
    #[serde(default)]
    pub workflow: Option<PathBuf>,
}
fn default_browser_kind() -> String {
    "chrome".into()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelMemberRole {
    Candidate,
    Reviewer,
    Refuter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPanelMemberConfig {
    pub id: String,
    pub role: PanelMemberRole,
    pub deployment: String,
    pub provider: ProviderConfig,
    #[serde(default = "default_panel_input_tokens")]
    pub max_input_tokens: u64,
    #[serde(default = "default_tokens")]
    pub max_output_tokens: u32,
    #[serde(default = "default_panel_cost")]
    pub max_cost_microusd: u64,
    #[serde(default)]
    pub input_cost_microusd_per_million_tokens: u64,
    #[serde(default)]
    pub output_cost_microusd_per_million_tokens: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_panel_weight")]
    pub weight_millis: u32,
}
fn default_panel_input_tokens() -> u64 {
    32_000
}
fn default_panel_cost() -> u64 {
    250_000
}
fn default_panel_weight() -> u32 {
    1_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPanelConfig {
    pub members: Vec<ModelPanelMemberConfig>,
    #[serde(default = "default_panel_quorum")]
    pub quorum: usize,
    #[serde(default = "default_panel_ratio")]
    pub acceptance_ratio_millis: u32,
}
fn default_panel_quorum() -> usize {
    2
}
fn default_panel_ratio() -> u32 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRunConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub template_ids: Vec<String>,
    #[serde(default = "default_chain_risk")]
    pub max_risk: String,
    #[serde(default = "default_chain_steps")]
    pub max_steps: u64,
    #[serde(default)]
    pub max_state_changes: u64,
}
fn default_chain_risk() -> String {
    "low".into()
}
fn default_chain_steps() -> u64 {
    40
}
fn default_steps() -> usize {
    20
}
fn default_model_tokens() -> u64 {
    500_000
}
impl RunConfig {
    pub fn validate(&self) -> Result<()> {
        self.overrides.validate()?;
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported config schema"
        );
        ensure!(!self.targets.is_empty(), "at least one target required");
        ensure!(
            (self.overrides.disables(Control::RequestBudget)
                || (self.targets.len() <= 100 && self.max_steps <= 1000))
                && self.max_steps > 0,
            "invalid run bounds"
        );
        ensure!(
            self.overrides.disables(Control::RateLimit)
                || (self.scope.requests_per_second > 0 && self.scope.requests_per_second <= 100),
            "request rate must be 1..100"
        );
        ensure!(
            self.overrides.disables(Control::DataSampling)
                || (self.scope.max_response_bytes > 0
                    && self.scope.max_response_bytes <= 10_485_760),
            "response limit must be 1..10MiB"
        );
        ensure!(
            self.overrides.disables(Control::Concurrency)
                || (1..=64).contains(&self.scope.max_concurrency),
            "concurrency must be 1..64"
        );
        if self.mode == Mode::Browser {
            ensure!(
                self.browser.is_some(),
                "browser mode requires browser configuration"
            );
        }
        if let Some(browser) = &self.browser {
            ensure!(
                self.mode == Mode::Browser && !browser.webdriver_endpoint.trim().is_empty(),
                "browser configuration requires browser mode and a WebDriver endpoint"
            );
            ensure!(
                ["chrome", "firefox", "safari", "compatible"].contains(&browser.browser.as_str()),
                "unsupported browser kind"
            );
            ensure!(
                browser.plan.is_none() || browser.workflow.is_none(),
                "browser plan and authenticated workflow are mutually exclusive"
            );
        }
        if self.mode == Mode::CloudLive {
            ensure!(
                self.cloud_plan.is_some(),
                "live cloud mode requires cloud_plan"
            );
        }
        if let Some(panel) = &self.model_panel {
            ensure!(
                panel.members.len() >= 2 && panel.quorum >= 2,
                "model panel requires at least two members and quorum two"
            );
            let providers: std::collections::BTreeSet<_> = panel
                .members
                .iter()
                .map(|m| m.provider.kind.as_str())
                .collect();
            ensure!(
                providers.len() >= 2,
                "model panel requires heterogeneous providers"
            );
            ensure!(
                panel.members.iter().all(|member| {
                    member.max_cost_microusd > 0
                        && (member.input_cost_microusd_per_million_tokens > 0
                            || member.output_cost_microusd_per_million_tokens > 0)
                }),
                "model panel members require a positive cost budget and fallback estimation rate"
            );
        }
        if let Some(chains) = &self.chains {
            ensure!(chains.max_steps > 0, "chain max_steps must be positive");
            ensure!(
                ["passive", "low", "moderate", "high", "critical"]
                    .contains(&chains.max_risk.as_str()),
                "invalid chain max_risk"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub kind: String,
    pub model: String,
    pub endpoint: String,
    #[serde(default)]
    pub key_env: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_tokens")]
    pub max_output_tokens: u32,
}
fn default_timeout() -> u64 {
    60
}
fn default_tokens() -> u32 {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSnapshot {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub status: RunStatus,
    pub config: RunConfig,
    pub findings: Vec<Finding>,
    pub receipt_ids: Vec<String>,
    pub decisions: Vec<serde_json::Value>,
    pub limitations: Vec<String>,
    pub accounts: Vec<AccountRecord>,
    pub attack_edges: Vec<AttackEdge>,
    pub completed_targets: Vec<String>,
    #[serde(default)]
    pub override_history: Vec<ExpertOverrides>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_skipped_confirmation() {
        assert!(!FindingState::Hypothesis.can_transition(FindingState::Confirmed));
        assert!(FindingState::Candidate.can_transition(FindingState::Reproduced));
    }
    #[test]
    fn model_cannot_set_state() {
        assert!(
            serde_json::from_str::<ToolAction>(r#"{"tool":"shell","command":"rm -rf /"}"#).is_err()
        );
    }
    #[test]
    fn schema_and_unknown_fields_are_strict() {
        assert!(serde_json::from_str::<SecretRef>("5").is_err());
        assert!(serde_json::from_str::<ToolAction>(
            r#"{"tool":"http_get","url":"http://localhost","scope":"*"}"#
        )
        .is_err());
    }
}
