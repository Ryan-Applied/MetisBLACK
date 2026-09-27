//! Versioned contracts. Model candidates deliberately cannot set finding state.
pub mod engagement;

pub use engagement::*;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: u32 = 1;
pub const OPEN_REDIRECT_OBSERVATION_SCHEMA_VERSION: u32 = 1;
pub const API_SCHEMA_OBSERVATION_SCHEMA_VERSION: u32 = 1;
pub const API_SCHEMA_DEFAULT_MAX_RESPONSE_BYTES: u32 = 1_048_576;
pub const API_SCHEMA_HARD_MAX_RESPONSE_BYTES: u32 = 16 * 1_048_576;
pub const API_SCHEMA_DEFAULT_MAX_SHAPE_NODES: u32 = 10_000;
pub const API_SCHEMA_HARD_MAX_SHAPE_NODES: u32 = 100_000;
pub const API_SCHEMA_DEFAULT_MAX_SHAPE_DEPTH: u16 = 24;
pub const API_SCHEMA_HARD_MAX_SHAPE_DEPTH: u16 = 64;
pub const API_SCHEMA_DEFAULT_MAX_PROPERTIES: u32 = 2_000;
pub const API_SCHEMA_HARD_MAX_PROPERTIES: u32 = 20_000;
pub const API_SCHEMA_DEFAULT_MAX_ARRAY_ITEMS: u32 = 1_000;
pub const API_SCHEMA_HARD_MAX_ARRAY_ITEMS: u32 = 10_000;
pub const SUBSCRIPTION_CLI_SCHEMA_VERSION: u32 = 1;
pub const SUBSCRIPTION_CLI_DEFAULT_MAX_STDOUT_BYTES: u64 = 4 * 1_048_576;
pub const SUBSCRIPTION_CLI_HARD_MAX_STDOUT_BYTES: u64 = 16 * 1_048_576;
pub const SUBSCRIPTION_CLI_DEFAULT_MAX_STDERR_BYTES: u64 = 1_048_576;
pub const SUBSCRIPTION_CLI_HARD_MAX_STDERR_BYTES: u64 = 4 * 1_048_576;
pub const SUBSCRIPTION_CLI_DEFAULT_MAX_EVENTS: u32 = 10_000;
pub const SUBSCRIPTION_CLI_HARD_MAX_EVENTS: u32 = 100_000;
pub const SUBSCRIPTION_CLI_DEFAULT_MAX_TURNS: u32 = 16;
pub const SUBSCRIPTION_CLI_HARD_MAX_TURNS: u32 = 64;
pub const SUBSCRIPTION_CLI_HARD_MAX_PROFILE_ENVIRONMENT: usize = 64;
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Fetch exactly one response for the bounded discovery state machine.
    /// Redirects are never followed and `allowed_origins` is an immutable
    /// acquisition boundary, not merely artifact metadata.
    WebDiscoveryFetch {
        plan_hash: String,
        request_id: String,
        url: String,
        allowed_origins: Vec<String>,
        max_response_bytes: u32,
    },
    /// Observe one response to a controlled open-redirect probe. The runtime
    /// constructs the probe value from `canary`; callers cannot supply an
    /// arbitrary redirect destination through this action.
    OpenRedirectProbe {
        endpoint: String,
        parameter: String,
        canary: String,
    },
    /// Observe exactly one read-only API response for a canonical, immutable
    /// plan/contract selector. The dedicated runtime never follows redirects,
    /// sends credentials, or retains response values.
    ApiSchemaProbe {
        plan_hash: String,
        contract_hash: String,
        probe_id: String,
        method: ApiProbeMethod,
        url: String,
        allowed_origins: Vec<String>,
        max_response_bytes: u32,
        max_shape_nodes: u32,
        max_shape_depth: u16,
        max_properties: u32,
        max_array_items: u32,
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
            Self::WebDiscoveryFetch { .. } => "web_discovery_fetch",
            Self::OpenRedirectProbe { .. } => "open_redirect_probe",
            Self::ApiSchemaProbe { .. } => "api_schema_probe",
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
            Self::WebDiscoveryFetch { url, .. } => url.clone(),
            Self::OpenRedirectProbe { endpoint, .. } => endpoint.clone(),
            Self::ApiSchemaProbe { url, .. } => url.clone(),
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

/// Authorization evidence embedded in live observations. Keeping this typed
/// prevents receipt consumers from silently ignoring whether an execution was
/// ordinarily authorized or admitted by an audited override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProvenance {
    pub authorized: bool,
    pub explicit_override: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    OpenRedirect,
    ApiSchema,
}

/// The only methods admitted by the schema-observation runtime. Using an enum
/// prevents case folding or an override from turning a read into a mutation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiProbeMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "OPTIONS")]
    Options,
}

impl ApiProbeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// Value-free representation of a JSON response. Object keys and array
/// positions are structural evidence; scalar values are deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonShape {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Array { elements: Vec<JsonShape> },
    Object { properties: Vec<JsonPropertyShape> },
}

/// Property names are values of a stable field rather than dynamic map keys.
/// This prevents the evidence redactor from mistaking a structural API field
/// such as `password` for a secret-bearing receipt key and corrupting the
/// typed shape during immutable capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JsonPropertyShape {
    pub name: String,
    pub shape: JsonShape,
}

impl JsonShape {
    pub fn node_count(&self) -> Result<u32> {
        fn count(shape: &JsonShape, total: &mut u32) -> Result<()> {
            *total = total
                .checked_add(1)
                .context("JSON shape node count overflow")?;
            match shape {
                JsonShape::Array { elements } => {
                    for element in elements {
                        count(element, total)?;
                    }
                }
                JsonShape::Object { properties } => {
                    ensure!(
                        properties
                            .windows(2)
                            .all(|pair| pair[0].name < pair[1].name)
                            && properties
                                .iter()
                                .all(|property| property.name.len() <= 4096),
                        "JSON object shape properties must be sorted, unique and bounded"
                    );
                    for property in properties {
                        count(&property.shape, total)?;
                    }
                }
                JsonShape::Null
                | JsonShape::Boolean
                | JsonShape::Integer
                | JsonShape::Number
                | JsonShape::String => {}
            }
            Ok(())
        }
        let mut total = 0;
        count(self, &mut total)?;
        Ok(total)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JsonBodyClassification {
    Empty,
    ValidJson,
    InvalidJson,
    InvalidUtf8,
    /// The finite byte ceiling was reached before the complete response body
    /// was observed, so the captured prefix cannot support a JSON claim.
    Truncated,
}

/// Typed provenance for a one-request, no-redirect, no-credential observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiRequestProvenance {
    pub resolved_addresses: Vec<String>,
    pub request_count: u8,
    pub redirect_followed: bool,
    pub proxy_used: bool,
    pub credentials_sent: bool,
    pub authorization_provenance: AuthorizationProvenance,
}

/// Strict value-free API response observation. `body_hash` is the exact hash
/// of the captured raw prefix; `body_truncated` states when the finite capture
/// ceiling prevented a whole-response hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiSchemaObservation {
    pub schema_version: u32,
    pub kind: ObservationKind,
    pub plan_hash: String,
    pub contract_hash: String,
    pub probe_id: String,
    pub method: ApiProbeMethod,
    pub url: String,
    pub status: u16,
    pub media_type: Option<String>,
    /// Sorted, lower-case header names only. Header values are not persisted.
    pub header_names: Vec<String>,
    pub headers_truncated: bool,
    pub set_cookie_present: bool,
    pub declared_content_length: Option<u64>,
    pub body_hash: String,
    pub body_bytes: u32,
    pub body_truncated: bool,
    pub json_classification: JsonBodyClassification,
    pub json_shape: Option<JsonShape>,
    pub shape_node_count: u32,
    pub shape_truncated: bool,
    pub max_response_bytes: u32,
    pub max_shape_nodes: u32,
    pub max_shape_depth: u16,
    pub max_properties: u32,
    pub max_array_items: u32,
    pub request_provenance: ApiRequestProvenance,
}

impl ApiSchemaObservation {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == API_SCHEMA_OBSERVATION_SCHEMA_VERSION,
            "unsupported API schema observation version"
        );
        ensure!(
            self.kind == ObservationKind::ApiSchema,
            "invalid API schema observation kind"
        );
        ensure!(
            is_canonical_sha256(&self.plan_hash),
            "invalid API plan hash"
        );
        ensure!(
            is_canonical_sha256(&self.contract_hash),
            "invalid API contract hash"
        );
        validate_api_probe_id(&self.probe_id)?;
        let parsed = url::Url::parse(&self.url).context("invalid API observation URL")?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.as_str() == self.url
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.fragment().is_none(),
            "API observation URL must be canonical credential-free HTTP(S) without a fragment"
        );
        ensure!((100..=599).contains(&self.status), "invalid HTTP status");
        ensure!(
            (1..=API_SCHEMA_HARD_MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
                && (1..=API_SCHEMA_HARD_MAX_SHAPE_NODES).contains(&self.max_shape_nodes)
                && (1..=API_SCHEMA_HARD_MAX_SHAPE_DEPTH).contains(&self.max_shape_depth)
                && (1..=API_SCHEMA_HARD_MAX_PROPERTIES).contains(&self.max_properties)
                && (1..=API_SCHEMA_HARD_MAX_ARRAY_ITEMS).contains(&self.max_array_items),
            "API observation bounds exceed hard ceilings"
        );
        ensure!(
            self.body_bytes <= self.max_response_bytes,
            "API observation body exceeds its capture bound"
        );
        ensure!(
            is_canonical_sha256(&self.body_hash),
            "invalid API body hash"
        );
        ensure!(
            self.header_names.len() <= 128
                && self.header_names.windows(2).all(|pair| pair[0] < pair[1])
                && self.header_names.iter().all(|name| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                        && !matches!(
                            name.as_str(),
                            "authorization"
                                | "proxy-authorization"
                                | "set-cookie"
                                | "www-authenticate"
                                | "proxy-authenticate"
                        )
                }),
            "API observation header names are not canonical and sanitized"
        );
        if let Some(media_type) = &self.media_type {
            ensure!(
                !media_type.is_empty()
                    && media_type.len() <= 127
                    && media_type.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(
                                byte,
                                b'/' | b'!'
                                    | b'#'
                                    | b'$'
                                    | b'&'
                                    | b'^'
                                    | b'_'
                                    | b'.'
                                    | b'+'
                                    | b'-'
                                    | b'*'
                            )
                    }),
                "invalid normalized API media type"
            );
        }
        match (&self.json_classification, &self.json_shape) {
            (JsonBodyClassification::ValidJson, Some(shape)) => {
                ensure!(!self.shape_truncated, "complete shape marked truncated");
                ensure!(
                    shape.node_count()? == self.shape_node_count
                        && self.shape_node_count <= self.max_shape_nodes,
                    "JSON shape node count is inconsistent"
                );
                shape.validate_capture_bounds(
                    self.max_shape_depth,
                    self.max_properties,
                    self.max_array_items,
                )?;
            }
            (JsonBodyClassification::ValidJson, None) => ensure!(
                self.shape_truncated && self.shape_node_count == 0,
                "valid JSON without a shape must record a node-cap truncation"
            ),
            (JsonBodyClassification::Truncated, None) => ensure!(
                self.body_truncated && !self.shape_truncated && self.shape_node_count == 0,
                "truncated bodies must carry only value-free inconclusive evidence"
            ),
            (JsonBodyClassification::Empty, None)
            | (JsonBodyClassification::InvalidJson, None)
            | (JsonBodyClassification::InvalidUtf8, None) => ensure!(
                !self.body_truncated && !self.shape_truncated && self.shape_node_count == 0,
                "non-JSON observations cannot carry shape evidence"
            ),
            _ => bail!("JSON classification contradicts shape evidence"),
        }
        ensure!(
            !self.body_truncated
                || matches!(self.json_classification, JsonBodyClassification::Truncated),
            "byte-truncated bodies cannot carry JSON classification or shape claims"
        );
        ensure!(
            !self.request_provenance.resolved_addresses.is_empty()
                && self.request_provenance.resolved_addresses.len() <= 64
                && self
                    .request_provenance
                    .resolved_addresses
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && self
                    .request_provenance
                    .resolved_addresses
                    .iter()
                    .all(|address| address.parse::<SocketAddr>().is_ok())
                && self.request_provenance.request_count == 1
                && !self.request_provenance.redirect_followed
                && !self.request_provenance.proxy_used
                && !self.request_provenance.credentials_sent
                && (self.request_provenance.authorization_provenance.authorized
                    || self
                        .request_provenance
                        .authorization_provenance
                        .explicit_override),
            "API request provenance is incomplete or unsafe"
        );
        Ok(())
    }
}

impl JsonShape {
    fn validate_capture_bounds(
        &self,
        max_depth: u16,
        max_properties: u32,
        max_array_items: u32,
    ) -> Result<()> {
        fn visit(
            shape: &JsonShape,
            depth: u16,
            max_depth: u16,
            max_properties: u32,
            max_array_items: u32,
        ) -> Result<()> {
            ensure!(
                depth <= max_depth,
                "JSON shape depth exceeds its capture bound"
            );
            match shape {
                JsonShape::Object { properties } => {
                    ensure!(
                        properties.len() <= usize::try_from(max_properties)?,
                        "JSON object shape exceeds its property bound"
                    );
                    for property in properties {
                        visit(
                            &property.shape,
                            depth.saturating_add(1),
                            max_depth,
                            max_properties,
                            max_array_items,
                        )?;
                    }
                }
                JsonShape::Array { elements } => {
                    ensure!(
                        elements.len() <= usize::try_from(max_array_items)?,
                        "JSON array shape exceeds its item bound"
                    );
                    for element in elements {
                        visit(
                            element,
                            depth.saturating_add(1),
                            max_depth,
                            max_properties,
                            max_array_items,
                        )?;
                    }
                }
                JsonShape::Null
                | JsonShape::Boolean
                | JsonShape::Integer
                | JsonShape::Number
                | JsonShape::String => {}
            }
            Ok(())
        }

        visit(self, 0, max_depth, max_properties, max_array_items)
    }
}

pub fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn validate_api_probe_id(probe_id: &str) -> Result<()> {
    ensure!(
        probe_id.len() == 75
            && probe_id.starts_with("api-schema-")
            && is_canonical_sha256(&probe_id[11..]),
        "API probe id must be api-schema-<canonical SHA-256>"
    );
    Ok(())
}

/// Strict receipt data for an observe-only open-redirect probe.
///
/// `location_matches_canary` reports only an exact match with the runtime-built
/// `canary_url`; it is an observation, not by itself a confirmed finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenRedirectObservation {
    pub schema_version: u32,
    pub kind: ObservationKind,
    pub endpoint: String,
    pub parameter: String,
    pub canary: String,
    pub probe_url: String,
    pub canary_url: String,
    pub status: u16,
    pub location: Option<String>,
    pub location_matches_canary: bool,
    pub headers: BTreeMap<String, String>,
    pub body_hash: String,
    pub resolved_addresses: Vec<String>,
    pub request_count: u8,
    pub redirect_followed: bool,
    pub authorization_provenance: AuthorizationProvenance,
}

impl OpenRedirectObservation {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == OPEN_REDIRECT_OBSERVATION_SCHEMA_VERSION,
            "unsupported open-redirect observation schema"
        );
        ensure!(
            self.kind == ObservationKind::OpenRedirect,
            "invalid open-redirect observation kind"
        );
        validate_open_redirect_inputs(&self.parameter, &self.canary)?;
        ensure!(
            !self.endpoint.is_empty(),
            "open-redirect endpoint is required"
        );
        ensure!(
            !self.probe_url.is_empty(),
            "open-redirect probe URL is required"
        );
        ensure!(
            self.canary_url == open_redirect_canary_url(&self.canary)?,
            "open-redirect canary URL does not match the canary"
        );
        ensure!(
            self.location_matches_canary
                == self
                    .location
                    .as_deref()
                    .is_some_and(|v| v == self.canary_url),
            "open-redirect match flag contradicts the observed Location"
        );
        ensure!(
            self.request_count == 1 && !self.redirect_followed,
            "open-redirect probes must observe exactly one response without following redirects"
        );
        ensure!(
            !self.body_hash.is_empty() && !self.resolved_addresses.is_empty(),
            "open-redirect observation is incomplete"
        );
        Ok(())
    }
}

pub fn validate_open_redirect_inputs(parameter: &str, canary: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&parameter.len())
            && parameter.is_ascii()
            && parameter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~'))
            && parameter
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric),
        "invalid open-redirect query parameter"
    );
    ensure!(
        (8..=128).contains(&canary.len())
            && canary.is_ascii()
            && canary
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && canary
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && canary
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "invalid open-redirect canary"
    );
    Ok(())
}

pub fn open_redirect_canary_url(canary: &str) -> Result<String> {
    validate_open_redirect_inputs("url", canary)?;
    Ok(format!("https://metisblack.invalid/{canary}"))
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
                | (
                    NeedsReview,
                    Candidate | Rejected | RetestedFixed | RetestedPresent
                )
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
    OpenRedirect {
        endpoint: String,
        parameter: String,
    },
    /// Binds a pure validator's canonical violation artifact to the exact live
    /// response observation without importing the validator crate here.
    ApiResponseContractViolation {
        plan_hash: String,
        contract_hash: String,
        probe_id: String,
        observation_body_hash: String,
        violation_hash: String,
    },
    Manual {
        procedure: String,
    },
}

impl Proof {
    pub fn validate(&self) -> Result<()> {
        if let Self::ApiResponseContractViolation {
            plan_hash,
            contract_hash,
            probe_id,
            observation_body_hash,
            violation_hash,
        } = self
        {
            ensure!(
                is_canonical_sha256(plan_hash)
                    && is_canonical_sha256(contract_hash)
                    && is_canonical_sha256(observation_body_hash)
                    && is_canonical_sha256(violation_hash),
                "API response contract proof hashes must be canonical SHA-256"
            );
            validate_api_probe_id(probe_id)?;
        }
        Ok(())
    }
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
        self.proof.validate()?;
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
    /// Optional strict web-discovery plan consumed only by black-box and
    /// grey-box modes. The plan is persisted separately so this shared domain
    /// crate does not depend on the discovery implementation crate.
    #[serde(default)]
    pub discovery_plan: Option<PathBuf>,
    /// SHA-256 fingerprint of the canonical plan copied into the run
    /// directory. Set by the engine before the first checkpoint.
    #[serde(default)]
    pub discovery_plan_hash: Option<String>,
    /// Optional strict API-validation plan for black-box and grey-box modes.
    /// As with discovery, the implementation contract lives in a pure crate.
    #[serde(default)]
    pub api_validation_plan: Option<PathBuf>,
    /// SHA-256 fingerprint of the engine-bound canonical API validation plan.
    #[serde(default)]
    pub api_validation_plan_hash: Option<String>,
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
        if self.discovery_plan.is_some() {
            ensure!(
                matches!(self.mode, Mode::Blackbox | Mode::Greybox),
                "web discovery plans require black-box or grey-box mode"
            );
        }
        if let Some(plan_hash) = &self.discovery_plan_hash {
            ensure!(
                self.discovery_plan.is_some()
                    && plan_hash.len() == 64
                    && plan_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "discovery_plan_hash requires a canonical discovery plan and SHA-256 value"
            );
        }
        if self.api_validation_plan.is_some() {
            ensure!(
                matches!(self.mode, Mode::Blackbox | Mode::Greybox),
                "API validation plans require black-box or grey-box mode"
            );
            ensure!(
                self.discovery_plan.is_some(),
                "API validation plans require a web discovery plan"
            );
        }
        if let Some(plan_hash) = &self.api_validation_plan_hash {
            ensure!(
                self.api_validation_plan.is_some()
                    && self.discovery_plan.is_some()
                    && self.discovery_plan_hash.is_some()
                    && is_canonical_sha256(plan_hash),
                "api_validation_plan_hash requires bound API and discovery plans with a canonical SHA-256 value"
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
            for member in &panel.members {
                member.provider.validate()?;
            }
        }
        if let Some(provider) = &self.provider {
            provider.validate()?;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCliKind {
    Claude,
    Codex,
}

impl SubscriptionCliKind {
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Claude => "anthropic",
            Self::Codex => "openai",
        }
    }

    pub const fn executable_name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCliAutonomy {
    #[default]
    InferenceOnly,
    ReadOnly,
    WorkspaceWrite,
    Unrestricted,
}

/// Strict configuration for a locally authenticated model-provider CLI.
///
/// This contract deliberately has no generic argv or command field. Provider
/// adapters own their fixed invocation grammar; operational permissions are
/// represented by `autonomy` and remain subject to central policy and sandbox
/// enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCliConfig {
    pub schema_version: u32,
    pub kind: SubscriptionCliKind,
    #[serde(default)]
    pub autonomy: SubscriptionCliAutonomy,
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default = "default_subscription_cli_stdout_bytes")]
    pub max_stdout_bytes: u64,
    #[serde(default = "default_subscription_cli_stderr_bytes")]
    pub max_stderr_bytes: u64,
    #[serde(default = "default_subscription_cli_events")]
    pub max_events: u32,
    #[serde(default = "default_subscription_cli_turns")]
    pub max_turns: u32,
    #[serde(default)]
    pub profile_environment: Vec<String>,
    #[serde(default)]
    pub inherit_environment: bool,
    /// Re-enable customization sources controlled by the selected CLI's fixed
    /// adapter flags. This lower-determinism route is unrestricted only.
    #[serde(default)]
    pub load_native_customizations: bool,
}

impl SubscriptionCliConfig {
    pub fn new(kind: SubscriptionCliKind) -> Self {
        Self {
            schema_version: SUBSCRIPTION_CLI_SCHEMA_VERSION,
            kind,
            autonomy: SubscriptionCliAutonomy::InferenceOnly,
            executable: None,
            working_directory: None,
            max_stdout_bytes: SUBSCRIPTION_CLI_DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: SUBSCRIPTION_CLI_DEFAULT_MAX_STDERR_BYTES,
            max_events: SUBSCRIPTION_CLI_DEFAULT_MAX_EVENTS,
            max_turns: SUBSCRIPTION_CLI_DEFAULT_MAX_TURNS,
            profile_environment: Vec::new(),
            inherit_environment: false,
            load_native_customizations: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SUBSCRIPTION_CLI_SCHEMA_VERSION,
            "unsupported subscription CLI schema"
        );
        ensure!(
            self.kind != SubscriptionCliKind::Codex
                || self.autonomy != SubscriptionCliAutonomy::InferenceOnly,
            "Codex inference-only is unsupported because the CLI has no verified no-tools mode; select read-only or a stronger explicitly authorized autonomy"
        );
        if let Some(executable) = &self.executable {
            ensure!(
                executable.is_absolute(),
                "subscription CLI executable must be an absolute path"
            );
        }
        if let Some(working_directory) = &self.working_directory {
            ensure!(
                working_directory.is_absolute(),
                "subscription CLI working directory must be an absolute path"
            );
        }
        ensure!(
            (1..=SUBSCRIPTION_CLI_HARD_MAX_STDOUT_BYTES).contains(&self.max_stdout_bytes),
            "subscription CLI stdout bound exceeds the hard ceiling"
        );
        ensure!(
            (1..=SUBSCRIPTION_CLI_HARD_MAX_STDERR_BYTES).contains(&self.max_stderr_bytes),
            "subscription CLI stderr bound exceeds the hard ceiling"
        );
        ensure!(
            (1..=SUBSCRIPTION_CLI_HARD_MAX_EVENTS).contains(&self.max_events),
            "subscription CLI event bound exceeds the hard ceiling"
        );
        ensure!(
            (1..=SUBSCRIPTION_CLI_HARD_MAX_TURNS).contains(&self.max_turns),
            "subscription CLI turn bound exceeds the hard ceiling"
        );
        ensure!(
            self.profile_environment.len() <= SUBSCRIPTION_CLI_HARD_MAX_PROFILE_ENVIRONMENT,
            "subscription CLI environment allowlist exceeds the hard ceiling"
        );
        ensure!(
            !self.inherit_environment || self.autonomy == SubscriptionCliAutonomy::Unrestricted,
            "blanket subscription CLI environment inheritance requires unrestricted autonomy"
        );
        ensure!(
            !self.load_native_customizations
                || self.autonomy == SubscriptionCliAutonomy::Unrestricted,
            "native subscription CLI customizations require unrestricted autonomy"
        );
        let mut names = std::collections::BTreeSet::new();
        for name in &self.profile_environment {
            ensure!(
                valid_environment_name(name),
                "invalid subscription CLI environment name"
            );
            ensure!(
                names.insert(name.to_ascii_uppercase()),
                "duplicate subscription CLI environment name"
            );
        }
        Ok(())
    }
}

fn default_subscription_cli_stdout_bytes() -> u64 {
    SUBSCRIPTION_CLI_DEFAULT_MAX_STDOUT_BYTES
}
fn default_subscription_cli_stderr_bytes() -> u64 {
    SUBSCRIPTION_CLI_DEFAULT_MAX_STDERR_BYTES
}
fn default_subscription_cli_events() -> u32 {
    SUBSCRIPTION_CLI_DEFAULT_MAX_EVENTS
}
fn default_subscription_cli_turns() -> u32 {
    SUBSCRIPTION_CLI_DEFAULT_MAX_TURNS
}
fn valid_environment_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
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
    #[serde(default)]
    pub subscription_cli: Option<SubscriptionCliConfig>,
}
impl ProviderConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(subscription) = &self.subscription_cli {
            subscription.validate()?;
            ensure!(
                self.kind == subscription.kind.provider_kind(),
                "subscription CLI is incompatible with provider kind"
            );
            ensure!(
                self.endpoint == "local://subscription",
                "subscription CLI provider endpoint must be exactly local://subscription"
            );
            ensure!(
                self.key_env.is_none(),
                "subscription CLI provider cannot declare key_env"
            );
        } else {
            ensure!(
                self.endpoint != "local://subscription",
                "local://subscription requires a typed subscription_cli configuration"
            );
        }
        Ok(())
    }
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
    #[test]
    fn open_redirect_contract_rejects_ambiguous_inputs_and_contradictions() -> Result<()> {
        for parameter in ["", "next&admin", "na me", "ümlaut", ".leading"] {
            assert!(validate_open_redirect_inputs(parameter, "canary-123456").is_err());
        }
        for canary in [
            "short",
            "Uppercase-123",
            "leading space",
            "-leading-123",
            "trailing-123-",
        ] {
            assert!(validate_open_redirect_inputs("next", canary).is_err());
        }
        validate_open_redirect_inputs("redirect_uri", "canary-123456")?;

        let mut observation = OpenRedirectObservation {
            schema_version: OPEN_REDIRECT_OBSERVATION_SCHEMA_VERSION,
            kind: ObservationKind::OpenRedirect,
            endpoint: "https://example.test/redirect".into(),
            parameter: "next".into(),
            canary: "canary-123456".into(),
            probe_url:
                "https://example.test/redirect?next=https%3A%2F%2Fmetisblack.invalid%2Fcanary-123456"
                    .into(),
            canary_url: "https://metisblack.invalid/canary-123456".into(),
            status: 302,
            location: Some("https://metisblack.invalid/canary-123456".into()),
            location_matches_canary: true,
            headers: BTreeMap::new(),
            body_hash: "fixture-hash".into(),
            resolved_addresses: vec!["192.0.2.1:443".into()],
            request_count: 1,
            redirect_followed: false,
            authorization_provenance: AuthorizationProvenance {
                authorized: true,
                explicit_override: false,
            },
        };
        observation.validate()?;
        observation.redirect_followed = true;
        assert!(observation.validate().is_err());

        let mut serialized = serde_json::to_value(&observation)?;
        serialized["untyped_claim"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OpenRedirectObservation>(serialized).is_err());
        Ok(())
    }

    #[test]
    fn api_schema_observation_is_strict_bounded_and_value_free() -> Result<()> {
        let shape = JsonShape::Object {
            properties: vec![
                JsonPropertyShape {
                    name: "active".into(),
                    shape: JsonShape::Boolean,
                },
                JsonPropertyShape {
                    name: "name".into(),
                    shape: JsonShape::String,
                },
                JsonPropertyShape {
                    name: "roles".into(),
                    shape: JsonShape::Array {
                        elements: vec![JsonShape::String],
                    },
                },
            ],
        };
        let observation = ApiSchemaObservation {
            schema_version: API_SCHEMA_OBSERVATION_SCHEMA_VERSION,
            kind: ObservationKind::ApiSchema,
            plan_hash: "a".repeat(64),
            contract_hash: "b".repeat(64),
            probe_id: format!("api-schema-{}", "c".repeat(64)),
            method: ApiProbeMethod::Get,
            url: "https://example.test/v1/users".into(),
            status: 200,
            media_type: Some("application/json".into()),
            header_names: vec!["content-length".into(), "content-type".into()],
            headers_truncated: false,
            set_cookie_present: true,
            declared_content_length: Some(87),
            body_hash: "d".repeat(64),
            body_bytes: 87,
            body_truncated: false,
            json_classification: JsonBodyClassification::ValidJson,
            shape_node_count: shape.node_count()?,
            json_shape: Some(shape),
            shape_truncated: false,
            max_response_bytes: 1024,
            max_shape_nodes: 32,
            max_shape_depth: API_SCHEMA_DEFAULT_MAX_SHAPE_DEPTH,
            max_properties: API_SCHEMA_DEFAULT_MAX_PROPERTIES,
            max_array_items: API_SCHEMA_DEFAULT_MAX_ARRAY_ITEMS,
            request_provenance: ApiRequestProvenance {
                resolved_addresses: vec!["192.0.2.1:443".into()],
                request_count: 1,
                redirect_followed: false,
                proxy_used: false,
                credentials_sent: false,
                authorization_provenance: AuthorizationProvenance {
                    authorized: true,
                    explicit_override: false,
                },
            },
        };
        observation.validate()?;
        let serialized = serde_json::to_string(&observation)?;
        for forbidden in ["alice", "administrator", "fixture-secret"] {
            assert!(!serialized.contains(forbidden));
        }

        let mut invalid = observation.clone();
        invalid.shape_node_count += 1;
        assert!(invalid.validate().is_err());
        invalid = observation.clone();
        invalid.request_provenance.redirect_followed = true;
        assert!(invalid.validate().is_err());
        invalid = observation.clone();
        invalid.header_names.push("set-cookie".into());
        assert!(invalid.validate().is_err());
        invalid = observation.clone();
        invalid.body_bytes = invalid.max_response_bytes + 1;
        assert!(invalid.validate().is_err());
        let mut credentialed = invalid.clone();
        credentialed.body_bytes = 1;
        credentialed.url = "https://user:password@example.test/v1/users".into();
        assert!(credentialed.validate().is_err());
        credentialed.url = "https://example.test/v1/users#fragment".into();
        assert!(credentialed.validate().is_err());

        let mut legal_media_type = observation.clone();
        legal_media_type.media_type = Some("application/vnd.foo_bar!#$&^+*-json".into());
        legal_media_type.validate()?;
        legal_media_type.media_type = Some("application/vnd.foo%bar".into());
        assert!(legal_media_type.validate().is_err());

        let mut noncanonical_addresses = observation.clone();
        noncanonical_addresses.request_provenance.resolved_addresses =
            vec!["192.0.2.2:443".into(), "192.0.2.1:443".into()];
        assert!(noncanonical_addresses.validate().is_err());

        let mut truncated = observation;
        truncated.body_bytes = truncated.max_response_bytes;
        truncated.body_truncated = true;
        truncated.json_classification = JsonBodyClassification::Truncated;
        truncated.json_shape = None;
        truncated.shape_node_count = 0;
        truncated.shape_truncated = false;
        truncated.validate()?;
        truncated.json_classification = JsonBodyClassification::ValidJson;
        assert!(truncated.validate().is_err());
        Ok(())
    }

    #[test]
    fn api_schema_action_rejects_untyped_methods_and_unknown_fields() -> Result<()> {
        let base = serde_json::json!({
            "tool": "api_schema_probe",
            "plan_hash": "a".repeat(64),
            "contract_hash": "b".repeat(64),
            "probe_id": format!("api-schema-{}", "c".repeat(64)),
            "method": "POST",
            "url": "https://example.test/v1",
            "allowed_origins": ["https://example.test"],
            "max_response_bytes": 1024,
            "max_shape_nodes": 100,
            "max_shape_depth": 24,
            "max_properties": 2000,
            "max_array_items": 1000
        });
        assert!(serde_json::from_value::<ToolAction>(base.clone()).is_err());
        let mut valid = base;
        valid["method"] = serde_json::json!("GET");
        serde_json::from_value::<ToolAction>(valid.clone())?;
        valid["credential"] = serde_json::json!("secret");
        assert!(serde_json::from_value::<ToolAction>(valid).is_err());
        Ok(())
    }

    #[test]
    fn api_validation_run_config_requires_connected_engine_bound_plans() -> Result<()> {
        let mut config = RunConfig {
            schema_version: SCHEMA_VERSION,
            mode: Mode::Blackbox,
            targets: vec!["https://example.test/".into()],
            scope: Scope::default(),
            output_dir: PathBuf::from("fixture-output"),
            source_root: None,
            base_ref: None,
            head_ref: None,
            provider: None,
            model_panel: None,
            browser: None,
            cloud_plan: None,
            discovery_plan: None,
            discovery_plan_hash: None,
            api_validation_plan: Some(PathBuf::from("api-plan.json")),
            api_validation_plan_hash: None,
            chains: None,
            playbooks: None,
            max_steps: default_steps(),
            max_model_tokens: default_model_tokens(),
            authorized: true,
            overrides: ExpertOverrides::default(),
        };
        assert!(config.validate().is_err());

        config.discovery_plan = Some(PathBuf::from("discovery-plan.json"));
        config.validate()?;
        config.api_validation_plan_hash = Some("b".repeat(64));
        assert!(config.validate().is_err());
        config.discovery_plan_hash = Some("a".repeat(64));
        config.validate()?;

        config.mode = Mode::Whitebox;
        assert!(config.validate().is_err());
        config.mode = Mode::Blackbox;
        config.api_validation_plan_hash = Some("B".repeat(64));
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn subscription_cli_contract_is_strict_and_provider_bound() -> Result<()> {
        let executable = std::env::current_exe()?;
        let working_directory = std::env::current_dir()?;
        let base = serde_json::json!({
            "kind": "anthropic",
            "model": "claude-fixture",
            "endpoint": "local://subscription",
            "key_env": null,
            "timeout_seconds": 60,
            "max_output_tokens": 4096,
            "subscription_cli": {
                "schema_version": 1,
                "kind": "claude",
                "autonomy": "workspace_write",
                "executable": executable,
                "working_directory": working_directory,
                "max_stdout_bytes": 4194304,
                "max_stderr_bytes": 1048576,
                "max_events": 10000,
                "max_turns": 16,
                "profile_environment": ["HOME", "PATH"],
                "inherit_environment": false
            }
        });
        let provider: ProviderConfig = serde_json::from_value(base.clone())?;
        provider.validate()?;

        let mut value = base.clone();
        value["subscription_cli"]["schema_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ProviderConfig>(value)?
            .validate()
            .is_err());

        let mut value = base.clone();
        value["subscription_cli"]["args"] = serde_json::json!(["--dangerously-skip-permissions"]);
        assert!(serde_json::from_value::<ProviderConfig>(value).is_err());

        let mut value = base.clone();
        value["subscription_cli"]["autonomy"] = serde_json::json!("root");
        assert!(serde_json::from_value::<ProviderConfig>(value).is_err());

        let mut value = base.clone();
        value["subscription_cli"]["executable"] = serde_json::json!("bin/claude");
        assert!(serde_json::from_value::<ProviderConfig>(value)?
            .validate()
            .is_err());

        let mut value = base.clone();
        value["kind"] = serde_json::json!("openai");
        assert!(serde_json::from_value::<ProviderConfig>(value)?
            .validate()
            .is_err());

        let mut value = base.clone();
        value["endpoint"] = serde_json::json!("https://api.anthropic.com");
        assert!(serde_json::from_value::<ProviderConfig>(value)?
            .validate()
            .is_err());

        let mut value = base.clone();
        value["key_env"] = serde_json::json!("ANTHROPIC_API_KEY");
        assert!(serde_json::from_value::<ProviderConfig>(value)?
            .validate()
            .is_err());
        Ok(())
    }

    #[test]
    fn subscription_cli_bounds_and_environment_allowlist_fail_closed() -> Result<()> {
        let mut config = SubscriptionCliConfig::new(SubscriptionCliKind::Codex);
        assert!(config.validate().is_err());
        config.autonomy = SubscriptionCliAutonomy::ReadOnly;
        config.validate()?;

        config.max_stdout_bytes = SUBSCRIPTION_CLI_HARD_MAX_STDOUT_BYTES + 1;
        assert!(config.validate().is_err());
        config.max_stdout_bytes = SUBSCRIPTION_CLI_DEFAULT_MAX_STDOUT_BYTES;
        config.max_stderr_bytes = 0;
        assert!(config.validate().is_err());
        config.max_stderr_bytes = SUBSCRIPTION_CLI_DEFAULT_MAX_STDERR_BYTES;
        config.max_events = SUBSCRIPTION_CLI_HARD_MAX_EVENTS + 1;
        assert!(config.validate().is_err());
        config.max_events = SUBSCRIPTION_CLI_DEFAULT_MAX_EVENTS;
        config.max_turns = SUBSCRIPTION_CLI_HARD_MAX_TURNS + 1;
        assert!(config.validate().is_err());
        config.max_turns = SUBSCRIPTION_CLI_DEFAULT_MAX_TURNS;
        config.profile_environment = vec!["PATH".into(), "path".into()];
        assert!(config.validate().is_err());
        config.profile_environment = vec!["BAD=VALUE".into()];
        assert!(config.validate().is_err());
        config.profile_environment.clear();
        config.inherit_environment = true;
        assert!(config.validate().is_err());
        config.autonomy = SubscriptionCliAutonomy::Unrestricted;
        config.validate()?;
        config.autonomy = SubscriptionCliAutonomy::ReadOnly;
        config.inherit_environment = false;
        config.load_native_customizations = true;
        assert!(config.validate().is_err());
        config.autonomy = SubscriptionCliAutonomy::Unrestricted;
        config.validate()?;
        Ok(())
    }
}
