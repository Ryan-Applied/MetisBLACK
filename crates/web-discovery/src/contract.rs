use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use storage::hash;
use url::Url;

pub const DISCOVERY_SCHEMA_VERSION: u32 = 1;

const MAX_SEEDS: usize = 256;
const MAX_ORIGINS: usize = 256;
const MAX_DEPTH: u16 = 64;
const MAX_RESOURCES: u32 = 100_000;
const MAX_DOCUMENT_BYTES: u32 = 16 * 1024 * 1024;
const MAX_REFERENCES_PER_DOCUMENT: u32 = 20_000;
const MAX_FORMS_PER_DOCUMENT: u32 = 2_000;
const MAX_CONTROLS_PER_FORM: u32 = 2_000;
const MAX_OPENAPI_OPERATIONS: u32 = 50_000;
const MAX_OMISSIONS: u32 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryBounds {
    pub max_depth: u16,
    pub max_resources: u32,
    pub max_document_bytes: u32,
    pub max_references_per_document: u32,
    pub max_forms_per_document: u32,
    pub max_controls_per_form: u32,
    pub max_openapi_operations: u32,
    pub max_omissions: u32,
}

impl Default for DiscoveryBounds {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_resources: 64,
            max_document_bytes: 1024 * 1024,
            max_references_per_document: 256,
            max_forms_per_document: 64,
            max_controls_per_form: 128,
            max_openapi_operations: 1_000,
            max_omissions: 1_000,
        }
    }
}

impl DiscoveryBounds {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_depth <= MAX_DEPTH, "max_depth exceeds {MAX_DEPTH}");
        validate_positive_bound(self.max_resources, MAX_RESOURCES, "max_resources")?;
        validate_positive_bound(
            self.max_document_bytes,
            MAX_DOCUMENT_BYTES,
            "max_document_bytes",
        )?;
        validate_positive_bound(
            self.max_references_per_document,
            MAX_REFERENCES_PER_DOCUMENT,
            "max_references_per_document",
        )?;
        validate_positive_bound(
            self.max_forms_per_document,
            MAX_FORMS_PER_DOCUMENT,
            "max_forms_per_document",
        )?;
        validate_positive_bound(
            self.max_controls_per_form,
            MAX_CONTROLS_PER_FORM,
            "max_controls_per_form",
        )?;
        validate_positive_bound(
            self.max_openapi_operations,
            MAX_OPENAPI_OPERATIONS,
            "max_openapi_operations",
        )?;
        validate_positive_bound(self.max_omissions, MAX_OMISSIONS, "max_omissions")?;
        Ok(())
    }
}

fn validate_positive_bound(value: u32, ceiling: u32, name: &str) -> Result<()> {
    ensure!(
        value > 0 && value <= ceiling,
        "{name} must be 1..={ceiling}"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub seed_urls: Vec<String>,
    /// Exact HTTP(S) origins. An empty list is canonicalized to the seed origins.
    pub allowed_origins: Vec<String>,
    pub bounds: DiscoveryBounds,
}

impl DiscoveryPlan {
    pub fn canonicalized(&self) -> Result<Self> {
        ensure!(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "unsupported discovery plan schema version"
        );
        ensure!(
            !self.plan_id.trim().is_empty() && self.plan_id.len() <= 160,
            "plan_id must contain 1..=160 characters"
        );
        self.bounds.validate()?;
        ensure!(
            !self.seed_urls.is_empty() && self.seed_urls.len() <= MAX_SEEDS,
            "seed_urls must contain 1..={MAX_SEEDS} entries"
        );
        ensure!(
            self.allowed_origins.len() <= MAX_ORIGINS,
            "allowed_origins exceeds {MAX_ORIGINS} entries"
        );

        let mut seed_urls = BTreeSet::new();
        let mut seed_origins = BTreeSet::new();
        for seed in &self.seed_urls {
            let canonical = canonical_http_url(seed)?;
            seed_origins.insert(origin_of(&canonical)?);
            seed_urls.insert(canonical);
        }
        ensure!(
            seed_urls.len() <= usize::try_from(self.bounds.max_resources)?,
            "seed URL count exceeds max_resources"
        );

        let mut allowed_origins = BTreeSet::new();
        if self.allowed_origins.is_empty() {
            allowed_origins = seed_origins;
        } else {
            for origin in &self.allowed_origins {
                allowed_origins.insert(canonical_origin(origin)?);
            }
        }
        for seed in &seed_urls {
            ensure!(
                allowed_origins.contains(&origin_of(seed)?),
                "seed URL origin is not allowed: {seed}"
            );
        }

        Ok(Self {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            plan_id: self.plan_id.trim().to_owned(),
            seed_urls: seed_urls.into_iter().collect(),
            allowed_origins: allowed_origins.into_iter().collect(),
            bounds: self.bounds.clone(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.canonicalized().map(|_| ())
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&self.canonicalized()?)?))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Automatic,
    Html,
    JavaScript,
    Robots,
    Sitemap,
    OpenApi,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Observed,
    Declared,
    Omitted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceLineage {
    Plan {
        plan_hash: String,
    },
    Receipt {
        receipt_id: String,
        receipt_content_hash: String,
        body_hash: String,
        source_url: String,
    },
    FailureReceipt {
        receipt_id: String,
        receipt_content_hash: String,
        source_url: String,
    },
}

impl SourceLineage {
    pub(crate) fn validate(&self, expected_plan_hash: &str) -> Result<()> {
        match self {
            Self::Plan { plan_hash } => ensure!(
                is_sha256(plan_hash) && plan_hash == expected_plan_hash,
                "invalid plan lineage"
            ),
            Self::Receipt {
                receipt_id,
                receipt_content_hash,
                body_hash,
                source_url,
            } => {
                ensure!(
                    !receipt_id.is_empty() && receipt_id.len() <= 256,
                    "invalid receipt id"
                );
                ensure!(
                    is_sha256(receipt_content_hash) && is_sha256(body_hash),
                    "receipt lineage hashes must be SHA-256"
                );
                canonical_http_url(source_url)?;
            }
            Self::FailureReceipt {
                receipt_id,
                receipt_content_hash,
                source_url,
            } => {
                ensure!(
                    !receipt_id.is_empty() && receipt_id.len() <= 256,
                    "invalid failure receipt id"
                );
                ensure!(
                    is_sha256(receipt_content_hash),
                    "failure receipt hash must be SHA-256"
                );
                canonical_http_url(source_url)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLineage {
    pub receipt_id: String,
    pub receipt_content_hash: String,
}

impl ReceiptLineage {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.receipt_id.is_empty() && self.receipt_id.len() <= 256,
            "invalid receipt id"
        );
        ensure!(
            is_sha256(&self.receipt_content_hash),
            "receipt content hash must be SHA-256"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryObservation {
    pub schema_version: u32,
    pub request_id: String,
    pub requested_url: String,
    pub effective_url: String,
    pub status_code: u16,
    pub media_type: Option<String>,
    pub body: String,
    pub body_hash: String,
    pub truncated: bool,
    pub receipt: ReceiptLineage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionFailureCode {
    Dns,
    Connection,
    Tls,
    Timeout,
    RedirectRejected,
    PolicyRejected,
    Transport,
    BodyUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryFailure {
    pub schema_version: u32,
    pub request_id: String,
    pub code: AcquisitionFailureCode,
    pub detail: String,
    pub receipt: ReceiptLineage,
}

impl DiscoveryObservation {
    pub fn from_body(
        request: &DiscoveryRequest,
        effective_url: impl Into<String>,
        status_code: u16,
        media_type: Option<String>,
        body: impl Into<String>,
        truncated: bool,
        receipt: ReceiptLineage,
    ) -> Self {
        let body = body.into();
        Self {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            requested_url: request.url.clone(),
            effective_url: effective_url.into(),
            status_code,
            media_type,
            body_hash: hash(body.as_bytes()),
            body,
            truncated,
            receipt,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub url: String,
    pub depth: u16,
    pub expected_kind: ResourceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ResourceRecord {
    pub url: String,
    pub depth: u16,
    pub kind: ResourceKind,
    pub state: EvidenceState,
    pub lineages: Vec<SourceLineage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FormControlShape {
    pub name: Option<String>,
    pub control_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FormShape {
    pub source_url: String,
    pub index: u32,
    pub method: String,
    pub action_url: String,
    pub controls: Vec<FormControlShape>,
    pub state: EvidenceState,
    pub lineage: SourceLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct DeclaredOperation {
    pub source_url: String,
    pub method: String,
    pub path_template: String,
    pub resolved_url_template: Option<String>,
    pub operation_id: Option<String>,
    pub state: EvidenceState,
    pub lineage: SourceLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RobotsDirectiveKind {
    Allow,
    Disallow,
    Sitemap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RobotsDirective {
    pub source_url: String,
    pub kind: RobotsDirectiveKind,
    pub value: String,
    pub resolved_url: Option<String>,
    pub state: EvidenceState,
    pub lineage: SourceLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    DepthLimit,
    ResourceLimit,
    ReferenceLimit,
    FormLimit,
    FormControlLimit,
    OpenApiOperationLimit,
    OmissionLimit,
    OutsideAllowedOrigin,
    UnsupportedScheme,
    MalformedReference,
    MalformedDocument,
    TruncatedInput,
    RemoteReference,
    UnsupportedOpenApiVersion,
    AcquisitionFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct OmissionRecord {
    pub subject: String,
    pub reason: OmissionReason,
    pub detail: String,
    pub state: EvidenceState,
    pub lineage: SourceLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ReverificationInput {
    pub sequence: u64,
    pub request_id: String,
    pub requested_url: String,
    pub effective_url: String,
    pub status_code: u16,
    pub media_type: Option<String>,
    pub captured_body_bytes: u32,
    pub body_hash: String,
    pub truncated: bool,
    pub receipt: ReceiptLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FailureReverificationInput {
    pub sequence: u64,
    pub request_id: String,
    pub requested_url: String,
    pub code: AcquisitionFailureCode,
    pub detail: String,
    pub receipt: ReceiptLineage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCheckpoint {
    pub schema_version: u32,
    pub plan_hash: String,
    pub transition_count: u64,
    pub frontier: Vec<DiscoveryRequest>,
    pub resources: Vec<ResourceRecord>,
    pub forms: Vec<FormShape>,
    pub operations: Vec<DeclaredOperation>,
    pub robots_directives: Vec<RobotsDirective>,
    pub omissions: Vec<OmissionRecord>,
    pub reverification_inputs: Vec<ReverificationInput>,
    pub failure_reverification_inputs: Vec<FailureReverificationInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryArtifact {
    pub schema_version: u32,
    pub plan_hash: String,
    pub checkpoint_hash: String,
    pub complete: bool,
    pub resources: Vec<ResourceRecord>,
    pub forms: Vec<FormShape>,
    pub operations: Vec<DeclaredOperation>,
    pub robots_directives: Vec<RobotsDirective>,
    pub omissions: Vec<OmissionRecord>,
    pub reverification_inputs: Vec<ReverificationInput>,
    pub failure_reverification_inputs: Vec<FailureReverificationInput>,
}

impl DiscoveryArtifact {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "unsupported discovery artifact schema version"
        );
        ensure!(
            is_sha256(&self.plan_hash) && is_sha256(&self.checkpoint_hash),
            "artifact lineage hashes must be SHA-256"
        );
        let mut resource_urls = BTreeSet::new();
        for resource in &self.resources {
            ensure!(
                canonical_http_url(&resource.url)? == resource.url,
                "resource URL is not canonical"
            );
            ensure!(
                resource_urls.insert(&resource.url),
                "duplicate resource URL"
            );
            ensure!(!resource.lineages.is_empty(), "resource lacks lineage");
            for lineage in &resource.lineages {
                lineage.validate(&self.plan_hash)?;
                validate_artifact_lineage_replay(
                    lineage,
                    &self.reverification_inputs,
                    &self.failure_reverification_inputs,
                )?;
            }
        }
        for form in &self.forms {
            ensure!(
                form.state == EvidenceState::Observed,
                "form must be observed"
            );
            validate_observed_derived_lineage(
                &form.lineage,
                &self.plan_hash,
                &form.source_url,
                "form",
            )?;
            validate_artifact_lineage_replay(
                &form.lineage,
                &self.reverification_inputs,
                &self.failure_reverification_inputs,
            )?;
        }
        for operation in &self.operations {
            ensure!(
                operation.state == EvidenceState::Declared,
                "OpenAPI operation must be declared"
            );
            validate_observed_derived_lineage(
                &operation.lineage,
                &self.plan_hash,
                &operation.source_url,
                "OpenAPI operation",
            )?;
            validate_artifact_lineage_replay(
                &operation.lineage,
                &self.reverification_inputs,
                &self.failure_reverification_inputs,
            )?;
        }
        for directive in &self.robots_directives {
            ensure!(
                directive.state == EvidenceState::Observed,
                "robots directive must be observed"
            );
            validate_observed_derived_lineage(
                &directive.lineage,
                &self.plan_hash,
                &directive.source_url,
                "robots directive",
            )?;
            validate_artifact_lineage_replay(
                &directive.lineage,
                &self.reverification_inputs,
                &self.failure_reverification_inputs,
            )?;
        }
        for omission in &self.omissions {
            ensure!(
                omission.state == EvidenceState::Omitted,
                "omission must have omitted state"
            );
            omission.lineage.validate(&self.plan_hash)?;
            ensure!(
                !matches!(omission.lineage, SourceLineage::Plan { .. }),
                "omission cannot claim plan lineage"
            );
            validate_artifact_lineage_replay(
                &omission.lineage,
                &self.reverification_inputs,
                &self.failure_reverification_inputs,
            )?;
        }
        for input in &self.reverification_inputs {
            ensure!(
                is_sha256(&input.body_hash),
                "invalid re-verification body hash"
            );
            input.receipt.validate()?;
            canonical_http_url(&input.requested_url)?;
            canonical_http_url(&input.effective_url)?;
        }
        for input in &self.failure_reverification_inputs {
            ensure!(
                !input.detail.is_empty() && input.detail.len() <= 1_024,
                "invalid acquisition failure detail"
            );
            input.receipt.validate()?;
            canonical_http_url(&input.requested_url)?;
        }
        validate_sequences(
            self.reverification_inputs
                .iter()
                .map(|input| input.sequence),
            self.failure_reverification_inputs
                .iter()
                .map(|input| input.sequence),
            None,
        )?;
        ensure!(
            self.canonicalized() == *self,
            "artifact collections are not canonical"
        );
        Ok(())
    }

    pub fn canonical_hash(&self) -> Result<String> {
        let canonical = self.canonicalized();
        canonical.validate()?;
        Ok(hash(&serde_json::to_vec(&canonical)?))
    }

    pub(crate) fn canonicalized(&self) -> Self {
        let mut value = self.clone();
        sort_dedup(&mut value.resources);
        sort_dedup(&mut value.forms);
        sort_dedup(&mut value.operations);
        sort_dedup(&mut value.robots_directives);
        sort_dedup(&mut value.omissions);
        sort_dedup(&mut value.reverification_inputs);
        sort_dedup(&mut value.failure_reverification_inputs);
        value
    }
}

pub(crate) fn validate_observed_derived_lineage(
    lineage: &SourceLineage,
    expected_plan_hash: &str,
    expected_source_url: &str,
    record_kind: &str,
) -> Result<()> {
    ensure!(
        canonical_http_url(expected_source_url)? == expected_source_url,
        "{record_kind} source URL is not canonical"
    );
    lineage.validate(expected_plan_hash)?;
    match lineage {
        SourceLineage::Receipt { source_url, .. } => ensure!(
            source_url == expected_source_url,
            "{record_kind} lineage source URL mismatch"
        ),
        SourceLineage::Plan { .. } => ensure!(false, "{record_kind} cannot claim plan lineage"),
        SourceLineage::FailureReceipt { .. } => {
            ensure!(false, "{record_kind} cannot claim failure receipt lineage")
        }
    };
    Ok(())
}

fn validate_artifact_lineage_replay(
    lineage: &SourceLineage,
    observations: &[ReverificationInput],
    failures: &[FailureReverificationInput],
) -> Result<()> {
    match lineage {
        SourceLineage::Plan { .. } => {}
        SourceLineage::Receipt {
            receipt_id,
            receipt_content_hash,
            body_hash,
            source_url,
        } => ensure!(
            observations.iter().any(|input| {
                input.receipt.receipt_id == *receipt_id
                    && input.receipt.receipt_content_hash == *receipt_content_hash
                    && input.body_hash == *body_hash
                    && input.effective_url == *source_url
            }),
            "receipt lineage lacks a matching replay input"
        ),
        SourceLineage::FailureReceipt {
            receipt_id,
            receipt_content_hash,
            source_url,
        } => ensure!(
            failures.iter().any(|input| {
                input.receipt.receipt_id == *receipt_id
                    && input.receipt.receipt_content_hash == *receipt_content_hash
                    && input.requested_url == *source_url
            }),
            "failure lineage lacks a matching replay input"
        ),
    };
    Ok(())
}

pub(crate) fn canonical_http_url(input: &str) -> Result<String> {
    ensure!(
        !input.is_empty() && input.len() <= 8_192,
        "URL must contain 1..=8192 bytes"
    );
    let mut parsed = Url::parse(input).with_context(|| format!("invalid URL: {input}"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "URL must use HTTP(S)"
    );
    ensure!(
        parsed.host_str().is_some(),
        "HTTP(S) URL must contain a host"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "URL user information is not permitted"
    );
    parsed.set_fragment(None);
    Ok(parsed.into())
}

pub(crate) fn canonical_origin(input: &str) -> Result<String> {
    let parsed = Url::parse(input).with_context(|| format!("invalid origin: {input}"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "origin must be HTTP(S)"
    );
    ensure!(
        parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "allowed origin cannot include credentials, path, query, or fragment"
    );
    Ok(parsed.origin().ascii_serialization())
}

pub(crate) fn origin_of(input: &str) -> Result<String> {
    let parsed = Url::parse(input)?;
    Ok(parsed.origin().ascii_serialization())
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn sort_dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}

pub(crate) fn validate_sequences(
    observations: impl Iterator<Item = u64>,
    failures: impl Iterator<Item = u64>,
    expected_count: Option<u64>,
) -> Result<()> {
    let mut values: Vec<_> = observations.chain(failures).collect();
    values.sort_unstable();
    let count = u64::try_from(values.len())?;
    if let Some(expected) = expected_count {
        ensure!(
            count == expected,
            "transition count does not match replay inputs"
        );
    }
    ensure!(
        values.iter().copied().eq(0..count),
        "replay sequences must be unique and contiguous from zero"
    );
    Ok(())
}
