use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use storage::hash;
use url::Url;

use crate::JsonShape;

pub const API_VALIDATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_SELECTORS: u32 = 10_000;
pub const MAX_DOCUMENT_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_REF_DEPTH: u16 = 64;
pub const MAX_REF_NODES: u32 = 100_000;
pub const MAX_SCHEMA_DEPTH: u16 = 64;
pub const MAX_SCHEMA_NODES: u32 = 100_000;
pub const MAX_PROPERTIES: u32 = 20_000;
pub const MAX_SHAPE_DEPTH: u16 = 64;
pub const MAX_SHAPE_NODES: u32 = 100_000;
pub const MAX_ARRAY_ITEMS: u32 = 10_000;
pub const MAX_RESULTS: u32 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidationBounds {
    pub max_selectors: u32,
    pub max_document_bytes: u32,
    pub max_response_bytes: u32,
    pub max_ref_depth: u16,
    pub max_ref_nodes: u32,
    pub max_schema_depth: u16,
    pub max_schema_nodes: u32,
    pub max_properties: u32,
    pub max_shape_depth: u16,
    pub max_shape_nodes: u32,
    pub max_array_items: u32,
    pub max_results: u32,
}

impl Default for ValidationBounds {
    fn default() -> Self {
        Self {
            max_selectors: 128,
            max_document_bytes: 2 * 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            max_ref_depth: 16,
            max_ref_nodes: 10_000,
            max_schema_depth: 24,
            max_schema_nodes: 10_000,
            max_properties: 2_000,
            max_shape_depth: 24,
            max_shape_nodes: 10_000,
            max_array_items: 1_000,
            max_results: 10_000,
        }
    }
}

impl ValidationBounds {
    pub fn validate(&self) -> Result<()> {
        positive(self.max_selectors, MAX_SELECTORS, "max_selectors")?;
        positive(
            self.max_document_bytes,
            MAX_DOCUMENT_BYTES,
            "max_document_bytes",
        )?;
        positive(
            self.max_response_bytes,
            MAX_RESPONSE_BYTES,
            "max_response_bytes",
        )?;
        depth(self.max_ref_depth, MAX_REF_DEPTH, "max_ref_depth")?;
        positive(self.max_ref_nodes, MAX_REF_NODES, "max_ref_nodes")?;
        depth(self.max_schema_depth, MAX_SCHEMA_DEPTH, "max_schema_depth")?;
        positive(self.max_schema_nodes, MAX_SCHEMA_NODES, "max_schema_nodes")?;
        positive(self.max_properties, MAX_PROPERTIES, "max_properties")?;
        depth(self.max_shape_depth, MAX_SHAPE_DEPTH, "max_shape_depth")?;
        positive(self.max_shape_nodes, MAX_SHAPE_NODES, "max_shape_nodes")?;
        positive(self.max_array_items, MAX_ARRAY_ITEMS, "max_array_items")?;
        positive(self.max_results, MAX_RESULTS, "max_results")?;
        Ok(())
    }
}

fn positive(value: u32, ceiling: u32, field: &str) -> Result<()> {
    ensure!(
        value > 0 && value <= ceiling,
        "{field} must be 1..={ceiling}"
    );
    Ok(())
}

fn depth(value: u16, ceiling: u16, field: &str) -> Result<()> {
    ensure!(
        value > 0 && value <= ceiling,
        "{field} must be 1..={ceiling}"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SafeMethod {
    Get,
    Head,
    Options,
}

impl SafeMethod {
    pub fn as_lowercase(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Options => "options",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct OperationSelector {
    pub discovery_plan_hash: String,
    pub openapi_source_url: String,
    pub method: SafeMethod,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl OperationSelector {
    pub fn validate(&self) -> Result<()> {
        validate_hash(&self.discovery_plan_hash, "discovery_plan_hash")?;
        ensure!(
            canonical_http_url(&self.openapi_source_url)? == self.openapi_source_url,
            "openapi_source_url is not canonical"
        );
        ensure!(
            self.path.starts_with('/') && self.path.len() <= 4_096,
            "path must be an absolute OpenAPI path of at most 4096 characters"
        );
        ensure!(
            !self.path.contains('#') && !self.path.contains('?'),
            "selector path must not contain query or fragment components"
        );
        ensure!(
            !self.path.contains('{') && !self.path.contains('}'),
            "selector path contains unresolved parameters"
        );
        if let Some(operation_id) = &self.operation_id {
            ensure!(
                !operation_id.trim().is_empty()
                    && operation_id.len() <= 512
                    && operation_id.trim() == operation_id,
                "operation_id must contain 1..=512 trimmed characters"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiValidationPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub selectors: Vec<OperationSelector>,
    pub bounds: ValidationBounds,
}

impl ApiValidationPlan {
    pub fn canonicalized(&self) -> Result<Self> {
        ensure!(
            self.schema_version == API_VALIDATION_SCHEMA_VERSION,
            "unsupported API validation plan schema version"
        );
        ensure!(
            !self.plan_id.trim().is_empty()
                && self.plan_id.len() <= 160
                && self.plan_id.trim() == self.plan_id,
            "plan_id must contain 1..=160 trimmed characters"
        );
        self.bounds.validate()?;
        ensure!(
            !self.selectors.is_empty()
                && self.selectors.len() <= usize::try_from(self.bounds.max_selectors)?,
            "selectors must contain 1..={} entries",
            self.bounds.max_selectors
        );
        ensure!(
            self.selectors.len().saturating_mul(2) <= usize::try_from(self.bounds.max_results)?,
            "max_results must cover a primary and independent replay for every selector"
        );
        let selectors: BTreeSet<_> = self
            .selectors
            .iter()
            .map(|selector| {
                selector.validate()?;
                Ok(selector.clone())
            })
            .collect::<Result<_>>()?;
        ensure!(
            selectors.len() == self.selectors.len(),
            "duplicate operation selector"
        );
        Ok(Self {
            schema_version: API_VALIDATION_SCHEMA_VERSION,
            plan_id: self.plan_id.clone(),
            selectors: selectors.into_iter().collect(),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLineage {
    pub receipt_id: String,
    pub receipt_content_hash: String,
}

impl ReceiptLineage {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.receipt_id.trim().is_empty()
                && self.receipt_id.len() <= 512
                && self.receipt_id.trim() == self.receipt_id,
            "receipt_id must contain 1..=512 trimmed characters"
        );
        validate_hash(&self.receipt_content_hash, "receipt_content_hash")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "status_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StatusSelector {
    Exact { status: u16 },
    Class { hundred: u16 },
    Default,
}

impl StatusSelector {
    pub fn matches(&self, status: u16) -> bool {
        match self {
            Self::Exact { status: expected } => status == *expected,
            Self::Class { hundred } => status / 100 == *hundred,
            Self::Default => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedKeyword {
    pub location: String,
    pub keyword: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "schema_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalizedSchema {
    Any,
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Object {
        required: Vec<String>,
        properties: BTreeMap<String, NormalizedSchema>,
    },
    Array {
        items: Box<NormalizedSchema>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaContract {
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<NormalizedSchema>,
    pub unsupported: Vec<UnsupportedKeyword>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseContract {
    pub status: StatusSelector,
    pub media: Vec<MediaContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationContract {
    pub selector: OperationSelector,
    /// Deterministic executable instance identifier. This is distinct from the
    /// optional OpenAPI `operationId` retained in `selector.operation_id`.
    pub probe_id: String,
    pub server_url: String,
    pub request_url: String,
    pub responses: Vec<ResponseContract>,
}

impl OperationContract {
    pub fn canonical_hash(&self) -> Result<String> {
        ensure!(
            valid_probe_id(&self.probe_id),
            "probe_id must be api-schema- followed by a lowercase SHA-256 value"
        );
        Ok(hash(&serde_json::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedOpenApi {
    pub schema_version: u32,
    pub source_url: String,
    pub document_hash: String,
    pub source_receipt: ReceiptLineage,
    pub operations: Vec<OperationContract>,
}

impl NormalizedOpenApi {
    pub fn canonical_hash(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == API_VALIDATION_SCHEMA_VERSION,
            "unsupported normalized OpenAPI schema version"
        );
        ensure!(
            canonical_http_url(&self.source_url)? == self.source_url,
            "source_url is not canonical"
        );
        validate_hash(&self.document_hash, "document_hash")?;
        self.source_receipt.validate()?;
        ensure!(
            !self.operations.is_empty(),
            "no selected operations normalized"
        );
        let mut previous = None;
        for operation in &self.operations {
            operation.selector.validate()?;
            ensure!(
                valid_probe_id(&operation.probe_id),
                "invalid API schema probe_id"
            );
            ensure!(
                operation.probe_id
                    == make_probe_id(
                        &operation.selector,
                        &operation.server_url,
                        &operation.request_url,
                        &operation.responses
                    )?,
                "API schema probe_id does not match its canonical contract"
            );
            ensure!(
                operation.selector.openapi_source_url == self.source_url,
                "operation source URL does not match document"
            );
            ensure!(
                canonical_http_url(&operation.server_url)? == operation.server_url,
                "server_url is not canonical"
            );
            ensure!(
                materialize_request_url(&operation.server_url, &operation.selector.path)?
                    == operation.request_url,
                "request_url is not the exact canonical server/path materialization"
            );
            ensure!(
                !operation.responses.is_empty(),
                "operation has no responses"
            );
            let encoded = serde_json::to_vec(&operation.selector)?;
            if let Some(prior) = &previous {
                ensure!(*prior < encoded, "operations are not canonical and unique");
            }
            previous = Some(encoded);
            validate_responses(&operation.responses)?;
        }
        Ok(())
    }
}

fn validate_responses(responses: &[ResponseContract]) -> Result<()> {
    let mut statuses = BTreeSet::new();
    let mut previous_status = None;
    for response in responses {
        match response.status {
            StatusSelector::Exact { status } => ensure!(
                (100..=599).contains(&status),
                "exact response status out of range"
            ),
            StatusSelector::Class { hundred } => ensure!(
                (1..=5).contains(&hundred),
                "response status class out of range"
            ),
            StatusSelector::Default => {}
        }
        ensure!(
            statuses.insert(response.status.clone()),
            "duplicate response status"
        );
        if let Some(previous) = &previous_status {
            ensure!(
                previous < &response.status,
                "response statuses are not canonically ordered"
            );
        }
        previous_status = Some(response.status.clone());
        let mut media = BTreeSet::new();
        let mut previous_media = None;
        for contract in &response.media {
            ensure!(
                normalize_media_type(&contract.media_type)? == contract.media_type,
                "media type is not canonical"
            );
            ensure!(
                media.insert(contract.media_type.clone()),
                "duplicate media type"
            );
            if let Some(previous) = &previous_media {
                ensure!(
                    previous < &contract.media_type,
                    "response media types are not canonically ordered"
                );
            }
            previous_media = Some(contract.media_type.clone());
            let mut unsupported = contract.unsupported.clone();
            unsupported.sort();
            unsupported.dedup();
            ensure!(
                unsupported == contract.unsupported,
                "unsupported keywords are not canonical"
            );
            ensure!(
                contract.unsupported.iter().all(|entry| {
                    !entry.location.trim().is_empty()
                        && !entry.keyword.trim().is_empty()
                        && entry.location.len() <= 16_384
                        && entry.keyword.len() <= 1_024
                }),
                "unsupported keyword metadata is invalid"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActualResponseObservation {
    pub selector: OperationSelector,
    pub probe_id: String,
    pub contract_hash: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_shape: Option<JsonShape>,
    pub body_present: bool,
    pub body_truncated: bool,
    pub malformed_json: bool,
    pub shape_truncated: bool,
    pub receipt: ReceiptLineage,
}

impl ActualResponseObservation {
    pub fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        ensure!(
            valid_probe_id(&self.probe_id),
            "invalid API schema probe_id"
        );
        validate_hash(&self.contract_hash, "contract_hash")?;
        ensure!((100..=599).contains(&self.status), "status out of range");
        if let Some(media_type) = &self.media_type {
            ensure!(
                normalize_media_type(media_type)? == *media_type,
                "media_type is not canonical"
            );
        }
        ensure!(
            self.body_present || self.json_shape.is_none(),
            "body-free observation cannot have a JSON shape"
        );
        ensure!(
            !(self.malformed_json && self.json_shape.is_some()),
            "malformed JSON cannot have a JSON shape"
        );
        self.receipt.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConformanceReason {
    TransientStatus {
        status: u16,
    },
    StatusUndeclared {
        status: u16,
    },
    MediaTypeMissing,
    MediaTypeUndeclared {
        media_type: String,
    },
    ResponseSchemaMissing,
    BodyMissing,
    BodyTruncated,
    MalformedJson,
    ShapeTruncated,
    JsonShapeUnavailable,
    UnsupportedSchema {
        keywords: Vec<UnsupportedKeyword>,
    },
    TypeMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    RequiredPropertyMissing {
        path: String,
        property: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "classification", rename_all = "snake_case", deny_unknown_fields)]
pub enum Conformance {
    Conforming,
    Violating { reasons: Vec<ConformanceReason> },
    Inconclusive { reasons: Vec<ConformanceReason> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub observation: ActualResponseObservation,
    pub result: Conformance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(
    tag = "replay_classification",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReplayClassification {
    Reproduced {
        violation_hash: String,
    },
    PrimaryNotViolating,
    IndependentConforming,
    IndependentInconclusive,
    ObservationMismatch {
        violation_hash: String,
        primary_status: u16,
        independent_status: u16,
        primary_media_type: Option<String>,
        independent_media_type: Option<String>,
    },
    ViolationMismatch {
        primary_violation_hash: String,
        independent_violation_hash: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayComparison {
    pub selector: OperationSelector,
    pub probe_id: String,
    pub contract_hash: String,
    pub primary: ValidationRecord,
    pub independent: ValidationRecord,
    pub classification: ReplayClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiValidationCheckpoint {
    pub schema_version: u32,
    pub plan_hash: String,
    pub contract_set_hash: String,
    pub pending: Vec<OperationSelector>,
    pub records: Vec<ValidationRecord>,
    pub replay_comparisons: Vec<ReplayComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiValidationArtifact {
    pub schema_version: u32,
    pub plan_hash: String,
    pub contract_set_hash: String,
    pub contracts: Vec<NormalizedOpenApi>,
    pub records: Vec<ValidationRecord>,
    pub replay_comparisons: Vec<ReplayComparison>,
    pub source_receipts: Vec<ReceiptLineage>,
    pub response_receipts: Vec<ReceiptLineage>,
}

impl ApiValidationArtifact {
    pub fn canonical_hash(&self) -> Result<String> {
        crate::validate::validate_artifact_structure(self)?;
        Ok(hash(&serde_json::to_vec(self)?))
    }

    pub fn verify(&self, plan: &ApiValidationPlan) -> Result<()> {
        crate::validate::verify_artifact(plan, self)
    }

    pub fn verified_canonical_hash(&self, plan: &ApiValidationPlan) -> Result<String> {
        self.verify(plan)?;
        self.canonical_hash()
    }
}

pub(crate) fn validate_hash(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be a lowercase SHA-256 value"
    );
    Ok(())
}

pub(crate) fn canonical_http_url(input: &str) -> Result<String> {
    let mut url = Url::parse(input)?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "URL must use HTTP(S)"
    );
    ensure!(url.host_str().is_some(), "URL must have a host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL must not contain userinfo"
    );
    ensure!(url.fragment().is_none(), "URL must not contain a fragment");
    if (url.scheme() == "http" && url.port() == Some(80))
        || (url.scheme() == "https" && url.port() == Some(443))
    {
        url.set_port(None)
            .map_err(|()| anyhow::anyhow!("invalid URL port"))?;
    }
    Ok(url.to_string())
}

pub(crate) fn normalize_media_type(input: &str) -> Result<String> {
    let base = input
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let (kind, subtype) = base
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("media type must contain type/subtype"))?;
    ensure!(
        !kind.is_empty()
            && !subtype.is_empty()
            && kind.bytes().all(media_token)
            && subtype.bytes().all(media_token),
        "invalid media type"
    );
    ensure!(
        (!kind.contains('*') && !subtype.contains('*'))
            || (kind == "*" && subtype == "*")
            || (!kind.contains('*') && subtype == "*"),
        "unsupported media wildcard"
    );
    Ok(base)
}

fn media_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$&^_.+-*".contains(&byte)
}

pub(crate) fn canonical_contract_set_hash(contracts: &[NormalizedOpenApi]) -> Result<String> {
    Ok(hash(&serde_json::to_vec(contracts)?))
}

pub(crate) fn make_probe_id(
    selector: &OperationSelector,
    server_url: &str,
    request_url: &str,
    responses: &[ResponseContract],
) -> Result<String> {
    let encoded = serde_json::to_vec(&(selector, server_url, request_url, responses))?;
    Ok(format!("api-schema-{}", hash(&encoded)))
}

fn valid_probe_id(value: &str) -> bool {
    value
        .strip_prefix("api-schema-")
        .is_some_and(|digest| validate_hash(digest, "probe_id").is_ok())
}

pub fn materialize_request_url(server_url: &str, path: &str) -> Result<String> {
    ensure!(
        path.starts_with('/') && !path.contains(['?', '#', '{', '}']),
        "request path must be exact, absolute, and contain no variables"
    );
    let mut server = Url::parse(&canonical_http_url(server_url)?)?;
    ensure!(
        server.query().is_none()
            && server.fragment().is_none()
            && server.username().is_empty()
            && server.password().is_none(),
        "server URL cannot carry query, fragment, or userinfo"
    );
    let base = server.path().trim_end_matches('/');
    let combined = if base.is_empty() {
        path.to_owned()
    } else {
        format!("{base}{path}")
    };
    server.set_path(&combined);
    canonical_http_url(server.as_str())
}
