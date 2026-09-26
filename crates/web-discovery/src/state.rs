use crate::{
    contract::{
        canonical_http_url, origin_of, sort_dedup, validate_observed_derived_lineage,
        validate_sequences, DiscoveryArtifact, DiscoveryCheckpoint, DiscoveryFailure,
        DiscoveryObservation, DiscoveryPlan, DiscoveryRequest, EvidenceState,
        FailureReverificationInput, OmissionReason, OmissionRecord, ResourceKind, ResourceRecord,
        ReverificationInput, SourceLineage, DISCOVERY_SCHEMA_VERSION,
    },
    parse::{
        parse_html, parse_javascript, parse_openapi, parse_robots, parse_sitemap,
        CandidateReference, ParsedDocument,
    },
};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use storage::hash;
use url::Url;

/// A pure state machine. It consumes already-receipted observations and never
/// performs network I/O. The first frontier item is always the only valid next
/// observation, which makes transitions and replay independent of scheduling.
#[derive(Debug, Clone)]
pub struct DiscoverySession {
    plan: DiscoveryPlan,
    checkpoint: DiscoveryCheckpoint,
}

impl DiscoverySession {
    pub fn start(plan: DiscoveryPlan) -> Result<Self> {
        let plan = plan.canonicalized()?;
        let plan_hash = plan.fingerprint()?;
        let plan_lineage = SourceLineage::Plan {
            plan_hash: plan_hash.clone(),
        };
        let mut frontier = Vec::new();
        let mut resources = Vec::new();
        for seed in &plan.seed_urls {
            let kind = infer_kind_from_url(seed, ResourceKind::Automatic);
            frontier.push(request(&plan_hash, seed, 0, kind)?);
            resources.push(ResourceRecord {
                url: seed.clone(),
                depth: 0,
                kind,
                state: EvidenceState::Declared,
                lineages: vec![plan_lineage.clone()],
            });
        }
        frontier.sort_by(frontier_order);
        resources.sort();
        let checkpoint = DiscoveryCheckpoint {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            plan_hash,
            transition_count: 0,
            frontier,
            resources,
            forms: vec![],
            operations: vec![],
            robots_directives: vec![],
            omissions: vec![],
            reverification_inputs: vec![],
            failure_reverification_inputs: vec![],
        };
        let session = Self { plan, checkpoint };
        session.validate()?;
        Ok(session)
    }

    pub fn resume(plan: DiscoveryPlan, checkpoint: DiscoveryCheckpoint) -> Result<Self> {
        let session = Self {
            plan: plan.canonicalized()?,
            checkpoint,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn plan(&self) -> &DiscoveryPlan {
        &self.plan
    }

    pub fn checkpoint(&self) -> &DiscoveryCheckpoint {
        &self.checkpoint
    }

    pub fn next_request(&self) -> Option<&DiscoveryRequest> {
        self.checkpoint.frontier.first()
    }

    pub fn is_complete(&self) -> bool {
        self.checkpoint.frontier.is_empty()
    }

    pub fn apply_observation(&mut self, observation: DiscoveryObservation) -> Result<()> {
        self.validate()?;
        let expected = self
            .next_request()
            .context("discovery checkpoint has no pending request")?
            .clone();
        validate_observation(&self.plan, &expected, &observation)?;

        let requested_url = canonical_http_url(&observation.requested_url)?;
        let effective_url = canonical_http_url(&observation.effective_url)?;
        let body_bytes = u32::try_from(observation.body.len())?;
        let lineage = SourceLineage::Receipt {
            receipt_id: observation.receipt.receipt_id.clone(),
            receipt_content_hash: observation.receipt.receipt_content_hash.clone(),
            body_hash: observation.body_hash.clone(),
            source_url: effective_url.clone(),
        };

        self.checkpoint.frontier.remove(0);
        self.observe_resource(
            &requested_url,
            expected.depth,
            expected.expected_kind,
            &lineage,
        )?;
        if effective_url != requested_url && self.origin_allowed(&effective_url)? {
            self.observe_resource(
                &effective_url,
                expected.depth,
                expected.expected_kind,
                &lineage,
            )?;
        }
        self.checkpoint
            .reverification_inputs
            .push(ReverificationInput {
                sequence: self.checkpoint.transition_count,
                request_id: observation.request_id,
                requested_url,
                effective_url: effective_url.clone(),
                status_code: observation.status_code,
                media_type: observation.media_type.clone(),
                captured_body_bytes: body_bytes,
                body_hash: observation.body_hash,
                truncated: observation.truncated,
                receipt: observation.receipt,
            });

        if observation.truncated {
            self.push_omission(
                effective_url.clone(),
                OmissionReason::TruncatedInput,
                "parser consumed a receipt-backed truncated prefix; completeness is not claimed",
                lineage.clone(),
            );
        }

        if !self.origin_allowed(&effective_url)? {
            self.record_omitted_resource(
                &effective_url,
                expected.depth,
                expected.expected_kind,
                &lineage,
            )?;
            self.push_omission(
                effective_url,
                OmissionReason::OutsideAllowedOrigin,
                "effective response URL is outside the plan's exact allowed origins",
                lineage,
            );
            self.finish_transition();
            return self.validate();
        }

        if (200..400).contains(&observation.status_code) && !observation.body.is_empty() {
            let kind = classify_document(
                &effective_url,
                observation.media_type.as_deref(),
                &observation.body,
                expected.expected_kind,
            );
            self.observe_resource(&effective_url, expected.depth, kind, &lineage)?;
            let parsed = match kind {
                ResourceKind::Html => parse_html(
                    &effective_url,
                    &observation.body,
                    &self.plan.bounds,
                    &lineage,
                ),
                ResourceKind::JavaScript => Ok(parse_javascript(
                    &effective_url,
                    &observation.body,
                    &self.plan.bounds,
                )),
                ResourceKind::Robots => Ok(parse_robots(
                    &effective_url,
                    &observation.body,
                    &self.plan.bounds,
                    &lineage,
                )),
                ResourceKind::Sitemap => {
                    parse_sitemap(&effective_url, &observation.body, &self.plan.bounds)
                }
                ResourceKind::OpenApi => parse_openapi(
                    &effective_url,
                    &observation.body,
                    &self.plan.bounds,
                    &lineage,
                ),
                ResourceKind::Automatic => Ok(ParsedDocument::default()),
            };
            match parsed {
                Ok(parsed) => self.apply_parsed(parsed, expected.depth, &lineage)?,
                Err(error) => {
                    let message = bounded_detail(&error.to_string());
                    let reason = if message.contains("OpenAPI version") {
                        OmissionReason::UnsupportedOpenApiVersion
                    } else {
                        OmissionReason::MalformedDocument
                    };
                    self.push_omission(effective_url, reason, message, lineage);
                }
            }
        }

        self.finish_transition();
        self.validate()
    }

    /// Records a terminal, receipt-backed acquisition failure without
    /// fabricating an HTTP status, effective URL, or response body.
    pub fn apply_failure(&mut self, failure: DiscoveryFailure) -> Result<()> {
        self.validate()?;
        let expected = self
            .next_request()
            .context("discovery checkpoint has no pending request")?
            .clone();
        ensure!(
            failure.schema_version == DISCOVERY_SCHEMA_VERSION,
            "unsupported discovery failure schema version"
        );
        ensure!(
            failure.request_id == expected.request_id,
            "failure does not match the BFS frontier head"
        );
        ensure!(
            !failure.detail.trim().is_empty() && failure.detail.len() <= 1_024,
            "failure detail must contain 1..=1024 bytes"
        );
        failure.receipt.validate()?;

        let lineage = SourceLineage::FailureReceipt {
            receipt_id: failure.receipt.receipt_id.clone(),
            receipt_content_hash: failure.receipt.receipt_content_hash.clone(),
            source_url: expected.url.clone(),
        };
        self.checkpoint.frontier.remove(0);
        self.record_omitted_resource(
            &expected.url,
            expected.depth,
            expected.expected_kind,
            &lineage,
        )?;
        self.checkpoint
            .failure_reverification_inputs
            .push(FailureReverificationInput {
                sequence: self.checkpoint.transition_count,
                request_id: failure.request_id,
                requested_url: expected.url.clone(),
                code: failure.code,
                detail: failure.detail.clone(),
                receipt: failure.receipt,
            });
        self.push_omission(
            expected.url,
            OmissionReason::AcquisitionFailure,
            failure.detail,
            lineage,
        );
        self.finish_transition();
        self.validate()
    }

    pub fn checkpoint_hash(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(&canonical_checkpoint(
            self.checkpoint.clone(),
        ))?))
    }

    pub fn artifact(&self) -> Result<DiscoveryArtifact> {
        self.validate()?;
        let artifact = DiscoveryArtifact {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            plan_hash: self.checkpoint.plan_hash.clone(),
            checkpoint_hash: self.checkpoint_hash()?,
            complete: self.is_complete(),
            resources: self.checkpoint.resources.clone(),
            forms: self.checkpoint.forms.clone(),
            operations: self.checkpoint.operations.clone(),
            robots_directives: self.checkpoint.robots_directives.clone(),
            omissions: self.checkpoint.omissions.clone(),
            reverification_inputs: self.checkpoint.reverification_inputs.clone(),
            failure_reverification_inputs: self.checkpoint.failure_reverification_inputs.clone(),
        }
        .canonicalized();
        Ok(artifact)
    }

    pub fn into_checkpoint(self) -> DiscoveryCheckpoint {
        canonical_checkpoint(self.checkpoint)
    }

    pub fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        let plan_hash = self.plan.fingerprint()?;
        ensure!(
            self.checkpoint.schema_version == DISCOVERY_SCHEMA_VERSION,
            "unsupported discovery checkpoint schema version"
        );
        ensure!(
            self.checkpoint.plan_hash == plan_hash,
            "checkpoint plan fingerprint mismatch"
        );
        let maximum = usize::try_from(self.plan.bounds.max_resources)?;
        ensure!(
            self.checkpoint.resources.len() <= maximum && self.checkpoint.frontier.len() <= maximum,
            "checkpoint resource bound exceeded"
        );
        ensure!(
            self.checkpoint.operations.len()
                <= usize::try_from(self.plan.bounds.max_openapi_operations)?,
            "checkpoint OpenAPI operation bound exceeded"
        );
        ensure!(
            self.checkpoint.omissions.len() <= usize::try_from(self.plan.bounds.max_omissions)?,
            "checkpoint omission bound exceeded"
        );
        validate_sequences(
            self.checkpoint
                .reverification_inputs
                .iter()
                .map(|input| input.sequence),
            self.checkpoint
                .failure_reverification_inputs
                .iter()
                .map(|input| input.sequence),
            Some(self.checkpoint.transition_count),
        )?;

        let canonical = canonical_checkpoint(self.checkpoint.clone());
        ensure!(
            canonical == self.checkpoint,
            "checkpoint collections are not canonical"
        );
        let mut frontier_urls = BTreeSet::new();
        for item in &self.checkpoint.frontier {
            ensure!(
                item.schema_version == DISCOVERY_SCHEMA_VERSION,
                "unsupported request schema version"
            );
            let url = canonical_http_url(&item.url)?;
            ensure!(url == item.url, "frontier URL is not canonical");
            ensure!(
                item.depth <= self.plan.bounds.max_depth,
                "frontier exceeds depth bound"
            );
            ensure!(
                item.request_id
                    == request_id(&plan_hash, &item.url, item.depth, item.expected_kind)?,
                "frontier request id mismatch"
            );
            ensure!(frontier_urls.insert(&item.url), "duplicate frontier URL");
            ensure!(
                self.origin_allowed(&item.url)?,
                "frontier URL outside scope"
            );
            let resource = self
                .checkpoint
                .resources
                .iter()
                .find(|resource| resource.url == item.url)
                .context("frontier URL lacks a declared resource record")?;
            ensure!(
                resource.state == EvidenceState::Declared
                    && resource.depth == item.depth
                    && resource.kind == item.expected_kind,
                "frontier request contradicts its resource record"
            );
        }
        let mut resource_urls = BTreeSet::new();
        for resource in &self.checkpoint.resources {
            ensure!(
                canonical_http_url(&resource.url)? == resource.url,
                "resource URL is not canonical"
            );
            ensure!(
                resource_urls.insert(&resource.url),
                "duplicate resource URL"
            );
            ensure!(!resource.lineages.is_empty(), "resource lacks lineage");
            ensure!(
                resource.depth <= self.plan.bounds.max_depth,
                "resource exceeds depth bound"
            );
            for lineage in &resource.lineages {
                lineage.validate(&plan_hash)?;
                if matches!(lineage, SourceLineage::Plan { .. }) {
                    ensure!(
                        resource.depth == 0 && self.plan.seed_urls.contains(&resource.url),
                        "plan lineage is only valid on depth-zero seed resources"
                    );
                }
                self.validate_lineage_replay(lineage)?;
            }
            ensure!(
                resource.state != EvidenceState::Declared
                    || self
                        .checkpoint
                        .frontier
                        .iter()
                        .any(|request| request.url == resource.url),
                "declared resource is missing from the frontier"
            );
        }
        for form in &self.checkpoint.forms {
            ensure!(
                form.state == EvidenceState::Observed,
                "form must be observed"
            );
            ensure!(
                form.controls.len() <= usize::try_from(self.plan.bounds.max_controls_per_form)?,
                "form control bound exceeded"
            );
            validate_observed_derived_lineage(&form.lineage, &plan_hash, &form.source_url, "form")?;
            self.validate_lineage_replay(&form.lineage)?;
        }
        for operation in &self.checkpoint.operations {
            ensure!(
                operation.state == EvidenceState::Declared,
                "OpenAPI operation must be declared"
            );
            validate_observed_derived_lineage(
                &operation.lineage,
                &plan_hash,
                &operation.source_url,
                "OpenAPI operation",
            )?;
            self.validate_lineage_replay(&operation.lineage)?;
        }
        for directive in &self.checkpoint.robots_directives {
            ensure!(
                directive.state == EvidenceState::Observed,
                "robots directive must be observed"
            );
            validate_observed_derived_lineage(
                &directive.lineage,
                &plan_hash,
                &directive.source_url,
                "robots directive",
            )?;
            self.validate_lineage_replay(&directive.lineage)?;
        }
        for omission in &self.checkpoint.omissions {
            ensure!(
                omission.state == EvidenceState::Omitted,
                "omission must have omitted state"
            );
            omission.lineage.validate(&plan_hash)?;
            ensure!(
                !matches!(omission.lineage, SourceLineage::Plan { .. }),
                "omission cannot claim plan lineage"
            );
            self.validate_lineage_replay(&omission.lineage)?;
        }
        for input in &self.checkpoint.reverification_inputs {
            ensure!(input.captured_body_bytes <= self.plan.bounds.max_document_bytes);
            ensure!(crate::contract::is_sha256(&input.body_hash));
            input.receipt.validate()?;
            canonical_http_url(&input.requested_url)?;
            canonical_http_url(&input.effective_url)?;
        }
        for input in &self.checkpoint.failure_reverification_inputs {
            ensure!(
                !input.detail.trim().is_empty() && input.detail.len() <= 1_024,
                "invalid failure re-verification input"
            );
            input.receipt.validate()?;
            canonical_http_url(&input.requested_url)?;
        }
        Ok(())
    }

    fn validate_lineage_replay(&self, lineage: &SourceLineage) -> Result<()> {
        match lineage {
            SourceLineage::Plan { plan_hash } => ensure!(
                plan_hash == &self.checkpoint.plan_hash,
                "plan lineage fingerprint mismatch"
            ),
            SourceLineage::Receipt {
                receipt_id,
                receipt_content_hash,
                body_hash,
                source_url,
            } => ensure!(
                self.checkpoint.reverification_inputs.iter().any(|input| {
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
                self.checkpoint
                    .failure_reverification_inputs
                    .iter()
                    .any(|input| {
                        input.receipt.receipt_id == *receipt_id
                            && input.receipt.receipt_content_hash == *receipt_content_hash
                            && input.requested_url == *source_url
                    }),
                "failure lineage lacks a matching replay input"
            ),
        }
        Ok(())
    }

    fn apply_parsed(
        &mut self,
        mut parsed: ParsedDocument,
        parent_depth: u16,
        lineage: &SourceLineage,
    ) -> Result<()> {
        for (subject, reason, detail) in parsed.omissions.drain(..) {
            self.push_omission(subject, reason, detail, lineage.clone());
        }
        for candidate in parsed.candidates {
            self.apply_candidate(candidate, parent_depth, lineage)?;
        }
        self.checkpoint.forms.extend(parsed.forms);
        self.checkpoint.operations.extend(parsed.operations);
        self.checkpoint.robots_directives.extend(parsed.robots);
        Ok(())
    }

    fn apply_candidate(
        &mut self,
        candidate: CandidateReference,
        parent_depth: u16,
        lineage: &SourceLineage,
    ) -> Result<()> {
        if let Some(reason) = candidate.failure {
            self.push_omission(
                candidate.raw,
                reason,
                "reference could not be converted to an HTTP(S) discovery resource",
                lineage.clone(),
            );
            return Ok(());
        }
        let Some(url) = candidate.resolved else {
            self.push_omission(
                candidate.raw,
                OmissionReason::MalformedReference,
                "reference resolution produced no canonical URL",
                lineage.clone(),
            );
            return Ok(());
        };
        let depth = parent_depth.saturating_add(1);
        let kind = infer_kind_from_url(&url, candidate.kind);
        if !self.origin_allowed(&url)? {
            self.record_omitted_resource(
                &url,
                depth.min(self.plan.bounds.max_depth),
                kind,
                lineage,
            )?;
            self.push_omission(
                url,
                OmissionReason::OutsideAllowedOrigin,
                "reference origin is outside the plan's exact allowed origins",
                lineage.clone(),
            );
            return Ok(());
        }
        if depth > self.plan.bounds.max_depth {
            self.record_omitted_resource(&url, self.plan.bounds.max_depth, kind, lineage)?;
            self.push_omission(
                url,
                OmissionReason::DepthLimit,
                format!("depth limit {} reached", self.plan.bounds.max_depth),
                lineage.clone(),
            );
            return Ok(());
        }

        if let Some(existing) = self
            .checkpoint
            .resources
            .iter_mut()
            .find(|resource| resource.url == url)
        {
            existing.lineages.push(lineage.clone());
            sort_dedup(&mut existing.lineages);
            // Already observed or queued: retain the shortest BFS depth and do
            // not create another request, eliminating cycles deterministically.
            existing.depth = existing.depth.min(depth);
            return Ok(());
        }

        if self.checkpoint.resources.len() >= usize::try_from(self.plan.bounds.max_resources)? {
            self.push_omission(
                url,
                OmissionReason::ResourceLimit,
                format!("resource limit {} reached", self.plan.bounds.max_resources),
                lineage.clone(),
            );
            return Ok(());
        }
        self.checkpoint.resources.push(ResourceRecord {
            url: url.clone(),
            depth,
            kind,
            state: EvidenceState::Declared,
            lineages: vec![lineage.clone()],
        });
        self.checkpoint
            .frontier
            .push(request(&self.checkpoint.plan_hash, &url, depth, kind)?);
        Ok(())
    }

    fn observe_resource(
        &mut self,
        url: &str,
        depth: u16,
        kind: ResourceKind,
        lineage: &SourceLineage,
    ) -> Result<()> {
        if let Some(resource) = self
            .checkpoint
            .resources
            .iter_mut()
            .find(|resource| resource.url == url)
        {
            resource.state = EvidenceState::Observed;
            resource.kind = kind;
            resource.depth = resource.depth.min(depth);
            resource.lineages.push(lineage.clone());
            sort_dedup(&mut resource.lineages);
        } else {
            ensure!(
                self.checkpoint.resources.len() < usize::try_from(self.plan.bounds.max_resources)?,
                "observed redirect exceeds resource bound"
            );
            self.checkpoint.resources.push(ResourceRecord {
                url: url.to_owned(),
                depth,
                kind,
                state: EvidenceState::Observed,
                lineages: vec![lineage.clone()],
            });
        }
        Ok(())
    }

    fn record_omitted_resource(
        &mut self,
        url: &str,
        depth: u16,
        kind: ResourceKind,
        lineage: &SourceLineage,
    ) -> Result<()> {
        if let Some(resource) = self
            .checkpoint
            .resources
            .iter_mut()
            .find(|resource| resource.url == url)
        {
            if resource.state != EvidenceState::Observed {
                resource.state = EvidenceState::Omitted;
            }
            resource.lineages.push(lineage.clone());
            sort_dedup(&mut resource.lineages);
        } else if self.checkpoint.resources.len() < usize::try_from(self.plan.bounds.max_resources)?
        {
            self.checkpoint.resources.push(ResourceRecord {
                url: url.to_owned(),
                depth,
                kind,
                state: EvidenceState::Omitted,
                lineages: vec![lineage.clone()],
            });
        }
        Ok(())
    }

    fn push_omission(
        &mut self,
        subject: impl Into<String>,
        reason: OmissionReason,
        detail: impl Into<String>,
        lineage: SourceLineage,
    ) {
        let maximum = usize::try_from(self.plan.bounds.max_omissions).unwrap_or(100_000);
        if self
            .checkpoint
            .omissions
            .iter()
            .any(|omission| omission.reason == OmissionReason::OmissionLimit)
        {
            return;
        }
        if reason != OmissionReason::OmissionLimit
            && self.checkpoint.omissions.len() >= maximum.saturating_sub(1)
        {
            self.checkpoint.omissions.push(OmissionRecord {
                subject: "discovery omissions".to_owned(),
                reason: OmissionReason::OmissionLimit,
                detail: format!(
                    "omission limit {maximum} reached; one or more additional gaps were suppressed"
                ),
                state: EvidenceState::Omitted,
                lineage,
            });
            return;
        }
        if self.checkpoint.omissions.len() >= maximum {
            return;
        }
        self.checkpoint.omissions.push(OmissionRecord {
            subject: subject.into(),
            reason,
            detail: bounded_detail(&detail.into()),
            state: EvidenceState::Omitted,
            lineage,
        });
    }

    fn origin_allowed(&self, url: &str) -> Result<bool> {
        Ok(self
            .plan
            .allowed_origins
            .binary_search(&origin_of(url)?)
            .is_ok())
    }

    fn finish_transition(&mut self) {
        self.checkpoint.transition_count = self.checkpoint.transition_count.saturating_add(1);
        self.checkpoint = canonical_checkpoint(self.checkpoint.clone());
    }
}

fn validate_observation(
    plan: &DiscoveryPlan,
    expected: &DiscoveryRequest,
    observation: &DiscoveryObservation,
) -> Result<()> {
    ensure!(
        observation.schema_version == DISCOVERY_SCHEMA_VERSION,
        "unsupported discovery observation schema version"
    );
    ensure!(
        observation.request_id == expected.request_id,
        "observation does not match the BFS frontier head"
    );
    ensure!(
        canonical_http_url(&observation.requested_url)? == expected.url,
        "observation requested URL mismatch"
    );
    canonical_http_url(&observation.effective_url)?;
    ensure!(
        (100..=599).contains(&observation.status_code),
        "invalid HTTP status code"
    );
    if let Some(media_type) = &observation.media_type {
        ensure!(
            !media_type.is_empty() && media_type.len() <= 256 && !media_type.contains(['\r', '\n']),
            "invalid media type"
        );
    }
    ensure!(
        observation.body.len() <= usize::try_from(plan.bounds.max_document_bytes)?,
        "observation body exceeds document bound"
    );
    ensure!(
        hash(observation.body.as_bytes()) == observation.body_hash,
        "observation body hash mismatch"
    );
    observation.receipt.validate()?;
    Ok(())
}

fn classify_document(
    url: &str,
    media_type: Option<&str>,
    body: &str,
    expected: ResourceKind,
) -> ResourceKind {
    if expected != ResourceKind::Automatic {
        return expected;
    }
    let lower_media = media_type.unwrap_or_default().to_ascii_lowercase();
    let lower_url = url.to_ascii_lowercase();
    let prefix = body.trim_start().chars().take(512).collect::<String>();
    let lower_prefix = prefix.to_ascii_lowercase();
    if lower_url.ends_with("/robots.txt") {
        ResourceKind::Robots
    } else if lower_url.ends_with(".xml")
        || lower_media.contains("xml")
            && (lower_prefix.contains("<urlset") || lower_prefix.contains("<sitemapindex"))
    {
        ResourceKind::Sitemap
    } else if lower_url.contains("openapi")
        || lower_url.contains("swagger")
        || lower_prefix.contains("\"openapi\"")
        || lower_prefix.contains("\"swagger\"")
        || lower_prefix.starts_with("openapi:")
        || lower_prefix.starts_with("swagger:")
    {
        ResourceKind::OpenApi
    } else if lower_media.contains("html")
        || lower_prefix.starts_with("<!doctype html")
        || lower_prefix.starts_with("<html")
    {
        ResourceKind::Html
    } else if lower_media.contains("javascript")
        || lower_media.contains("ecmascript")
        || lower_url.ends_with(".js")
        || lower_url.ends_with(".mjs")
    {
        ResourceKind::JavaScript
    } else {
        ResourceKind::Automatic
    }
}

fn infer_kind_from_url(url: &str, proposed: ResourceKind) -> ResourceKind {
    if proposed != ResourceKind::Automatic {
        return proposed;
    }
    let parsed = Url::parse(url).ok();
    let path = parsed
        .as_ref()
        .map(|url| url.path())
        .unwrap_or(url)
        .to_ascii_lowercase();
    if path.ends_with("/robots.txt") || path == "/robots.txt" {
        ResourceKind::Robots
    } else if path.ends_with(".xml") {
        ResourceKind::Sitemap
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        ResourceKind::JavaScript
    } else if path.contains("openapi") || path.contains("swagger") {
        ResourceKind::OpenApi
    } else if path.ends_with(".html") || path.ends_with(".htm") || path.ends_with('/') {
        ResourceKind::Html
    } else {
        proposed
    }
}

#[derive(Serialize)]
struct RequestIdentity<'a> {
    schema_version: u32,
    plan_hash: &'a str,
    url: &'a str,
    depth: u16,
    expected_kind: ResourceKind,
}

fn request(
    plan_hash: &str,
    url: &str,
    depth: u16,
    expected_kind: ResourceKind,
) -> Result<DiscoveryRequest> {
    Ok(DiscoveryRequest {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        request_id: request_id(plan_hash, url, depth, expected_kind)?,
        url: url.to_owned(),
        depth,
        expected_kind,
    })
}

fn request_id(
    plan_hash: &str,
    url: &str,
    depth: u16,
    expected_kind: ResourceKind,
) -> Result<String> {
    Ok(format!(
        "discovery-{}",
        hash(&serde_json::to_vec(&RequestIdentity {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            plan_hash,
            url,
            depth,
            expected_kind,
        })?)
    ))
}

fn canonical_checkpoint(mut checkpoint: DiscoveryCheckpoint) -> DiscoveryCheckpoint {
    checkpoint.frontier.sort_by(frontier_order);
    checkpoint
        .frontier
        .dedup_by(|left, right| left.url == right.url);
    for resource in &mut checkpoint.resources {
        sort_dedup(&mut resource.lineages);
    }
    sort_dedup(&mut checkpoint.resources);
    sort_dedup(&mut checkpoint.forms);
    sort_dedup(&mut checkpoint.operations);
    sort_dedup(&mut checkpoint.robots_directives);
    sort_dedup(&mut checkpoint.omissions);
    sort_dedup(&mut checkpoint.reverification_inputs);
    sort_dedup(&mut checkpoint.failure_reverification_inputs);
    checkpoint
}

fn frontier_order(left: &DiscoveryRequest, right: &DiscoveryRequest) -> std::cmp::Ordering {
    (left.depth, &left.url, left.expected_kind).cmp(&(right.depth, &right.url, right.expected_kind))
}

fn bounded_detail(value: &str) -> String {
    if value.len() <= 1_024 {
        return value.to_owned();
    }
    let mut end = 1_024;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{DiscoveryBounds, ReceiptLineage};

    fn plan(seeds: Vec<&str>) -> DiscoveryPlan {
        DiscoveryPlan {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            plan_id: "unit".to_owned(),
            seed_urls: seeds.into_iter().map(ToOwned::to_owned).collect(),
            allowed_origins: vec![],
            bounds: DiscoveryBounds::default(),
        }
    }

    fn observe(request: &DiscoveryRequest, body: &str, media_type: &str) -> DiscoveryObservation {
        DiscoveryObservation::from_body(
            request,
            request.url.clone(),
            200,
            Some(media_type.to_owned()),
            body,
            false,
            ReceiptLineage {
                receipt_id: format!("receipt-{}", &request.request_id[10..18]),
                receipt_content_hash: hash(request.request_id.as_bytes()),
            },
        )
    }

    #[test]
    fn breadth_first_order_is_stable_and_cycles_are_deduplicated() {
        let mut session = DiscoverySession::start(plan(vec!["https://example.test/"])).unwrap();
        let root = session.next_request().unwrap().clone();
        session
            .apply_observation(observe(
                &root,
                r#"<a href="/z">z</a><a href="/a">a</a><a href="/a">again</a>"#,
                "text/html",
            ))
            .unwrap();
        assert_eq!(
            session.next_request().unwrap().url,
            "https://example.test/a"
        );
        let a = session.next_request().unwrap().clone();
        session
            .apply_observation(observe(
                &a,
                r#"<a href="/">root</a><a href="/a/deep">deep</a>"#,
                "text/html",
            ))
            .unwrap();
        assert_eq!(
            session.next_request().unwrap().url,
            "https://example.test/z"
        );
        assert_eq!(
            session
                .checkpoint()
                .resources
                .iter()
                .filter(|resource| resource.url == "https://example.test/a")
                .count(),
            1
        );
    }

    #[test]
    fn resume_rejects_modified_checkpoint() {
        let plan = plan(vec!["https://example.test/"]);
        let session = DiscoverySession::start(plan.clone()).unwrap();
        let mut checkpoint = session.into_checkpoint();
        checkpoint.frontier[0].request_id = "forged".to_owned();
        assert!(DiscoverySession::resume(plan, checkpoint).is_err());
    }
}
