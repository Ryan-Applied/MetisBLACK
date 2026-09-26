use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use storage::hash;

use crate::{
    canonical_contract_set_hash, ActualResponseObservation, ApiValidationArtifact,
    ApiValidationCheckpoint, ApiValidationPlan, Conformance, ConformanceReason, JsonShape,
    NormalizedOpenApi, NormalizedSchema, OperationContract, OperationSelector,
    ReplayClassification, ReplayComparison, ResponseContract, StatusSelector, ValidationBounds,
    ValidationRecord, API_VALIDATION_SCHEMA_VERSION,
};

#[derive(Debug, Clone)]
pub struct ApiValidationSession {
    plan: ApiValidationPlan,
    contracts: Vec<NormalizedOpenApi>,
    checkpoint: ApiValidationCheckpoint,
}

impl ApiValidationSession {
    pub fn start(plan: ApiValidationPlan, contracts: Vec<NormalizedOpenApi>) -> Result<Self> {
        let plan = plan.canonicalized()?;
        let contracts = canonical_contracts(contracts)?;
        validate_contract_coverage(&plan, &contracts)?;
        let checkpoint = ApiValidationCheckpoint {
            schema_version: API_VALIDATION_SCHEMA_VERSION,
            plan_hash: plan.fingerprint()?,
            contract_set_hash: canonical_contract_set_hash(&contracts)?,
            pending: plan.selectors.clone(),
            records: Vec::new(),
            replay_comparisons: Vec::new(),
        };
        Ok(Self {
            plan,
            contracts,
            checkpoint,
        })
    }

    pub fn resume(
        plan: ApiValidationPlan,
        contracts: Vec<NormalizedOpenApi>,
        checkpoint: ApiValidationCheckpoint,
    ) -> Result<Self> {
        let mut session = Self::start(plan, contracts)?;
        session.validate_checkpoint(&checkpoint)?;
        session.checkpoint = checkpoint;
        Ok(session)
    }

    pub fn checkpoint(&self) -> &ApiValidationCheckpoint {
        &self.checkpoint
    }

    pub fn pending(&self) -> &[OperationSelector] {
        &self.checkpoint.pending
    }

    pub fn operation_contract(&self, selector: &OperationSelector) -> Option<&OperationContract> {
        find_operation(&self.contracts, selector)
    }

    pub fn apply_observation(&mut self, observation: ActualResponseObservation) -> Result<()> {
        observation.validate()?;
        ensure!(
            self.checkpoint
                .pending
                .binary_search(&observation.selector)
                .is_ok(),
            "observation selector is not pending"
        );
        if let Some(shape) = &observation.json_shape {
            shape.validate(&self.plan.bounds)?;
        }
        ensure!(
            !all_response_receipts(&self.checkpoint).contains(&observation.receipt.receipt_id),
            "response receipt is already bound to a validation record"
        );
        ensure!(
            self.checkpoint.records.len() + self.checkpoint.replay_comparisons.len()
                < usize::try_from(self.plan.bounds.max_results)?,
            "validation and replay results exceed max_results"
        );
        let operation = self
            .operation_contract(&observation.selector)
            .context("observation selector has no normalized operation")?;
        ensure!(
            operation.probe_id == observation.probe_id,
            "observation probe_id does not match normalized operation"
        );
        ensure!(
            operation.canonical_hash()? == observation.contract_hash,
            "observation contract_hash does not match normalized operation"
        );
        let result = classify_response(operation, &observation)?;
        self.checkpoint.records.push(ValidationRecord {
            observation: observation.clone(),
            result,
        });
        self.checkpoint.records.sort_by(record_order);
        self.checkpoint
            .pending
            .retain(|selector| selector != &observation.selector);
        Ok(())
    }

    pub fn apply_replay_observation(
        &mut self,
        observation: ActualResponseObservation,
    ) -> Result<()> {
        observation.validate()?;
        if let Some(shape) = &observation.json_shape {
            shape.validate(&self.plan.bounds)?;
        }
        let primary = self
            .checkpoint
            .records
            .iter()
            .find(|record| record.observation.selector == observation.selector)
            .cloned()
            .context("independent replay has no primary validation record")?;
        ensure!(
            !self
                .checkpoint
                .replay_comparisons
                .iter()
                .any(|comparison| comparison.selector == observation.selector),
            "selector already has an independent replay comparison"
        );
        ensure!(
            !all_response_receipts(&self.checkpoint).contains(&observation.receipt.receipt_id),
            "response receipt is already bound to validation evidence"
        );
        ensure!(
            self.checkpoint.records.len() + self.checkpoint.replay_comparisons.len()
                < usize::try_from(self.plan.bounds.max_results)?,
            "validation and replay results exceed max_results"
        );
        let operation = self
            .operation_contract(&observation.selector)
            .context("replay selector has no normalized operation")?;
        ensure!(
            operation.probe_id == observation.probe_id,
            "replay probe_id does not match normalized operation"
        );
        ensure!(
            operation.canonical_hash()? == observation.contract_hash,
            "replay contract_hash does not match normalized operation"
        );
        let independent = ValidationRecord {
            result: classify_response(operation, &observation)?,
            observation,
        };
        self.checkpoint
            .replay_comparisons
            .push(compare_replay(primary, independent)?);
        self.checkpoint.replay_comparisons.sort_by(replay_order);
        Ok(())
    }

    pub fn artifact(&self) -> Result<ApiValidationArtifact> {
        ensure!(
            self.checkpoint.pending.is_empty(),
            "API validation is incomplete"
        );
        for record in &self.checkpoint.records {
            if matches!(record.result, Conformance::Violating { .. }) {
                ensure!(
                    self.checkpoint
                        .replay_comparisons
                        .iter()
                        .any(|comparison| comparison.selector == record.observation.selector),
                    "violating result requires an independent replay comparison"
                );
            }
        }
        let mut source_receipts: Vec<_> = self
            .contracts
            .iter()
            .map(|contract| contract.source_receipt.clone())
            .collect();
        source_receipts.sort();
        source_receipts.dedup();
        let mut response_receipts: Vec<_> = self
            .checkpoint
            .records
            .iter()
            .map(|record| record.observation.receipt.clone())
            .chain(
                self.checkpoint
                    .replay_comparisons
                    .iter()
                    .map(|comparison| comparison.independent.observation.receipt.clone()),
            )
            .collect();
        response_receipts.sort();
        response_receipts.dedup();
        let artifact = ApiValidationArtifact {
            schema_version: API_VALIDATION_SCHEMA_VERSION,
            plan_hash: self.checkpoint.plan_hash.clone(),
            contract_set_hash: self.checkpoint.contract_set_hash.clone(),
            contracts: self.contracts.clone(),
            records: self.checkpoint.records.clone(),
            replay_comparisons: self.checkpoint.replay_comparisons.clone(),
            source_receipts,
            response_receipts,
        };
        artifact.verify(&self.plan)?;
        Ok(artifact)
    }

    fn validate_checkpoint(&self, checkpoint: &ApiValidationCheckpoint) -> Result<()> {
        ensure!(
            checkpoint.schema_version == API_VALIDATION_SCHEMA_VERSION,
            "unsupported API validation checkpoint schema version"
        );
        ensure!(
            checkpoint.plan_hash == self.plan.fingerprint()?,
            "checkpoint plan hash mismatch"
        );
        ensure!(
            checkpoint.contract_set_hash == canonical_contract_set_hash(&self.contracts)?,
            "checkpoint contract set hash mismatch"
        );
        ensure!(
            checkpoint.records.len() + checkpoint.replay_comparisons.len()
                <= usize::try_from(self.plan.bounds.max_results)?,
            "checkpoint results exceed max_results"
        );
        let mut rebuilt = Self::start(self.plan.clone(), self.contracts.clone())?;
        let mut records = checkpoint.records.clone();
        records.sort_by(record_order);
        ensure!(
            records == checkpoint.records,
            "checkpoint records are not canonical"
        );
        for record in records {
            let expected_result = record.result.clone();
            let selector = record.observation.selector.clone();
            rebuilt.apply_observation(record.observation)?;
            ensure!(
                rebuilt
                    .checkpoint
                    .records
                    .iter()
                    .find(|entry| entry.observation.selector == selector)
                    .map(|entry| &entry.result)
                    == Some(&expected_result),
                "checkpoint result does not independently replay"
            );
        }
        let mut comparisons = checkpoint.replay_comparisons.clone();
        comparisons.sort_by(replay_order);
        ensure!(
            comparisons == checkpoint.replay_comparisons,
            "checkpoint replay comparisons are not canonical"
        );
        for comparison in comparisons {
            let expected = comparison.clone();
            rebuilt.apply_replay_observation(comparison.independent.observation)?;
            ensure!(
                rebuilt
                    .checkpoint
                    .replay_comparisons
                    .iter()
                    .find(|entry| entry.selector == expected.selector)
                    == Some(&expected),
                "checkpoint replay comparison does not independently replay"
            );
        }
        ensure!(
            rebuilt.checkpoint.pending == checkpoint.pending,
            "checkpoint pending selectors do not match replayed records"
        );
        Ok(())
    }
}

pub fn compare_replay(
    primary: ValidationRecord,
    independent: ValidationRecord,
) -> Result<ReplayComparison> {
    ensure!(
        primary.observation.selector == independent.observation.selector,
        "replay selector does not match primary"
    );
    ensure!(
        primary.observation.probe_id == independent.observation.probe_id,
        "replay probe_id does not match primary"
    );
    ensure!(
        primary.observation.contract_hash == independent.observation.contract_hash,
        "replay contract_hash does not match primary"
    );
    ensure!(
        primary.observation.receipt.receipt_id != independent.observation.receipt.receipt_id,
        "independent replay must use a distinct receipt"
    );
    let classification = match (&primary.result, &independent.result) {
        (
            Conformance::Violating {
                reasons: primary_reasons,
            },
            Conformance::Violating {
                reasons: replay_reasons,
            },
        ) => {
            let primary_hash = violation_hash(primary_reasons)?;
            let independent_hash = violation_hash(replay_reasons)?;
            if primary_reasons == replay_reasons
                && replay_surface_matches(&primary.observation, &independent.observation)
            {
                ReplayClassification::Reproduced {
                    violation_hash: primary_hash,
                }
            } else if primary_reasons == replay_reasons {
                ReplayClassification::ObservationMismatch {
                    violation_hash: primary_hash,
                    primary_status: primary.observation.status,
                    independent_status: independent.observation.status,
                    primary_media_type: primary.observation.media_type.clone(),
                    independent_media_type: independent.observation.media_type.clone(),
                }
            } else {
                ReplayClassification::ViolationMismatch {
                    primary_violation_hash: primary_hash,
                    independent_violation_hash: independent_hash,
                }
            }
        }
        (Conformance::Violating { .. }, Conformance::Conforming) => {
            ReplayClassification::IndependentConforming
        }
        (Conformance::Violating { .. }, Conformance::Inconclusive { .. }) => {
            ReplayClassification::IndependentInconclusive
        }
        _ => ReplayClassification::PrimaryNotViolating,
    };
    Ok(ReplayComparison {
        selector: primary.observation.selector.clone(),
        probe_id: primary.observation.probe_id.clone(),
        contract_hash: primary.observation.contract_hash.clone(),
        primary,
        independent,
        classification,
    })
}

fn replay_surface_matches(
    primary: &ActualResponseObservation,
    independent: &ActualResponseObservation,
) -> bool {
    primary.status == independent.status && primary.media_type == independent.media_type
}

pub fn violation_hash(reasons: &[ConformanceReason]) -> Result<String> {
    let mut canonical = reasons.to_vec();
    canonical.sort();
    canonical.dedup();
    ensure!(canonical == reasons, "violation reasons are not canonical");
    Ok(hash(&serde_json::to_vec(&canonical)?))
}

pub fn classify_response(
    operation: &OperationContract,
    observation: &ActualResponseObservation,
) -> Result<Conformance> {
    observation.validate()?;
    ensure!(
        operation.selector == observation.selector,
        "selector mismatch"
    );
    ensure!(
        operation.probe_id == observation.probe_id,
        "probe_id mismatch"
    );
    ensure!(
        operation.canonical_hash()? == observation.contract_hash,
        "contract hash mismatch"
    );

    if matches!(observation.status, 408 | 429) || observation.status >= 500 {
        return Ok(Conformance::Inconclusive {
            reasons: vec![ConformanceReason::TransientStatus {
                status: observation.status,
            }],
        });
    }

    let Some(response) = select_response(&operation.responses, observation.status) else {
        return Ok(Conformance::Inconclusive {
            reasons: vec![ConformanceReason::StatusUndeclared {
                status: observation.status,
            }],
        });
    };
    if operation.selector.method == crate::SafeMethod::Head && !observation.body_present {
        return Ok(Conformance::Conforming);
    }
    if response.media.is_empty() {
        return Ok(if observation.body_present {
            Conformance::Inconclusive {
                reasons: vec![ConformanceReason::ResponseSchemaMissing],
            }
        } else {
            Conformance::Conforming
        });
    }
    let Some(actual_media) = &observation.media_type else {
        return Ok(if observation.body_present {
            Conformance::Inconclusive {
                reasons: vec![ConformanceReason::MediaTypeMissing],
            }
        } else {
            Conformance::Inconclusive {
                reasons: vec![ConformanceReason::BodyMissing],
            }
        });
    };
    let media = response
        .media
        .iter()
        .find(|contract| media_matches(&contract.media_type, actual_media));
    let Some(media) = media else {
        return Ok(Conformance::Violating {
            reasons: vec![ConformanceReason::MediaTypeUndeclared {
                media_type: actual_media.clone(),
            }],
        });
    };

    let mut inconclusive = Vec::new();
    if observation.body_truncated {
        inconclusive.push(ConformanceReason::BodyTruncated);
    }
    if observation.malformed_json {
        inconclusive.push(ConformanceReason::MalformedJson);
    }
    if observation.shape_truncated {
        inconclusive.push(ConformanceReason::ShapeTruncated);
    }
    if !media.unsupported.is_empty() {
        inconclusive.push(ConformanceReason::UnsupportedSchema {
            keywords: media.unsupported.clone(),
        });
    }
    canonicalize_reasons(&mut inconclusive);
    if !inconclusive.is_empty() {
        return Ok(Conformance::Inconclusive {
            reasons: inconclusive,
        });
    }

    let Some(schema) = &media.schema else {
        return Ok(Conformance::Conforming);
    };
    if !observation.body_present {
        return Ok(Conformance::Violating {
            reasons: vec![ConformanceReason::BodyMissing],
        });
    }
    let Some(shape) = &observation.json_shape else {
        return Ok(Conformance::Inconclusive {
            reasons: vec![ConformanceReason::JsonShapeUnavailable],
        });
    };
    let mut violations = Vec::new();
    compare_schema(schema, shape, "$", &mut violations);
    canonicalize_reasons(&mut violations);
    Ok(if violations.is_empty() {
        Conformance::Conforming
    } else {
        Conformance::Violating {
            reasons: violations,
        }
    })
}

pub(crate) fn verify_artifact(
    plan: &ApiValidationPlan,
    artifact: &ApiValidationArtifact,
) -> Result<()> {
    validate_artifact_structure(artifact)?;
    let plan = plan.canonicalized()?;
    ensure!(
        artifact.schema_version == API_VALIDATION_SCHEMA_VERSION,
        "unsupported API validation artifact schema version"
    );
    ensure!(
        artifact.plan_hash == plan.fingerprint()?,
        "artifact plan hash mismatch"
    );
    let contracts = canonical_contracts(artifact.contracts.clone())?;
    ensure!(
        contracts == artifact.contracts,
        "artifact contracts are not canonical"
    );
    validate_contract_coverage(&plan, &contracts)?;
    ensure!(
        artifact.contract_set_hash == canonical_contract_set_hash(&contracts)?,
        "artifact contract set hash mismatch"
    );
    ensure!(
        artifact.records.len() == plan.selectors.len(),
        "artifact result coverage mismatch"
    );
    ensure!(
        artifact.records.len() + artifact.replay_comparisons.len()
            <= usize::try_from(plan.bounds.max_results)?,
        "artifact results exceed max_results"
    );
    let mut records = artifact.records.clone();
    records.sort_by(record_order);
    ensure!(
        records == artifact.records,
        "artifact records are not canonical"
    );
    let mut seen = BTreeSet::new();
    for record in &artifact.records {
        ensure!(
            seen.insert(record.observation.selector.clone()),
            "artifact contains duplicate selector results"
        );
        if let Some(shape) = &record.observation.json_shape {
            shape.validate(&plan.bounds)?;
        }
        let operation = find_operation(&contracts, &record.observation.selector)
            .context("artifact observation has no normalized operation")?;
        ensure!(
            classify_response(operation, &record.observation)? == record.result,
            "artifact result does not independently replay"
        );
    }
    let mut comparisons = artifact.replay_comparisons.clone();
    comparisons.sort_by(replay_order);
    ensure!(
        comparisons == artifact.replay_comparisons,
        "artifact replay comparisons are not canonical"
    );
    let mut replayed_selectors = BTreeSet::new();
    for comparison in &artifact.replay_comparisons {
        ensure!(
            replayed_selectors.insert(comparison.selector.clone()),
            "artifact contains duplicate replay comparisons"
        );
        let primary = artifact
            .records
            .iter()
            .find(|record| record.observation.selector == comparison.selector)
            .context("replay comparison has no primary record")?;
        ensure!(
            primary == &comparison.primary,
            "replay comparison primary does not match artifact record"
        );
        if let Some(shape) = &comparison.independent.observation.json_shape {
            shape.validate(&plan.bounds)?;
        }
        let operation = find_operation(&contracts, &comparison.selector)
            .context("replay comparison has no normalized operation")?;
        ensure!(
            classify_response(operation, &comparison.independent.observation)?
                == comparison.independent.result,
            "independent replay result does not replay"
        );
        ensure!(
            compare_replay(comparison.primary.clone(), comparison.independent.clone())?
                == *comparison,
            "replay comparison classification does not independently replay"
        );
    }
    for record in &artifact.records {
        if matches!(record.result, Conformance::Violating { .. }) {
            ensure!(
                replayed_selectors.contains(&record.observation.selector),
                "violating artifact result has no independent replay comparison"
            );
        }
    }
    let mut expected_sources: Vec<_> = contracts
        .iter()
        .map(|contract| contract.source_receipt.clone())
        .collect();
    expected_sources.sort();
    expected_sources.dedup();
    ensure!(
        artifact.source_receipts == expected_sources,
        "artifact source receipt index mismatch"
    );
    let mut expected_responses: Vec<_> = artifact
        .records
        .iter()
        .map(|record| record.observation.receipt.clone())
        .chain(
            artifact
                .replay_comparisons
                .iter()
                .map(|comparison| comparison.independent.observation.receipt.clone()),
        )
        .collect();
    expected_responses.sort();
    expected_responses.dedup();
    ensure!(
        expected_responses.len() == artifact.records.len() + artifact.replay_comparisons.len(),
        "artifact reuses a response receipt"
    );
    ensure!(
        artifact.response_receipts == expected_responses,
        "artifact response receipt index mismatch"
    );
    Ok(())
}

pub(crate) fn validate_artifact_structure(artifact: &ApiValidationArtifact) -> Result<()> {
    ensure!(
        artifact.schema_version == API_VALIDATION_SCHEMA_VERSION,
        "unsupported API validation artifact schema version"
    );
    crate::validate_hash(&artifact.plan_hash, "plan_hash")?;
    crate::validate_hash(&artifact.contract_set_hash, "contract_set_hash")?;
    let contracts = canonical_contracts(artifact.contracts.clone())?;
    let hard_bounds = hard_validation_bounds();
    ensure!(
        contracts
            .iter()
            .map(|contract| contract.operations.len())
            .sum::<usize>()
            <= usize::try_from(hard_bounds.max_selectors)?,
        "artifact operation count exceeds hard ceiling"
    );
    ensure!(
        artifact.records.len() + artifact.replay_comparisons.len()
            <= usize::try_from(hard_bounds.max_results)?,
        "artifact result count exceeds hard ceiling"
    );
    for operation in contracts.iter().flat_map(|contract| &contract.operations) {
        validate_operation_bounds(operation, &hard_bounds)?;
    }
    ensure!(
        contracts == artifact.contracts,
        "artifact contracts are not canonical"
    );
    ensure!(
        artifact.contract_set_hash == canonical_contract_set_hash(&contracts)?,
        "artifact contract set hash mismatch"
    );
    let mut records = artifact.records.clone();
    records.sort_by(record_order);
    ensure!(
        records == artifact.records,
        "artifact records are not canonical"
    );
    let mut selectors = BTreeSet::new();
    for record in &artifact.records {
        ensure!(
            selectors.insert(record.observation.selector.clone()),
            "artifact contains duplicate selector results"
        );
        if let Some(shape) = &record.observation.json_shape {
            shape.validate(&hard_bounds)?;
        }
        let operation = find_operation(&contracts, &record.observation.selector)
            .context("artifact observation has no normalized operation")?;
        ensure!(
            classify_response(operation, &record.observation)? == record.result,
            "artifact result does not independently replay"
        );
    }
    let mut comparisons = artifact.replay_comparisons.clone();
    comparisons.sort_by(replay_order);
    ensure!(
        comparisons == artifact.replay_comparisons,
        "artifact replay comparisons are not canonical"
    );
    let mut replayed = BTreeSet::new();
    for comparison in &artifact.replay_comparisons {
        ensure!(
            replayed.insert(comparison.selector.clone()),
            "artifact contains duplicate replay comparisons"
        );
        if let Some(shape) = &comparison.independent.observation.json_shape {
            shape.validate(&hard_bounds)?;
        }
        let primary = artifact
            .records
            .iter()
            .find(|record| record.observation.selector == comparison.selector)
            .context("replay comparison has no primary record")?;
        ensure!(
            primary == &comparison.primary,
            "replay primary record mismatch"
        );
        let operation = find_operation(&contracts, &comparison.selector)
            .context("replay comparison has no normalized operation")?;
        ensure!(
            classify_response(operation, &comparison.independent.observation)?
                == comparison.independent.result,
            "independent replay result does not replay"
        );
        ensure!(
            compare_replay(comparison.primary.clone(), comparison.independent.clone())?
                == *comparison,
            "replay comparison classification does not replay"
        );
    }
    for record in &artifact.records {
        if matches!(record.result, Conformance::Violating { .. }) {
            ensure!(
                replayed.contains(&record.observation.selector),
                "violating artifact result has no independent replay comparison"
            );
        }
    }
    let mut source_receipts: Vec<_> = contracts
        .iter()
        .map(|contract| contract.source_receipt.clone())
        .collect();
    source_receipts.sort();
    source_receipts.dedup();
    ensure!(
        source_receipts == artifact.source_receipts,
        "artifact source receipt index mismatch"
    );
    let mut response_receipts: Vec<_> = artifact
        .records
        .iter()
        .map(|record| record.observation.receipt.clone())
        .chain(
            artifact
                .replay_comparisons
                .iter()
                .map(|comparison| comparison.independent.observation.receipt.clone()),
        )
        .collect();
    let response_count = response_receipts.len();
    response_receipts.sort();
    response_receipts.dedup();
    ensure!(
        response_receipts.len() == response_count,
        "artifact reuses a response receipt"
    );
    ensure!(
        response_receipts == artifact.response_receipts,
        "artifact response receipt index mismatch"
    );
    Ok(())
}

fn hard_validation_bounds() -> ValidationBounds {
    ValidationBounds {
        max_selectors: crate::MAX_SELECTORS,
        max_document_bytes: crate::MAX_DOCUMENT_BYTES,
        max_response_bytes: crate::MAX_RESPONSE_BYTES,
        max_ref_depth: crate::MAX_REF_DEPTH,
        max_ref_nodes: crate::MAX_REF_NODES,
        max_schema_depth: crate::MAX_SCHEMA_DEPTH,
        max_schema_nodes: crate::MAX_SCHEMA_NODES,
        max_properties: crate::MAX_PROPERTIES,
        max_shape_depth: crate::MAX_SHAPE_DEPTH,
        max_shape_nodes: crate::MAX_SHAPE_NODES,
        max_array_items: crate::MAX_ARRAY_ITEMS,
        max_results: crate::MAX_RESULTS,
    }
}

fn canonical_contracts(mut contracts: Vec<NormalizedOpenApi>) -> Result<Vec<NormalizedOpenApi>> {
    ensure!(!contracts.is_empty(), "normalized contract set is empty");
    let mut receipt_ids = BTreeSet::new();
    for contract in &contracts {
        contract.validate()?;
        ensure!(
            receipt_ids.insert(contract.source_receipt.receipt_id.clone()),
            "one source receipt cannot back multiple OpenAPI documents"
        );
    }
    contracts.sort_by(|left, right| left.source_url.cmp(&right.source_url));
    ensure!(
        contracts
            .windows(2)
            .all(|pair| pair[0].source_url != pair[1].source_url),
        "duplicate normalized OpenAPI source URL"
    );
    Ok(contracts)
}

fn validate_contract_coverage(
    plan: &ApiValidationPlan,
    contracts: &[NormalizedOpenApi],
) -> Result<()> {
    let mut coverage = BTreeMap::new();
    for contract in contracts {
        for operation in &contract.operations {
            validate_operation_bounds(operation, &plan.bounds)?;
            *coverage.entry(operation.selector.clone()).or_insert(0_u32) += 1;
        }
    }
    for selector in &plan.selectors {
        ensure!(
            coverage.get(selector) == Some(&1),
            "selector must resolve to exactly one normalized operation"
        );
    }
    ensure!(
        coverage.len() == plan.selectors.len(),
        "contract set contains operations outside the plan"
    );
    Ok(())
}

fn validate_operation_bounds(
    operation: &OperationContract,
    bounds: &ValidationBounds,
) -> Result<()> {
    ensure!(
        operation.responses.len() <= usize::try_from(bounds.max_properties)?,
        "response contract count exceeds bounds"
    );
    let mut nodes = 0_u32;
    for response in &operation.responses {
        ensure!(
            response.media.len() <= usize::try_from(bounds.max_properties)?,
            "media contract count exceeds bounds"
        );
        for media in &response.media {
            if let Some(schema) = &media.schema {
                validate_schema_bounds(schema, bounds, 0, &mut nodes)?;
            }
        }
    }
    Ok(())
}

fn validate_schema_bounds(
    schema: &NormalizedSchema,
    bounds: &ValidationBounds,
    depth: u16,
    nodes: &mut u32,
) -> Result<()> {
    ensure!(
        depth <= bounds.max_schema_depth,
        "normalized schema exceeds depth bound"
    );
    *nodes = nodes.saturating_add(1);
    ensure!(
        *nodes <= bounds.max_schema_nodes,
        "normalized schema exceeds node bound"
    );
    match schema {
        NormalizedSchema::Object {
            required,
            properties,
        } => {
            ensure!(
                properties.len() <= usize::try_from(bounds.max_properties)?,
                "normalized schema exceeds property bound"
            );
            let mut canonical_required = required.clone();
            canonical_required.sort();
            canonical_required.dedup();
            ensure!(
                canonical_required == *required,
                "required properties are not canonical"
            );
            ensure!(
                required.iter().all(|name| properties.contains_key(name)),
                "required property is absent from normalized properties"
            );
            for child in properties.values() {
                validate_schema_bounds(child, bounds, depth + 1, nodes)?;
            }
        }
        NormalizedSchema::Array { items } => {
            validate_schema_bounds(items, bounds, depth + 1, nodes)?;
        }
        _ => {}
    }
    Ok(())
}

fn find_operation<'a>(
    contracts: &'a [NormalizedOpenApi],
    selector: &OperationSelector,
) -> Option<&'a OperationContract> {
    contracts
        .iter()
        .flat_map(|contract| &contract.operations)
        .find(|operation| &operation.selector == selector)
}

fn select_response(responses: &[ResponseContract], status: u16) -> Option<&ResponseContract> {
    responses
        .iter()
        .find(|response| response.status == (StatusSelector::Exact { status }))
        .or_else(|| {
            responses.iter().find(|response| {
                response.status
                    == (StatusSelector::Class {
                        hundred: status / 100,
                    })
            })
        })
        .or_else(|| {
            responses
                .iter()
                .find(|response| response.status == StatusSelector::Default)
        })
}

fn media_matches(contract: &str, actual: &str) -> bool {
    if contract == actual || contract == "*/*" {
        return true;
    }
    contract
        .strip_suffix("/*")
        .is_some_and(|prefix| actual.starts_with(&format!("{prefix}/")))
}

fn compare_schema(
    schema: &NormalizedSchema,
    shape: &JsonShape,
    path: &str,
    reasons: &mut Vec<ConformanceReason>,
) {
    let matches = match (schema, shape) {
        (NormalizedSchema::Any, _) => true,
        (NormalizedSchema::Null, JsonShape::Null)
        | (NormalizedSchema::Boolean, JsonShape::Boolean)
        | (NormalizedSchema::Integer, JsonShape::Integer)
        | (NormalizedSchema::Number, JsonShape::Integer | JsonShape::Number)
        | (NormalizedSchema::String, JsonShape::String) => true,
        (
            NormalizedSchema::Object {
                required,
                properties,
            },
            JsonShape::Object { properties: actual },
        ) => {
            for property in required {
                if !actual.contains_key(property) {
                    reasons.push(ConformanceReason::RequiredPropertyMissing {
                        path: path.to_owned(),
                        property: property.clone(),
                    });
                }
            }
            for (name, actual_shape) in actual {
                if let Some(expected) = properties.get(name) {
                    compare_schema(
                        expected,
                        actual_shape,
                        &format!("{path}.{}", escape_path(name)),
                        reasons,
                    );
                }
            }
            true
        }
        (NormalizedSchema::Array { items }, JsonShape::Array { item_shapes }) => {
            for item_shape in item_shapes {
                compare_schema(items, item_shape, &format!("{path}[]"), reasons);
            }
            true
        }
        _ => false,
    };
    if !matches {
        reasons.push(ConformanceReason::TypeMismatch {
            path: path.to_owned(),
            expected: schema_kind(schema).to_owned(),
            actual: shape.kind().to_owned(),
        });
    }
}

fn schema_kind(schema: &NormalizedSchema) -> &'static str {
    match schema {
        NormalizedSchema::Any => "any",
        NormalizedSchema::Null => "null",
        NormalizedSchema::Boolean => "boolean",
        NormalizedSchema::Integer => "integer",
        NormalizedSchema::Number => "number",
        NormalizedSchema::String => "string",
        NormalizedSchema::Object { .. } => "object",
        NormalizedSchema::Array { .. } => "array",
    }
}

fn escape_path(name: &str) -> String {
    name.replace('~', "~0").replace('.', "~1")
}

fn canonicalize_reasons(reasons: &mut Vec<ConformanceReason>) {
    reasons.sort();
    reasons.dedup();
}

fn record_order(left: &ValidationRecord, right: &ValidationRecord) -> std::cmp::Ordering {
    left.observation.selector.cmp(&right.observation.selector)
}

fn replay_order(left: &ReplayComparison, right: &ReplayComparison) -> std::cmp::Ordering {
    left.selector.cmp(&right.selector)
}

fn all_response_receipts(checkpoint: &ApiValidationCheckpoint) -> BTreeSet<String> {
    checkpoint
        .records
        .iter()
        .map(|record| record.observation.receipt.receipt_id.clone())
        .chain(checkpoint.replay_comparisons.iter().map(|comparison| {
            comparison
                .independent
                .observation
                .receipt
                .receipt_id
                .clone()
        }))
        .collect()
}
