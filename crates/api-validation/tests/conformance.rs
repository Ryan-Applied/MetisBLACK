mod common;

use api_validation::*;
use common::*;
use serde_json::json;

fn classify(status: u16, media: Option<&str>, body: Option<serde_json::Value>) -> Conformance {
    let operation = operation();
    let observation = observation(&operation, status, media, body, "response");
    classify_response(&operation, &observation).unwrap()
}

#[test]
fn exact_status_media_type_required_and_nested_types_conform() {
    assert_eq!(
        classify(
            200,
            Some("application/json"),
            Some(json!({"id": 7, "tags": ["red", "blue"]}))
        ),
        Conformance::Conforming
    );
    assert_eq!(classify(204, None, None), Conformance::Conforming);
}

#[test]
fn undeclared_status_is_inconclusive_but_media_mismatch_is_a_violation() {
    assert_eq!(
        classify(
            201,
            Some("application/json"),
            Some(json!({"id": 1, "tags": []}))
        ),
        Conformance::Inconclusive {
            reasons: vec![ConformanceReason::StatusUndeclared { status: 201 }]
        }
    );
    assert_eq!(
        classify(
            200,
            Some("application/problem+json"),
            Some(json!({"id": 1, "tags": []}))
        ),
        Conformance::Violating {
            reasons: vec![ConformanceReason::MediaTypeUndeclared {
                media_type: "application/problem+json".to_owned()
            }]
        }
    );
    assert_eq!(
        classify(204, Some("application/json"), Some(json!({}))),
        Conformance::Inconclusive {
            reasons: vec![ConformanceReason::ResponseSchemaMissing]
        }
    );
}

#[test]
fn head_without_a_body_does_not_inherit_get_style_body_requirements() {
    let mut head_plan = plan();
    head_plan.selectors[0].method = SafeMethod::Head;
    head_plan.selectors[0].operation_id = Some("headUsers".to_owned());
    let document = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"head":{"operationId":"headUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}}}}}}}}
    }"##;
    let normalized = normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document,
            receipt: receipt("head-source", 'e'),
        },
        &head_plan,
    )
    .unwrap();
    let operation = &normalized.operations[0];
    let observed = observation(operation, 200, None, None, "head-response");
    assert_eq!(
        classify_response(operation, &observed).unwrap(),
        Conformance::Conforming
    );
}

#[test]
fn exact_type_required_and_array_item_near_negatives_violate() {
    assert_eq!(
        classify(
            200,
            Some("application/json"),
            Some(json!({"id": "7", "tags": ["ok"]}))
        ),
        Conformance::Violating {
            reasons: vec![ConformanceReason::TypeMismatch {
                path: "$.id".to_owned(),
                expected: "integer".to_owned(),
                actual: "string".to_owned(),
            }]
        }
    );
    assert_eq!(
        classify(200, Some("application/json"), Some(json!({"tags": ["ok"]}))),
        Conformance::Violating {
            reasons: vec![ConformanceReason::RequiredPropertyMissing {
                path: "$".to_owned(),
                property: "id".to_owned(),
            }]
        }
    );
    assert_eq!(
        classify(
            200,
            Some("application/json"),
            Some(json!({"id": 7, "tags": ["ok", 2]}))
        ),
        Conformance::Violating {
            reasons: vec![ConformanceReason::TypeMismatch {
                path: "$.tags[]".to_owned(),
                expected: "string".to_owned(),
                actual: "integer".to_owned(),
            }]
        }
    );
}

#[test]
fn transient_statuses_are_always_inconclusive() {
    for status in [408, 429, 500, 503, 599] {
        assert_eq!(
            classify(status, None, None),
            Conformance::Inconclusive {
                reasons: vec![ConformanceReason::TransientStatus { status }]
            }
        );
    }
}

#[test]
fn exact_status_precedes_class_and_default_fallbacks() {
    let document = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{
        "200":{"description":"exact","content":{"application/json":{"schema":{"type":"string"}}}},
        "2XX":{"description":"class","content":{"application/json":{"schema":{"type":"integer"}}}},
        "default":{"description":"default","content":{"application/json":{"schema":{"type":"boolean"}}}}
      }}}}
    }"##;
    let normalized = normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document,
            receipt: receipt("status-source", 'e'),
        },
        &plan(),
    )
    .unwrap();
    let operation = &normalized.operations[0];
    for (status, body) in [(200, json!("ok")), (201, json!(7)), (404, json!(true))] {
        let observed = observation(
            operation,
            status,
            Some("application/json"),
            Some(body),
            &format!("status-{status}"),
        );
        assert_eq!(
            classify_response(operation, &observed).unwrap(),
            Conformance::Conforming
        );
    }
}

#[test]
fn truncation_malformed_json_missing_shape_and_unsupported_schema_are_inconclusive() {
    let operation = operation();
    let mut truncated = observation(
        &operation,
        200,
        Some("application/json"),
        Some(json!({"id": 1, "tags": []})),
        "truncated",
    );
    truncated.body_truncated = true;
    assert!(matches!(
        classify_response(&operation, &truncated).unwrap(),
        Conformance::Inconclusive { .. }
    ));

    let mut malformed = observation(&operation, 200, Some("application/json"), None, "malformed");
    malformed.body_present = true;
    malformed.malformed_json = true;
    assert_eq!(
        classify_response(&operation, &malformed).unwrap(),
        Conformance::Inconclusive {
            reasons: vec![ConformanceReason::MalformedJson]
        }
    );

    let mut unavailable = malformed.clone();
    unavailable.malformed_json = false;
    unavailable.receipt.receipt_id = "unavailable".to_owned();
    assert_eq!(
        classify_response(&operation, &unavailable).unwrap(),
        Conformance::Inconclusive {
            reasons: vec![ConformanceReason::JsonShapeUnavailable]
        }
    );

    let unsupported_document = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"string","pattern":"^[a-z]+$"}}}}}}}}
    }"##;
    let normalized = normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document: unsupported_document,
            receipt: receipt("unsupported-source", 'e'),
        },
        &plan(),
    )
    .unwrap();
    let unsupported_operation = &normalized.operations[0];
    let unsupported_observation = observation(
        unsupported_operation,
        200,
        Some("application/json"),
        Some(json!("valid")),
        "unsupported-response",
    );
    assert!(matches!(
        classify_response(unsupported_operation, &unsupported_observation).unwrap(),
        Conformance::Inconclusive { reasons }
            if matches!(&reasons[..], [ConformanceReason::UnsupportedSchema { .. }])
    ));
}

#[test]
fn session_binds_receipts_and_independent_replay_before_sealing_violation() {
    let validation_plan = plan();
    let contract = normalized();
    let operation = contract.operations[0].clone();
    let mut session =
        ApiValidationSession::start(validation_plan.clone(), vec![contract.clone()]).unwrap();
    let primary = observation(
        &operation,
        200,
        Some("application/json"),
        Some(json!({"tags": []})),
        "primary-response",
    );
    session.apply_observation(primary).unwrap();
    assert!(session
        .artifact()
        .unwrap_err()
        .to_string()
        .contains("independent replay"));

    let replay = observation(
        &operation,
        200,
        Some("application/json"),
        Some(json!({"tags": []})),
        "independent-response",
    );
    session.apply_replay_observation(replay).unwrap();
    let artifact = session.artifact().unwrap();
    artifact.verify(&validation_plan).unwrap();
    assert_eq!(artifact.response_receipts.len(), 2);
    assert!(matches!(
        artifact.replay_comparisons[0].classification,
        ReplayClassification::Reproduced { .. }
    ));

    let resumed = ApiValidationSession::resume(
        validation_plan,
        vec![contract],
        session.checkpoint().clone(),
    )
    .unwrap();
    assert_eq!(
        resumed.artifact().unwrap().canonical_hash().unwrap(),
        artifact.canonical_hash().unwrap()
    );
}

#[test]
fn replay_requires_exact_canonical_violation_and_distinct_receipt() {
    let contract = normalized();
    let operation = contract.operations[0].clone();
    let mut session = ApiValidationSession::start(plan(), vec![contract]).unwrap();
    session
        .apply_observation(observation(
            &operation,
            200,
            Some("application/json"),
            Some(json!({"tags": []})),
            "primary",
        ))
        .unwrap();
    session
        .apply_replay_observation(observation(
            &operation,
            200,
            Some("application/json"),
            Some(json!({"id": "wrong", "tags": []})),
            "independent",
        ))
        .unwrap();
    let artifact = session.artifact().unwrap();
    assert!(matches!(
        artifact.replay_comparisons[0].classification,
        ReplayClassification::ViolationMismatch { .. }
    ));

    let mut tampered = artifact.clone();
    tampered.replay_comparisons[0].classification = ReplayClassification::PrimaryNotViolating;
    assert!(tampered.verify(&plan()).is_err());

    let mut unknown = serde_json::to_value(artifact).unwrap();
    unknown["future"] = json!(true);
    assert!(serde_json::from_value::<ApiValidationArtifact>(unknown).is_err());
}

#[test]
fn replay_is_not_reproduced_when_status_or_media_surface_differs() {
    let document = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{
        "200":{"description":"ok","content":{
          "application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}},
          "application/problem+json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}}
        }},
        "201":{"description":"created","content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}}}}
      }}}}
    }"##;
    let normalized = normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document,
            receipt: receipt("surface-source", 'e'),
        },
        &plan(),
    )
    .unwrap();
    let operation = &normalized.operations[0];
    let primary_observation = observation(
        operation,
        200,
        Some("application/json"),
        Some(json!({})),
        "surface-primary",
    );
    let primary = ValidationRecord {
        result: classify_response(operation, &primary_observation).unwrap(),
        observation: primary_observation,
    };

    let status_observation = observation(
        operation,
        201,
        Some("application/json"),
        Some(json!({})),
        "surface-status",
    );
    let status_replay = ValidationRecord {
        result: classify_response(operation, &status_observation).unwrap(),
        observation: status_observation,
    };
    assert!(matches!(
        compare_replay(primary.clone(), status_replay)
            .unwrap()
            .classification,
        ReplayClassification::ObservationMismatch { .. }
    ));

    let media_observation = observation(
        operation,
        200,
        Some("application/problem+json"),
        Some(json!({})),
        "surface-media",
    );
    let media_replay = ValidationRecord {
        result: classify_response(operation, &media_observation).unwrap(),
        observation: media_observation,
    };
    assert!(matches!(
        compare_replay(primary, media_replay)
            .unwrap()
            .classification,
        ReplayClassification::ObservationMismatch { .. }
    ));
}

#[test]
fn conforming_result_can_seal_without_an_unnecessary_replay() {
    let validation_plan = plan();
    let contract = normalized();
    let operation = contract.operations[0].clone();
    let mut session = ApiValidationSession::start(validation_plan.clone(), vec![contract]).unwrap();
    session
        .apply_observation(observation(
            &operation,
            200,
            Some("application/json"),
            Some(json!({"id": 1, "tags": []})),
            "conforming",
        ))
        .unwrap();
    let artifact = session.artifact().unwrap();
    assert!(artifact.replay_comparisons.is_empty());
    artifact.verify(&validation_plan).unwrap();
}
