mod common;

use api_validation::*;
use common::*;
use serde_json::json;

#[test]
fn strict_versioned_contracts_reject_unknown_fields_and_unsafe_methods() {
    let mut plan_value = serde_json::to_value(plan()).unwrap();
    plan_value["future"] = json!(true);
    assert!(serde_json::from_value::<ApiValidationPlan>(plan_value).is_err());

    let mut wrong_version = plan();
    wrong_version.schema_version += 1;
    assert!(wrong_version.validate().is_err());

    let mut selector_value = serde_json::to_value(selector()).unwrap();
    selector_value["method"] = json!("post");
    assert!(serde_json::from_value::<OperationSelector>(selector_value).is_err());

    let session = ApiValidationSession::start(plan(), vec![normalized()]).unwrap();
    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    checkpoint["future"] = json!([]);
    assert!(serde_json::from_value::<ApiValidationCheckpoint>(checkpoint).is_err());
}

#[test]
fn bounds_have_finite_defaults_and_enforced_hard_ceilings() {
    ValidationBounds::default().validate().unwrap();

    let bounds = ValidationBounds {
        max_selectors: 0,
        ..ValidationBounds::default()
    };
    assert!(bounds.validate().is_err());

    let bounds = ValidationBounds {
        max_document_bytes: MAX_DOCUMENT_BYTES + 1,
        ..ValidationBounds::default()
    };
    assert!(bounds.validate().is_err());

    let bounds = ValidationBounds {
        max_response_bytes: MAX_RESPONSE_BYTES + 1,
        ..ValidationBounds::default()
    };
    assert!(bounds.validate().is_err());

    let bounds = ValidationBounds {
        max_ref_depth: MAX_REF_DEPTH + 1,
        ..ValidationBounds::default()
    };
    assert!(bounds.validate().is_err());

    for bounds in [
        ValidationBounds {
            max_selectors: MAX_SELECTORS + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_ref_nodes: MAX_REF_NODES + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_schema_depth: MAX_SCHEMA_DEPTH + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_schema_nodes: MAX_SCHEMA_NODES + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_properties: MAX_PROPERTIES + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_shape_depth: MAX_SHAPE_DEPTH + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_shape_nodes: MAX_SHAPE_NODES + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_array_items: MAX_ARRAY_ITEMS + 1,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            max_results: MAX_RESULTS + 1,
            ..ValidationBounds::default()
        },
    ] {
        assert!(bounds.validate().is_err());
    }

    let mut impossible = plan();
    impossible.bounds.max_results = 1;
    impossible.selectors.push(OperationSelector {
        path: "/health".to_owned(),
        operation_id: None,
        ..selector()
    });
    assert!(impossible.validate().is_err());

    let mut no_replay_capacity = plan();
    no_replay_capacity.bounds.max_results = 1;
    assert!(no_replay_capacity.validate().is_err());
}

#[test]
fn selector_and_receipt_lineage_are_exact() {
    let mut variable = selector();
    variable.path = "/users/{id}".to_owned();
    assert!(variable.validate().is_err());

    let mut query = selector();
    query.path = "/users?admin=true".to_owned();
    assert!(query.validate().is_err());

    let mut bad_hash = selector();
    bad_hash.discovery_plan_hash = "A".repeat(64);
    assert!(bad_hash.validate().is_err());

    let mut bad_receipt = receipt("receipt", 'f');
    bad_receipt.receipt_content_hash.pop();
    assert!(bad_receipt.validate().is_err());
}

#[test]
fn plan_hash_is_canonical_and_stable() {
    let mut forward = plan();
    forward.selectors.push(OperationSelector {
        method: SafeMethod::Head,
        path: "/health".to_owned(),
        operation_id: None,
        ..selector()
    });
    let mut reverse = forward.clone();
    reverse.selectors.reverse();
    assert_eq!(
        forward.fingerprint().unwrap(),
        reverse.fingerprint().unwrap()
    );
    assert_eq!(
        forward.canonicalized().unwrap().selectors,
        reverse.canonicalized().unwrap().selectors
    );
    assert_eq!(
        forward.fingerprint().unwrap(),
        "be2f2d0dacd3b914c3a0566fc8d4b7bb244d68a5c0ba2e3ecc244cac4df3cc58"
    );
}

#[test]
fn json_shapes_never_retain_scalar_values_and_are_canonical() {
    let value = json!({
        "password": "hunter2",
        "count": 987654321,
        "enabled": true,
        "items": ["alpha", 17, "beta", 18]
    });
    let capture = JsonShapeCapture::from_json(&value, &ValidationBounds::default()).unwrap();
    let encoded = serde_json::to_string(&capture).unwrap();
    assert!(!encoded.contains("hunter2"));
    assert!(!encoded.contains("987654321"));
    assert!(!encoded.contains("alpha"));
    assert!(!encoded.contains("beta"));
    assert!(!encoded.contains("17"));
    assert!(!encoded.contains("18"));

    let first =
        JsonShapeCapture::from_json(&json!([1, "x", 2]), &ValidationBounds::default()).unwrap();
    let second =
        JsonShapeCapture::from_json(&json!(["y", 3]), &ValidationBounds::default()).unwrap();
    assert_eq!(first.shape, second.shape);
}

#[test]
fn shape_capture_reports_caps_without_fabricating_complete_evidence() {
    let bounds = ValidationBounds {
        max_shape_nodes: 2,
        max_array_items: 2,
        ..ValidationBounds::default()
    };
    let capture = JsonShapeCapture::from_json(&json!({"a":{"b":{"c":1}},"z":2}), &bounds).unwrap();
    assert!(capture.truncated);
    assert!(capture.visited_nodes <= 2);

    let op = operation();
    let mut observed = observation(&op, 200, Some("application/json"), None, "shape-cap");
    observed.body_present = true;
    observed.shape_truncated = true;
    observed.validate().unwrap();
    assert!(matches!(
        classify_response(&op, &observed).unwrap(),
        Conformance::Inconclusive { .. }
    ));
}

#[test]
fn shape_depth_ceiling_produces_a_valid_truncated_capture() {
    let bounds = ValidationBounds {
        max_shape_depth: 1,
        ..ValidationBounds::default()
    };
    let capture = JsonShapeCapture::from_json(
        &json!({"level_one":{"level_two":{"level_three":true}}}),
        &bounds,
    )
    .unwrap();
    assert!(capture.truncated);
    capture.validate(&bounds).unwrap();
}
