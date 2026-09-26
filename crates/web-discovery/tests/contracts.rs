use serde_json::json;
use storage::hash;
use web_discovery::{
    DiscoveryArtifact, DiscoveryBounds, DiscoveryCheckpoint, DiscoveryObservation, DiscoveryPlan,
    DiscoverySession, EvidenceState, ReceiptLineage, SourceLineage, DISCOVERY_SCHEMA_VERSION,
};

fn plan(seeds: &[&str]) -> DiscoveryPlan {
    DiscoveryPlan {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        plan_id: "contract-fixture".to_owned(),
        seed_urls: seeds.iter().map(|seed| (*seed).to_owned()).collect(),
        allowed_origins: vec![],
        bounds: DiscoveryBounds::default(),
    }
}

fn observation(
    session: &DiscoverySession,
    body: &str,
    media_type: &str,
    truncated: bool,
) -> DiscoveryObservation {
    let request = session.next_request().expect("pending request");
    DiscoveryObservation::from_body(
        request,
        request.url.clone(),
        200,
        Some(media_type.to_owned()),
        body,
        truncated,
        ReceiptLineage {
            receipt_id: format!("receipt-{}", &request.request_id[10..26]),
            receipt_content_hash: hash(request.request_id.as_bytes()),
        },
    )
}

#[test]
fn contracts_reject_unknown_fields_and_unknown_schema_versions() {
    let mut plan_value = serde_json::to_value(plan(&["https://example.test/"])).unwrap();
    plan_value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<DiscoveryPlan>(plan_value).is_err());

    let mut unsupported = plan(&["https://example.test/"]);
    unsupported.schema_version += 1;
    assert!(DiscoverySession::start(unsupported).is_err());

    let session = DiscoverySession::start(plan(&["https://example.test/"])).unwrap();
    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    checkpoint["future_field"] = json!([]);
    assert!(serde_json::from_value::<DiscoveryCheckpoint>(checkpoint).is_err());

    let mut artifact = serde_json::to_value(session.artifact().unwrap()).unwrap();
    artifact["future_field"] = json!("not silently accepted");
    assert!(serde_json::from_value::<DiscoveryArtifact>(artifact).is_err());
}

#[test]
fn plan_and_artifact_hashes_are_order_independent_and_stable() {
    let forward = plan(&["https://example.test/z", "https://example.test/a"]);
    let reverse = plan(&["https://example.test/a", "https://example.test/z"]);
    assert_eq!(
        forward.fingerprint().unwrap(),
        reverse.fingerprint().unwrap()
    );
    assert_eq!(
        forward.fingerprint().unwrap(),
        "9fdc12b63c8a73fc748e5d8ace811025c99b62143b8e6879dc110ca70a381cc9"
    );

    let mut session = DiscoverySession::start(plan(&["https://example.test/"])).unwrap();
    let input = observation(
        &session,
        r#"<a href="/z">z</a><a href="/a">a</a>"#,
        "text/html",
        false,
    );
    session.apply_observation(input).unwrap();
    let artifact = session.artifact().unwrap();
    let mut reordered = artifact.clone();
    reordered.resources.reverse();
    assert_eq!(
        artifact.canonical_hash().unwrap(),
        reordered.canonical_hash().unwrap()
    );
    assert_eq!(
        artifact.canonical_hash().unwrap(),
        "84ce355a8c7bd07934e4e4f661c2605a6a47c4e53427dd45e6ba38db59845b1f"
    );
}

#[test]
fn finite_bounds_reject_zero_and_excessive_inputs() {
    let mut invalid = plan(&["https://example.test/"]);
    invalid.bounds.max_resources = 0;
    assert!(invalid.validate().is_err());

    let mut invalid = plan(&["https://example.test/"]);
    invalid.bounds.max_document_bytes = 16 * 1024 * 1024 + 1;
    assert!(invalid.validate().is_err());

    let mut invalid = plan(&["https://example.test/a", "https://example.test/b"]);
    invalid.bounds.max_resources = 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn semantic_validation_rejects_conflicting_records_for_one_resource_url() {
    let source_plan = plan(&["https://example.test/"]);
    let mut session = DiscoverySession::start(source_plan.clone()).unwrap();
    let input = observation(&session, "<html></html>", "text/html", false);
    session.apply_observation(input).unwrap();

    let mut artifact = session.artifact().unwrap();
    let mut duplicate = artifact.resources[0].clone();
    duplicate.state = EvidenceState::Omitted;
    artifact.resources.push(duplicate);
    artifact.resources.sort();
    let error = artifact.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate resource URL"), "{error}");

    let mut checkpoint = session.into_checkpoint();
    let mut duplicate = checkpoint.resources[0].clone();
    duplicate.state = EvidenceState::Omitted;
    checkpoint.resources.push(duplicate);
    checkpoint.resources.sort();
    let error = DiscoverySession::resume(source_plan, checkpoint)
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate resource URL"), "{error}");
}

#[test]
fn semantic_validation_rejects_plan_lineage_on_derived_records() {
    let source_plan = plan(&["https://example.test/"]);
    let mut session = DiscoverySession::start(source_plan.clone()).unwrap();
    let input = observation(
        &session,
        r#"<form action="/submit"><input name="value"></form>"#,
        "text/html",
        false,
    );
    session.apply_observation(input).unwrap();

    let invalid_lineage = SourceLineage::Plan {
        plan_hash: source_plan.fingerprint().unwrap(),
    };
    let mut artifact = session.artifact().unwrap();
    artifact.forms[0].lineage = invalid_lineage.clone();
    let error = artifact.validate().unwrap_err().to_string();
    assert!(error.contains("form cannot claim plan lineage"), "{error}");

    let mut checkpoint = session.into_checkpoint();
    checkpoint.forms[0].lineage = invalid_lineage;
    let error = DiscoverySession::resume(source_plan, checkpoint)
        .unwrap_err()
        .to_string();
    assert!(error.contains("form cannot claim plan lineage"), "{error}");
}
