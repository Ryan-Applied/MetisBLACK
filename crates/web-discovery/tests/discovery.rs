use storage::hash;
use web_discovery::{
    AcquisitionFailureCode, DiscoveryBounds, DiscoveryFailure, DiscoveryObservation, DiscoveryPlan,
    DiscoverySession, EvidenceState, OmissionReason, ReceiptLineage, ResourceKind,
    RobotsDirectiveKind, DISCOVERY_SCHEMA_VERSION,
};

fn plan(seed: &str) -> DiscoveryPlan {
    DiscoveryPlan {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        plan_id: "discovery-fixture".to_owned(),
        seed_urls: vec![seed.to_owned()],
        allowed_origins: vec![],
        bounds: DiscoveryBounds::default(),
    }
}

fn apply(session: &mut DiscoverySession, body: &str, media_type: &str, truncated: bool) {
    let request = session.next_request().unwrap().clone();
    let observation = DiscoveryObservation::from_body(
        &request,
        request.url.clone(),
        200,
        Some(media_type.to_owned()),
        body,
        truncated,
        ReceiptLineage {
            receipt_id: format!("receipt-{}", &request.request_id[10..26]),
            receipt_content_hash: hash(request.request_id.as_bytes()),
        },
    );
    session.apply_observation(observation).unwrap();
}

#[test]
fn robots_sitemap_html_and_javascript_are_typed_and_receipted() {
    let mut session = DiscoverySession::start(plan("https://example.test/robots.txt")).unwrap();
    apply(
        &mut session,
        "User-agent: *\nDisallow: /private\nAllow: /public\nSitemap: /sitemap.xml",
        "text/plain",
        false,
    );
    assert_eq!(
        session.next_request().unwrap().expected_kind,
        ResourceKind::Sitemap
    );
    assert!(session
        .checkpoint()
        .robots_directives
        .iter()
        .any(|directive| directive.kind == RobotsDirectiveKind::Disallow));

    apply(
        &mut session,
        "<urlset><url><loc>https://example.test/index.html</loc></url></urlset>",
        "application/xml",
        false,
    );
    apply(
        &mut session,
        r#"<html><script src="/app.js"></script><form action="/login" method="post"><input name="user"><input type="password" name="pass" required value="never-persist"></form></html>"#,
        "text/html",
        false,
    );
    assert_eq!(
        session.next_request().unwrap().url,
        "https://example.test/app.js"
    );
    apply(
        &mut session,
        r#"fetch('/api/items'); const duplicate = "/api/items"; const remote = "https://elsewhere.test/x";"#,
        "application/javascript",
        false,
    );

    let artifact = session.artifact().unwrap();
    artifact.validate().unwrap();
    assert_eq!(artifact.forms.len(), 1);
    assert_eq!(artifact.forms[0].state, EvidenceState::Observed);
    assert!(!serde_json::to_string(&artifact)
        .unwrap()
        .contains("never-persist"));
    assert!(artifact
        .resources
        .iter()
        .any(|resource| resource.url == "https://example.test/api/items"));
    assert!(artifact.omissions.iter().any(|omission| {
        omission.reason == OmissionReason::OutsideAllowedOrigin
            && omission.state == EvidenceState::Omitted
    }));
    assert!(artifact
        .reverification_inputs
        .iter()
        .all(|input| !input.receipt.receipt_id.is_empty()));
}

#[test]
fn openapi_json_and_yaml_operations_are_declared_not_findings() {
    let mut json = DiscoverySession::start(plan("https://example.test/openapi.json")).unwrap();
    apply(
        &mut json,
        r#"{"openapi":"3.1.0","servers":[{"url":"/v3"}],"paths":{"/users/{id}":{"get":{"operationId":"getUser"}}},"components":{"schemas":{"Remote":{"$ref":"https://schemas.test/remote.json"}}}}"#,
        "application/json",
        false,
    );
    let artifact = json.artifact().unwrap();
    assert_eq!(artifact.operations.len(), 1);
    assert_eq!(artifact.operations[0].state, EvidenceState::Declared);
    assert_eq!(artifact.operations[0].method, "GET");
    assert!(artifact.operations[0]
        .resolved_url_template
        .as_deref()
        .unwrap()
        .ends_with("/v3/users/{id}"));
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::RemoteReference));

    let mut yaml = DiscoverySession::start(plan("https://example.test/swagger.yaml")).unwrap();
    apply(
        &mut yaml,
        "swagger: '2.0'\nhost: api.example.test\nbasePath: /v2\nschemes: [https]\npaths:\n  /pets:\n    post:\n      operationId: createPet\n",
        "application/yaml",
        false,
    );
    let operation = &yaml.artifact().unwrap().operations[0];
    assert_eq!(operation.method, "POST");
    assert_eq!(operation.operation_id.as_deref(), Some("createPet"));
    assert_eq!(
        operation.resolved_url_template.as_deref(),
        Some("https://api.example.test/v2/pets")
    );
}

#[test]
fn malformed_and_truncated_documents_never_claim_complete_parsing() {
    let mut session = DiscoverySession::start(plan("https://example.test/openapi.json")).unwrap();
    apply(&mut session, "{not-json", "application/json", true);
    let artifact = session.artifact().unwrap();
    assert!(artifact.complete);
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::TruncatedInput));
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::MalformedDocument));
    assert!(artifact.reverification_inputs[0].truncated);
}

#[test]
fn omission_and_robots_limits_are_explicit_without_off_by_one() {
    let mut bounded = plan("https://example.test/");
    bounded.bounds.max_omissions = 2;
    let mut session = DiscoverySession::start(bounded).unwrap();
    apply(
        &mut session,
        r#"<a href="https://outside-1.test/">one</a><a href="https://outside-2.test/">two</a><a href="https://outside-3.test/">three</a>"#,
        "text/html",
        false,
    );
    let artifact = session.artifact().unwrap();
    assert_eq!(artifact.omissions.len(), 2);
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::OmissionLimit));

    let mut bounded = plan("https://example.test/robots.txt");
    bounded.bounds.max_references_per_document = 1;
    let mut robots = DiscoverySession::start(bounded).unwrap();
    apply(
        &mut robots,
        "Allow: /first\nDisallow: /second",
        "text/plain",
        false,
    );
    assert_eq!(robots.checkpoint().robots_directives.len(), 1);
    assert!(robots
        .checkpoint()
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::ReferenceLimit));
}

#[test]
fn acceptance_depth_and_resource_caps_are_exact_and_explicit() {
    let mut depth_plan = plan("https://example.test/");
    depth_plan.bounds.max_depth = 0;
    let mut depth = DiscoverySession::start(depth_plan).unwrap();
    apply(
        &mut depth,
        r#"<a href="/child">child</a>"#,
        "text/html",
        false,
    );
    assert!(depth.is_complete());
    let artifact = depth.artifact().unwrap();
    let child = artifact
        .resources
        .iter()
        .find(|resource| resource.url == "https://example.test/child")
        .unwrap();
    assert_eq!(child.state, EvidenceState::Omitted);
    assert_eq!(child.depth, 0);
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::DepthLimit));

    let mut resource_plan = plan("https://example.test/");
    resource_plan.bounds.max_resources = 1;
    let mut resources = DiscoverySession::start(resource_plan).unwrap();
    apply(
        &mut resources,
        r#"<a href="/child">child</a>"#,
        "text/html",
        false,
    );
    let artifact = resources.artifact().unwrap();
    assert!(resources.is_complete());
    assert_eq!(artifact.resources.len(), 1);
    assert_eq!(artifact.resources[0].url, "https://example.test/");
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::ResourceLimit));
}

#[test]
fn acceptance_reference_form_and_control_caps_retain_exact_prefixes() {
    let mut reference_plan = plan("https://example.test/");
    reference_plan.bounds.max_references_per_document = 1;
    let mut references = DiscoverySession::start(reference_plan).unwrap();
    apply(
        &mut references,
        r#"<a href="/z">z</a><a href="/a">a</a>"#,
        "text/html",
        false,
    );
    let artifact = references.artifact().unwrap();
    assert_eq!(
        references.next_request().unwrap().url,
        "https://example.test/a"
    );
    assert!(!artifact
        .resources
        .iter()
        .any(|resource| resource.url == "https://example.test/z"));
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::ReferenceLimit));

    let mut form_plan = plan("https://example.test/");
    form_plan.bounds.max_forms_per_document = 1;
    let mut forms = DiscoverySession::start(form_plan).unwrap();
    apply(
        &mut forms,
        r#"<form action="/one"></form><form action="/two"></form>"#,
        "text/html",
        false,
    );
    let artifact = forms.artifact().unwrap();
    assert_eq!(artifact.forms.len(), 1);
    assert_eq!(artifact.forms[0].index, 0);
    assert_eq!(artifact.forms[0].action_url, "https://example.test/one");
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::FormLimit));

    let mut control_plan = plan("https://example.test/");
    control_plan.bounds.max_controls_per_form = 1;
    let mut controls = DiscoverySession::start(control_plan).unwrap();
    apply(
        &mut controls,
        r#"<form action="/submit"><input name="first"><input name="second"></form>"#,
        "text/html",
        false,
    );
    let artifact = controls.artifact().unwrap();
    assert_eq!(artifact.forms.len(), 1);
    assert_eq!(artifact.forms[0].controls.len(), 1);
    assert_eq!(artifact.forms[0].controls[0].name.as_deref(), Some("first"));
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::FormControlLimit));
}

#[test]
fn acceptance_openapi_operation_cap_is_sorted_and_explicit() {
    let mut source_plan = plan("https://example.test/openapi.json");
    source_plan.bounds.max_openapi_operations = 1;
    let mut session = DiscoverySession::start(source_plan).unwrap();
    apply(
        &mut session,
        r#"{"openapi":"3.1.0","paths":{"/z":{"post":{"operationId":"z"}},"/a":{"get":{"operationId":"a"}}}}"#,
        "application/json",
        false,
    );
    let artifact = session.artifact().unwrap();
    assert_eq!(artifact.operations.len(), 1);
    assert_eq!(artifact.operations[0].method, "GET");
    assert_eq!(artifact.operations[0].path_template, "/a");
    assert_eq!(artifact.operations[0].operation_id.as_deref(), Some("a"));
    assert!(artifact
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::OpenApiOperationLimit));
}

fn failure(session: &DiscoverySession, code: AcquisitionFailureCode) -> DiscoveryFailure {
    let request = session.next_request().unwrap();
    DiscoveryFailure {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        request_id: request.request_id.clone(),
        code,
        detail: "receipt-backed fixture acquisition failure".to_owned(),
        receipt: ReceiptLineage {
            receipt_id: format!("failure-{}", &request.request_id[10..26]),
            receipt_content_hash: hash(request.request_id.as_bytes()),
        },
    }
}

#[test]
fn failures_are_fail_closed_ordered_and_resumable() {
    let source_plan = plan("https://example.test/");
    let mut session = DiscoverySession::start(source_plan.clone()).unwrap();
    let before = session.checkpoint().clone();
    let mut wrong = failure(&session, AcquisitionFailureCode::Timeout);
    wrong.request_id = "wrong-frontier-request".to_owned();
    assert!(session.apply_failure(wrong).is_err());
    assert_eq!(session.checkpoint(), &before);

    let terminal = failure(&session, AcquisitionFailureCode::Timeout);
    session.apply_failure(terminal).unwrap();
    assert!(session.is_complete());
    assert_eq!(session.checkpoint().transition_count, 1);
    assert_eq!(
        session.checkpoint().failure_reverification_inputs[0].sequence,
        0
    );
    assert_eq!(
        session.checkpoint().resources[0].state,
        EvidenceState::Omitted
    );
    assert!(session
        .checkpoint()
        .omissions
        .iter()
        .any(|omission| omission.reason == OmissionReason::AcquisitionFailure));

    let checkpoint = session.clone().into_checkpoint();
    let resumed = DiscoverySession::resume(source_plan, checkpoint).unwrap();
    assert_eq!(
        session.artifact().unwrap().canonical_hash().unwrap(),
        resumed.artifact().unwrap().canonical_hash().unwrap()
    );
}

#[test]
fn ordered_transition_replay_rebuilds_the_same_artifact() {
    let source_plan = plan("https://example.test/");
    let mut original = DiscoverySession::start(source_plan.clone()).unwrap();
    let root_request = original.next_request().unwrap().clone();
    let root = DiscoveryObservation::from_body(
        &root_request,
        root_request.url.clone(),
        200,
        Some("text/html".to_owned()),
        r#"<a href="/b">b</a><a href="/a">a</a>"#,
        false,
        ReceiptLineage {
            receipt_id: "receipt-root".to_owned(),
            receipt_content_hash: hash(b"receipt-root"),
        },
    );
    original.apply_observation(root.clone()).unwrap();
    let a_request = original.next_request().unwrap().clone();
    let a = DiscoveryObservation::from_body(
        &a_request,
        a_request.url.clone(),
        200,
        Some("text/html".to_owned()),
        r#"<a href="/deep">deep</a>"#,
        false,
        ReceiptLineage {
            receipt_id: "receipt-a".to_owned(),
            receipt_content_hash: hash(b"receipt-a"),
        },
    );
    original.apply_observation(a.clone()).unwrap();
    let b_failure = failure(&original, AcquisitionFailureCode::Connection);
    original.apply_failure(b_failure.clone()).unwrap();

    let mut non_contiguous = original.checkpoint().clone();
    non_contiguous.failure_reverification_inputs[0].sequence = 1;
    assert!(DiscoverySession::resume(source_plan.clone(), non_contiguous).is_err());

    let mut replay = DiscoverySession::start(source_plan).unwrap();
    replay.apply_observation(root).unwrap();
    replay.apply_observation(a).unwrap();
    replay.apply_failure(b_failure).unwrap();
    assert_eq!(original.checkpoint().reverification_inputs[0].sequence, 0);
    assert_eq!(original.checkpoint().reverification_inputs[1].sequence, 1);
    assert_eq!(
        original.checkpoint().failure_reverification_inputs[0].sequence,
        2
    );
    assert_eq!(
        original.artifact().unwrap().canonical_hash().unwrap(),
        replay.artifact().unwrap().canonical_hash().unwrap()
    );
}
