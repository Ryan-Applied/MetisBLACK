use std::collections::BTreeSet;

use metisblack_cloud_runtime::{
    AdapterReport, CloudBoundary, CrossBoundaryAuthorization, EdgeDisposition, EdgeEvidence,
    EdgeRelation, GapKind, GraphGap, IamBinding, IamEdgeCandidate, IamGraphBuilder, IamNode,
    Observation, PrincipalKind, PrincipalNode, Provider, ResourceNode, RoleNode,
};
use serde_json::json;

fn evidence(provider: Provider, scope: &str) -> EdgeEvidence {
    EdgeEvidence {
        provider,
        authorizing_scope_id: scope.into(),
        source_audit_ids: BTreeSet::from(["audit-1".into()]),
        source_resource_ids: BTreeSet::from(["resource-1".into()]),
    }
}

fn principal(boundary: &CloudBoundary, id: &str) -> IamNode {
    IamNode::Principal(PrincipalNode {
        boundary: boundary.clone(),
        principal_id: id.into(),
        kind: PrincipalKind::User,
    })
}

fn resource(boundary: &CloudBoundary, id: &str) -> IamNode {
    IamNode::Resource(ResourceNode {
        boundary: boundary.clone(),
        resource_type: "test".into(),
        resource_id: id.into(),
    })
}

fn confirmed(
    builder: &mut IamGraphBuilder,
    from: metisblack_cloud_runtime::NodeKey,
    to: metisblack_cloud_runtime::NodeKey,
    scope: &str,
) {
    let disposition = builder
        .add_edge(IamEdgeCandidate {
            from,
            to,
            relation: EdgeRelation::GrantsCapability,
            evidence: evidence(Provider::Aws, scope),
            cross_boundary_authorization: CrossBoundaryAuthorization::Denied,
        })
        .unwrap();
    assert!(matches!(disposition, EdgeDisposition::Confirmed(_)));
}

#[test]
fn direct_reachability_has_one_evidence_backed_edge() {
    let boundary = CloudBoundary::new(Provider::Aws, "111");
    let mut builder = IamGraphBuilder::new();
    let from = builder.add_node(principal(&boundary, "alice")).unwrap();
    let to = builder.add_node(resource(&boundary, "bucket")).unwrap();
    confirmed(&mut builder, from.clone(), to.clone(), "111");
    let graph = builder.finish();

    let path = graph.shortest_path(&from, &to).unwrap().unwrap();
    assert_eq!(path.nodes, vec![from, to]);
    assert_eq!(path.edges.len(), 1);
}

#[test]
fn transitive_and_cyclic_queries_are_shortest_and_cycle_safe() {
    let boundary = CloudBoundary::new(Provider::Aws, "111");
    let mut builder = IamGraphBuilder::new();
    let principal = builder.add_node(principal(&boundary, "alice")).unwrap();
    let role = builder
        .add_node(IamNode::Role(RoleNode {
            boundary: boundary.clone(),
            role_id: "admin".into(),
        }))
        .unwrap();
    let resource = builder.add_node(resource(&boundary, "db")).unwrap();
    confirmed(&mut builder, principal.clone(), role.clone(), "111");
    confirmed(&mut builder, role.clone(), resource.clone(), "111");
    confirmed(&mut builder, resource.clone(), principal.clone(), "111");
    let graph = builder.finish();

    let reachable = graph.reachable_from(&principal).unwrap();
    assert_eq!(reachable, BTreeSet::from([role.clone(), resource.clone()]));
    let path = graph.shortest_path(&principal, &resource).unwrap().unwrap();
    assert_eq!(path.nodes, vec![principal, role, resource]);
    assert_eq!(path.edges.len(), 2);
}

#[test]
fn cross_boundary_candidate_is_denied_without_explicit_source_authorization() {
    let source_boundary = CloudBoundary::new(Provider::Aws, "111");
    let target_boundary = CloudBoundary::new(Provider::Aws, "222");
    let mut builder = IamGraphBuilder::new();
    let from = builder
        .add_node(principal(&source_boundary, "foreign-user"))
        .unwrap();
    let to = builder
        .add_node(resource(&target_boundary, "target-role"))
        .unwrap();
    let disposition = builder
        .add_edge(IamEdgeCandidate {
            from: from.clone(),
            to: to.clone(),
            relation: EdgeRelation::CanAssumeRole,
            evidence: evidence(Provider::Aws, "222"),
            cross_boundary_authorization: CrossBoundaryAuthorization::Denied,
        })
        .unwrap();
    assert!(matches!(disposition, EdgeDisposition::RecordedGap(_)));
    let graph = builder.finish();
    assert!(graph.shortest_path(&from, &to).unwrap().is_none());
    assert!(graph
        .gaps
        .values()
        .any(|gap| gap.kind == GapKind::CrossBoundaryDenied));
}

#[test]
fn missing_evidence_is_an_unknown_not_a_reachable_edge() {
    let boundary = CloudBoundary::new(Provider::Aws, "111");
    let mut builder = IamGraphBuilder::new();
    let from = builder.add_node(principal(&boundary, "alice")).unwrap();
    let to = builder.add_node(resource(&boundary, "db")).unwrap();
    let disposition = builder
        .add_edge(IamEdgeCandidate {
            from: from.clone(),
            to: to.clone(),
            relation: EdgeRelation::GrantsCapability,
            evidence: EdgeEvidence {
                provider: Provider::Aws,
                authorizing_scope_id: "111".into(),
                source_audit_ids: BTreeSet::new(),
                source_resource_ids: BTreeSet::from(["db".into()]),
            },
            cross_boundary_authorization: CrossBoundaryAuthorization::Denied,
        })
        .unwrap();
    assert!(matches!(disposition, EdgeDisposition::RecordedGap(_)));
    let graph = builder.finish();
    assert!(graph.shortest_path(&from, &to).unwrap().is_none());
    assert!(graph
        .gaps
        .values()
        .any(|gap| gap.kind == GapKind::MissingEvidence));
}

#[allow(clippy::too_many_arguments)]
fn observation(
    provider: Provider,
    scope_id: &str,
    resource_type: &str,
    resource_id: &str,
    role: &str,
    principal: &str,
    audit: &str,
    configuration: serde_json::Value,
) -> Observation {
    Observation {
        provider,
        scope_id: scope_id.into(),
        location: None,
        service: "iam".into(),
        resource_type: resource_type.into(),
        resource_id: resource_id.into(),
        name: resource_id.into(),
        configuration,
        iam: vec![IamBinding {
            role: role.into(),
            principal: principal.into(),
            condition: None,
        }],
        source_audit_id: audit.into(),
    }
}

fn key_for<F>(report: &AdapterReport, predicate: F) -> metisblack_cloud_runtime::NodeKey
where
    F: Fn(&IamNode) -> bool,
{
    report
        .graph
        .nodes
        .iter()
        .find_map(|(key, node)| predicate(node).then(|| key.clone()))
        .expect("fixture node")
}

#[test]
fn provider_adapters_emit_conservative_evidence_paths() {
    let fixtures = [
        observation(
            Provider::Aws,
            "111",
            "iam_role",
            "role-a",
            "AuditRole",
            "arn:aws:iam::111:user/alice",
            "audit-aws",
            json!({"RoleName":"AuditRole"}),
        ),
        observation(
            Provider::Azure,
            "sub-1",
            "role_assignment",
            "assignment-a",
            "Reader",
            "principal-azure",
            "audit-azure",
            json!({"principalType":"User"}),
        ),
        observation(
            Provider::Gcp,
            "project-1",
            "project_iam_policy",
            "project-1",
            "roles/viewer",
            "user:bob@example.test",
            "audit-gcp",
            json!({"bindings":[]}),
        ),
    ];
    let report = AdapterReport::from_observations(&fixtures).unwrap();
    for provider in [Provider::Aws, Provider::Azure, Provider::Gcp] {
        let subject = key_for(
            &report,
            |node| matches!(node, IamNode::Principal(value) if value.boundary.provider == provider),
        );
        let resource = key_for(
            &report,
            |node| matches!(node, IamNode::Resource(value) if value.boundary.provider == provider),
        );
        let path = report
            .graph
            .shortest_path(&subject, &resource)
            .unwrap()
            .unwrap();
        assert_eq!(path.edges.len(), 3);
        assert!(path.edges.iter().all(|edge| report
            .graph
            .edges
            .get(edge)
            .is_some_and(|value| !value.evidence.source_audit_ids.is_empty())));
    }
    assert_eq!(report.graph.gaps.len(), 3);
}

#[test]
fn explicit_aws_cross_account_trust_is_reachable_and_evidence_backed() {
    let fixture = observation(
        Provider::Aws,
        "222",
        "iam_role",
        "target-role",
        "TargetRole",
        "arn:aws:iam::111:role/SourceRole",
        "audit-trust",
        json!({"RoleName":"TargetRole"}),
    );
    let report = AdapterReport::from_observations(&[fixture]).unwrap();
    let subject = key_for(&report, |node| matches!(node, IamNode::Principal(_)));
    let resource = key_for(&report, |node| matches!(node, IamNode::Resource(_)));
    let path = report
        .graph
        .shortest_path(&subject, &resource)
        .unwrap()
        .unwrap();
    let first = report.graph.edges.get(&path.edges[0]).unwrap();
    assert!(first.crosses_boundary);
    assert_eq!(first.evidence.authorizing_scope_id, "222");
}

#[test]
fn assumptions_are_serialized_but_never_traversed_and_serialization_is_deterministic() {
    let one = observation(
        Provider::Gcp,
        "project-1",
        "project_iam_policy",
        "project-1",
        "roles/viewer",
        "user:a@example.test",
        "audit-a",
        json!({}),
    );
    let two = observation(
        Provider::Azure,
        "sub-1",
        "role_assignment",
        "assignment-1",
        "Reader",
        "principal-b",
        "audit-b",
        json!({}),
    );
    let forward = AdapterReport::from_observations(&[one.clone(), two.clone()]).unwrap();
    let reverse = AdapterReport::from_observations(&[two, one]).unwrap();
    assert_eq!(
        forward.graph.canonical_json().unwrap(),
        reverse.graph.canonical_json().unwrap()
    );

    let boundary = CloudBoundary::new(Provider::Aws, "111");
    let mut builder = IamGraphBuilder::new();
    let from = builder.add_node(principal(&boundary, "a")).unwrap();
    let to = builder.add_node(resource(&boundary, "b")).unwrap();
    builder
        .record_gap(GraphGap::new(
            GapKind::Assumption,
            Some(from.clone()),
            Some(to.clone()),
            "group membership is asserted but was not observed",
            BTreeSet::from(["audit-assumption".into()]),
        ))
        .unwrap();
    let graph = builder.finish();
    assert!(graph.shortest_path(&from, &to).unwrap().is_none());
    assert!(graph.canonical_json().unwrap().contains("assumption"));
}
