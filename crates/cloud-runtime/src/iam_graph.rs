//! Provider-neutral, evidence-only IAM reachability.
//!
//! The graph intentionally separates confirmed edges from inference gaps.
//! Reachability queries never traverse assumptions, missing evidence, or
//! cross-boundary candidates without an explicit authorization record.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{IamBinding, Observation, Provider};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CloudBoundary {
    pub provider: Provider,
    /// AWS account ID, Azure subscription ID, or GCP project ID.
    pub scope_id: String,
}

impl CloudBoundary {
    pub fn new(provider: Provider, scope_id: impl Into<String>) -> Self {
        Self {
            provider,
            scope_id: scope_id.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    ServiceAccount,
    Federated,
    Workload,
    Public,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalNode {
    pub boundary: CloudBoundary,
    pub principal_id: String,
    pub kind: PrincipalKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleNode {
    pub boundary: CloudBoundary,
    pub role_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupNode {
    pub boundary: CloudBoundary,
    pub group_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceNode {
    pub boundary: CloudBoundary,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyNode {
    pub boundary: CloudBoundary,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityNode {
    pub boundary: CloudBoundary,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IamNode {
    Principal(PrincipalNode),
    Role(RoleNode),
    Group(GroupNode),
    Resource(ResourceNode),
    Policy(PolicyNode),
    Capability(CapabilityNode),
}

impl IamNode {
    pub fn boundary(&self) -> &CloudBoundary {
        match self {
            Self::Principal(node) => &node.boundary,
            Self::Role(node) => &node.boundary,
            Self::Group(node) => &node.boundary,
            Self::Resource(node) => &node.boundary,
            Self::Policy(node) => &node.boundary,
            Self::Capability(node) => &node.boundary,
        }
    }

    pub fn key(&self) -> NodeKey {
        let identity = match self {
            Self::Principal(node) => format!("principal|{:?}|{}", node.kind, node.principal_id),
            Self::Role(node) => format!("role|{}", node.role_id),
            Self::Group(node) => format!("group|{}", node.group_id),
            Self::Resource(node) => {
                format!("resource|{}|{}", node.resource_type, node.resource_id)
            }
            Self::Policy(node) => format!("policy|{}", node.policy_id),
            Self::Capability(node) => format!("capability|{}", node.action),
        };
        NodeKey(format!(
            "node-{}",
            &sha256(
                format!(
                    "{:?}|{}|{identity}",
                    self.boundary().provider,
                    self.boundary().scope_id
                )
                .as_bytes()
            )[..32]
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeKey(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdgeId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRelation {
    MemberOfGroup,
    SubjectOfPolicy,
    TrustsPrincipal,
    GrantsRole,
    CanAssumeRole,
    AppliesToResource,
    GrantsCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeEvidence {
    pub provider: Provider,
    /// Boundary in which the authorizing policy was observed.
    pub authorizing_scope_id: String,
    pub source_audit_ids: BTreeSet<String>,
    pub source_resource_ids: BTreeSet<String>,
}

impl EdgeEvidence {
    pub fn from_observation(observation: &Observation) -> Self {
        Self {
            provider: observation.provider,
            authorizing_scope_id: observation.scope_id.clone(),
            source_audit_ids: BTreeSet::from([observation.source_audit_id.clone()]),
            source_resource_ids: BTreeSet::from([observation.resource_id.clone()]),
        }
    }

    fn is_complete(&self) -> bool {
        !self.authorizing_scope_id.trim().is_empty()
            && !self.source_audit_ids.is_empty()
            && !self.source_resource_ids.is_empty()
            && self
                .source_audit_ids
                .iter()
                .all(|value| !value.trim().is_empty())
            && self
                .source_resource_ids
                .iter()
                .all(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossBoundaryAuthorization {
    /// No boundary crossing is expected. A crossing candidate is denied.
    Denied,
    /// The source policy explicitly named the foreign principal or resource.
    ExplicitInSourcePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IamEdgeCandidate {
    pub from: NodeKey,
    pub to: NodeKey,
    pub relation: EdgeRelation,
    pub evidence: EdgeEvidence,
    pub cross_boundary_authorization: CrossBoundaryAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBackedEdge {
    pub edge_id: EdgeId,
    pub from: NodeKey,
    pub to: NodeKey,
    pub relation: EdgeRelation,
    pub evidence: EdgeEvidence,
    pub crosses_boundary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    Assumption,
    Unknown,
    MissingEvidence,
    CrossBoundaryDenied,
    UnsupportedSemantics,
}

/// A non-traversable inference gap. Gaps are never silently promoted to edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphGap {
    pub gap_id: String,
    pub kind: GapKind,
    pub from: Option<NodeKey>,
    pub to: Option<NodeKey>,
    pub statement: String,
    pub source_audit_ids: BTreeSet<String>,
}

impl GraphGap {
    pub fn new(
        kind: GapKind,
        from: Option<NodeKey>,
        to: Option<NodeKey>,
        statement: impl Into<String>,
        source_audit_ids: BTreeSet<String>,
    ) -> Self {
        let statement = statement.into();
        let seed = serde_json::to_vec(&(kind, &from, &to, &statement, &source_audit_ids))
            .expect("serializable gap identity");
        Self {
            gap_id: format!("gap-{}", &sha256(&seed)[..32]),
            kind,
            from,
            to,
            statement,
            source_audit_ids,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeDisposition {
    Confirmed(EdgeId),
    RecordedGap(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IamGraphError {
    MissingNode(NodeKey),
    ConflictingNode(NodeKey),
    ProviderMismatch,
    InvalidGap(String),
}

impl Display for IamGraphError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNode(node) => write!(f, "IAM graph node does not exist: {}", node.0),
            Self::ConflictingNode(node) => {
                write!(f, "IAM graph node identity conflict: {}", node.0)
            }
            Self::ProviderMismatch => write!(f, "cross-provider IAM edges are unsupported"),
            Self::InvalidGap(message) => write!(f, "invalid IAM inference gap: {message}"),
        }
    }
}

impl std::error::Error for IamGraphError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IamReachabilityGraph {
    pub nodes: BTreeMap<NodeKey, IamNode>,
    pub edges: BTreeMap<EdgeId, EvidenceBackedEdge>,
    pub gaps: BTreeMap<String, GraphGap>,
}

impl IamReachabilityGraph {
    pub fn node(&self, key: &NodeKey) -> Option<&IamNode> {
        self.nodes.get(key)
    }

    /// Confirmed nodes reachable from `start`, excluding `start` itself.
    pub fn reachable_from(&self, start: &NodeKey) -> Result<BTreeSet<NodeKey>, IamGraphError> {
        if !self.nodes.contains_key(start) {
            return Err(IamGraphError::MissingNode(start.clone()));
        }
        let adjacency = self.adjacency();
        let mut visited = BTreeSet::from([start.clone()]);
        let mut queue = VecDeque::from([start.clone()]);
        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&current) {
                for (neighbor, _) in neighbors {
                    if visited.insert(neighbor.clone()) {
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }
        visited.remove(start);
        Ok(visited)
    }

    /// Deterministic shortest confirmed path. Gaps and assumptions are ignored.
    pub fn shortest_path(
        &self,
        start: &NodeKey,
        target: &NodeKey,
    ) -> Result<Option<PathQuery>, IamGraphError> {
        if !self.nodes.contains_key(start) {
            return Err(IamGraphError::MissingNode(start.clone()));
        }
        if !self.nodes.contains_key(target) {
            return Err(IamGraphError::MissingNode(target.clone()));
        }
        if start == target {
            return Ok(Some(PathQuery {
                nodes: vec![start.clone()],
                edges: Vec::new(),
            }));
        }
        let adjacency = self.adjacency();
        let mut visited = BTreeSet::from([start.clone()]);
        let mut previous: BTreeMap<NodeKey, (NodeKey, EdgeId)> = BTreeMap::new();
        let mut queue = VecDeque::from([start.clone()]);
        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&current) {
                for (neighbor, edge_id) in neighbors {
                    if visited.insert(neighbor.clone()) {
                        previous.insert(neighbor.clone(), (current.clone(), edge_id.clone()));
                        if neighbor == target {
                            return Ok(Some(reconstruct_path(start, target, &previous)));
                        }
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    fn adjacency(&self) -> BTreeMap<NodeKey, BTreeSet<(NodeKey, EdgeId)>> {
        let mut result: BTreeMap<NodeKey, BTreeSet<(NodeKey, EdgeId)>> = BTreeMap::new();
        for edge in self.edges.values() {
            result
                .entry(edge.from.clone())
                .or_default()
                .insert((edge.to.clone(), edge.edge_id.clone()));
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathQuery {
    pub nodes: Vec<NodeKey>,
    pub edges: Vec<EdgeId>,
}

fn reconstruct_path(
    start: &NodeKey,
    target: &NodeKey,
    previous: &BTreeMap<NodeKey, (NodeKey, EdgeId)>,
) -> PathQuery {
    let mut nodes = vec![target.clone()];
    let mut edges = Vec::new();
    let mut current = target;
    while current != start {
        let (parent, edge) = previous
            .get(current)
            .expect("BFS predecessor chain is complete");
        edges.push(edge.clone());
        nodes.push(parent.clone());
        current = parent;
    }
    nodes.reverse();
    edges.reverse();
    PathQuery { nodes, edges }
}

#[derive(Debug, Clone, Default)]
pub struct IamGraphBuilder {
    graph: IamReachabilityGraph,
}

impl IamGraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: IamNode) -> Result<NodeKey, IamGraphError> {
        let key = node.key();
        if let Some(existing) = self.graph.nodes.get(&key) {
            if existing != &node {
                return Err(IamGraphError::ConflictingNode(key));
            }
            return Ok(key);
        }
        self.graph.nodes.insert(key.clone(), node);
        Ok(key)
    }

    pub fn add_edge(
        &mut self,
        candidate: IamEdgeCandidate,
    ) -> Result<EdgeDisposition, IamGraphError> {
        let from = self
            .graph
            .nodes
            .get(&candidate.from)
            .ok_or_else(|| IamGraphError::MissingNode(candidate.from.clone()))?;
        let to = self
            .graph
            .nodes
            .get(&candidate.to)
            .ok_or_else(|| IamGraphError::MissingNode(candidate.to.clone()))?;
        if from.boundary().provider != to.boundary().provider
            || candidate.evidence.provider != to.boundary().provider
        {
            return Err(IamGraphError::ProviderMismatch);
        }
        if !candidate.evidence.is_complete() {
            let gap = GraphGap::new(
                GapKind::MissingEvidence,
                Some(candidate.from),
                Some(candidate.to),
                "candidate edge lacks an audit or source-resource reference",
                candidate.evidence.source_audit_ids,
            );
            let id = gap.gap_id.clone();
            self.graph.gaps.insert(id.clone(), gap);
            return Ok(EdgeDisposition::RecordedGap(id));
        }
        let crosses_boundary = from.boundary() != to.boundary();
        if crosses_boundary
            && candidate.cross_boundary_authorization
                != CrossBoundaryAuthorization::ExplicitInSourcePolicy
        {
            let gap = GraphGap::new(
                GapKind::CrossBoundaryDenied,
                Some(candidate.from),
                Some(candidate.to),
                "cross-boundary reachability denied without an explicit source-policy grant",
                candidate.evidence.source_audit_ids,
            );
            let id = gap.gap_id.clone();
            self.graph.gaps.insert(id.clone(), gap);
            return Ok(EdgeDisposition::RecordedGap(id));
        }
        if candidate.evidence.authorizing_scope_id != to.boundary().scope_id {
            let gap = GraphGap::new(
                GapKind::MissingEvidence,
                Some(candidate.from),
                Some(candidate.to),
                "edge evidence was not captured in the destination authorization boundary",
                candidate.evidence.source_audit_ids,
            );
            let id = gap.gap_id.clone();
            self.graph.gaps.insert(id.clone(), gap);
            return Ok(EdgeDisposition::RecordedGap(id));
        }
        let seed = serde_json::to_vec(&(
            &candidate.from,
            &candidate.to,
            candidate.relation,
            &candidate.evidence,
        ))
        .expect("serializable edge identity");
        let edge_id = EdgeId(format!("edge-{}", &sha256(&seed)[..32]));
        self.graph.edges.insert(
            edge_id.clone(),
            EvidenceBackedEdge {
                edge_id: edge_id.clone(),
                from: candidate.from,
                to: candidate.to,
                relation: candidate.relation,
                evidence: candidate.evidence,
                crosses_boundary,
            },
        );
        Ok(EdgeDisposition::Confirmed(edge_id))
    }

    pub fn record_gap(&mut self, gap: GraphGap) -> Result<(), IamGraphError> {
        if gap.statement.trim().is_empty() {
            return Err(IamGraphError::InvalidGap(
                "gap statement cannot be empty".into(),
            ));
        }
        self.graph.gaps.insert(gap.gap_id.clone(), gap);
        Ok(())
    }

    pub fn finish(self) -> IamReachabilityGraph {
        self.graph
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterReport {
    pub graph: IamReachabilityGraph,
    pub source_observation_count: usize,
}

impl AdapterReport {
    /// Conservatively adapt the normalized IAM already emitted by cloud
    /// workflows. No permission or group-membership inference is performed.
    pub fn from_observations(observations: &[Observation]) -> Result<Self, IamGraphError> {
        let mut ordered = observations.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|observation| {
            (
                observation.provider,
                observation.scope_id.as_str(),
                observation.resource_id.as_str(),
                observation.source_audit_id.as_str(),
            )
        });
        let mut builder = IamGraphBuilder::new();
        for observation in ordered {
            adapt_observation(&mut builder, observation)?;
        }
        Ok(Self {
            graph: builder.finish(),
            source_observation_count: observations.len(),
        })
    }
}

fn adapt_observation(
    builder: &mut IamGraphBuilder,
    observation: &Observation,
) -> Result<(), IamGraphError> {
    let boundary = CloudBoundary::new(observation.provider, observation.scope_id.clone());
    let resource = builder.add_node(IamNode::Resource(ResourceNode {
        boundary: boundary.clone(),
        resource_type: observation.resource_type.clone(),
        resource_id: observation.resource_id.clone(),
    }))?;
    let mut bindings = observation.iam.iter().collect::<Vec<_>>();
    bindings.sort_by_key(|binding| {
        (
            binding.role.as_str(),
            binding.principal.as_str(),
            binding.condition.as_deref(),
        )
    });
    for (index, binding) in bindings.into_iter().enumerate() {
        adapt_binding(builder, observation, binding, index, &boundary, &resource)?;
    }
    Ok(())
}

fn adapt_binding(
    builder: &mut IamGraphBuilder,
    observation: &Observation,
    binding: &IamBinding,
    index: usize,
    boundary: &CloudBoundary,
    resource: &NodeKey,
) -> Result<(), IamGraphError> {
    let role = builder.add_node(IamNode::Role(RoleNode {
        boundary: boundary.clone(),
        role_id: binding.role.clone(),
    }))?;
    let policy = builder.add_node(IamNode::Policy(PolicyNode {
        boundary: boundary.clone(),
        policy_id: format!("{}#binding-{index}", observation.resource_id),
    }))?;
    let (subject_node, explicit_boundary) = subject_node(observation, binding, boundary);
    let group_subject = matches!(subject_node, IamNode::Group(_));
    let subject = builder.add_node(subject_node)?;
    let evidence = EdgeEvidence::from_observation(observation);
    let cross = if explicit_boundary {
        CrossBoundaryAuthorization::ExplicitInSourcePolicy
    } else {
        CrossBoundaryAuthorization::Denied
    };
    builder.add_edge(IamEdgeCandidate {
        from: subject.clone(),
        to: policy.clone(),
        relation: EdgeRelation::SubjectOfPolicy,
        evidence: evidence.clone(),
        cross_boundary_authorization: cross,
    })?;
    let policy_relation =
        if observation.provider == Provider::Aws && observation.resource_type == "iam_role" {
            EdgeRelation::CanAssumeRole
        } else {
            EdgeRelation::GrantsRole
        };
    builder.add_edge(IamEdgeCandidate {
        from: policy,
        to: role.clone(),
        relation: policy_relation,
        evidence: evidence.clone(),
        cross_boundary_authorization: CrossBoundaryAuthorization::Denied,
    })?;
    builder.add_edge(IamEdgeCandidate {
        from: role.clone(),
        to: resource.clone(),
        relation: EdgeRelation::AppliesToResource,
        evidence: evidence.clone(),
        cross_boundary_authorization: CrossBoundaryAuthorization::Denied,
    })?;
    builder.record_gap(GraphGap::new(
        GapKind::Unknown,
        Some(role),
        None,
        "effective capabilities were not present in the normalized IAM observation",
        evidence.source_audit_ids.clone(),
    ))?;
    if group_subject {
        builder.record_gap(GraphGap::new(
            GapKind::Unknown,
            None,
            Some(subject),
            "group membership was not present in the normalized IAM observation",
            evidence.source_audit_ids,
        ))?;
    }
    Ok(())
}

fn subject_node(
    observation: &Observation,
    binding: &IamBinding,
    target: &CloudBoundary,
) -> (IamNode, bool) {
    if is_group(binding, &observation.configuration) {
        return (
            IamNode::Group(GroupNode {
                boundary: target.clone(),
                group_id: binding.principal.clone(),
            }),
            false,
        );
    }
    let mut boundary = target.clone();
    let mut explicitly_foreign = false;
    if observation.provider == Provider::Aws {
        if let Some(account) = aws_account_from_arn(&binding.principal) {
            if account != target.scope_id {
                boundary.scope_id = account;
                explicitly_foreign = true;
            }
        }
    }
    (
        IamNode::Principal(PrincipalNode {
            boundary,
            principal_id: binding.principal.clone(),
            kind: classify_principal(observation.provider, &binding.principal),
        }),
        explicitly_foreign,
    )
}

fn is_group(binding: &IamBinding, configuration: &Value) -> bool {
    binding.principal.starts_with("group:")
        || configuration
            .get("principalType")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("group"))
}

fn classify_principal(provider: Provider, principal: &str) -> PrincipalKind {
    if matches!(principal, "*" | "allUsers" | "allAuthenticatedUsers") {
        return PrincipalKind::Public;
    }
    let lower = principal.to_ascii_lowercase();
    if lower.contains("serviceaccount")
        || lower.contains("service-account")
        || lower.starts_with("serviceaccount:")
    {
        PrincipalKind::ServiceAccount
    } else if lower.contains("oidc") || lower.contains("saml") || lower.starts_with("principalset:")
    {
        PrincipalKind::Federated
    } else if provider == Provider::Azure && lower.contains("managedidentity") {
        PrincipalKind::Workload
    } else if lower.contains("user") || lower.starts_with("user:") || lower.contains('@') {
        PrincipalKind::User
    } else {
        PrincipalKind::Unknown
    }
}

fn aws_account_from_arn(principal: &str) -> Option<String> {
    let fields = principal.split(':').collect::<Vec<_>>();
    (fields.len() >= 6 && fields.first() == Some(&"arn") && !fields[4].is_empty())
        .then(|| fields[4].to_string())
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
