//! Heterogeneous, evidence-preserving model validation panels.
//!
//! A panel may rank or reject claims, but cannot manufacture receipts or turn a
//! model opinion into empirical confirmation. Every member is invoked with a
//! fresh message context and is isolated behind independent budgets.
use anyhow::{anyhow, bail, ensure, Context, Result};
use domain::{now_ms, Candidate};
use futures::{stream, StreamExt};
use providers::{Message, Provider, ToolDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use storage::hash;

pub type BackendFuture<'a> = Pin<Box<dyn Future<Output = Result<BackendReply>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PanelRole {
    Candidate,
    Reviewer,
    Refuter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderIdentity {
    /// Vendor or independently operated inference service (for example `openai`).
    pub provider: String,
    pub model: String,
    /// Distinguishes separately governed deployments of the same vendor/model.
    pub deployment: String,
}
impl ProviderIdentity {
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.provider, self.model, self.deployment)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.provider.trim().is_empty()
                && !self.model.trim().is_empty()
                && !self.deployment.trim().is_empty(),
            "provider identity fields must not be empty"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBudget {
    pub authorized: bool,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_cost_microusd: u64,
    /// Price-based fallback when the provider has no native cost telemetry.
    pub input_cost_microusd_per_million_tokens: u64,
    pub output_cost_microusd_per_million_tokens: u64,
    pub timeout_ms: u64,
    pub max_retries: u8,
    pub weight_millis: u32,
}
impl Default for ProviderBudget {
    fn default() -> Self {
        Self {
            authorized: false,
            max_input_tokens: 32_000,
            max_output_tokens: 4_096,
            max_cost_microusd: 250_000,
            input_cost_microusd_per_million_tokens: 0,
            output_cost_microusd_per_million_tokens: 0,
            timeout_ms: 60_000,
            max_retries: 2,
            weight_millis: 1_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelInvocation {
    pub run_id: String,
    pub fresh_context_id: String,
    pub role: PanelRole,
    pub prompt: String,
    pub candidates: Vec<CandidateEnvelope>,
    pub allowed_receipt_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendReply {
    pub submission: PanelSubmission,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_microusd: Option<u64>,
    #[serde(default)]
    pub assurance: BTreeMap<String, String>,
}

/// Provider-independent backend. Implementations must not retain conversation
/// messages between calls. The panel supplies a unique `fresh_context_id` and a
/// complete, standalone invocation each time.
pub trait ModelBackend: Send + Sync {
    fn identity(&self) -> ProviderIdentity;
    fn requires_authorization(&self) -> bool {
        true
    }
    fn invoke(&self, invocation: PanelInvocation) -> BackendFuture<'_>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PanelSubmission {
    Candidate { candidate: Box<Candidate> },
    Review { review: Review },
    Refutation { refutation: Refutation },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    Support,
    Oppose,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub candidate_id: String,
    pub verdict: ReviewVerdict,
    pub rationale: String,
    #[serde(default)]
    pub receipt_ids: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefutationVerdict {
    Sustained,
    Dismissed,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refutation {
    pub candidate_id: String,
    pub verdict: RefutationVerdict,
    pub rationale: String,
    #[serde(default)]
    pub receipt_ids: Vec<String>,
    pub confidence: f64,
}

pub struct PanelMember {
    pub id: String,
    pub role: PanelRole,
    pub budget: ProviderBudget,
    pub calibration: Option<CalibrationMetadata>,
    pub backend: Arc<dyn ModelBackend>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationMetadata {
    pub benchmark: String,
    pub samples: u64,
    /// Brier score multiplied by 1000; lower is better.
    pub brier_score_millis: u32,
    pub evaluated_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    pub max_concurrency: usize,
    pub quorum: usize,
    pub minimum_support_weight_millis: u64,
    pub acceptance_ratio_millis: u32,
    pub max_submission_bytes: usize,
}
impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            quorum: 2,
            minimum_support_weight_millis: 2_000,
            acceptance_ratio_millis: 600,
            max_submission_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PanelRequest {
    pub run_id: String,
    pub prompt: String,
    pub allowed_receipt_ids: BTreeSet<String>,
    pub cancelled: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEnvelope {
    pub id: String,
    pub candidate: Candidate,
    pub proponents: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusVerdict {
    Accepted,
    Rejected,
    NoQuorum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissentRecord {
    pub member_id: String,
    pub identity: ProviderIdentity,
    pub role: PanelRole,
    pub rationale: String,
    pub receipt_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRecord {
    pub candidate: CandidateEnvelope,
    pub verdict: ConsensusVerdict,
    pub supporting_members: Vec<String>,
    pub opposing_members: Vec<String>,
    pub support_weight_millis: u64,
    pub opposition_weight_millis: u64,
    pub support_ratio_millis: u32,
    pub dissent: Vec<DissentRecord>,
    pub assurance: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub member_id: String,
    pub identity: ProviderIdentity,
    pub role: PanelRole,
    pub attempt: u8,
    pub fresh_context_id: String,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub status: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelFailure {
    pub member_id: String,
    pub identity: ProviderIdentity,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelReport {
    pub run_id: String,
    pub members: Vec<(String, ProviderIdentity, PanelRole)>,
    pub consensus: Vec<ConsensusRecord>,
    pub failures: Vec<PanelFailure>,
    pub audit: Vec<AuditRecord>,
    pub calibrated: bool,
    pub calibrations: BTreeMap<String, CalibrationMetadata>,
    pub assurance: BTreeMap<String, String>,
}

pub struct ModelPanel {
    config: PanelConfig,
    members: Vec<PanelMember>,
}

#[derive(Clone)]
struct SuccessfulCall {
    member_id: String,
    identity: ProviderIdentity,
    role: PanelRole,
    weight: u64,
    reply: BackendReply,
}

struct CallResult {
    call: Option<SuccessfulCall>,
    failure: Option<PanelFailure>,
    audit: Vec<AuditRecord>,
}

impl ModelPanel {
    pub fn new(config: PanelConfig, mut members: Vec<PanelMember>) -> Result<Self> {
        ensure!(
            config.max_concurrency > 0,
            "panel concurrency must be positive"
        );
        ensure!(config.quorum >= 2, "multimodel quorum must be at least two");
        ensure!(
            (500..=1_000).contains(&config.acceptance_ratio_millis),
            "acceptance ratio must be 500..1000"
        );
        ensure!(
            members.len() >= 2,
            "multimodel validation needs at least two members"
        );
        members.sort_by(|a, b| a.id.cmp(&b.id));
        let mut ids = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut providers = BTreeSet::new();
        for member in &members {
            ensure!(
                !member.id.trim().is_empty(),
                "panel member id cannot be empty"
            );
            ensure!(ids.insert(member.id.clone()), "duplicate panel member id");
            let identity = member.backend.identity();
            identity.validate()?;
            ensure!(
                identities.insert(identity.key()),
                "duplicate provider/model/deployment identity"
            );
            providers.insert(identity.provider);
            ensure!(
                member.budget.weight_millis > 0,
                "member weight must be positive"
            );
            ensure!(
                member.budget.timeout_ms > 0,
                "member timeout must be positive"
            );
            if let Some(calibration) = &member.calibration {
                ensure!(
                    !calibration.benchmark.trim().is_empty()
                        && calibration.samples > 0
                        && calibration.brier_score_millis <= 1_000,
                    "invalid provider calibration metadata"
                );
            }
            ensure!(
                member.budget.max_input_tokens > 0 && member.budget.max_output_tokens > 0,
                "member token budgets must be positive"
            );
        }
        ensure!(
            providers.len() >= 2,
            "a single provider cannot masquerade as heterogeneous multimodel validation"
        );
        ensure!(
            members.iter().any(|m| m.role == PanelRole::Candidate),
            "panel requires a candidate member"
        );
        Ok(Self { config, members })
    }

    pub async fn run(&self, request: PanelRequest) -> Result<PanelReport> {
        ensure!(!request.run_id.trim().is_empty(), "run id required");
        ensure!(!request.prompt.trim().is_empty(), "panel prompt required");
        ensure!(!request.cancelled.load(Ordering::SeqCst), "panel cancelled");

        let (candidate_calls, mut failures, mut audit) =
            self.run_stage(PanelRole::Candidate, &request, &[]).await?;
        let mut candidate_map: BTreeMap<String, CandidateEnvelope> = BTreeMap::new();
        let mut candidate_support: BTreeMap<String, Vec<SuccessfulCall>> = BTreeMap::new();
        for call in candidate_calls {
            let PanelSubmission::Candidate { candidate } = &call.reply.submission else {
                failures.push(failure(
                    &call,
                    "candidate member returned wrong submission type",
                ));
                continue;
            };
            if let Err(error) = validate_candidate(candidate, &request.allowed_receipt_ids) {
                failures.push(failure(&call, &format!("invalid candidate: {error}")));
                continue;
            }
            let id = candidate_fingerprint(candidate)?;
            candidate_map
                .entry(id.clone())
                .and_modify(|c| c.proponents.push(call.member_id.clone()))
                .or_insert(CandidateEnvelope {
                    id: id.clone(),
                    candidate: candidate.as_ref().clone(),
                    proponents: vec![call.member_id.clone()],
                });
            candidate_support.entry(id).or_default().push(call);
        }
        let candidates: Vec<_> = candidate_map.into_values().collect();
        let (review_calls, review_failures, review_audit) = self
            .run_stage(PanelRole::Reviewer, &request, &candidates)
            .await?;
        let (refute_calls, refute_failures, refute_audit) = self
            .run_stage(PanelRole::Refuter, &request, &candidates)
            .await?;
        failures.extend(review_failures);
        failures.extend(refute_failures);
        audit.extend(review_audit);
        audit.extend(refute_audit);

        let known: BTreeSet<_> = candidates.iter().map(|c| c.id.clone()).collect();
        let mut opinions: BTreeMap<String, Vec<SuccessfulCall>> = BTreeMap::new();
        for call in review_calls.into_iter().chain(refute_calls) {
            let validated_target = match &call.reply.submission {
                PanelSubmission::Review { review } => validate_opinion(
                    &review.candidate_id,
                    review.confidence,
                    &review.rationale,
                    &review.receipt_ids,
                    &known,
                    &request.allowed_receipt_ids,
                )
                .map(|()| review.candidate_id.clone()),
                PanelSubmission::Refutation { refutation } => validate_opinion(
                    &refutation.candidate_id,
                    refutation.confidence,
                    &refutation.rationale,
                    &refutation.receipt_ids,
                    &known,
                    &request.allowed_receipt_ids,
                )
                .map(|()| refutation.candidate_id.clone()),
                PanelSubmission::Candidate { .. } => {
                    failures.push(failure(&call, "validator returned candidate submission"));
                    continue;
                }
            };
            let target = match validated_target {
                Ok(target) => target,
                Err(error) => {
                    failures.push(failure(&call, &format!("invalid opinion: {error}")));
                    continue;
                }
            };
            opinions.entry(target).or_default().push(call);
        }

        let mut consensus = vec![];
        for candidate in candidates {
            let mut supports = candidate_support.remove(&candidate.id).unwrap_or_default();
            let mut opposes = vec![];
            let mut dissent = vec![];
            let mut assurance = BTreeMap::new();
            for call in opinions.remove(&candidate.id).unwrap_or_default() {
                for (key, value) in &call.reply.assurance {
                    assurance.insert(format!("{}:{key}", call.member_id), value.clone());
                }
                match &call.reply.submission {
                    PanelSubmission::Review { review } => match review.verdict {
                        ReviewVerdict::Support => supports.push(call),
                        ReviewVerdict::Oppose => {
                            dissent.push(dissent_review(
                                &call,
                                &review.rationale,
                                &review.receipt_ids,
                            ));
                            opposes.push(call);
                        }
                        ReviewVerdict::Abstain => dissent.push(dissent_review(
                            &call,
                            &review.rationale,
                            &review.receipt_ids,
                        )),
                    },
                    PanelSubmission::Refutation { refutation } => match refutation.verdict {
                        RefutationVerdict::Sustained => {
                            dissent.push(dissent_review(
                                &call,
                                &refutation.rationale,
                                &refutation.receipt_ids,
                            ));
                            opposes.push(call);
                        }
                        RefutationVerdict::Dismissed => supports.push(call),
                        RefutationVerdict::Inconclusive => dissent.push(dissent_review(
                            &call,
                            &refutation.rationale,
                            &refutation.receipt_ids,
                        )),
                    },
                    PanelSubmission::Candidate { .. } => {}
                }
            }
            supports.sort_by(|a, b| a.member_id.cmp(&b.member_id));
            opposes.sort_by(|a, b| a.member_id.cmp(&b.member_id));
            dissent.sort_by(|a, b| a.member_id.cmp(&b.member_id));
            let support_weight: u64 = supports.iter().map(|c| c.weight).sum();
            let opposition_weight: u64 = opposes.iter().map(|c| c.weight).sum();
            let total = support_weight + opposition_weight;
            let ratio = if total == 0 {
                0
            } else {
                ((support_weight.saturating_mul(1_000)) / total) as u32
            };
            // Quorum is counted by independently governed vendor trust domain,
            // not by model/deployment identity. Multiple models, regions or
            // API endpoints from one provider remain one correlated vote.
            let distinct_supporting_providers: BTreeSet<_> = supports
                .iter()
                .map(|support| support.identity.provider.clone())
                .collect();
            let verdict = if distinct_supporting_providers.len() < self.config.quorum
                || support_weight < self.config.minimum_support_weight_millis
            {
                ConsensusVerdict::NoQuorum
            } else if ratio >= self.config.acceptance_ratio_millis {
                ConsensusVerdict::Accepted
            } else {
                ConsensusVerdict::Rejected
            };
            assurance.insert(
                "method".into(),
                "weighted-independent-provider-consensus".into(),
            );
            assurance.insert("evidence_policy".into(), "existing-receipts-only".into());
            assurance.insert("quorum_trust_domain".into(), "provider_vendor".into());
            assurance.insert(
                "distinct_supporting_providers".into(),
                distinct_supporting_providers.len().to_string(),
            );
            consensus.push(ConsensusRecord {
                candidate,
                verdict,
                supporting_members: supports.into_iter().map(|c| c.member_id).collect(),
                opposing_members: opposes.into_iter().map(|c| c.member_id).collect(),
                support_weight_millis: support_weight,
                opposition_weight_millis: opposition_weight,
                support_ratio_millis: ratio,
                dissent,
                assurance,
            });
        }
        consensus.sort_by(|a, b| a.candidate.id.cmp(&b.candidate.id));
        failures.sort_by(|a, b| a.member_id.cmp(&b.member_id).then(a.reason.cmp(&b.reason)));
        audit.sort_by(|a, b| {
            a.member_id
                .cmp(&b.member_id)
                .then(a.attempt.cmp(&b.attempt))
                .then(a.role.cmp(&b.role))
        });
        let members = self
            .members
            .iter()
            .map(|m| (m.id.clone(), m.backend.identity(), m.role))
            .collect();
        let calibrations: BTreeMap<_, _> = self
            .members
            .iter()
            .filter_map(|member| {
                member
                    .calibration
                    .clone()
                    .map(|calibration| (member.id.clone(), calibration))
            })
            .collect();
        let mut panel_assurance = BTreeMap::new();
        panel_assurance.insert(
            "fresh_contexts".into(),
            "enforced-per-member-attempt".into(),
        );
        panel_assurance.insert("heterogeneous_providers".into(), "enforced".into());
        panel_assurance.insert("failure_isolation".into(), "per-member".into());
        Ok(PanelReport {
            run_id: request.run_id,
            members,
            calibrated: !self.members.is_empty() && calibrations.len() == self.members.len(),
            calibrations,
            consensus,
            failures,
            audit,
            assurance: panel_assurance,
        })
    }

    async fn run_stage(
        &self,
        role: PanelRole,
        request: &PanelRequest,
        candidates: &[CandidateEnvelope],
    ) -> Result<(Vec<SuccessfulCall>, Vec<PanelFailure>, Vec<AuditRecord>)> {
        let members: Vec<_> = self.members.iter().filter(|m| m.role == role).collect();
        let results =
            stream::iter(members.into_iter().map(|member| async move {
                self.invoke_member(member, request, candidates).await
            }))
            .buffer_unordered(self.config.max_concurrency)
            .collect::<Vec<_>>()
            .await;
        let mut calls = vec![];
        let mut failures = vec![];
        let mut audit = vec![];
        for result in results {
            audit.extend(result.audit);
            if let Some(call) = result.call {
                calls.push(call);
            }
            if let Some(failure) = result.failure {
                failures.push(failure);
            }
        }
        calls.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Ok((calls, failures, audit))
    }

    async fn invoke_member(
        &self,
        member: &PanelMember,
        request: &PanelRequest,
        candidates: &[CandidateEnvelope],
    ) -> CallResult {
        let identity = member.backend.identity();
        if member.backend.requires_authorization() && !member.budget.authorized {
            return CallResult {
                call: None,
                failure: Some(PanelFailure {
                    member_id: member.id.clone(),
                    identity,
                    reason: "provider not authorized".into(),
                }),
                audit: vec![],
            };
        }
        let estimated_input = estimate_tokens(
            request.prompt.len()
                + serde_json::to_vec(candidates).map_or(0, |serialized| serialized.len()),
        );
        if estimated_input > member.budget.max_input_tokens {
            return CallResult {
                call: None,
                failure: Some(PanelFailure {
                    member_id: member.id.clone(),
                    identity,
                    reason: "input token budget exhausted".into(),
                }),
                audit: vec![],
            };
        }
        let mut audit = vec![];
        let attempts = member.budget.max_retries.saturating_add(1);
        for attempt in 1..=attempts {
            if request.cancelled.load(Ordering::SeqCst) {
                return CallResult {
                    call: None,
                    failure: Some(PanelFailure {
                        member_id: member.id.clone(),
                        identity,
                        reason: "panel cancelled".into(),
                    }),
                    audit,
                };
            }
            let fresh_context_id = format!(
                "{}-{}-{:?}-{attempt}",
                request.run_id, member.id, member.role
            );
            let invocation = PanelInvocation {
                run_id: request.run_id.clone(),
                fresh_context_id: fresh_context_id.clone(),
                role: member.role,
                prompt: request.prompt.clone(),
                candidates: candidates.to_vec(),
                allowed_receipt_ids: request.allowed_receipt_ids.clone(),
            };
            let started_ms = now_ms();
            let provider_call = tokio::time::timeout(
                Duration::from_millis(member.budget.timeout_ms),
                member.backend.invoke(invocation),
            );
            tokio::pin!(provider_call);
            let outcome = tokio::select! {
                result = &mut provider_call => result,
                () = wait_for_cancel(request.cancelled.as_ref()) => {
                    let finished_ms = now_ms();
                    audit.push(AuditRecord {
                        member_id: member.id.clone(), identity: identity.clone(), role: member.role,
                        attempt, fresh_context_id, started_ms, finished_ms, status: "cancelled".into(),
                        input_tokens: estimated_input, output_tokens: 0, cost_microusd: 0,
                        detail: "panel cancelled during provider invocation".into(),
                    });
                    return CallResult { call: None, failure: Some(PanelFailure {
                        member_id: member.id.clone(), identity, reason: "panel cancelled".into(),
                    }), audit };
                }
            };
            let finished_ms = now_ms();
            match outcome {
                Ok(Ok(reply)) => {
                    let serialized = serde_json::to_vec(&reply.submission).unwrap_or_default();
                    let output_tokens = reply
                        .output_tokens
                        .unwrap_or_else(|| estimate_tokens(serialized.len()));
                    let input_tokens = reply.input_tokens.unwrap_or(estimated_input);
                    let estimated_cost = if member.budget.input_cost_microusd_per_million_tokens > 0
                        || member.budget.output_cost_microusd_per_million_tokens > 0
                    {
                        Some(
                            input_tokens
                                .saturating_mul(
                                    member.budget.input_cost_microusd_per_million_tokens,
                                )
                                .saturating_add(output_tokens.saturating_mul(
                                    member.budget.output_cost_microusd_per_million_tokens,
                                ))
                                .div_ceil(1_000_000),
                        )
                    } else {
                        None
                    };
                    let known_cost = reply.cost_microusd.or(estimated_cost);
                    let cost = known_cost.unwrap_or(0);
                    let invalid = if serialized.len() > self.config.max_submission_bytes {
                        Some("submission exceeds byte limit")
                    } else if input_tokens > member.budget.max_input_tokens {
                        Some("reported input exceeds token budget")
                    } else if output_tokens > member.budget.max_output_tokens {
                        Some("output token budget exhausted")
                    } else if known_cost.is_none() {
                        Some("cost telemetry unavailable and no estimation rates configured")
                    } else if cost > member.budget.max_cost_microusd {
                        Some("provider cost budget exhausted")
                    } else if !submission_matches_role(member.role, &reply.submission) {
                        Some("submission type does not match assigned role")
                    } else {
                        None
                    };
                    audit.push(AuditRecord {
                        member_id: member.id.clone(),
                        identity: identity.clone(),
                        role: member.role,
                        attempt,
                        fresh_context_id,
                        started_ms,
                        finished_ms,
                        status: if invalid.is_some() {
                            "rejected"
                        } else {
                            "completed"
                        }
                        .into(),
                        input_tokens,
                        output_tokens,
                        cost_microusd: cost,
                        detail: invalid.unwrap_or("valid structured submission").into(),
                    });
                    if let Some(reason) = invalid {
                        return CallResult {
                            call: None,
                            failure: Some(PanelFailure {
                                member_id: member.id.clone(),
                                identity,
                                reason: reason.into(),
                            }),
                            audit,
                        };
                    }
                    return CallResult {
                        call: Some(SuccessfulCall {
                            member_id: member.id.clone(),
                            identity,
                            role: member.role,
                            weight: u64::from(member.budget.weight_millis),
                            reply,
                        }),
                        failure: None,
                        audit,
                    };
                }
                Ok(Err(error)) => audit.push(AuditRecord {
                    member_id: member.id.clone(),
                    identity: identity.clone(),
                    role: member.role,
                    attempt,
                    fresh_context_id,
                    started_ms,
                    finished_ms,
                    status: "provider_error".into(),
                    input_tokens: estimated_input,
                    output_tokens: 0,
                    cost_microusd: 0,
                    detail: error.to_string(),
                }),
                Err(_) => audit.push(AuditRecord {
                    member_id: member.id.clone(),
                    identity: identity.clone(),
                    role: member.role,
                    attempt,
                    fresh_context_id,
                    started_ms,
                    finished_ms,
                    status: "timeout".into(),
                    input_tokens: estimated_input,
                    output_tokens: 0,
                    cost_microusd: 0,
                    detail: "provider timeout".into(),
                }),
            }
        }
        let reason = audit
            .last()
            .map_or_else(|| "provider failed".into(), |a| a.detail.clone());
        CallResult {
            call: None,
            failure: Some(PanelFailure {
                member_id: member.id.clone(),
                identity,
                reason,
            }),
            audit,
        }
    }
}

fn estimate_tokens(bytes: usize) -> u64 {
    (bytes as u64).div_ceil(4).max(1)
}
async fn wait_for_cancel(cancelled: &AtomicBool) {
    while !cancelled.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn submission_matches_role(role: PanelRole, submission: &PanelSubmission) -> bool {
    matches!(
        (role, submission),
        (PanelRole::Candidate, PanelSubmission::Candidate { .. })
            | (PanelRole::Reviewer, PanelSubmission::Review { .. })
            | (PanelRole::Refuter, PanelSubmission::Refutation { .. })
    )
}
fn validate_candidate(candidate: &Candidate, allowed: &BTreeSet<String>) -> Result<()> {
    candidate.validate()?;
    ensure!(
        !candidate.receipt_ids.is_empty(),
        "panel candidates require receipts"
    );
    ensure!(
        candidate.receipt_ids.iter().all(|id| allowed.contains(id)),
        "candidate cites unknown or fabricated receipt"
    );
    Ok(())
}
fn validate_opinion(
    candidate_id: &str,
    confidence: f64,
    rationale: &str,
    receipts: &[String],
    known: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        known.contains(candidate_id),
        "opinion references unknown candidate"
    );
    ensure!(
        (0.0..=1.0).contains(&confidence),
        "invalid opinion confidence"
    );
    ensure!(!rationale.trim().is_empty(), "opinion rationale required");
    ensure!(
        receipts.iter().all(|id| allowed.contains(id)),
        "opinion cites unknown or fabricated receipt"
    );
    Ok(())
}
pub fn candidate_fingerprint(candidate: &Candidate) -> Result<String> {
    let normalized = json!({
        "title": candidate.title,
        "description": candidate.description,
        "severity": candidate.severity,
        "location": candidate.location,
        "impact": candidate.impact,
        "receipt_ids": candidate.receipt_ids,
        "proof": candidate.proof,
    });
    Ok(format!(
        "candidate-{}",
        hash(&serde_json::to_vec(&normalized)?)
    ))
}
fn failure(call: &SuccessfulCall, reason: &str) -> PanelFailure {
    PanelFailure {
        member_id: call.member_id.clone(),
        identity: call.identity.clone(),
        reason: reason.into(),
    }
}
fn dissent_review(call: &SuccessfulCall, rationale: &str, receipts: &[String]) -> DissentRecord {
    DissentRecord {
        member_id: call.member_id.clone(),
        identity: call.identity.clone(),
        role: call.role,
        rationale: rationale.into(),
        receipt_ids: receipts.to_vec(),
    }
}

/// Adapter for the native provider crate. Each invocation clones the configured
/// provider and sends exactly one new user message; no prior model conversation
/// is reused.
#[derive(Clone)]
pub struct NativeProviderBackend {
    provider: Provider,
    identity: ProviderIdentity,
}
impl NativeProviderBackend {
    pub fn new(provider: Provider, deployment: impl Into<String>) -> Result<Self> {
        let raw = provider.identity();
        let (kind, model) = raw
            .split_once(':')
            .context("native provider identity missing separator")?;
        Ok(Self {
            provider,
            identity: ProviderIdentity {
                provider: kind.into(),
                model: model.into(),
                deployment: deployment.into(),
            },
        })
    }
}
impl ModelBackend for NativeProviderBackend {
    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }
    fn requires_authorization(&self) -> bool {
        self.identity.provider != "mock"
    }
    fn invoke(&self, invocation: PanelInvocation) -> BackendFuture<'_> {
        Box::pin(async move {
            let mut provider = self.provider.clone();
            let tools = panel_definitions(invocation.role);
            let prompt = serde_json::to_string(&invocation)?;
            let reply = provider
                .complete(&[Message::User(prompt)], &tools)
                .await
                .context("native provider panel invocation failed")?;
            ensure!(
                reply.calls.len() == 1,
                "provider must submit exactly one panel result"
            );
            let call = &reply.calls[0];
            ensure!(
                call.name == "submit_panel_result",
                "unexpected panel tool call"
            );
            let submission = decode_native_submission(invocation.role, call.arguments.clone())?;
            Ok(BackendReply {
                submission,
                input_tokens: reply.input_tokens,
                output_tokens: reply.output_tokens,
                cost_microusd: None,
                assurance: BTreeMap::from([(
                    "native_tool_call".into(),
                    "structured-submit_panel_result".into(),
                )]),
            })
        })
    }
}

fn panel_definitions(role: PanelRole) -> Vec<ToolDefinition> {
    let schema = match role {
        PanelRole::Candidate => json!({
            "type":"object","properties":{"candidate":{"type":"object"}},
            "required":["candidate"],"additionalProperties":false
        }),
        PanelRole::Reviewer => json!({
            "type":"object","properties":{
                "candidate_id":{"type":"string"},"verdict":{"type":"string","enum":["support","oppose","abstain"]},
                "rationale":{"type":"string"},"receipt_ids":{"type":"array","items":{"type":"string"}},
                "confidence":{"type":"number","minimum":0,"maximum":1}
            },"required":["candidate_id","verdict","rationale","receipt_ids","confidence"],"additionalProperties":false
        }),
        PanelRole::Refuter => json!({
            "type":"object","properties":{
                "candidate_id":{"type":"string"},"verdict":{"type":"string","enum":["sustained","dismissed","inconclusive"]},
                "rationale":{"type":"string"},"receipt_ids":{"type":"array","items":{"type":"string"}},
                "confidence":{"type":"number","minimum":0,"maximum":1}
            },"required":["candidate_id","verdict","rationale","receipt_ids","confidence"],"additionalProperties":false
        }),
    };
    vec![ToolDefinition {
        name: "submit_panel_result".into(),
        description:
            "Submit the assigned independent panel result. Cite only supplied receipt IDs.".into(),
        schema,
    }]
}
fn decode_native_submission(role: PanelRole, value: Value) -> Result<PanelSubmission> {
    Ok(match role {
        PanelRole::Candidate => PanelSubmission::Candidate {
            candidate: Box::new(serde_json::from_value(
                value
                    .get("candidate")
                    .cloned()
                    .context("candidate missing")?,
            )?),
        },
        PanelRole::Reviewer => PanelSubmission::Review {
            review: serde_json::from_value(value)?,
        },
        PanelRole::Refuter => PanelSubmission::Refutation {
            refutation: serde_json::from_value(value)?,
        },
    })
}

/// Deterministic test double supporting delay, failures, usage and structured replies.
pub struct MockBackend {
    identity: ProviderIdentity,
    outcomes: Mutex<VecDeque<MockOutcome>>,
}
#[derive(Debug, Clone)]
pub enum MockOutcome {
    Reply(BackendReply),
    Error(String),
    Delayed { delay_ms: u64, reply: BackendReply },
}
impl MockBackend {
    pub fn new(identity: ProviderIdentity, outcomes: Vec<MockOutcome>) -> Self {
        Self {
            identity,
            outcomes: Mutex::new(outcomes.into()),
        }
    }
}
impl ModelBackend for MockBackend {
    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }
    fn requires_authorization(&self) -> bool {
        false
    }
    fn invoke(&self, _invocation: PanelInvocation) -> BackendFuture<'_> {
        let outcome = self
            .outcomes
            .lock()
            .map_err(|_| anyhow!("mock outcome lock poisoned"))
            .and_then(|mut outcomes| outcomes.pop_front().context("mock outcomes exhausted"));
        Box::pin(async move {
            match outcome? {
                MockOutcome::Reply(reply) => Ok(reply),
                MockOutcome::Error(error) => bail!(error),
                MockOutcome::Delayed { delay_ms, reply } => {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    Ok(reply)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{Proof, Severity};

    fn candidate(receipt: &str) -> Candidate {
        Candidate {
            title: "Scoped issue".into(),
            description: "Observed issue".into(),
            severity: Severity::Medium,
            severity_justification: "Demonstrated impact".into(),
            cvss: None,
            cwe: vec![],
            owasp: vec![],
            mitre: vec![],
            location: "https://target.test".into(),
            payload: String::new(),
            impact: "Bounded impact".into(),
            remediation: "Fix it".into(),
            confidence: 0.8,
            auth_context: String::new(),
            test_identity: None,
            receipt_ids: vec![receipt.into()],
            screenshots: vec![],
            chains_from: vec![],
            proof: Proof::Manual {
                procedure: "independent replay required".into(),
            },
        }
    }
    fn reply(submission: PanelSubmission) -> BackendReply {
        BackendReply {
            submission,
            input_tokens: Some(10),
            output_tokens: Some(10),
            cost_microusd: Some(10),
            assurance: BTreeMap::new(),
        }
    }
    fn candidate_submission(candidate: Candidate) -> PanelSubmission {
        PanelSubmission::Candidate {
            candidate: Box::new(candidate),
        }
    }
    fn backend(provider: &str, model: &str, submission: PanelSubmission) -> Arc<dyn ModelBackend> {
        Arc::new(MockBackend::new(
            ProviderIdentity {
                provider: provider.into(),
                model: model.into(),
                deployment: "test".into(),
            },
            vec![MockOutcome::Reply(reply(submission))],
        ))
    }
    fn member(id: &str, role: PanelRole, backend: Arc<dyn ModelBackend>) -> PanelMember {
        PanelMember {
            id: id.into(),
            role,
            budget: ProviderBudget::default(),
            calibration: None,
            backend,
        }
    }
    fn request() -> PanelRequest {
        PanelRequest {
            run_id: "test-run".into(),
            prompt: "validate".into(),
            allowed_receipt_ids: BTreeSet::from(["receipt-1".into()]),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn quorum_and_deterministic_merge() -> Result<()> {
        let c = candidate("receipt-1");
        let id = candidate_fingerprint(&c)?;
        let panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "z",
                    PanelRole::Candidate,
                    backend("vendor-a", "m1", candidate_submission(c)),
                ),
                member(
                    "a",
                    PanelRole::Reviewer,
                    backend(
                        "vendor-b",
                        "m2",
                        PanelSubmission::Review {
                            review: Review {
                                candidate_id: id,
                                verdict: ReviewVerdict::Support,
                                rationale: "receipt supports claim".into(),
                                receipt_ids: vec!["receipt-1".into()],
                                confidence: 0.9,
                            },
                        },
                    ),
                ),
            ],
        )?;
        let report = panel.run(request()).await?;
        assert_eq!(report.consensus[0].verdict, ConsensusVerdict::Accepted);
        assert_eq!(report.consensus[0].supporting_members, vec!["a", "z"]);
        Ok(())
    }

    #[tokio::test]
    async fn records_dissent() -> Result<()> {
        let c = candidate("receipt-1");
        let id = candidate_fingerprint(&c)?;
        let config = PanelConfig {
            acceptance_ratio_millis: 500,
            ..PanelConfig::default()
        };
        let panel = ModelPanel::new(
            config,
            vec![
                member(
                    "finder",
                    PanelRole::Candidate,
                    backend("a", "m1", candidate_submission(c)),
                ),
                member(
                    "critic",
                    PanelRole::Refuter,
                    backend(
                        "b",
                        "m2",
                        PanelSubmission::Refutation {
                            refutation: Refutation {
                                candidate_id: id,
                                verdict: RefutationVerdict::Sustained,
                                rationale: "alternate explanation".into(),
                                receipt_ids: vec![],
                                confidence: 0.8,
                            },
                        },
                    ),
                ),
            ],
        )?;
        let report = panel.run(request()).await?;
        assert_eq!(report.consensus[0].dissent.len(), 1);
        assert_eq!(report.consensus[0].verdict, ConsensusVerdict::NoQuorum);
        Ok(())
    }

    #[tokio::test]
    async fn same_vendor_models_cannot_form_quorum_when_other_vendor_dissents() -> Result<()> {
        let c = candidate("receipt-1");
        let id = candidate_fingerprint(&c)?;
        let panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "vendor-a-finder",
                    PanelRole::Candidate,
                    backend("vendor-a", "model-1", candidate_submission(c)),
                ),
                member(
                    "vendor-a-reviewer",
                    PanelRole::Reviewer,
                    backend(
                        "vendor-a",
                        "model-2",
                        PanelSubmission::Review {
                            review: Review {
                                candidate_id: id.clone(),
                                verdict: ReviewVerdict::Support,
                                rationale: "same vendor agrees".into(),
                                receipt_ids: vec!["receipt-1".into()],
                                confidence: 0.9,
                            },
                        },
                    ),
                ),
                member(
                    "vendor-b-refuter",
                    PanelRole::Refuter,
                    backend(
                        "vendor-b",
                        "model-3",
                        PanelSubmission::Refutation {
                            refutation: Refutation {
                                candidate_id: id,
                                verdict: RefutationVerdict::Sustained,
                                rationale: "independent vendor dissents".into(),
                                receipt_ids: vec![],
                                confidence: 0.8,
                            },
                        },
                    ),
                ),
            ],
        )?;
        let report = panel.run(request()).await?;
        assert_eq!(report.consensus[0].verdict, ConsensusVerdict::NoQuorum);
        assert_eq!(
            report.consensus[0].assurance["distinct_supporting_providers"],
            "1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn timeout_and_partial_outage_are_isolated() -> Result<()> {
        let c = candidate("receipt-1");
        let slow = Arc::new(MockBackend::new(
            ProviderIdentity {
                provider: "b".into(),
                model: "m2".into(),
                deployment: "test".into(),
            },
            vec![MockOutcome::Delayed {
                delay_ms: 50,
                reply: reply(candidate_submission(c.clone())),
            }],
        ));
        let mut slow_member = member("slow", PanelRole::Candidate, slow);
        slow_member.budget.timeout_ms = 1;
        slow_member.budget.max_retries = 0;
        let panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "ok",
                    PanelRole::Candidate,
                    backend("a", "m1", candidate_submission(c)),
                ),
                slow_member,
            ],
        )?;
        let report = panel.run(request()).await?;
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.consensus[0].verdict, ConsensusVerdict::NoQuorum);
        Ok(())
    }

    #[tokio::test]
    async fn malicious_fabricated_receipt_is_rejected() -> Result<()> {
        let panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "bad",
                    PanelRole::Candidate,
                    backend("a", "m1", candidate_submission(candidate("invented"))),
                ),
                member(
                    "spare",
                    PanelRole::Candidate,
                    backend("b", "m2", candidate_submission(candidate("receipt-1"))),
                ),
            ],
        )?;
        let report = panel.run(request()).await?;
        assert!(report.failures.iter().any(|f| f.member_id == "bad"));
        assert_eq!(report.consensus.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn malicious_opinion_isolated_and_cancellation_interrupts_calls() -> Result<()> {
        let c = candidate("receipt-1");
        let invalid_panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "finder",
                    PanelRole::Candidate,
                    backend("a", "m1", candidate_submission(c.clone())),
                ),
                member(
                    "bad-review",
                    PanelRole::Reviewer,
                    backend(
                        "b",
                        "m2",
                        PanelSubmission::Review {
                            review: Review {
                                candidate_id: "invented-candidate".into(),
                                verdict: ReviewVerdict::Support,
                                rationale: "trust me".into(),
                                receipt_ids: vec![],
                                confidence: 1.0,
                            },
                        },
                    ),
                ),
            ],
        )?;
        let report = invalid_panel.run(request()).await?;
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.member_id == "bad-review"));

        let delayed = |provider: &str, model: &str| -> Arc<dyn ModelBackend> {
            Arc::new(MockBackend::new(
                ProviderIdentity {
                    provider: provider.into(),
                    model: model.into(),
                    deployment: "test".into(),
                },
                vec![MockOutcome::Delayed {
                    delay_ms: 500,
                    reply: reply(candidate_submission(c.clone())),
                }],
            ))
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut cancel_request = request();
        cancel_request.cancelled = cancelled.clone();
        let cancel_panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                member("slow-a", PanelRole::Candidate, delayed("a", "m1")),
                member("slow-b", PanelRole::Candidate, delayed("b", "m2")),
            ],
        )?;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancelled.store(true, Ordering::SeqCst);
        });
        let report = cancel_panel.run(cancel_request).await?;
        assert!(report
            .failures
            .iter()
            .all(|failure| failure.reason == "panel cancelled"));
        Ok(())
    }

    #[test]
    fn duplicate_identity_and_single_provider_are_rejected() {
        let c = candidate("receipt-1");
        let one = || backend("same", "m", candidate_submission(c.clone()));
        assert!(ModelPanel::new(
            PanelConfig::default(),
            vec![
                member("a", PanelRole::Candidate, one()),
                member("b", PanelRole::Candidate, one()),
            ]
        )
        .is_err());
        assert!(ModelPanel::new(
            PanelConfig::default(),
            vec![
                member(
                    "a",
                    PanelRole::Candidate,
                    backend("same", "m1", candidate_submission(c.clone()))
                ),
                member(
                    "b",
                    PanelRole::Candidate,
                    backend("same", "m2", candidate_submission(c))
                ),
            ]
        )
        .is_err());
    }

    #[tokio::test]
    async fn budget_exhaustion_fails_only_member() -> Result<()> {
        let c = candidate("receipt-1");
        let mut expensive = member(
            "expensive",
            PanelRole::Candidate,
            backend("a", "m1", candidate_submission(c.clone())),
        );
        expensive.budget.max_cost_microusd = 1;
        let panel = ModelPanel::new(
            PanelConfig::default(),
            vec![
                expensive,
                member(
                    "ok",
                    PanelRole::Candidate,
                    backend("b", "m2", candidate_submission(c)),
                ),
            ],
        )?;
        let report = panel.run(request()).await?;
        assert!(report
            .failures
            .iter()
            .any(|f| f.reason.contains("cost budget")));
        Ok(())
    }
}
