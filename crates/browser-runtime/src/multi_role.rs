//! Authenticated multi-role workflows with isolated sessions and neutral evidence comparison.

use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use zeroize::Zeroizing;

pub const AUTHENTICATED_WORKFLOW_SCHEMA_VERSION: u32 = 1;

/// A serializable authenticated workflow. Roles are executed in lexical role
/// order so equivalent documents produce the same aggregate ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedBrowserWorkflow {
    pub schema_version: u32,
    pub name: String,
    pub roles: Vec<AuthenticatedRolePlan>,
}

impl AuthenticatedBrowserWorkflow {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == AUTHENTICATED_WORKFLOW_SCHEMA_VERSION,
            "unsupported authenticated browser workflow schema"
        );
        validate_role_name(&self.name, "workflow name")?;
        ensure!(
            (2..=64).contains(&self.roles.len()),
            "authenticated browser workflow requires 2..=64 roles"
        );
        let mut roles = BTreeSet::new();
        let mut resolver_keys = BTreeSet::new();
        for role in &self.roles {
            role.validate()?;
            ensure!(
                roles.insert(role.role.clone()),
                "duplicate authenticated browser role"
            );
            for binding in role.secret_bindings.values() {
                ensure!(
                    resolver_keys.insert(binding.resolver_key.clone()),
                    "authenticated roles must use distinct secret resolver keys"
                );
            }
        }
        Ok(())
    }

    /// Fingerprint of the validated canonical workflow. Secret values never
    /// enter this digest; only resolver keys are present in the document.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.roles.sort_by(|a, b| a.role.cmp(&b.role));
        Ok(hash(&serde_json::to_vec(&canonical)?))
    }
}

/// One role and its isolated browser plan. Environment names inside `plan`
/// are logical binding names in this layer, not direct secret source names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRolePlan {
    pub role: String,
    pub plan: BrowserPlan,
    pub secret_bindings: BTreeMap<String, RoleSecretBinding>,
}

impl AuthenticatedRolePlan {
    pub fn validate(&self) -> Result<()> {
        validate_role_name(&self.role, "role name")?;
        self.plan.validate()?;
        ensure!(
            !self.secret_bindings.is_empty(),
            "authenticated role requires at least one secret binding"
        );
        let referenced = validate_authenticated_plan(&self.plan)?;
        let configured: BTreeSet<_> = self.secret_bindings.keys().cloned().collect();
        ensure!(
            referenced == configured,
            "role secret bindings must exactly match plan secret references"
        );
        for (logical_name, binding) in &self.secret_bindings {
            validate_logical_secret_name(logical_name)?;
            binding.validate()?;
        }
        Ok(())
    }
}

/// A reference resolved only at execution time. The referenced value is never
/// part of the serializable workflow or its result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSecretBinding {
    pub resolver_key: String,
}

impl RoleSecretBinding {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.resolver_key.is_empty()
                && self.resolver_key.len() <= 512
                && self.resolver_key.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "_-.:/@".contains(character)
                }),
            "invalid role secret resolver key"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedWorkflowStatus {
    Completed,
    PartiallyFailed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatedRoleResult {
    pub role: String,
    pub result: BrowserPlanResult,
}

/// Hash-only role evidence for a later authorization/IDOR correlator. This
/// deliberately contains no vulnerability, access-equivalence, or severity
/// verdict and no raw observation data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeutralRoleEvidence {
    pub role: String,
    pub observation_hashes: Vec<String>,
    pub artifact_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeutralRoleComparisonRecord {
    pub schema_version: u32,
    pub content_hash: String,
    pub roles: Vec<NeutralRoleEvidence>,
}

impl NeutralRoleComparisonRecord {
    fn from_results(results: &[AuthenticatedRoleResult]) -> Result<Self> {
        let roles = results
            .iter()
            .map(|role| {
                let artifact_hashes = role
                    .result
                    .artifacts
                    .iter()
                    .chain(
                        role.result
                            .observations
                            .iter()
                            .flat_map(|observation| &observation.record.artifacts),
                    )
                    .map(|artifact| artifact.sha256.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                NeutralRoleEvidence {
                    role: role.role.clone(),
                    observation_hashes: role
                        .result
                        .observations
                        .iter()
                        .map(|observation| observation.content_hash.clone())
                        .collect(),
                    artifact_hashes,
                }
            })
            .collect::<Vec<_>>();
        let content_hash = hash(&serde_json::to_vec(&roles)?);
        Ok(Self {
            schema_version: AUTHENTICATED_WORKFLOW_SCHEMA_VERSION,
            content_hash,
            roles,
        })
    }

    pub fn verify(&self) -> bool {
        self.schema_version == AUTHENTICATED_WORKFLOW_SCHEMA_VERSION
            && serde_json::to_vec(&self.roles).is_ok_and(|bytes| hash(&bytes) == self.content_hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatedBrowserWorkflowResult {
    pub schema_version: u32,
    pub workflow_name: String,
    pub workflow_fingerprint: String,
    pub status: AuthenticatedWorkflowStatus,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub roles: Vec<AuthenticatedRoleResult>,
    pub comparison: NeutralRoleComparisonRecord,
}

/// Executes each role in a fresh WebDriver session. A role-level browser
/// failure is represented in that role's result and does not prevent later
/// roles from running. All role executors observe the runtime's shared
/// cancellation flag and central budgets.
pub struct AuthenticatedBrowserWorkflowExecutor {
    runtime: BrowserRuntime,
    secrets: Arc<dyn SecretResolver>,
}

impl AuthenticatedBrowserWorkflowExecutor {
    pub fn new(runtime: BrowserRuntime) -> Self {
        Self {
            runtime,
            secrets: Arc::new(EnvironmentSecretResolver),
        }
    }

    pub fn with_secret_resolver(runtime: BrowserRuntime, secrets: Arc<dyn SecretResolver>) -> Self {
        Self { runtime, secrets }
    }

    pub async fn execute(
        &self,
        workflow: &AuthenticatedBrowserWorkflow,
    ) -> Result<AuthenticatedBrowserWorkflowResult> {
        workflow.validate()?;
        let workflow_fingerprint = workflow.fingerprint()?;
        let started_ms = now_ms();
        let mut ordered = workflow.roles.iter().collect::<Vec<_>>();
        ordered.sort_by(|a, b| a.role.cmp(&b.role));
        let mut roles = Vec::with_capacity(ordered.len());
        for role in ordered {
            let resolver = Arc::new(BoundRoleSecretResolver {
                bindings: role.secret_bindings.clone(),
                upstream: self.secrets.clone(),
            });
            let result = BrowserPlanExecutor::with_secret_resolver(self.runtime.clone(), resolver)
                .execute(&role.plan)
                .await?;
            roles.push(AuthenticatedRoleResult {
                role: role.role.clone(),
                result,
            });
        }
        let status = aggregate_status(&roles);
        let comparison = NeutralRoleComparisonRecord::from_results(&roles)?;
        Ok(AuthenticatedBrowserWorkflowResult {
            schema_version: AUTHENTICATED_WORKFLOW_SCHEMA_VERSION,
            workflow_name: workflow.name.clone(),
            workflow_fingerprint,
            status,
            started_ms,
            finished_ms: now_ms(),
            roles,
            comparison,
        })
    }
}

struct BoundRoleSecretResolver {
    bindings: BTreeMap<String, RoleSecretBinding>,
    upstream: Arc<dyn SecretResolver>,
}

impl SecretResolver for BoundRoleSecretResolver {
    fn resolve(&self, name: &str) -> std::result::Result<Zeroizing<String>, BrowserError> {
        let binding = self.bindings.get(name).ok_or_else(|| {
            BrowserError::new(
                BrowserErrorKind::InvalidInput,
                format!("unbound authenticated role secret {name}"),
            )
        })?;
        self.upstream.resolve(&binding.resolver_key)
    }
}

fn aggregate_status(roles: &[AuthenticatedRoleResult]) -> AuthenticatedWorkflowStatus {
    if roles
        .iter()
        .any(|role| role.result.status == BrowserPlanStatus::Cancelled)
    {
        return AuthenticatedWorkflowStatus::Cancelled;
    }
    let completed = roles
        .iter()
        .filter(|role| role.result.status == BrowserPlanStatus::Completed)
        .count();
    if completed == roles.len() {
        AuthenticatedWorkflowStatus::Completed
    } else if completed == 0 {
        AuthenticatedWorkflowStatus::Failed
    } else {
        AuthenticatedWorkflowStatus::PartiallyFailed
    }
}

fn validate_authenticated_plan(plan: &BrowserPlan) -> Result<BTreeSet<String>> {
    for (key, value) in &plan.session.additional_capabilities {
        ensure!(
            !sensitive_key(key),
            "authenticated workflow cannot serialize credential capability fields"
        );
        ensure_no_inline_capability_credentials(value)?;
    }
    let mut referenced = BTreeSet::new();
    for step in &plan.steps {
        match &step.action {
            BrowserStepAction::Navigate { url } => ensure_no_url_credentials(url)?,
            BrowserStepAction::SendKeys { value, .. }
            | BrowserStepAction::Fill { value, .. }
            | BrowserStepAction::SetStorage { value, .. } => {
                collect_bound_value(value, &mut referenced)?;
            }
            BrowserStepAction::AddCookie { cookie } => {
                collect_bound_value(&cookie.value, &mut referenced)?;
            }
            BrowserStepAction::Javascript { script, arguments } => {
                ensure_no_inline_script_credentials(script)?;
                for argument in arguments {
                    match argument {
                        PlanArgument::Environment { name } => {
                            referenced.insert(name.clone());
                        }
                        PlanArgument::Public { value } => {
                            ensure_no_inline_public_argument(value)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(referenced)
}

fn collect_bound_value(value: &PlanValue, referenced: &mut BTreeSet<String>) -> Result<()> {
    match value {
        PlanValue::Environment { name } => {
            referenced.insert(name.clone());
            Ok(())
        }
        PlanValue::Public { .. } => anyhow::bail!(
            "authenticated workflow values must use role secret bindings, not inline public values"
        ),
    }
}

fn ensure_no_url_credentials(raw: &str) -> Result<()> {
    let url = Url::parse(raw).context("invalid authenticated workflow URL")?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "authenticated workflow URL cannot contain inline credentials"
    );
    for (name, value) in url.query_pairs() {
        ensure!(
            value.is_empty() || !sensitive_key(&name),
            "authenticated workflow URL cannot contain credential query values"
        );
    }
    Ok(())
}

fn ensure_no_inline_script_credentials(script: &str) -> Result<()> {
    let normalized = script.to_ascii_lowercase().replace([' ', '\t', '\n'], "");
    ensure!(
        !sensitive_fragments()
            .iter()
            .any(|fragment| normalized.contains(fragment)),
        "authenticated workflow JavaScript cannot contain inline credentials"
    );
    Ok(())
}

fn ensure_no_inline_capability_credentials(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                ensure!(
                    !sensitive_key(key),
                    "authenticated workflow cannot serialize credential capability fields"
                );
                ensure_no_inline_capability_credentials(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                ensure_no_inline_capability_credentials(nested)?;
            }
        }
        Value::String(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            ensure!(
                !normalized.starts_with("bearer ")
                    && !normalized.starts_with("basic ")
                    && !normalized.contains("-----begin private key-----"),
                "authenticated workflow cannot serialize credential values"
            );
        }
        _ => {}
    }
    Ok(())
}

fn ensure_no_inline_public_argument(value: &Value) -> Result<()> {
    match value {
        Value::String(_) => anyhow::bail!(
            "authenticated workflow JavaScript string arguments must use role secret bindings"
        ),
        Value::Object(object) => {
            for (key, nested) in object {
                ensure!(
                    !sensitive_key(key),
                    "authenticated workflow cannot serialize credential argument fields"
                );
                ensure_no_inline_public_argument(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                ensure_no_inline_public_argument(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn sensitive_key(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "authorization",
        "cookie",
        "sessionid",
        "clientsecret",
        "accesskey",
        "privatekey",
        "credential",
        "credentials",
        "username",
    ]
    .iter()
    .any(|candidate| normalized == *candidate || normalized.ends_with(candidate))
}

fn sensitive_fragments() -> &'static [&'static str] {
    &[
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "apikey=",
        "authorization=",
        "bearer ",
        "basic ",
        "-----beginprivatekey-----",
    ]
}

fn validate_role_name(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.len() <= 160
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:@".contains(character)),
        "invalid {label}"
    );
    Ok(())
}

fn validate_logical_secret_name(value: &str) -> Result<()> {
    let mut characters = value.chars();
    ensure!(
        characters
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
            && characters.all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "invalid logical role secret name"
    );
    Ok(())
}
