use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{CloudError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Aws,
    Azure,
    Gcp,
}

impl Provider {
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Azure => "az",
            Self::Gcp => "gcloud",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsIdentity {
    pub account_id: String,
    pub arn: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureIdentity {
    pub tenant_id: String,
    pub subscription_id: String,
    pub principal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpIdentity {
    pub project_id: String,
    pub principal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum CloudIdentity {
    Aws(AwsIdentity),
    Azure(AzureIdentity),
    Gcp(GcpIdentity),
}

impl CloudIdentity {
    pub fn stable_id(&self) -> String {
        match self {
            Self::Aws(identity) => identity.account_id.clone(),
            Self::Azure(identity) => {
                format!("{}/{}", identity.tenant_id, identity.subscription_id)
            }
            Self::Gcp(identity) => format!("{}/{}", identity.project_id, identity.principal),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsAccountScope {
    pub expected: AwsIdentity,
    pub credential_context: String,
    pub profile: Option<String>,
    pub regions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureSubscriptionScope {
    pub expected: AzureIdentity,
    pub credential_context: String,
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpProjectScope {
    pub expected: GcpIdentity,
    pub credential_context: String,
    pub regions: Vec<String>,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum CloudScope {
    Aws {
        accounts: Vec<AwsAccountScope>,
    },
    Azure {
        subscriptions: Vec<AzureSubscriptionScope>,
    },
    Gcp {
        projects: Vec<GcpProjectScope>,
    },
}

impl CloudScope {
    pub fn validate(&self) -> Result<()> {
        let (provider, len) = match self {
            Self::Aws { accounts } => (Provider::Aws, accounts.len()),
            Self::Azure { subscriptions } => (Provider::Azure, subscriptions.len()),
            Self::Gcp { projects } => (Provider::Gcp, projects.len()),
        };
        if len == 0 {
            return Err(CloudError::InvalidScope(format!(
                "{provider:?} scope has no targets"
            )));
        }
        match self {
            Self::Aws { accounts } => {
                for account in accounts {
                    validate_identifier("AWS account", &account.expected.account_id)?;
                    validate_context(&account.credential_context)?;
                    for region in &account.regions {
                        validate_location(region)?;
                    }
                    if let Some(profile) = &account.profile {
                        validate_identifier("AWS profile", profile)?;
                    }
                }
            }
            Self::Azure { subscriptions } => {
                for subscription in subscriptions {
                    validate_identifier("Azure tenant", &subscription.expected.tenant_id)?;
                    validate_identifier(
                        "Azure subscription",
                        &subscription.expected.subscription_id,
                    )?;
                    validate_context(&subscription.credential_context)?;
                    for location in &subscription.locations {
                        validate_location(location)?;
                    }
                }
            }
            Self::Gcp { projects } => {
                for project in projects {
                    validate_identifier("GCP project", &project.expected.project_id)?;
                    validate_identifier("GCP principal", &project.expected.principal)?;
                    validate_context(&project.credential_context)?;
                    for region in &project.regions {
                        validate_location(region)?;
                    }
                    for zone in &project.zones {
                        validate_location(zone)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_context(value: &str) -> Result<()> {
    validate_identifier("credential context", value)
}

fn validate_location(value: &str) -> Result<()> {
    validate_identifier("location", value)
}

fn validate_identifier(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:@/".contains(&byte))
    {
        return Err(CloudError::InvalidScope(format!(
            "unsafe {kind} identifier"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamBinding {
    pub role: String,
    pub principal: String,
    pub condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub provider: Provider,
    pub scope_id: String,
    pub location: Option<String>,
    pub service: String,
    pub resource_type: String,
    pub resource_id: String,
    pub name: String,
    pub configuration: Value,
    pub iam: Vec<IamBinding>,
    pub source_audit_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedFindingInput {
    pub provider: Provider,
    pub scope_id: String,
    pub title: String,
    pub category: String,
    pub severity: FindingSeverity,
    pub asset_id: String,
    pub evidence_audit_ids: Vec<String>,
    pub attributes: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedCapability {
    pub provider: Provider,
    pub scope_id: String,
    pub service: String,
    pub operation: String,
    pub reason: String,
    pub audit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkflowResult {
    pub verified_identities: Vec<CloudIdentity>,
    pub observations: Vec<Observation>,
    pub finding_inputs: Vec<NormalizedFindingInput>,
    pub unsupported: Vec<UnsupportedCapability>,
    pub audits: Vec<crate::audit::CommandAudit>,
}
