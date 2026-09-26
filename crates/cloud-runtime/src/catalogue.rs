use serde::{Deserialize, Serialize};

use crate::error::{CloudError, Result};
use crate::types::Provider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    AccessPolicy,
    ResourceConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    ReadOnly,
    Mutation(MutationKind),
}

/// Every cloud operation MetisBLACK may invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    AwsVersion,
    AwsCallerIdentity,
    AwsIamRoles,
    AwsS3Buckets,
    AwsEc2Instances,
    AwsLambdaFunctions,
    AwsEksClusters,
    AwsRdsInstances,
    AwsS3PutPublicAccessBlock,
    AzureVersion,
    AzureAccountShow,
    AzureRoleAssignments,
    AzureStorageAccounts,
    AzureVirtualMachines,
    AzureAksClusters,
    AzureKeyVaults,
    AzureRoleAssignmentCreate,
    GcpVersion,
    GcpActiveAccount,
    GcpProjectDescribe,
    GcpIamPolicy,
    GcpStorageBuckets,
    GcpComputeInstances,
    GcpGkeClusters,
    GcpSecrets,
    GcpIamBindingAdd,
}

impl Operation {
    pub const fn provider(self) -> Provider {
        match self {
            Self::AwsVersion
            | Self::AwsCallerIdentity
            | Self::AwsIamRoles
            | Self::AwsS3Buckets
            | Self::AwsEc2Instances
            | Self::AwsLambdaFunctions
            | Self::AwsEksClusters
            | Self::AwsRdsInstances
            | Self::AwsS3PutPublicAccessBlock => Provider::Aws,
            Self::AzureVersion
            | Self::AzureAccountShow
            | Self::AzureRoleAssignments
            | Self::AzureStorageAccounts
            | Self::AzureVirtualMachines
            | Self::AzureAksClusters
            | Self::AzureKeyVaults
            | Self::AzureRoleAssignmentCreate => Provider::Azure,
            _ => Provider::Gcp,
        }
    }

    pub const fn service(self) -> &'static str {
        match self {
            Self::AwsVersion | Self::AzureVersion | Self::GcpVersion => "cli",
            Self::AwsCallerIdentity => "sts",
            Self::AwsIamRoles | Self::GcpIamPolicy | Self::GcpIamBindingAdd => "iam",
            Self::AwsS3Buckets | Self::AwsS3PutPublicAccessBlock => "s3",
            Self::AwsEc2Instances => "ec2",
            Self::AwsLambdaFunctions => "lambda",
            Self::AwsEksClusters => "eks",
            Self::AwsRdsInstances => "rds",
            Self::AzureAccountShow => "account",
            Self::AzureRoleAssignments | Self::AzureRoleAssignmentCreate => "role",
            Self::AzureStorageAccounts => "storage",
            Self::AzureVirtualMachines => "vm",
            Self::AzureAksClusters => "aks",
            Self::AzureKeyVaults => "keyvault",
            Self::GcpActiveAccount => "auth",
            Self::GcpProjectDescribe => "projects",
            Self::GcpStorageBuckets => "storage",
            Self::GcpComputeInstances => "compute",
            Self::GcpGkeClusters => "gke",
            Self::GcpSecrets => "secrets",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AwsVersion | Self::AzureVersion | Self::GcpVersion => "version",
            Self::AwsCallerIdentity => "get_caller_identity",
            Self::AwsIamRoles => "list_roles",
            Self::AwsS3Buckets => "list_buckets",
            Self::AwsEc2Instances => "describe_instances",
            Self::AwsLambdaFunctions => "list_functions",
            Self::AwsEksClusters => "list_clusters",
            Self::AwsRdsInstances => "describe_db_instances",
            Self::AwsS3PutPublicAccessBlock => "put_public_access_block",
            Self::AzureAccountShow => "show",
            Self::AzureRoleAssignments => "assignment_list",
            Self::AzureStorageAccounts => "account_list",
            Self::AzureVirtualMachines => "list",
            Self::AzureAksClusters => "list",
            Self::AzureKeyVaults => "list",
            Self::AzureRoleAssignmentCreate => "assignment_create",
            Self::GcpActiveAccount => "active_account",
            Self::GcpProjectDescribe => "describe",
            Self::GcpIamPolicy => "get_iam_policy",
            Self::GcpStorageBuckets => "buckets_list",
            Self::GcpComputeInstances => "instances_list",
            Self::GcpGkeClusters => "clusters_list",
            Self::GcpSecrets => "secrets_list",
            Self::GcpIamBindingAdd => "add_iam_policy_binding",
        }
    }

    pub const fn class(self) -> CommandClass {
        match self {
            Self::AwsS3PutPublicAccessBlock => {
                CommandClass::Mutation(MutationKind::ResourceConfiguration)
            }
            Self::AzureRoleAssignmentCreate | Self::GcpIamBindingAdd => {
                CommandClass::Mutation(MutationKind::AccessPolicy)
            }
            _ => CommandClass::ReadOnly,
        }
    }

    pub(crate) fn fixed_prefix(self) -> &'static [&'static str] {
        match self {
            Self::AwsVersion => &["--version"],
            Self::AwsCallerIdentity => &["sts", "get-caller-identity"],
            Self::AwsIamRoles => &["iam", "list-roles"],
            Self::AwsS3Buckets => &["s3api", "list-buckets"],
            Self::AwsEc2Instances => &["ec2", "describe-instances"],
            Self::AwsLambdaFunctions => &["lambda", "list-functions"],
            Self::AwsEksClusters => &["eks", "list-clusters"],
            Self::AwsRdsInstances => &["rds", "describe-db-instances"],
            Self::AwsS3PutPublicAccessBlock => &["s3api", "put-public-access-block"],
            Self::AzureVersion => &["version"],
            Self::AzureAccountShow => &["account", "show"],
            Self::AzureRoleAssignments => &["role", "assignment", "list"],
            Self::AzureStorageAccounts => &["storage", "account", "list"],
            Self::AzureVirtualMachines => &["vm", "list"],
            Self::AzureAksClusters => &["aks", "list"],
            Self::AzureKeyVaults => &["keyvault", "list"],
            Self::AzureRoleAssignmentCreate => &["role", "assignment", "create"],
            Self::GcpVersion => &["version"],
            Self::GcpActiveAccount => &["auth", "list"],
            Self::GcpProjectDescribe => &["projects", "describe"],
            Self::GcpIamPolicy => &["projects", "get-iam-policy"],
            Self::GcpStorageBuckets => &["storage", "buckets", "list"],
            Self::GcpComputeInstances => &["compute", "instances", "list"],
            Self::GcpGkeClusters => &["container", "clusters", "list"],
            Self::GcpSecrets => &["secrets", "list"],
            Self::GcpIamBindingAdd => &["projects", "add-iam-policy-binding"],
        }
    }

    pub(crate) const fn page_token_flag(self) -> Option<&'static str> {
        match self.provider() {
            Provider::Aws => Some("--starting-token"),
            Provider::Azure => Some("--next-token"),
            Provider::Gcp => Some("--page-token"),
        }
    }
}

/// A typed argv request. No shell command representation is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    operation: Operation,
    arguments: Vec<String>,
}

impl CommandRequest {
    pub fn new(operation: Operation, arguments: Vec<String>) -> Result<Self> {
        let prefix = operation.fixed_prefix();
        if arguments.len() < prefix.len()
            || !prefix
                .iter()
                .zip(arguments.iter())
                .all(|(expected, actual)| *expected == actual)
        {
            return Err(CloudError::CommandDenied(format!(
                "argv does not match typed operation {}:{}",
                operation.service(),
                operation.name()
            )));
        }
        if arguments.iter().any(|value| value.contains('\0')) {
            return Err(CloudError::CommandDenied(
                "argv contains an invalid NUL byte".into(),
            ));
        }
        Ok(Self {
            operation,
            arguments,
        })
    }

    pub(crate) fn catalogue(operation: Operation, tail: &[String]) -> Self {
        let mut arguments = operation
            .fixed_prefix()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        arguments.extend_from_slice(tail);
        Self {
            operation,
            arguments,
        }
    }

    pub const fn operation(&self) -> Operation {
        self.operation
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}
