use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::digest::{digest, SHA256};
use serde_json::{json, Value};

use crate::audit::{AuditStatus, CommandAudit};
use crate::catalogue::{CommandClass, CommandRequest, Operation};
use crate::credentials::{CloudCredentials, CredentialContext};
use crate::error::{CloudError, Result};
use crate::process::{CancellationToken, CommandRunner, CommandSpec, ProcessOutput};
use crate::types::{
    AwsAccountScope, AwsIdentity, AzureIdentity, AzureSubscriptionScope, CloudIdentity, CloudScope,
    FindingSeverity, GcpIdentity, GcpProjectScope, IamBinding, NormalizedFindingInput, Observation,
    Provider, UnsupportedCapability, WorkflowResult,
};

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub command_timeout: Duration,
    pub output_cap_bytes: usize,
    pub max_commands: usize,
    pub max_pages_per_operation: usize,
    pub cancellation: CancellationToken,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(30),
            output_cap_bytes: 4 * 1024 * 1024,
            max_commands: 256,
            max_pages_per_operation: 20,
            cancellation: CancellationToken::default(),
        }
    }
}

impl RuntimeOptions {
    fn validate(&self) -> Result<()> {
        if self.command_timeout.is_zero()
            || self.output_cap_bytes == 0
            || self.max_commands == 0
            || self.max_pages_per_operation == 0
        {
            return Err(CloudError::InvalidScope(
                "cloud runtime budgets must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Explicit, auditable permission to run catalogue-listed cloud mutations.
/// The constructor intentionally requires a fixed acknowledgement phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpertMutationCapability {
    actor: String,
    reason: String,
}

impl ExpertMutationCapability {
    pub const ACKNOWLEDGEMENT: &'static str = "I AUTHORIZE CLOUD MUTATIONS";

    pub fn authorize(actor: &str, reason: &str, acknowledgement: &str) -> Result<Self> {
        if acknowledgement != Self::ACKNOWLEDGEMENT {
            return Err(CloudError::MutationCapabilityRequired(
                "exact acknowledgement phrase was not supplied".into(),
            ));
        }
        if actor.trim().len() < 2 || reason.trim().len() < 10 {
            return Err(CloudError::MutationCapabilityRequired(
                "actor and a meaningful reason are mandatory".into(),
            ));
        }
        Ok(Self {
            actor: actor.trim().into(),
            reason: reason.trim().into(),
        })
    }

    fn provenance(&self) -> String {
        format!("actor={}; reason={}", self.actor, self.reason)
    }
}

pub struct CloudRuntime<R> {
    runner: R,
    options: RuntimeOptions,
}

/// A lossless workflow result. Unlike `CloudRuntime::run`, this preserves all
/// completed work and command audits when a later operation terminates the run.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowOutcome {
    pub result: WorkflowResult,
    pub terminal_error: Option<CloudError>,
}

impl WorkflowOutcome {
    pub const fn is_success(&self) -> bool {
        self.terminal_error.is_none()
    }
}

impl<R: CommandRunner> CloudRuntime<R> {
    pub fn new(runner: R, options: RuntimeOptions) -> Result<Self> {
        options.validate()?;
        Ok(Self { runner, options })
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Execute a complete, identity-verified, read-only provider workflow.
    pub fn run(
        &self,
        scope: &CloudScope,
        credentials: &CloudCredentials,
    ) -> Result<WorkflowResult> {
        let outcome = self.run_with_outcome(scope, credentials);
        match outcome.terminal_error {
            Some(error) => Err(error),
            None => Ok(outcome.result),
        }
    }

    /// Execute a workflow while retaining partial results on terminal failure.
    ///
    /// This is the preferred API for production orchestration: every audit,
    /// verified identity, observation, and unsupported capability produced
    /// before failure remains available beside the terminal error.
    pub fn run_with_outcome(
        &self,
        scope: &CloudScope,
        credentials: &CloudCredentials,
    ) -> WorkflowOutcome {
        let mut state = ExecutionState::default();
        let terminal_error = scope.validate().and_then(|()| match scope {
            CloudScope::Aws { accounts } => {
                for account in accounts {
                    self.run_aws(account, credentials, &mut state)?;
                }
                Ok(())
            }
            CloudScope::Azure { subscriptions } => {
                for subscription in subscriptions {
                    self.run_azure(subscription, credentials, &mut state)?;
                }
                Ok(())
            }
            CloudScope::Gcp { projects } => {
                for project in projects {
                    self.run_gcp(project, credentials, &mut state)?;
                }
                Ok(())
            }
        });
        state.result.finding_inputs = findings_from(&state.result.observations);
        WorkflowOutcome {
            result: state.result,
            terminal_error: terminal_error.err(),
        }
    }

    /// Execute a single catalogue-listed command. Mutation operations require a
    /// separately constructed expert capability and retain its provenance.
    pub fn execute_command(
        &self,
        scope_id: &str,
        credential_context_name: &str,
        credential_context: &CredentialContext,
        request: &CommandRequest,
        mutation_capability: Option<&ExpertMutationCapability>,
    ) -> Result<(ProcessOutput, CommandAudit)> {
        let mut state = ExecutionState::default();
        let executable = self.discover(request.operation().provider())?;
        let (mut output, audit) = self.execute_once(
            scope_id,
            credential_context_name,
            credential_context,
            request,
            &executable,
            mutation_capability,
            &mut state,
        )?;
        output.stdout = redact_text(&output.stdout, credential_context.secret_literals());
        output.stderr = redact_text(&output.stderr, credential_context.secret_literals());
        Ok((output, audit))
    }

    fn discover(&self, provider: Provider) -> Result<PathBuf> {
        self.runner
            .discover(provider.executable())
            .map(|probe| probe.resolved)
    }

    fn verify_cli(
        &self,
        provider: Provider,
        scope_id: &str,
        context_name: &str,
        context: &CredentialContext,
        executable: &Path,
        state: &mut ExecutionState,
    ) -> Result<()> {
        let operation = match provider {
            Provider::Aws => Operation::AwsVersion,
            Provider::Azure => Operation::AzureVersion,
            Provider::Gcp => Operation::GcpVersion,
        };
        let request = CommandRequest::catalogue(operation, &[]);
        let (output, audit) = self.execute_once(
            scope_id,
            context_name,
            context,
            &request,
            executable,
            None,
            state,
        )?;
        state.result.audits.push(audit);
        if output.exit_code != Some(0)
            || !valid_cli_version(provider, &output.stdout, &output.stderr)
        {
            return Err(CloudError::CapabilityCheck(format!(
                "{} version command was unsuccessful or unrecognized",
                provider.executable()
            )));
        }
        Ok(())
    }

    fn run_aws(
        &self,
        scope: &AwsAccountScope,
        credentials: &CloudCredentials,
        state: &mut ExecutionState,
    ) -> Result<()> {
        let context = credentials.get(&scope.credential_context, Provider::Aws)?;
        let executable = self.discover(Provider::Aws)?;
        self.verify_cli(
            Provider::Aws,
            &scope.expected.account_id,
            &scope.credential_context,
            context,
            &executable,
            state,
        )?;
        let common = aws_common(scope);
        let identity_request = CommandRequest::catalogue(Operation::AwsCallerIdentity, &common);
        let identity_value = self.required_json(
            &scope.expected.account_id,
            &scope.credential_context,
            context,
            &identity_request,
            &executable,
            state,
        )?;
        let actual = AwsIdentity {
            account_id: string_field(&identity_value, &["Account", "account"])
                .ok_or_else(|| parse_error(Operation::AwsCallerIdentity, "missing Account"))?,
            arn: string_field(&identity_value, &["Arn", "arn"]),
            user_id: string_field(&identity_value, &["UserId", "userId"]),
        };
        verify_aws_identity(&scope.expected, &actual)?;
        state
            .result
            .verified_identities
            .push(CloudIdentity::Aws(actual));

        for operation in [Operation::AwsIamRoles, Operation::AwsS3Buckets] {
            let request = CommandRequest::catalogue(operation, &common);
            self.optional_pages(
                &scope.expected.account_id,
                &scope.credential_context,
                context,
                request,
                &executable,
                state,
                |value, audit_id| normalize_aws(operation, value, audit_id, scope, None),
            )?;
        }
        for region in &scope.regions {
            for operation in [
                Operation::AwsEc2Instances,
                Operation::AwsLambdaFunctions,
                Operation::AwsEksClusters,
                Operation::AwsRdsInstances,
            ] {
                let mut tail = common.clone();
                tail.extend(["--region".into(), region.clone()]);
                let request = CommandRequest::catalogue(operation, &tail);
                self.optional_pages(
                    &scope.expected.account_id,
                    &scope.credential_context,
                    context,
                    request,
                    &executable,
                    state,
                    |value, audit_id| {
                        normalize_aws(operation, value, audit_id, scope, Some(region))
                    },
                )?;
            }
        }
        Ok(())
    }

    fn run_azure(
        &self,
        scope: &AzureSubscriptionScope,
        credentials: &CloudCredentials,
        state: &mut ExecutionState,
    ) -> Result<()> {
        let context = credentials.get(&scope.credential_context, Provider::Azure)?;
        let executable = self.discover(Provider::Azure)?;
        let scope_id = format!(
            "{}/{}",
            scope.expected.tenant_id, scope.expected.subscription_id
        );
        self.verify_cli(
            Provider::Azure,
            &scope_id,
            &scope.credential_context,
            context,
            &executable,
            state,
        )?;
        let common = vec!["--output".into(), "json".into()];
        let identity_request = CommandRequest::catalogue(Operation::AzureAccountShow, &common);
        let value = self.required_json(
            &scope_id,
            &scope.credential_context,
            context,
            &identity_request,
            &executable,
            state,
        )?;
        let actual = AzureIdentity {
            tenant_id: string_field(&value, &["tenantId", "tenant_id"])
                .ok_or_else(|| parse_error(Operation::AzureAccountShow, "missing tenantId"))?,
            subscription_id: string_field(&value, &["id", "subscriptionId"])
                .ok_or_else(|| parse_error(Operation::AzureAccountShow, "missing id"))?,
            principal: value
                .pointer("/user/name")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        };
        verify_azure_identity(&scope.expected, &actual)?;
        state
            .result
            .verified_identities
            .push(CloudIdentity::Azure(actual));

        for operation in [
            Operation::AzureRoleAssignments,
            Operation::AzureStorageAccounts,
            Operation::AzureVirtualMachines,
            Operation::AzureAksClusters,
            Operation::AzureKeyVaults,
        ] {
            let mut tail = vec![
                "--subscription".into(),
                scope.expected.subscription_id.clone(),
                "--output".into(),
                "json".into(),
            ];
            if operation == Operation::AzureRoleAssignments {
                tail.push("--all".into());
            }
            let request = CommandRequest::catalogue(operation, &tail);
            self.optional_pages(
                &scope_id,
                &scope.credential_context,
                context,
                request,
                &executable,
                state,
                |value, audit_id| normalize_azure(operation, value, audit_id, scope, &scope_id),
            )?;
        }
        Ok(())
    }

    fn run_gcp(
        &self,
        scope: &GcpProjectScope,
        credentials: &CloudCredentials,
        state: &mut ExecutionState,
    ) -> Result<()> {
        let context = credentials.get(&scope.credential_context, Provider::Gcp)?;
        let executable = self.discover(Provider::Gcp)?;
        self.verify_cli(
            Provider::Gcp,
            &scope.expected.project_id,
            &scope.credential_context,
            context,
            &executable,
            state,
        )?;
        let account_request = CommandRequest::catalogue(
            Operation::GcpActiveAccount,
            &["--filter=status:ACTIVE".into(), "--format=json".into()],
        );
        let accounts = self.required_json(
            &scope.expected.project_id,
            &scope.credential_context,
            context,
            &account_request,
            &executable,
            state,
        )?;
        let principal = accounts
            .as_array()
            .and_then(|values| {
                values.iter().find_map(|value| {
                    let active = value.get("status").and_then(Value::as_str) == Some("ACTIVE");
                    active
                        .then(|| value.get("account").and_then(Value::as_str))
                        .flatten()
                })
            })
            .ok_or_else(|| parse_error(Operation::GcpActiveAccount, "no active account"))?
            .to_string();
        let project_request = CommandRequest::catalogue(
            Operation::GcpProjectDescribe,
            &[scope.expected.project_id.clone(), "--format=json".into()],
        );
        let project = self.required_json(
            &scope.expected.project_id,
            &scope.credential_context,
            context,
            &project_request,
            &executable,
            state,
        )?;
        let actual = GcpIdentity {
            project_id: string_field(&project, &["projectId", "project_id"])
                .ok_or_else(|| parse_error(Operation::GcpProjectDescribe, "missing projectId"))?,
            principal,
        };
        verify_gcp_identity(&scope.expected, &actual)?;
        state
            .result
            .verified_identities
            .push(CloudIdentity::Gcp(actual));

        for operation in [
            Operation::GcpIamPolicy,
            Operation::GcpStorageBuckets,
            Operation::GcpComputeInstances,
            Operation::GcpGkeClusters,
            Operation::GcpSecrets,
        ] {
            let tail = gcp_tail(operation, scope);
            let request = CommandRequest::catalogue(operation, &tail);
            self.optional_pages(
                &scope.expected.project_id,
                &scope.credential_context,
                context,
                request,
                &executable,
                state,
                |value, audit_id| normalize_gcp(operation, value, audit_id, scope),
            )?;
        }
        Ok(())
    }

    fn required_json(
        &self,
        scope_id: &str,
        context_name: &str,
        context: &CredentialContext,
        request: &CommandRequest,
        executable: &Path,
        state: &mut ExecutionState,
    ) -> Result<Value> {
        let (output, audit) = self.execute_once(
            scope_id,
            context_name,
            context,
            request,
            executable,
            None,
            state,
        )?;
        state.result.audits.push(audit);
        if output.timed_out || output.cancelled {
            return Err(CloudError::Timeout {
                operation: request.operation().name().into(),
            });
        }
        if output.exit_code != Some(0) {
            return Err(CloudError::Process(redact_text(
                &output.stderr,
                context.secret_literals(),
            )));
        }
        parse_json(request.operation(), &output.stdout)
    }

    #[allow(clippy::too_many_arguments)]
    fn optional_pages<F>(
        &self,
        scope_id: &str,
        context_name: &str,
        context: &CredentialContext,
        request: CommandRequest,
        executable: &Path,
        state: &mut ExecutionState,
        mut normalize: F,
    ) -> Result<()>
    where
        F: FnMut(&Value, &str) -> Vec<Observation>,
    {
        let mut next_token: Option<String> = None;
        let mut seen = BTreeSet::new();
        for page in 0..self.options.max_pages_per_operation {
            let mut arguments = request.arguments().to_vec();
            if let Some(token) = &next_token {
                arguments.push(
                    request
                        .operation()
                        .page_token_flag()
                        .expect("provider has pagination")
                        .into(),
                );
                arguments.push(token.clone());
            }
            let page_request = CommandRequest::new(request.operation(), arguments)?;
            let (output, mut audit) = self.execute_once(
                scope_id,
                context_name,
                context,
                &page_request,
                executable,
                None,
                state,
            )?;
            let audit_id = audit.audit_id.clone();
            if output.timed_out || output.cancelled {
                state.result.audits.push(audit);
                return Err(CloudError::Timeout {
                    operation: request.operation().name().into(),
                });
            }
            if output.exit_code != Some(0) {
                audit.status = AuditStatus::Unsupported;
                state.result.audits.push(audit);
                state.result.unsupported.push(UnsupportedCapability {
                    provider: request.operation().provider(),
                    scope_id: scope_id.into(),
                    service: request.operation().service().into(),
                    operation: request.operation().name().into(),
                    reason: redact_text(&output.stderr, context.secret_literals()),
                    audit_id: Some(audit_id),
                });
                return Ok(());
            }
            state.result.audits.push(audit);
            let mut value = parse_json(request.operation(), &output.stdout)?;
            redact_json(&mut value, context.secret_literals());
            state
                .result
                .observations
                .extend(normalize(&value, &audit_id));
            next_token = pagination_token(&value);
            let Some(token) = next_token.as_ref() else {
                return Ok(());
            };
            if !seen.insert(token.clone()) {
                return Err(CloudError::Parse {
                    operation: request.operation().name().into(),
                    message: "provider repeated a pagination token".into(),
                });
            }
            if page + 1 == self.options.max_pages_per_operation {
                return Err(CloudError::BudgetExceeded {
                    budget: self.options.max_pages_per_operation,
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_once(
        &self,
        scope_id: &str,
        context_name: &str,
        context: &CredentialContext,
        request: &CommandRequest,
        executable: &Path,
        mutation_capability: Option<&ExpertMutationCapability>,
        state: &mut ExecutionState,
    ) -> Result<(ProcessOutput, CommandAudit)> {
        if context.provider() != request.operation().provider() {
            return Err(CloudError::CommandDenied(
                "credential provider does not match command provider".into(),
            ));
        }
        let authorization = match request.operation().class() {
            CommandClass::ReadOnly => None,
            CommandClass::Mutation(_) => Some(
                mutation_capability
                    .ok_or_else(|| {
                        CloudError::MutationCapabilityRequired(format!(
                            "{}:{}",
                            request.operation().service(),
                            request.operation().name()
                        ))
                    })?
                    .provenance(),
            ),
        };
        if state.commands >= self.options.max_commands {
            return Err(CloudError::BudgetExceeded {
                budget: self.options.max_commands,
            });
        }
        state.commands += 1;
        let environment = context
            .environment()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        let spec = CommandSpec::new(
            request.operation(),
            executable.to_path_buf(),
            request.arguments().to_vec(),
            environment,
            self.options.command_timeout,
            self.options.output_cap_bytes,
            self.options.cancellation.clone(),
        );
        let output = self.runner.run(&spec)?;
        let status = if output.timed_out || output.cancelled {
            AuditStatus::TimedOut
        } else if output.exit_code == Some(0) {
            AuditStatus::Succeeded
        } else {
            AuditStatus::Failed {
                exit_code: output.exit_code,
            }
        };
        let argv = redact_argv(request.arguments());
        let seed = format!(
            "{}|{:?}|{}|{}|{}|{}",
            state.commands,
            request.operation(),
            scope_id,
            output.started_unix_ms,
            sha256(output.stdout.as_bytes()),
            sha256(output.stderr.as_bytes())
        );
        let audit = CommandAudit {
            audit_id: format!("cloud-{}", &sha256(seed.as_bytes())[..24]),
            provider: request.operation().provider(),
            scope_id: scope_id.into(),
            credential_context: context_name.into(),
            executable: executable.display().to_string(),
            argv,
            environment_names: context.environment_names(),
            service: request.operation().service().into(),
            operation: request.operation().name().into(),
            class: request.operation().class(),
            started_unix_ms: output.started_unix_ms,
            duration_ms: output.duration.as_millis(),
            status,
            stdout_sha256: sha256(output.stdout.as_bytes()),
            stderr_sha256: sha256(output.stderr.as_bytes()),
            stdout_bytes: output.stdout_bytes,
            stderr_bytes: output.stderr_bytes,
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            mutation_authorization: authorization,
        };
        Ok((output, audit))
    }
}

#[derive(Default)]
struct ExecutionState {
    commands: usize,
    result: WorkflowResult,
}

fn aws_common(scope: &AwsAccountScope) -> Vec<String> {
    let mut result = vec!["--output".into(), "json".into(), "--no-cli-pager".into()];
    if let Some(profile) = &scope.profile {
        result.extend(["--profile".into(), profile.clone()]);
    }
    result
}

fn gcp_tail(operation: Operation, scope: &GcpProjectScope) -> Vec<String> {
    match operation {
        Operation::GcpIamPolicy => vec![scope.expected.project_id.clone(), "--format=json".into()],
        _ => vec![
            format!("--project={}", scope.expected.project_id),
            "--format=json".into(),
        ],
    }
}

fn verify_aws_identity(expected: &AwsIdentity, actual: &AwsIdentity) -> Result<()> {
    let matches = expected.account_id == actual.account_id
        && expected
            .arn
            .as_ref()
            .is_none_or(|value| actual.arn.as_ref() == Some(value))
        && expected
            .user_id
            .as_ref()
            .is_none_or(|value| actual.user_id.as_ref() == Some(value));
    if matches {
        Ok(())
    } else {
        Err(CloudError::IdentityMismatch {
            expected: CloudIdentity::Aws(expected.clone()).stable_id(),
            actual: CloudIdentity::Aws(actual.clone()).stable_id(),
        })
    }
}

fn verify_azure_identity(expected: &AzureIdentity, actual: &AzureIdentity) -> Result<()> {
    let matches = expected.tenant_id == actual.tenant_id
        && expected.subscription_id == actual.subscription_id
        && expected
            .principal
            .as_ref()
            .is_none_or(|value| actual.principal.as_ref() == Some(value));
    if matches {
        Ok(())
    } else {
        Err(CloudError::IdentityMismatch {
            expected: CloudIdentity::Azure(expected.clone()).stable_id(),
            actual: CloudIdentity::Azure(actual.clone()).stable_id(),
        })
    }
}

fn verify_gcp_identity(expected: &GcpIdentity, actual: &GcpIdentity) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(CloudError::IdentityMismatch {
            expected: CloudIdentity::Gcp(expected.clone()).stable_id(),
            actual: CloudIdentity::Gcp(actual.clone()).stable_id(),
        })
    }
}

fn parse_json(operation: Operation, text: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|error| CloudError::Parse {
        operation: operation.name().into(),
        message: error.to_string(),
    })
}

fn valid_cli_version(provider: Provider, stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    match provider {
        Provider::Aws => combined.contains("aws-cli/"),
        Provider::Azure => combined.contains("azure-cli"),
        Provider::Gcp => {
            combined.contains("google cloud sdk") || combined.contains("google-cloud-sdk")
        }
    }
}

fn parse_error(operation: Operation, message: &str) -> CloudError {
    CloudError::Parse {
        operation: operation.name().into(),
        message: message.into(),
    }
}

fn string_field(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    })
}

fn pagination_token(value: &Value) -> Option<String> {
    [
        "NextToken",
        "nextToken",
        "continuationToken",
        "next_page_token",
        "nextPageToken",
    ]
    .iter()
    .find_map(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(ToString::to_string)
    })
}

fn normalize_aws(
    operation: Operation,
    value: &Value,
    audit_id: &str,
    scope: &AwsAccountScope,
    region: Option<&String>,
) -> Vec<Observation> {
    let values = match operation {
        Operation::AwsIamRoles => array_field(value, "Roles"),
        Operation::AwsS3Buckets => array_field(value, "Buckets"),
        Operation::AwsEc2Instances => value
            .get("Reservations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|reservation| reservation.get("Instances").and_then(Value::as_array))
            .flatten()
            .collect(),
        Operation::AwsLambdaFunctions => array_field(value, "Functions"),
        Operation::AwsEksClusters => value
            .get("clusters")
            .and_then(Value::as_array)
            .map(|values| values.iter().collect())
            .unwrap_or_default(),
        Operation::AwsRdsInstances => array_field(value, "DBInstances"),
        _ => Vec::new(),
    };
    values
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let (kind, fields) = match operation {
                Operation::AwsIamRoles => ("iam_role", &["Arn", "RoleId", "RoleName"][..]),
                Operation::AwsS3Buckets => ("s3_bucket", &["Name"][..]),
                Operation::AwsEc2Instances => ("ec2_instance", &["InstanceId"][..]),
                Operation::AwsLambdaFunctions => {
                    ("lambda_function", &["FunctionArn", "FunctionName"][..])
                }
                Operation::AwsEksClusters => ("eks_cluster", &["name"][..]),
                Operation::AwsRdsInstances => (
                    "rds_instance",
                    &["DBInstanceArn", "DBInstanceIdentifier"][..],
                ),
                _ => ("resource", &[][..]),
            };
            let mut result = observation(
                Provider::Aws,
                &scope.expected.account_id,
                region.cloned(),
                operation.service(),
                kind,
                item,
                fields,
                index,
                audit_id,
            );
            if operation == Operation::AwsIamRoles {
                result.iam = aws_role_bindings(item);
            }
            result
        })
        .collect()
}

fn normalize_azure(
    operation: Operation,
    value: &Value,
    audit_id: &str,
    scope: &AzureSubscriptionScope,
    scope_id: &str,
) -> Vec<Observation> {
    let values = value
        .as_array()
        .map(|values| values.iter().collect::<Vec<_>>())
        .or_else(|| {
            value
                .get("value")
                .and_then(Value::as_array)
                .map(|v| v.iter().collect())
        })
        .unwrap_or_default();
    values
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let location = string_field(item, &["location"]);
            if !scope.locations.is_empty()
                && location
                    .as_ref()
                    .is_some_and(|value| !scope.locations.contains(value))
            {
                return None;
            }
            let (kind, fields) = match operation {
                Operation::AzureRoleAssignments => ("role_assignment", &["id", "principalId"][..]),
                Operation::AzureStorageAccounts => ("storage_account", &["id", "name"][..]),
                Operation::AzureVirtualMachines => ("virtual_machine", &["id", "name"][..]),
                Operation::AzureAksClusters => ("aks_cluster", &["id", "name"][..]),
                Operation::AzureKeyVaults => ("key_vault", &["id", "name"][..]),
                _ => ("resource", &[][..]),
            };
            let mut result = observation(
                Provider::Azure,
                scope_id,
                location,
                operation.service(),
                kind,
                item,
                fields,
                index,
                audit_id,
            );
            if operation == Operation::AzureRoleAssignments {
                let role = string_field(item, &["roleDefinitionName", "roleDefinitionId"])
                    .unwrap_or_else(|| "unknown".into());
                if let Some(principal) = string_field(item, &["principalId", "principalName"]) {
                    result.iam.push(IamBinding {
                        role,
                        principal,
                        condition: string_field(item, &["condition"]),
                    });
                }
            }
            Some(result)
        })
        .collect()
}

fn normalize_gcp(
    operation: Operation,
    value: &Value,
    audit_id: &str,
    scope: &GcpProjectScope,
) -> Vec<Observation> {
    if operation == Operation::GcpIamPolicy {
        let bindings = value
            .get("bindings")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .flat_map(|binding| {
                        let role = binding
                            .get("role")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        binding
                            .get("members")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(move |member| {
                                member.as_str().map(|principal| IamBinding {
                                    role: role.clone(),
                                    principal: principal.into(),
                                    condition: None,
                                })
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return vec![Observation {
            provider: Provider::Gcp,
            scope_id: scope.expected.project_id.clone(),
            location: None,
            service: "iam".into(),
            resource_type: "project_iam_policy".into(),
            resource_id: scope.expected.project_id.clone(),
            name: scope.expected.project_id.clone(),
            configuration: value.clone(),
            iam: bindings,
            source_audit_id: audit_id.into(),
        }];
    }
    let values = value
        .as_array()
        .map(|values| values.iter().collect::<Vec<_>>())
        .or_else(|| {
            value
                .get("items")
                .and_then(Value::as_array)
                .map(|v| v.iter().collect())
        })
        .unwrap_or_default();
    values
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let (kind, fields) = match operation {
                Operation::GcpStorageBuckets => ("storage_bucket", &["id", "name"][..]),
                Operation::GcpComputeInstances => ("compute_instance", &["id", "name"][..]),
                Operation::GcpGkeClusters => ("gke_cluster", &["id", "name"][..]),
                Operation::GcpSecrets => ("secret", &["name"][..]),
                _ => ("resource", &[][..]),
            };
            let location = string_field(item, &["location", "region", "zone"]);
            if matches!(
                operation,
                Operation::GcpComputeInstances | Operation::GcpGkeClusters
            ) && !gcp_location_selected(scope, location.as_deref())
            {
                return None;
            }
            Some(observation(
                Provider::Gcp,
                &scope.expected.project_id,
                location,
                operation.service(),
                kind,
                item,
                fields,
                index,
                audit_id,
            ))
        })
        .collect()
}

fn aws_role_bindings(value: &Value) -> Vec<IamBinding> {
    let role = string_field(value, &["RoleName", "Arn"]).unwrap_or_else(|| "unknown".into());
    let Some(principal) = value.pointer("/AssumeRolePolicyDocument/Statement") else {
        return Vec::new();
    };
    let statements = principal
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![principal.clone()]);
    statements
        .iter()
        .flat_map(|statement| {
            let condition = statement.get("Condition").map(Value::to_string);
            let role = role.clone();
            collect_principals(statement.get("Principal").unwrap_or(&Value::Null))
                .into_iter()
                .map(move |principal| IamBinding {
                    role: role.clone(),
                    principal,
                    condition: condition.clone(),
                })
        })
        .collect()
}

fn collect_principals(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values.iter().flat_map(collect_principals).collect(),
        Value::Object(values) => values.values().flat_map(collect_principals).collect(),
        _ => Vec::new(),
    }
}

fn gcp_location_selected(scope: &GcpProjectScope, location: Option<&str>) -> bool {
    if scope.regions.is_empty() && scope.zones.is_empty() {
        return true;
    }
    let Some(location) = location else {
        return true;
    };
    scope.regions.iter().any(|region| {
        location == region
            || location
                .strip_prefix(region)
                .is_some_and(|tail| tail.starts_with('-'))
    }) || scope.zones.iter().any(|zone| location == zone)
}

fn array_field<'a>(value: &'a Value, field: &str) -> Vec<&'a Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| values.iter().collect())
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn observation(
    provider: Provider,
    scope_id: &str,
    location: Option<String>,
    service: &str,
    kind: &str,
    item: &Value,
    id_fields: &[&str],
    index: usize,
    audit_id: &str,
) -> Observation {
    let id = item
        .as_str()
        .map(ToString::to_string)
        .or_else(|| string_field(item, id_fields))
        .unwrap_or_else(|| format!("{kind}-{index}"));
    let name = string_field(item, &["name", "Name", "RoleName", "FunctionName"])
        .unwrap_or_else(|| id.clone());
    Observation {
        provider,
        scope_id: scope_id.into(),
        location,
        service: service.into(),
        resource_type: kind.into(),
        resource_id: id,
        name,
        configuration: item.clone(),
        iam: Vec::new(),
        source_audit_id: audit_id.into(),
    }
}

fn findings_from(observations: &[Observation]) -> Vec<NormalizedFindingInput> {
    observations
        .iter()
        .map(|observation| {
            let public = contains_public_access(&observation.configuration)
                || observation.iam.iter().any(|binding| {
                    binding.principal == "allUsers"
                        || binding.principal == "allAuthenticatedUsers"
                        || binding.principal == "*"
                });
            NormalizedFindingInput {
                provider: observation.provider,
                scope_id: observation.scope_id.clone(),
                title: if public {
                    format!("Public access signal on {}", observation.name)
                } else {
                    format!("Cloud configuration observed: {}", observation.name)
                },
                category: if public {
                    "cloud_public_access".into()
                } else {
                    "cloud_inventory".into()
                },
                severity: if public {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Info
                },
                asset_id: observation.resource_id.clone(),
                evidence_audit_ids: vec![observation.source_audit_id.clone()],
                attributes: json!({
                    "service": observation.service,
                    "resource_type": observation.resource_type,
                    "location": observation.location,
                }),
            }
        })
        .collect()
}

fn contains_public_access(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            matches!(value.as_str(), "allUsers" | "allAuthenticatedUsers" | "*")
        }
        Value::Array(values) => values.iter().any(contains_public_access),
        Value::Object(values) => values.iter().any(|(key, value)| {
            (key.to_ascii_lowercase().contains("public") && value == &Value::Bool(true))
                || contains_public_access(value)
        }),
        _ => false,
    }
}

fn redact_text<'a>(text: &str, secrets: impl Iterator<Item = &'a str>) -> String {
    secrets.fold(text.to_string(), |result, secret| {
        if secret.len() >= 3 {
            result.replace(secret, "[REDACTED]")
        } else {
            result
        }
    })
}

fn redact_json<'a>(value: &mut Value, secrets: impl Iterator<Item = &'a str>) {
    let secrets = secrets
        .filter(|secret| secret.len() >= 3)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    fn walk(value: &mut Value, secrets: &[String]) {
        match value {
            Value::String(text) => {
                for secret in secrets {
                    *text = text.replace(secret, "[REDACTED]");
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, secrets);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    walk(value, secrets);
                }
            }
            _ => {}
        }
    }
    walk(value, &secrets);
}

fn redact_argv(arguments: &[String]) -> Vec<String> {
    let sensitive = [
        "--password",
        "--client-secret",
        "--secret",
        "--token",
        "--access-key",
    ];
    let mut redact_next = false;
    arguments
        .iter()
        .map(|argument| {
            if redact_next {
                redact_next = false;
                return "[REDACTED]".into();
            }
            if sensitive.contains(&argument.as_str()) {
                redact_next = true;
                return argument.clone();
            }
            if sensitive
                .iter()
                .any(|flag| argument.starts_with(&format!("{flag}=")))
            {
                return format!(
                    "{}=[REDACTED]",
                    argument.split('=').next().unwrap_or("--secret")
                );
            }
            argument.clone()
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::SecretValue;
    use crate::process::{MockCall, MockRunner};

    fn credentials(provider: Provider, name: &str) -> CloudCredentials {
        let variable = match provider {
            Provider::Aws => "AWS_SECRET_ACCESS_KEY",
            Provider::Azure => "AZURE_CLIENT_SECRET",
            Provider::Gcp => "GOOGLE_APPLICATION_CREDENTIALS",
        };
        let context = CredentialContext::new(
            provider,
            [(variable, SecretValue::new("very-secret-value").unwrap())],
        )
        .unwrap();
        let mut result = CloudCredentials::default();
        result.insert(name, context).unwrap();
        result
    }

    #[test]
    fn identity_mismatch_stops_before_enumeration() {
        let runner = MockRunner::new([
            MockCall::json(Operation::AwsVersion, "aws-cli/2.0"),
            MockCall::json(
                Operation::AwsCallerIdentity,
                r#"{"Account":"999999999999","Arn":"arn:wrong"}"#,
            ),
        ]);
        let runtime = CloudRuntime::new(runner.clone(), RuntimeOptions::default()).unwrap();
        let scope = CloudScope::Aws {
            accounts: vec![AwsAccountScope {
                expected: AwsIdentity {
                    account_id: "111111111111".into(),
                    arn: None,
                    user_id: None,
                },
                credential_context: "aws-main".into(),
                profile: None,
                regions: vec!["us-east-1".into()],
            }],
        };
        let error = runtime
            .run(&scope, &credentials(Provider::Aws, "aws-main"))
            .unwrap_err();
        assert!(matches!(error, CloudError::IdentityMismatch { .. }));
        assert_eq!(runner.calls().len(), 2);
        assert_eq!(runner.remaining(), 0);
    }

    #[test]
    fn structured_outcome_preserves_partial_work_and_failed_command_audit() {
        let runner = MockRunner::new([
            MockCall::json(Operation::AwsVersion, "aws-cli/2.0"),
            MockCall::json(Operation::AwsCallerIdentity, r#"{"Account":"111"}"#),
            MockCall::json(
                Operation::AwsIamRoles,
                r#"{"Roles":[{"RoleName":"observed-before-failure"}]}"#,
            ),
            MockCall::json(Operation::AwsS3Buckets, r#"{"Buckets":[]}"#),
            MockCall::json(Operation::AwsVersion, "aws-cli/2.0"),
            MockCall::failure(
                Operation::AwsCallerIdentity,
                42,
                "credential expired after first account",
            ),
        ]);
        let runtime = CloudRuntime::new(runner, RuntimeOptions::default()).unwrap();
        let account = |id: &str| AwsAccountScope {
            expected: AwsIdentity {
                account_id: id.into(),
                arn: None,
                user_id: None,
            },
            credential_context: "aws-main".into(),
            profile: None,
            regions: Vec::new(),
        };
        let scope = CloudScope::Aws {
            accounts: vec![account("111"), account("222")],
        };
        let outcome = runtime.run_with_outcome(&scope, &credentials(Provider::Aws, "aws-main"));

        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.terminal_error,
            Some(CloudError::Process(_))
        ));
        assert_eq!(outcome.result.verified_identities.len(), 1);
        assert_eq!(outcome.result.observations.len(), 1);
        assert_eq!(outcome.result.finding_inputs.len(), 1);
        assert_eq!(outcome.result.audits.len(), 6);
        assert!(matches!(
            outcome.result.audits.last().map(|audit| &audit.status),
            Some(AuditStatus::Failed {
                exit_code: Some(42)
            })
        ));
    }

    #[test]
    fn mutation_requires_typed_expert_capability() {
        let runner = MockRunner::new([MockCall::json(Operation::AwsS3PutPublicAccessBlock, "{}")]);
        let runtime = CloudRuntime::new(runner.clone(), RuntimeOptions::default()).unwrap();
        let credentials = credentials(Provider::Aws, "aws-main");
        let context = credentials.get("aws-main", Provider::Aws).unwrap();
        let request = CommandRequest::new(
            Operation::AwsS3PutPublicAccessBlock,
            vec![
                "s3api".into(),
                "put-public-access-block".into(),
                "--bucket".into(),
                "example".into(),
            ],
        )
        .unwrap();
        let error = runtime
            .execute_command("111", "aws-main", context, &request, None)
            .unwrap_err();
        assert!(matches!(error, CloudError::MutationCapabilityRequired(_)));
        assert!(runner.calls().is_empty());
        let capability = ExpertMutationCapability::authorize(
            "operator@example.test",
            "approved remediation test",
            ExpertMutationCapability::ACKNOWLEDGEMENT,
        )
        .unwrap();
        let (_, audit) = runtime
            .execute_command("111", "aws-main", context, &request, Some(&capability))
            .unwrap();
        assert!(audit.mutation_authorization.unwrap().contains("operator"));
    }

    #[test]
    fn direct_argv_preserves_injection_text_as_one_argument() {
        let runner = MockRunner::new([MockCall::json(Operation::AwsIamRoles, r#"{"Roles":[]}"#)]);
        let runtime = CloudRuntime::new(runner.clone(), RuntimeOptions::default()).unwrap();
        let credentials = credentials(Provider::Aws, "aws-main");
        let request = CommandRequest::new(
            Operation::AwsIamRoles,
            vec!["iam".into(), "list-roles".into(), "; touch /tmp/pwn".into()],
        )
        .unwrap();
        runtime
            .execute_command(
                "111",
                "aws-main",
                credentials.get("aws-main", Provider::Aws).unwrap(),
                &request,
                None,
            )
            .unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].arguments[2], "; touch /tmp/pwn");
    }

    #[test]
    fn credentials_are_absent_from_debug_audits_and_errors() {
        let runner = MockRunner::new([MockCall::failure(
            Operation::AwsIamRoles,
            1,
            "provider echoed very-secret-value",
        )]);
        let runtime = CloudRuntime::new(runner, RuntimeOptions::default()).unwrap();
        let credentials = credentials(Provider::Aws, "aws-main");
        let request = CommandRequest::new(
            Operation::AwsIamRoles,
            vec!["iam".into(), "list-roles".into()],
        )
        .unwrap();
        let (output, audit) = runtime
            .execute_command(
                "111",
                "aws-main",
                credentials.get("aws-main", Provider::Aws).unwrap(),
                &request,
                None,
            )
            .unwrap();
        assert!(!output.stderr.contains("very-secret-value"));
        assert!(output.stderr.contains("[REDACTED]"));
        assert!(!format!("{audit:?}").contains("very-secret-value"));
        assert!(!format!("{credentials:?}").contains("very-secret-value"));
    }

    #[test]
    fn pagination_and_command_budget_are_enforced() {
        let runner = MockRunner::new([
            MockCall::json(Operation::AwsVersion, "aws-cli/2.0"),
            MockCall::json(Operation::AwsCallerIdentity, r#"{"Account":"111"}"#),
            MockCall::json(
                Operation::AwsIamRoles,
                r#"{"Roles":[{"RoleName":"one"}],"NextToken":"page-2"}"#,
            ),
            MockCall::json(Operation::AwsIamRoles, r#"{"Roles":[{"RoleName":"two"}]}"#),
        ]);
        let runtime = CloudRuntime::new(
            runner.clone(),
            RuntimeOptions {
                max_commands: 4,
                ..RuntimeOptions::default()
            },
        )
        .unwrap();
        let scope = CloudScope::Aws {
            accounts: vec![AwsAccountScope {
                expected: AwsIdentity {
                    account_id: "111".into(),
                    arn: None,
                    user_id: None,
                },
                credential_context: "aws-main".into(),
                profile: None,
                regions: Vec::new(),
            }],
        };
        let error = runtime
            .run(&scope, &credentials(Provider::Aws, "aws-main"))
            .unwrap_err();
        assert!(matches!(error, CloudError::BudgetExceeded { budget: 4 }));
        let calls = runner.calls();
        assert!(calls[3].arguments.contains(&"--starting-token".into()));
        assert!(calls[3].arguments.contains(&"page-2".into()));
    }
}
