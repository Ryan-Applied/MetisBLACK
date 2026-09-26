use metisblack_cloud_runtime::{
    AwsAccountScope, AwsIdentity, AzureIdentity, AzureSubscriptionScope, CloudCredentials,
    CloudRuntime, CloudScope, CredentialContext, FindingSeverity, GcpIdentity, GcpProjectScope,
    MockCall, MockRunner, Operation, Provider, RuntimeOptions, SecretValue,
};

fn credential(provider: Provider, name: &str) -> CloudCredentials {
    let (key, value) = match provider {
        Provider::Aws => ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE"),
        Provider::Azure => ("AZURE_CLIENT_ID", "azure-client"),
        Provider::Gcp => (
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/isolated/credential.json",
        ),
    };
    let context = CredentialContext::new(
        provider,
        [(key, SecretValue::new(value).expect("valid secret"))],
    )
    .expect("valid context");
    let mut credentials = CloudCredentials::default();
    credentials.insert(name, context).expect("valid name");
    credentials
}

#[test]
fn aws_end_to_end_yields_normalized_observations_and_findings() {
    let runner = MockRunner::new([
        MockCall::json(Operation::AwsVersion, "aws-cli/2.15"),
        MockCall::json(
            Operation::AwsCallerIdentity,
            r#"{"Account":"111111111111","Arn":"arn:aws:iam::111111111111:user/auditor","UserId":"AID1"}"#,
        ),
        MockCall::json(
            Operation::AwsIamRoles,
            r#"{"Roles":[{"RoleName":"AuditRole","RoleId":"R1"}]}"#,
        ),
        MockCall::json(
            Operation::AwsS3Buckets,
            r#"{"Buckets":[{"Name":"public-assets","public":true}]}"#,
        ),
        MockCall::json(
            Operation::AwsEc2Instances,
            r#"{"Reservations":[{"Instances":[{"InstanceId":"i-1"}]}]}"#,
        ),
        MockCall::json(
            Operation::AwsLambdaFunctions,
            r#"{"Functions":[{"FunctionName":"worker","FunctionArn":"arn:lambda:1"}]}"#,
        ),
        MockCall::json(Operation::AwsEksClusters, r#"{"clusters":["prod"]}"#),
        MockCall::json(
            Operation::AwsRdsInstances,
            r#"{"DBInstances":[{"DBInstanceIdentifier":"db-1"}]}"#,
        ),
    ]);
    let runtime = CloudRuntime::new(runner.clone(), RuntimeOptions::default()).unwrap();
    let scope = CloudScope::Aws {
        accounts: vec![AwsAccountScope {
            expected: AwsIdentity {
                account_id: "111111111111".into(),
                arn: Some("arn:aws:iam::111111111111:user/auditor".into()),
                user_id: Some("AID1".into()),
            },
            credential_context: "aws-prod".into(),
            profile: Some("audit".into()),
            regions: vec!["us-east-1".into()],
        }],
    };
    let result = runtime
        .run(&scope, &credential(Provider::Aws, "aws-prod"))
        .unwrap();
    assert_eq!(result.verified_identities.len(), 1);
    assert_eq!(result.observations.len(), 6);
    assert!(result
        .finding_inputs
        .iter()
        .any(|finding| finding.severity == FindingSeverity::High));
    assert_eq!(result.audits.len(), 8);
    assert!(result.unsupported.is_empty());
    assert_eq!(runner.remaining(), 0);
}

#[test]
fn azure_end_to_end_yields_normalized_observations_and_findings() {
    let runner = MockRunner::new([
        MockCall::json(Operation::AzureVersion, r#"{"azure-cli":"2.60"}"#),
        MockCall::json(
            Operation::AzureAccountShow,
            r#"{"tenantId":"tenant-1","id":"sub-1","user":{"name":"auditor@example.test"}}"#,
        ),
        MockCall::json(
            Operation::AzureRoleAssignments,
            r#"[{"id":"role-1","principalId":"principal-1"}]"#,
        ),
        MockCall::json(
            Operation::AzureStorageAccounts,
            r#"[{"id":"storage-1","name":"assets","location":"eastus","public":true}]"#,
        ),
        MockCall::json(
            Operation::AzureVirtualMachines,
            r#"[{"id":"vm-1","name":"api","location":"eastus"}]"#,
        ),
        MockCall::json(
            Operation::AzureAksClusters,
            r#"[{"id":"aks-1","name":"prod","location":"eastus"}]"#,
        ),
        MockCall::json(
            Operation::AzureKeyVaults,
            r#"[{"id":"vault-1","name":"secrets","location":"eastus"}]"#,
        ),
    ]);
    let runtime = CloudRuntime::new(runner, RuntimeOptions::default()).unwrap();
    let scope = CloudScope::Azure {
        subscriptions: vec![AzureSubscriptionScope {
            expected: AzureIdentity {
                tenant_id: "tenant-1".into(),
                subscription_id: "sub-1".into(),
                principal: Some("auditor@example.test".into()),
            },
            credential_context: "azure-prod".into(),
            locations: vec!["eastus".into()],
        }],
    };
    let result = runtime
        .run(&scope, &credential(Provider::Azure, "azure-prod"))
        .unwrap();
    assert_eq!(result.observations.len(), 5);
    assert!(result
        .finding_inputs
        .iter()
        .all(|finding| finding.provider == Provider::Azure));
    assert!(result
        .finding_inputs
        .iter()
        .any(|finding| finding.category == "cloud_public_access"));
}

#[test]
fn gcp_end_to_end_yields_normalized_iam_and_resource_findings() {
    let runner = MockRunner::new([
        MockCall::json(Operation::GcpVersion, "Google Cloud SDK 480"),
        MockCall::json(
            Operation::GcpActiveAccount,
            r#"[{"account":"auditor@example.test","status":"ACTIVE"}]"#,
        ),
        MockCall::json(
            Operation::GcpProjectDescribe,
            r#"{"projectId":"project-one"}"#,
        ),
        MockCall::json(
            Operation::GcpIamPolicy,
            r#"{"bindings":[{"role":"roles/viewer","members":["allUsers"]}]}"#,
        ),
        MockCall::json(
            Operation::GcpStorageBuckets,
            r#"[{"id":"bucket-1","name":"assets","location":"US"}]"#,
        ),
        MockCall::json(
            Operation::GcpComputeInstances,
            r#"[{"id":"vm-1","name":"api","zone":"us-central1-a"}]"#,
        ),
        MockCall::json(
            Operation::GcpGkeClusters,
            r#"[{"id":"gke-1","name":"prod","location":"us-central1"}]"#,
        ),
        MockCall::json(
            Operation::GcpSecrets,
            r#"[{"name":"projects/project-one/secrets/db"}]"#,
        ),
    ]);
    let runtime = CloudRuntime::new(runner, RuntimeOptions::default()).unwrap();
    let scope = CloudScope::Gcp {
        projects: vec![GcpProjectScope {
            expected: GcpIdentity {
                project_id: "project-one".into(),
                principal: "auditor@example.test".into(),
            },
            credential_context: "gcp-prod".into(),
            regions: vec!["us-central1".into()],
            zones: vec!["us-central1-a".into()],
        }],
    };
    let result = runtime
        .run(&scope, &credential(Provider::Gcp, "gcp-prod"))
        .unwrap();
    assert_eq!(result.observations.len(), 5);
    let iam = result
        .observations
        .iter()
        .find(|observation| observation.resource_type == "project_iam_policy")
        .unwrap();
    assert_eq!(iam.iam[0].principal, "allUsers");
    assert!(result
        .finding_inputs
        .iter()
        .any(|finding| finding.severity == FindingSeverity::High));
}

#[test]
fn unsupported_optional_service_is_reported_without_aborting_workflow() {
    let runner = MockRunner::new([
        MockCall::json(Operation::AwsVersion, "aws-cli/2.15"),
        MockCall::json(Operation::AwsCallerIdentity, r#"{"Account":"111"}"#),
        MockCall::json(Operation::AwsIamRoles, r#"{"Roles":[]}"#),
        MockCall::failure(Operation::AwsS3Buckets, 254, "service is not available"),
    ]);
    let runtime = CloudRuntime::new(runner, RuntimeOptions::default()).unwrap();
    let scope = CloudScope::Aws {
        accounts: vec![AwsAccountScope {
            expected: AwsIdentity {
                account_id: "111".into(),
                arn: None,
                user_id: None,
            },
            credential_context: "aws-test".into(),
            profile: None,
            regions: Vec::new(),
        }],
    };
    let result = runtime
        .run(&scope, &credential(Provider::Aws, "aws-test"))
        .unwrap();
    assert_eq!(result.unsupported.len(), 1);
    assert_eq!(result.unsupported[0].service, "s3");
}
