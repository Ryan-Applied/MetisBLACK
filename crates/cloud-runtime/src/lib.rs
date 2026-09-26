//! Policy-enforced cloud CLI workflows for MetisBLACK.
//!
//! The crate deliberately treats provider CLIs as an untrusted process boundary:
//! commands are represented as argv, matched against a typed catalogue, executed
//! without a shell, and emitted with audit metadata that can be sealed by the
//! evidence crate. Credentials are passed through an isolated child environment
//! and are never included in receipts or `Debug` output.

#![forbid(unsafe_code)]

mod audit;
mod catalogue;
mod credentials;
mod error;
mod process;
mod runtime;
mod types;

pub use audit::{AuditStatus, CommandAudit, CommandReceiptInput};
pub use catalogue::{CommandClass, CommandRequest, MutationKind, Operation};
pub use credentials::{CloudCredentials, CredentialContext, SecretValue};
pub use error::{CloudError, Result};
pub use process::{
    CancellationToken, CommandRunner, CommandSpec, ExecutableProbe, MockCall, MockRunner,
    ObservedCall, ProcessOutput, SystemRunner,
};
pub use runtime::{CloudRuntime, ExpertMutationCapability, RuntimeOptions, WorkflowOutcome};
pub use types::{
    AwsAccountScope, AwsIdentity, AzureIdentity, AzureSubscriptionScope, CloudIdentity, CloudScope,
    FindingSeverity, GcpIdentity, GcpProjectScope, IamBinding, NormalizedFindingInput, Observation,
    Provider, UnsupportedCapability, WorkflowResult,
};
