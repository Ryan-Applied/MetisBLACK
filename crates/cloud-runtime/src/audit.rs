use serde::{Deserialize, Serialize};

use crate::catalogue::CommandClass;
use crate::types::Provider;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Succeeded,
    Failed { exit_code: Option<i32> },
    TimedOut,
    Denied,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandAudit {
    pub audit_id: String,
    pub provider: Provider,
    pub scope_id: String,
    pub credential_context: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub environment_names: Vec<String>,
    pub service: String,
    pub operation: String,
    pub class: CommandClass,
    pub started_unix_ms: u128,
    pub duration_ms: u128,
    pub status: AuditStatus,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub mutation_authorization: Option<String>,
}

/// Stable input intended for sealing by `metisblack-evidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandReceiptInput {
    pub audit: CommandAudit,
    pub canonical_json: String,
}

impl CommandAudit {
    pub fn receipt_input(&self) -> std::result::Result<CommandReceiptInput, serde_json::Error> {
        let canonical_json = serde_json::to_string(self)?;
        Ok(CommandReceiptInput {
            audit: self.clone(),
            canonical_json,
        })
    }
}
