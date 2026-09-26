use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, CloudError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudError {
    InvalidScope(String),
    InvalidCredential(String),
    MissingCredentials(String),
    ExecutableNotFound(String),
    CapabilityCheck(String),
    IdentityMismatch { expected: String, actual: String },
    CommandDenied(String),
    MutationCapabilityRequired(String),
    BudgetExceeded { budget: usize },
    Timeout { operation: String },
    Process(String),
    Parse { operation: String, message: String },
}

impl Display for CloudError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScope(value) => write!(f, "invalid cloud scope: {value}"),
            Self::InvalidCredential(value) => write!(f, "invalid cloud credential: {value}"),
            Self::MissingCredentials(value) => write!(f, "missing credentials: {value}"),
            Self::ExecutableNotFound(value) => write!(f, "cloud executable not found: {value}"),
            Self::CapabilityCheck(value) => write!(f, "cloud CLI capability check failed: {value}"),
            Self::IdentityMismatch { expected, actual } => {
                write!(
                    f,
                    "caller identity mismatch: expected {expected}, got {actual}"
                )
            }
            Self::CommandDenied(value) => write!(f, "cloud command denied: {value}"),
            Self::MutationCapabilityRequired(value) => {
                write!(f, "expert mutation capability required: {value}")
            }
            Self::BudgetExceeded { budget } => {
                write!(f, "cloud command budget exceeded ({budget})")
            }
            Self::Timeout { operation } => write!(f, "cloud command timed out: {operation}"),
            Self::Process(value) => write!(f, "cloud process failed: {value}"),
            Self::Parse { operation, message } => {
                write!(f, "cannot parse {operation} output: {message}")
            }
        }
    }
}

impl std::error::Error for CloudError {}
