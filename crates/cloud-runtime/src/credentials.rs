use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use zeroize::Zeroize;

use crate::error::{CloudError, Result};
use crate::types::Provider;

/// A secret environment value. Its debug representation is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(CloudError::InvalidCredential(
                "secret values must be non-empty and NUL-free".into(),
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Credentials for one named provider context (for example, an AWS account).
///
/// Only documented provider credential variables are accepted. This prevents
/// credentials from smuggling process-control variables such as `LD_PRELOAD`.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialContext {
    provider: Provider,
    values: BTreeMap<String, SecretValue>,
}

impl CredentialContext {
    pub fn new<I, K>(provider: Provider, values: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, SecretValue)>,
        K: Into<String>,
    {
        let mut checked = BTreeMap::new();
        for (key, value) in values {
            let key = key.into();
            if !allowed_variable(provider, &key) {
                return Err(CloudError::InvalidCredential(format!(
                    "{key} is not an allowed {provider:?} credential variable"
                )));
            }
            checked.insert(key, value);
        }
        Ok(Self {
            provider,
            values: checked,
        })
    }

    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub fn environment_names(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }

    pub(crate) fn environment(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_str(), value.expose()))
    }

    pub(crate) fn secret_literals(&self) -> impl Iterator<Item = &str> {
        self.values.values().map(SecretValue::expose)
    }
}

impl Debug for CredentialContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialContext")
            .field("provider", &self.provider)
            .field("environment_names", &self.environment_names())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CloudCredentials {
    contexts: BTreeMap<String, CredentialContext>,
}

impl CloudCredentials {
    pub fn insert(&mut self, name: impl Into<String>, context: CredentialContext) -> Result<()> {
        let name = name.into();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(CloudError::InvalidCredential(
                "credential context name contains unsafe characters".into(),
            ));
        }
        self.contexts.insert(name, context);
        Ok(())
    }

    pub fn get(&self, name: &str, provider: Provider) -> Result<&CredentialContext> {
        let context = self
            .contexts
            .get(name)
            .ok_or_else(|| CloudError::MissingCredentials(name.into()))?;
        if context.provider != provider {
            return Err(CloudError::MissingCredentials(format!(
                "context {name} belongs to {:?}, not {provider:?}",
                context.provider
            )));
        }
        Ok(context)
    }
}

fn allowed_variable(provider: Provider, key: &str) -> bool {
    let common = ["CLOUDSDK_CONFIG", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"];
    let allowed: &[&str] = match provider {
        Provider::Aws => &[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_ROLE_ARN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_DEFAULT_REGION",
            "AWS_REGION",
        ],
        Provider::Azure => &[
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_FEDERATED_TOKEN_FILE",
            "AZURE_CONFIG_DIR",
        ],
        Provider::Gcp => &[
            "GOOGLE_APPLICATION_CREDENTIALS",
            "CLOUDSDK_CONFIG",
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
            "CLOUDSDK_CORE_PROJECT",
            "CLOUDSDK_CORE_ACCOUNT",
            "GOOGLE_CLOUD_PROJECT",
        ],
    };
    allowed.contains(&key) || (provider == Provider::Gcp && common.contains(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted_and_process_control_is_rejected() {
        let secret = SecretValue::new("super-secret").unwrap();
        assert!(!format!("{secret:?}").contains("super-secret"));
        let error = CredentialContext::new(Provider::Aws, [("LD_PRELOAD", secret)]).unwrap_err();
        assert!(matches!(error, CloudError::InvalidCredential(_)));
    }
}
