//! Protected atomic snapshots, redaction, and an authenticated encrypted vault.
use anyhow::{anyhow, bail, ensure, Context, Result};
use domain::{now_ms, SecretRef};
use regex::Regex;
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use zeroize::Zeroizing;

pub fn hash(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn random_id(prefix: &str) -> Result<String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("secure randomness unavailable"))?;
    Ok(format!(
        "{prefix}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
pub fn safe_component(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 160
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && s != "."
            && s != "..",
        "invalid storage identifier"
    );
    Ok(())
}

pub fn secure_dir(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "storage directory cannot be a symlink"
        );
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private(path: &Path) -> Result<std::fs::File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("file requires parent directory")?;
    secure_dir(parent)?;
    ensure!(
        !fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false),
        "cannot replace a symlink"
    );
    let tmp = parent.join(random_id(".write")?);
    let result = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(value)?)
}
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "refusing symlinked state"
    );
    // Size policy belongs to the producing/ingesting subsystem. A second fixed
    // cap here would make legitimately sampled/overridden runs impossible to
    // resume or verify after they had already been written successfully.
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Values are redacted recursively as well as by recognizable text patterns.
#[derive(Clone, Default)]
pub struct Redactor {
    known: Vec<String>,
    disabled: bool,
}
impl Redactor {
    pub fn with_override(overrides: &domain::ExpertOverrides) -> Self {
        Self {
            known: vec![],
            disabled: overrides.disables(domain::Control::SecretRedaction),
        }
    }
    pub fn register(&mut self, value: &str) {
        if !value.is_empty() {
            self.known.push(value.to_owned());
            self.known.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }
    pub fn text(&self, input: &str) -> String {
        if self.disabled {
            return input.to_owned();
        }
        static RULES: OnceLock<Vec<Regex>> = OnceLock::new();
        let rules=RULES.get_or_init(||[
            r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            r#"(?i)(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+"#,
            r#"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[\"']?\s*[:=]\s*[\"']?[^\s\"',;}]+"#,
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{16,}\b",
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            r"(?i)(?:https?://)[^\s/@:]+:[^\s/@]+@",
        ].iter().map(|r|Regex::new(r).expect("static redaction regex")).collect());
        let mut s = input.to_owned();
        for value in &self.known {
            s = s.replace(value, "[REDACTED]");
        }
        for rule in rules {
            s = rule.replace_all(&s, "[REDACTED]").into_owned();
        }
        s
    }
    pub fn value(&self, value: &mut serde_json::Value) {
        if self.disabled {
            return;
        }
        match value {
            serde_json::Value::String(s) => *s = self.text(s),
            serde_json::Value::Array(a) => {
                for v in a {
                    self.value(v);
                }
            }
            serde_json::Value::Object(o) => {
                for (k, v) in o {
                    let lower = k.to_lowercase();
                    if [
                        "authorization",
                        "cookie",
                        "set-cookie",
                        "password",
                        "secret",
                        "api_key",
                        "access_token",
                        "refresh_token",
                        "private_key",
                        "client_secret",
                    ]
                    .contains(&lower.as_str())
                    {
                        *v = serde_json::Value::String("[REDACTED]".into());
                    } else {
                        self.value(v);
                    }
                }
            }
            _ => {}
        }
    }
    pub fn sanitize<T: Serialize + DeserializeOwned>(&self, value: &T) -> Result<T> {
        let mut v = serde_json::to_value(value)?;
        self.value(&mut v);
        Ok(serde_json::from_value(v)?)
    }
}

pub struct Vault {
    root: PathBuf,
    key: aead::LessSafeKey,
}
impl Vault {
    pub fn open(root: &Path) -> Result<Self> {
        secure_dir(root)?;
        let key_path = root.join("vault.key");
        if !key_path.exists() {
            let mut bytes = Zeroizing::new(vec![0u8; 32]);
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| anyhow!("randomness unavailable"))?;
            let mut f = create_private(&key_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        ensure!(
            !fs::symlink_metadata(&key_path)?.file_type().is_symlink(),
            "vault key cannot be symlinked"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(&key_path)?.permissions().mode() & 0o077 == 0,
                "vault key permissions are too broad"
            );
        }
        let key_bytes = Zeroizing::new(fs::read(&key_path)?);
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| anyhow!("invalid vault key"))?;
        Ok(Self {
            root: root.to_owned(),
            key: aead::LessSafeKey::new(key),
        })
    }
    pub fn put(&self, value: &str) -> Result<SecretRef> {
        let id = random_id("secret")?;
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow!("randomness unavailable"))?;
        let mut encrypted = value.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(id.as_bytes()),
                &mut encrypted,
            )
            .map_err(|_| anyhow!("vault encryption failed"))?;
        let mut bytes = nonce.to_vec();
        bytes.extend(encrypted);
        atomic_write(&self.root.join(format!("{id}.vault")), &bytes)?;
        Ok(SecretRef(id))
    }
    pub fn resolve(&self, reference: &SecretRef) -> Result<Zeroizing<String>> {
        safe_component(&reference.0)?;
        let p = self.root.join(format!("{}.vault", reference.0));
        ensure!(
            !fs::symlink_metadata(&p)?.file_type().is_symlink(),
            "vault entry cannot be symlinked"
        );
        let mut bytes = Zeroizing::new(fs::read(p)?);
        ensure!(bytes.len() >= 28, "invalid encrypted entry");
        let nonce: [u8; 12] = bytes[..12].try_into()?;
        let raw = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(reference.0.as_bytes()),
                &mut bytes[12..],
            )
            .map_err(|_| anyhow!("vault authentication failed"))?;
        Ok(Zeroizing::new(std::str::from_utf8(raw)?.to_owned()))
    }
    pub fn forget(&self, reference: &SecretRef) -> Result<()> {
        safe_component(&reference.0)?;
        fs::remove_file(self.root.join(format!("{}.vault", reference.0)))?;
        Ok(())
    }
}

/// Exclusive process lock; stale locks require explicit recovery after checking PID.
pub struct RunLock {
    path: PathBuf,
}
impl RunLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        secure_dir(root)?;
        let path = root.join("run.lock");
        match create_private(&path) {
            Ok(mut f) => {
                write!(f, "{} {}", std::process::id(), now_ms())?;
                Ok(Self { path })
            }
            Err(_) => bail!(
                "run is locked; verify no writer is active before removing {}",
                path.display()
            ),
        }
    }
}
impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_vault_and_permissions() -> Result<()> {
        let d = tempfile::tempdir()?;
        let v = Vault::open(&d.path().join("vault"))?;
        let r = v.put("sensitive-test-material")?;
        assert_eq!(v.resolve(&r)?.as_str(), "sensitive-test-material");
        let raw = fs::read(d.path().join(format!("vault/{}.vault", r.0)))?;
        assert!(!String::from_utf8_lossy(&raw).contains("sensitive-test-material"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(d.path().join("vault/vault.key"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }
    #[test]
    fn redacts_nested_secrets() {
        let mut r = Redactor::default();
        r.register("unique-sensitive-value");
        let mut v = serde_json::json!({"nested":{"password":"abc"},"message":"Authorization: Bearer xyz\nunique-sensitive-value"});
        r.value(&mut v);
        assert!(!v.to_string().contains("xyz"));
        assert!(!v.to_string().contains("abc"));
        assert!(!v.to_string().contains("unique-sensitive-value"));
    }
    #[test]
    fn hash_known_vector() {
        assert_eq!(
            hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn rejects_path_traversal() {
        assert!(safe_component("../../vault.key").is_err());
    }
}
