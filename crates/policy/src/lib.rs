//! Scope is evaluated on every operation, redirect and resolved address.
use anyhow::{bail, ensure, Context, Result};
use domain::{Control, ExpertOverrides, NetworkRule, Scope, ToolAction};
use ipnet::IpNet;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    ReadOnly,
    StateChanging,
    Destructive,
    PrivilegeChanging,
    PackageInstallation,
    CredentialOperation,
    ExternalCodeDownload,
    DenialOfService,
    Unknown,
}
pub fn classify_command(program: &str, args: &[String]) -> CommandClass {
    let base = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    match base {
        "rm" | "mkfs" | "dd" | "format" | "shred" => CommandClass::Destructive,
        "sudo" | "su" | "chmod" | "chown" => CommandClass::PrivilegeChanging,
        "apt" | "apt-get" | "brew" | "pip" | "pip3" | "npm" | "cargo" => {
            CommandClass::PackageInstallation
        }
        "passwd" | "chpasswd" | "security" => CommandClass::CredentialOperation,
        "curl" | "wget" => CommandClass::ExternalCodeDownload,
        "hping3" | "ab" | "wrk" | "stress" => CommandClass::DenialOfService,
        "touch" | "mkdir" | "mv" | "cp" | "tee" => CommandClass::StateChanging,
        "git"
            if args
                .first()
                .is_some_and(|a| ["rev-parse", "merge-base", "ls-tree"].contains(&a.as_str()))
                && !args.iter().any(|a| {
                    a.starts_with("--output")
                        || a.starts_with("--ext-diff")
                        || a.starts_with("--textconv")
                        || a == "-c"
                        || a.starts_with("--exec-path")
                        || a.starts_with("--config-env")
                }) =>
        {
            CommandClass::ReadOnly
        }
        "true" | "false" => CommandClass::ReadOnly,
        _ => CommandClass::Unknown,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub requests: u64,
    pub state_changes: u64,
    pub accounts: u64,
}
#[derive(Clone)]
pub struct Policy {
    scope: Scope,
    cidrs: Vec<IpNet>,
    usage: Arc<Mutex<Usage>>,
    overrides: ExpertOverrides,
}
impl Policy {
    pub fn new(scope: Scope) -> Result<Self> {
        Self::with_overrides(scope, ExpertOverrides::default())
    }
    pub fn with_overrides(mut scope: Scope, overrides: ExpertOverrides) -> Result<Self> {
        overrides.validate()?;
        ensure!(
            overrides.disables(Control::RateLimit) || scope.requests_per_second > 0,
            "request rate must be positive"
        );
        for rule in &mut scope.network {
            ensure!(
                !rule.host.contains(['/', ':', '@']) || rule.host.parse::<IpAddr>().is_ok(),
                "invalid scope host"
            );
            rule.host = normalize_host(&rule.host)?;
            ensure!(!rule.ports.is_empty(), "allowed ports required");
            ensure!(
                rule.paths.iter().all(|p| p.starts_with('/')
                    && !p.contains(['?', '#', '%'])
                    && !p.split('/').any(|x| x == "..")),
                "invalid scope path"
            );
        }
        scope.excluded_hosts = scope
            .excluded_hosts
            .iter()
            .map(|h| normalize_host(h))
            .collect::<Result<_>>()?;
        for root in &mut scope.roots {
            *root = root.canonicalize().context("scope root does not exist")?;
        }
        let cidrs = scope
            .cidrs
            .iter()
            .map(|c| c.parse().context("invalid CIDR"))
            .collect::<Result<_>>()?;
        Ok(Self {
            scope,
            cidrs,
            usage: Arc::new(Mutex::new(Usage::default())),
            overrides,
        })
    }
    pub fn overrides(&self) -> &ExpertOverrides {
        &self.overrides
    }
    pub fn bypasses(&self, control: Control) -> bool {
        self.overrides.disables(control)
    }
    /// Redirect override grants destination/path permission only for a redirect
    /// hop. The original URL must still pass the ordinary scope checks.
    pub fn redirect_policy(&self) -> Self {
        let mut next = self.clone();
        if self.bypasses(Control::Redirects) {
            next.overrides
                .controls
                .extend([Control::Scope, Control::Network]);
        }
        next
    }
    fn gate(&self, condition: bool, control: Control, message: &str) -> Result<()> {
        ensure!(condition || self.bypasses(control), "{message}");
        Ok(())
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn usage(&self) -> Usage {
        *self.usage.lock().expect("usage mutex")
    }
    pub fn reserve(&self, state_change: bool, account: bool) -> Result<()> {
        let mut u = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("budget lock failed"))?;
        self.gate(
            u.requests < self.scope.max_requests,
            Control::RequestBudget,
            "request budget exhausted",
        )?;
        if state_change || account {
            self.gate(
                u.state_changes < self.scope.max_state_changes,
                Control::StateChanges,
                "state-change budget exhausted",
            )?;
        }
        if account {
            self.gate(
                u.accounts < self.scope.max_accounts,
                Control::AccountBudget,
                "account budget exhausted",
            )?;
        }
        u.requests += 1;
        if state_change || account {
            u.state_changes += 1;
        }
        if account {
            u.accounts += 1;
        }
        Ok(())
    }
    pub fn restore_usage(&self, requests: u64) -> Result<()> {
        self.restore_budgets(requests, 0, 0)
    }
    pub fn restore_budgets(&self, requests: u64, state_changes: u64, accounts: u64) -> Result<()> {
        let mut u = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("budget lock failed"))?;
        u.requests = u.requests.max(requests);
        u.state_changes = u.state_changes.max(state_changes);
        u.accounts = u.accounts.max(accounts);
        Ok(())
    }
    pub fn check_action(&self, action: &ToolAction) -> Result<()> {
        match action {
            ToolAction::HttpGet { url }
            | ToolAction::CreateAccount { url, .. }
            | ToolAction::AiPrompt { url, .. } => {
                self.check_url(url)?;
            }
            ToolAction::HttpRequest { url, method, .. } => {
                self.check_url(url)?;
                if !["GET", "HEAD", "OPTIONS"].contains(&method.to_ascii_uppercase().as_str()) {
                    self.gate(false,Control::StateChanges,"generic mutating HTTP requires state_changes override; use typed account or AI operations otherwise")?;
                    self.gate(false,Control::AccountBudget,"generic mutating HTTP can create accounts and requires account_budget override")?;
                }
            }
            ToolAction::SourceRead {
                path,
                start_line,
                end_line,
            } => {
                ensure!(
                    *start_line > 0
                        && end_line >= start_line
                        && (self.bypasses(Control::DataSampling) || end_line - start_line < 2000),
                    "invalid source line range"
                );
                self.check_path(path)?;
            }
            ToolAction::DnsResolve { host } => {
                self.check_host(host, None)?;
            }
            ToolAction::TcpConnect { host, port } => {
                self.check_host(host, Some(*port))?;
            }
            ToolAction::Shell {
                program,
                args,
                working_dir,
            } => {
                self.gate(
                    false,
                    Control::ToolCapabilities,
                    "shell tool requires tool_capabilities override",
                )?;
                self.gate(
                    false,
                    Control::Sandbox,
                    "shell tool requires sandbox override",
                )?;
                self.gate(
                    false,
                    Control::Network,
                    "unsandboxed shell requires network override",
                )?;
                self.gate(
                    false,
                    Control::FilesystemRoots,
                    "unsandboxed shell requires filesystem_roots override",
                )?;
                self.check_path(working_dir)?;
                if !self.bypasses(Control::CommandRisk) {
                    let control = match classify_command(program, args) {
                        CommandClass::Destructive => Control::DestructiveActions,
                        CommandClass::PrivilegeChanging => Control::PrivilegeChanges,
                        CommandClass::PackageInstallation => Control::PackageInstallation,
                        CommandClass::ExternalCodeDownload => Control::ExternalDownloads,
                        CommandClass::CredentialOperation => Control::SecretExposure,
                        CommandClass::StateChanging => Control::StateChanges,
                        CommandClass::ReadOnly => return Ok(()),
                        _ => Control::CommandRisk,
                    };
                    self.gate(false, control, "command class requires explicit override")?;
                }
            }
            ToolAction::External {
                subsystem, target, ..
            } => match subsystem.as_str() {
                "browser" => {
                    self.check_url(target)?;
                }
                "cloud" => self.gate(
                    self.scope
                        .cloud_accounts
                        .iter()
                        .any(|account| account == target),
                    Control::CloudIdentity,
                    "cloud account is outside the declared scope",
                )?,
                _ => self.gate(
                    false,
                    Control::ToolCapabilities,
                    "external subsystem requires tool_capabilities override",
                )?,
            },
        }
        Ok(())
    }
    pub fn check_url(&self, raw: &str) -> Result<Url> {
        let u = Url::parse(raw).context("invalid target URL")?;
        ensure!(
            ["http", "https"].contains(&u.scheme()),
            "only HTTP(S) URLs supported"
        );
        self.gate(
            u.username().is_empty() && u.password().is_none(),
            Control::SecretExposure,
            "URL credentials prohibited",
        )?;
        ensure!(
            u.fragment().is_none(),
            "URL fragment is not a network target"
        );
        let host = u
            .host_str()
            .context("URL host required")?
            .trim_matches(['[', ']']);
        let port = u.port_or_known_default().context("URL port required")?;
        self.check_host(host, Some(port))?;
        let path = decode_path(u.path())?;
        if !self.bypasses(Control::Scope) {
            self.gate(
                !self
                    .scope
                    .excluded_paths
                    .iter()
                    .any(|p| path_within(&path, p)),
                Control::Paths,
                "URL path excluded",
            )?;
        }
        let destination_override =
            self.bypasses(Control::Destinations) || self.bypasses(Control::ThirdParty);
        let permitted = self.scope.network.iter().any(|r| {
            (host_matches(host, r)
                || (self.bypasses(Control::Subdomains) && host.ends_with(&format!(".{}", r.host)))
                || destination_override)
                && (r.ports.contains(&port) || self.bypasses(Control::Ports))
                && r.paths.iter().any(|p| path_within(&path, p))
        }) || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| self.cidrs.iter().any(|n| n.contains(&ip)))
            && (self.scope.cidr_ports.contains(&port) || self.bypasses(Control::Ports));
        if !self.bypasses(Control::Scope) && !self.bypasses(Control::Network) {
            self.gate(
                permitted,
                Control::Paths,
                "URL path not in an explicit network rule",
            )?;
        }
        if let Some(q) = u.query() {
            self.gate(
                !q.to_ascii_lowercase().split('&').any(|p| {
                    ["token=", "password=", "secret=", "api_key="]
                        .iter()
                        .any(|k| p.starts_with(k))
                }),
                Control::SecretExposure,
                "secrets in URL query prohibited",
            )?;
        }
        Ok(u)
    }
    pub fn check_host(&self, host: &str, port: Option<u16>) -> Result<()> {
        let h = normalize_host(host)?;
        if self.bypasses(Control::Scope) || self.bypasses(Control::Network) {
            return Ok(());
        }
        ensure!(
            self.bypasses(Control::Destinations)
                || self.bypasses(Control::ThirdParty)
                || !self
                    .scope
                    .excluded_hosts
                    .iter()
                    .any(|e| h == *e || h.ends_with(&format!(".{e}"))),
            "host explicitly excluded"
        );
        let matched = self.scope.network.iter().any(|r| {
            (host_matches(&h, r)
                || (self.bypasses(Control::Subdomains) && h.ends_with(&format!(".{}", r.host)))
                || self.bypasses(Control::Destinations)
                || self.bypasses(Control::ThirdParty))
                && (self.bypasses(Control::Ports) || port.is_none_or(|p| r.ports.contains(&p)))
        });
        let ip = h.parse::<IpAddr>().ok();
        let in_cidr = ip.is_some_and(|i| self.cidrs.iter().any(|n| n.contains(&i)));
        ensure!(
            matched
                || (in_cidr
                    && (port.is_none_or(|p| self.scope.cidr_ports.contains(&p))
                        || self.bypasses(Control::Ports))),
            "host/port outside scope"
        );
        if let Some(ip) = ip {
            self.check_ip(&h, ip)?;
        }
        Ok(())
    }
    pub fn check_ip(&self, host: &str, ip: IpAddr) -> Result<()> {
        if self.bypasses(Control::Scope)
            || self.bypasses(Control::Network)
            || self.bypasses(Control::Cidrs)
        {
            return Ok(());
        }
        let explicit_ip = self
            .scope
            .network
            .iter()
            .any(|r| r.host.parse::<IpAddr>().ok() == Some(ip));
        let cidr = self.cidrs.iter().any(|n| n.contains(&ip));
        ensure!(
            !self
                .scope
                .excluded_hosts
                .iter()
                .any(|h| h.parse::<IpAddr>().ok() == Some(ip)),
            "resolved IP excluded"
        );
        if !self.cidrs.is_empty() {
            ensure!(cidr || explicit_ip, "DNS address outside allowed CIDRs");
        }
        if !is_public(ip) {
            ensure!(
                self.scope.allow_private
                    && (explicit_ip || cidr || normalize_host(host)? == "localhost"),
                "private/link-local address not authorized"
            );
        }
        Ok(())
    }
    pub fn check_path(&self, path: &Path) -> Result<PathBuf> {
        if !self.bypasses(Control::FilesystemRoots) && !self.bypasses(Control::Scope) {
            ensure!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "parent traversal prohibited"
            );
            ensure!(
                !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
                "source symlinks prohibited"
            );
        }
        let p = path.canonicalize().context("source path unavailable")?;
        if !self.bypasses(Control::Scope) {
            self.gate(
                self.scope.roots.iter().any(|r| p == *r || p.starts_with(r)),
                Control::FilesystemRoots,
                "source path outside scope",
            )?;
        }
        self.gate(
            !is_secret_path(&p),
            Control::SecretExposure,
            "secret/state file excluded",
        )?;
        Ok(p)
    }
}
pub fn is_secret_path(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy().to_lowercase();
        [
            ".git",
            ".ssh",
            ".aws",
            ".azure",
            ".gnupg",
            ".metisblack",
            ".env",
            "vault.key",
        ]
        .contains(&s.as_str())
            || s.ends_with(".pem")
            || s.ends_with(".key")
            || s.ends_with(".vault")
            || (s.starts_with(".env.") && !s.ends_with("example") && !s.ends_with("sample"))
    })
}
pub fn normalize_host(host: &str) -> Result<String> {
    let h = host.trim_matches(['[', ']']).trim_end_matches('.');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    match url::Host::parse(h)? {
        url::Host::Domain(d) => Ok(d.to_lowercase()),
        other => Ok(other.to_string()),
    }
}
fn host_matches(host: &str, rule: &NetworkRule) -> bool {
    let Ok(h) = normalize_host(host) else {
        return false;
    };
    h == rule.host || (rule.subdomains && h.ends_with(&format!(".{}", rule.host)))
}
fn path_within(path: &str, base: &str) -> bool {
    base == "/" || path == base || path.starts_with(&format!("{}/", base.trim_end_matches('/')))
}
fn decode_path(path: &str) -> Result<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            ensure!(i + 2 < bytes.len(), "invalid path escape");
            let h = std::str::from_utf8(&bytes[i + 1..i + 3])?;
            let b = u8::from_str_radix(h, 16)?;
            ensure!(
                ![b'%', b'/', b'\\', 0].contains(&b),
                "ambiguous path encoding rejected"
            );
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let out = String::from_utf8(out)?;
    ensure!(
        !out.contains('\\') && !out.split('/').any(|s| s == ".." || s == "."),
        "ambiguous path rejected"
    );
    Ok(out)
}
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0xdb8))
        }
    }
}
pub fn scope_for_url(raw: &str) -> Result<Scope> {
    let u = Url::parse(raw)?;
    let host = u
        .host_str()
        .context("URL host required")?
        .trim_matches(['[', ']']);
    let port = u.port_or_known_default().context("URL port required")?;
    Ok(Scope {
        network: vec![NetworkRule {
            host: normalize_host(host)?,
            subdomains: false,
            ports: vec![port],
            paths: vec!["/".into()],
        }],
        allow_private: host == "localhost"
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        ..Scope::default()
    })
}
pub fn reject_arbitrary_command(_program: &str) -> Result<()> {
    bail!("arbitrary subprocess execution is unavailable: no policy-enforcing sandbox configured")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusions_and_encoding() -> Result<()> {
        let mut s = scope_for_url("https://example.com")?;
        s.excluded_paths = vec!["/admin".into()];
        let p = Policy::new(s)?;
        assert!(p.check_url("https://example.com/admin/users").is_err());
        assert!(p.check_url("https://example.com/%61dmin").is_err());
        assert!(p.check_url("https://example.com/%252fadmin").is_err());
        assert!(p.check_url("https://example.com.evil.test/").is_err());
        assert!(p.check_url("https://example.com:444/").is_err());
        Ok(())
    }
    #[test]
    fn rebinding_private_and_ipv6_blocked() -> Result<()> {
        let p = Policy::new(scope_for_url("https://example.com")?)?;
        assert!(p.check_ip("example.com", "127.0.0.1".parse()?).is_err());
        assert!(p
            .check_ip("example.com", "::ffff:127.0.0.1".parse()?)
            .is_err());
        Ok(())
    }
    #[test]
    fn atomic_account_budget() -> Result<()> {
        let p = Policy::new(Scope {
            max_accounts: 1,
            max_state_changes: 1,
            ..Scope::default()
        })?;
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || p.reserve(true, true).is_ok())
            })
            .collect();
        let n = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|b| *b)
            .count();
        assert_eq!(n, 1);
        assert_eq!(p.usage().accounts, 1);
        Ok(())
    }
    #[test]
    fn path_boundary() -> Result<()> {
        let d = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::write(d.path().join("a.rs"), "x")?;
        std::fs::write(outside.path().join("a.rs"), "x")?;
        let p = Policy::new(Scope {
            roots: vec![d.path().into()],
            ..Scope::default()
        })?;
        assert!(p.check_path(&d.path().join("a.rs")).is_ok());
        assert!(p.check_path(&outside.path().join("a.rs")).is_err());
        Ok(())
    }
}
