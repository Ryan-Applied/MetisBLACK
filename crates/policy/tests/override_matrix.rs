use anyhow::Result;
use domain::{Control, ExpertOverrides, NetworkRule, Scope, ToolAction};
use metisblack_policy::Policy;

fn expert(controls: Vec<Control>) -> ExpertOverrides {
    ExpertOverrides {
        controls,
        reason: "Local policy regression test".into(),
        actor: "test-operator".into(),
        acknowledged: true,
        ..Default::default()
    }
}
fn scoped() -> Scope {
    Scope {
        network: vec![NetworkRule {
            host: "example.test".into(),
            subdomains: false,
            ports: vec![443],
            paths: vec!["/allowed".into()],
        }],
        excluded_paths: vec!["/denied".into()],
        ..Default::default()
    }
}

#[test]
fn url_controls_do_not_silently_disable_neighboring_controls() -> Result<()> {
    let cases = [
        (Control::Paths, "https://example.test/other"),
        (Control::Ports, "https://example.test:8443/allowed"),
        (Control::Subdomains, "https://sub.example.test/allowed"),
        (Control::Destinations, "https://other.test/allowed"),
        (Control::ThirdParty, "https://other.test/allowed"),
        (Control::Network, "https://other.test/allowed"),
        (Control::Scope, "https://other.test/allowed"),
    ];
    for (control, url) in cases {
        assert!(
            Policy::new(scoped())?.check_url(url).is_err(),
            "default {control:?}"
        );
        assert!(
            Policy::with_overrides(scoped(), expert(vec![control]))?
                .check_url(url)
                .is_ok(),
            "override {control:?}"
        );
        assert!(
            Policy::with_overrides(scoped(), expert(vec![Control::Timeouts]))?
                .check_url(url)
                .is_err(),
            "adjacent timeout {control:?}"
        );
    }
    for control in [Control::Ports, Control::Subdomains] {
        let p = Policy::with_overrides(scoped(), expert(vec![control]))?;
        assert!(p.check_url("https://example.test/other").is_err());
        assert!(p.check_url("https://example.test/denied").is_err());
    }
    for control in [Control::Destinations, Control::ThirdParty] {
        let p = Policy::with_overrides(scoped(), expert(vec![control]))?;
        assert!(p.check_url("https://other.test/other").is_err());
        assert!(p.check_url("https://other.test:8443/allowed").is_err());
        assert!(p.check_url("https://other.test/denied").is_err());
    }
    let p = Policy::with_overrides(scoped(), expert(vec![Control::Paths]))?;
    assert!(p.check_url("https://other.test/allowed").is_err());
    assert!(p.check_url("https://example.test:8443/allowed").is_err());
    Ok(())
}
#[test]
fn redirect_override_is_local_to_redirect_hops() -> Result<()> {
    let p = Policy::with_overrides(scoped(), expert(vec![Control::Redirects]))?;
    assert!(p.check_url("https://other.test/path").is_err());
    assert!(p
        .redirect_policy()
        .check_url("https://other.test/path")
        .is_ok());
    Ok(())
}
#[test]
fn budget_controls_have_independent_overrides() -> Result<()> {
    for control in [
        Control::RequestBudget,
        Control::StateChanges,
        Control::AccountBudget,
    ] {
        let mut scope = scoped();
        scope.max_requests = 10;
        scope.max_state_changes = 10;
        scope.max_accounts = 10;
        match control {
            Control::RequestBudget => scope.max_requests = 0,
            Control::StateChanges => scope.max_state_changes = 0,
            Control::AccountBudget => scope.max_accounts = 0,
            _ => unreachable!(),
        };
        let state = control != Control::RequestBudget;
        let account = control == Control::AccountBudget;
        assert!(Policy::new(scope.clone())?.reserve(state, account).is_err());
        assert!(
            Policy::with_overrides(scope.clone(), expert(vec![control]))?
                .reserve(state, account)
                .is_ok()
        );
        assert!(
            Policy::with_overrides(scope, expert(vec![Control::Timeouts]))?
                .reserve(state, account)
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn cidr_scopes_have_explicit_ports_and_address_override() -> Result<()> {
    let scope = Scope {
        cidrs: vec!["127.0.0.0/8".into()],
        cidr_ports: vec![8443],
        allow_private: true,
        ..Default::default()
    };
    let p = Policy::new(scope)?;
    assert!(p.check_url("http://127.0.0.1:8443/anything").is_ok());
    assert!(p.check_url("http://127.0.0.1:22/").is_err());
    assert!(Policy::new(scoped())?
        .check_ip("example.test", "127.0.0.1".parse()?)
        .is_err());
    assert!(
        Policy::with_overrides(scoped(), expert(vec![Control::Cidrs]))?
            .check_ip("example.test", "127.0.0.1".parse()?)
            .is_ok()
    );
    Ok(())
}
#[test]
fn filesystem_and_secret_exposure_are_separate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::fs::write(outside.path().join("a.rs"), "example")?;
    std::fs::write(root.path().join(".env"), "PASSWORD=fixture")?;
    let scope = Scope {
        roots: vec![root.path().into()],
        ..Default::default()
    };
    assert!(Policy::new(scope.clone())?
        .check_path(&outside.path().join("a.rs"))
        .is_err());
    assert!(
        Policy::with_overrides(scope.clone(), expert(vec![Control::FilesystemRoots]))?
            .check_path(&outside.path().join("a.rs"))
            .is_ok()
    );
    assert!(
        Policy::with_overrides(scope.clone(), expert(vec![Control::FilesystemRoots]))?
            .check_path(&root.path().join(".env"))
            .is_err()
    );
    assert!(
        Policy::with_overrides(scope, expert(vec![Control::SecretExposure]))?
            .check_path(&root.path().join(".env"))
            .is_ok()
    );
    Ok(())
}
#[test]
fn command_risk_controls_require_all_unsandboxed_boundaries() -> Result<()> {
    let root = tempfile::tempdir()?;
    let infrastructure = vec![
        Control::ToolCapabilities,
        Control::Sandbox,
        Control::Network,
        Control::FilesystemRoots,
    ];
    for (program, control) in [
        ("rm", Control::DestructiveActions),
        ("sudo", Control::PrivilegeChanges),
        ("pip", Control::PackageInstallation),
        ("curl", Control::ExternalDownloads),
        ("touch", Control::StateChanges),
        ("passwd", Control::SecretExposure),
        ("sh", Control::CommandRisk),
    ] {
        let action = ToolAction::Shell {
            program: program.into(),
            args: vec![],
            working_dir: root.path().into(),
        };
        let scope = Scope {
            roots: vec![root.path().into()],
            ..Default::default()
        };
        assert!(Policy::new(scope.clone())?.check_action(&action).is_err());
        assert!(
            Policy::with_overrides(scope.clone(), expert(infrastructure.clone()))?
                .check_action(&action)
                .is_err()
        );
        let mut allowed = infrastructure.clone();
        allowed.push(control);
        assert!(
            Policy::with_overrides(scope, expert(allowed))?
                .check_action(&action)
                .is_ok(),
            "{control:?}"
        );
    }
    Ok(())
}
#[test]
fn unsafe_all_expands_every_control_and_requires_acknowledgement() -> Result<()> {
    let mut o = expert(vec![]);
    o.unsafe_all = true;
    for control in Control::ALL {
        assert!(o.disables(*control));
    }
    assert_eq!(o.disabled_controls(), Control::ALL);
    let p = Policy::with_overrides(scoped(), o.clone())?;
    assert!(p.check_url("http://127.0.0.1:8/denied").is_ok());
    o.acknowledged = false;
    assert!(Policy::with_overrides(scoped(), o).is_err());
    Ok(())
}

#[test]
fn path_authorization_overrides_do_not_disable_path_syntax_invariants() -> Result<()> {
    let mut all = expert(vec![]);
    all.unsafe_all = true;
    for overrides in [
        ExpertOverrides::default(),
        expert(vec![Control::Paths]),
        expert(vec![Control::Scope]),
        expert(vec![Control::Ports]),
        all,
    ] {
        let p = Policy::with_overrides(scoped(), overrides)?;
        for malformed in [
            "https://example.test/allowed%2fescape",
            "https://example.test/allowed%5cescape",
            "https://example.test/%zz",
            "https://example.test/%252e",
        ] {
            assert!(
                p.check_url(malformed).is_err(),
                "ambiguous syntax admitted: {malformed}"
            );
        }
    }
    let p = Policy::with_overrides(scoped(), expert(vec![Control::Paths]))?;
    assert!(p.check_url("https://example.test/valid%20path").is_ok());
    Ok(())
}
