use anyhow::Result;
use serde_json::Value;
use std::process::Command;

#[test]
fn unsafe_cli_requires_actor_reason_and_acknowledgement() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_metisblack");
    let denied = Command::new(binary)
        .args(["run", "https://example.test", "--dry-run", "--unsafe-all"])
        .output()?;
    assert!(!denied.status.success());
    let allowed = Command::new(binary)
        .args([
            "run",
            "https://example.test",
            "--dry-run",
            "--unsafe-all",
            "--override-actor",
            "test-operator",
            "--override-reason",
            "Isolated CLI regression fixture",
            "--acknowledge-unsafe",
        ])
        .output()?;
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(String::from_utf8_lossy(&allowed.stderr).contains("EXPERT OVERRIDES"));
    let config: Value = serde_json::from_slice(&allowed.stdout)?;
    assert_eq!(config["overrides"]["unsafe_all"], true);
    assert_eq!(config["overrides"]["acknowledged"], true);
    Ok(())
}
#[test]
fn cli_control_and_builtin_catalogs_are_machine_readable() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_metisblack");
    let output = Command::new(binary).args(["controls"]).output()?;
    assert!(output.status.success());
    let controls: Value = serde_json::from_slice(&output.stdout)?;
    assert!(controls.to_string().contains("confirmation"));
    let output = Command::new(binary).args(["agents", "builtins"]).output()?;
    assert!(output.status.success());
    let library: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(library["playbooks"].as_array().unwrap().len(), 9);
    Ok(())
}

#[test]
fn discovery_plan_is_wired_for_blackbox_and_greybox_only() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_metisblack");
    let fixture = tempfile::tempdir()?;
    let discovery_plan = fixture.path().join("web-discovery.json");
    let discovery_plan_arg = discovery_plan.display().to_string();

    let blackbox = Command::new(binary)
        .args([
            "run",
            "https://example.test",
            "--dry-run",
            "--discovery-plan",
            &discovery_plan_arg,
        ])
        .output()?;
    assert!(
        blackbox.status.success(),
        "{}",
        String::from_utf8_lossy(&blackbox.stderr)
    );
    let blackbox_config: Value = serde_json::from_slice(&blackbox.stdout)?;
    assert_eq!(blackbox_config["mode"], "blackbox");
    assert_eq!(
        blackbox_config["discovery_plan"],
        discovery_plan.display().to_string()
    );

    let greybox = Command::new(binary)
        .args([
            "greybox",
            &fixture.path().display().to_string(),
            "--url",
            "https://example.test",
            "--dry-run",
            "--discovery-plan",
            &discovery_plan_arg,
        ])
        .output()?;
    assert!(
        greybox.status.success(),
        "{}",
        String::from_utf8_lossy(&greybox.stderr)
    );
    let greybox_config: Value = serde_json::from_slice(&greybox.stdout)?;
    assert_eq!(greybox_config["mode"], "greybox");
    assert_eq!(
        greybox_config["discovery_plan"],
        discovery_plan.display().to_string()
    );

    let rejected = Command::new(binary)
        .args([
            "whitebox",
            &fixture.path().display().to_string(),
            "--dry-run",
            "--discovery-plan",
            &discovery_plan_arg,
        ])
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("web discovery plans require black-box or grey-box mode"));
    Ok(())
}

#[tokio::test]
async fn saved_actions_display_effective_unsafe_banners() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_metisblack");
    let source = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = source.path().join("README.md");
    storage::atomic_write(&path, b"Fixture source")?;
    let mut config = orchestrator::default_config(
        domain::Mode::Whitebox,
        vec![source.path().display().to_string()],
        root.path().into(),
    )?;
    config.overrides = domain::ExpertOverrides {
        controls: vec![domain::Control::DataSampling],
        actor: "saved-banner-operator".into(),
        reason: "Saved action fixture override".into(),
        acknowledged: true,
        ..Default::default()
    };
    orchestrator::Engine::new(config)?.run().await?;
    let request = root.path().join("action.json");
    storage::write_json(
        &request,
        &serde_json::json!({"tool":"source_read","path":path,"start_line":1,"end_line":1}),
    )?;
    let integration = root.path().join("integration.json");
    storage::write_json(
        &integration,
        &serde_json::json!({"kind":"github","endpoint":"https://example.test","token_env":"UNUSED","project":"fixture/repo","issue":"1"}),
    )?;
    let run = root.path().display().to_string();
    let request = request.display().to_string();
    let integration = integration.display().to_string();
    for args in [
        vec!["inspect", &run],
        vec!["resume", &run],
        vec!["retest", &run, "missing"],
        vec!["tool", &run, "--request", &request],
        vec!["integrations", &integration, &run],
    ] {
        let result = Command::new(binary).args(&args).output()?;
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("EXPERT OVERRIDES ACTIVE") && stderr.contains("saved-banner-operator"),
            "missing banner for {args:?}: {stderr}"
        );
    }
    let result = Command::new(binary)
        .args([
            "accept",
            &run,
            "missing",
            "--override",
            "confirmation",
            "--override-actor",
            "replacement-operator",
            "--override-reason",
            "Explicit acceptance fixture",
            "--acknowledge-unsafe",
        ])
        .output()?;
    assert!(String::from_utf8_lossy(&result.stderr).contains("replacement-operator"));
    Ok(())
}
