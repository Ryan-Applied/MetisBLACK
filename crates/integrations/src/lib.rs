//! Explicit publication; assessment never posts to external systems implicitly.
use anyhow::{ensure, Context, Result};
use domain::{Control, ExpertOverrides, Finding, RunSnapshot, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use storage::Redactor;

pub fn gate_trips(findings: &[Finding], threshold: Severity, pr: bool) -> bool {
    gate_trips_with_operator(findings, threshold, pr, false)
}
pub fn gate_trips_with_operator(
    findings: &[Finding],
    threshold: Severity,
    pr: bool,
    include_operator: bool,
) -> bool {
    findings.iter().any(|f| {
        (f.state.confirmed()
            || (include_operator && f.state == domain::FindingState::OperatorAccepted))
            && f.candidate.severity >= threshold
            && (!pr || f.introduced == Some(true))
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationConfig {
    pub kind: String,
    pub endpoint: String,
    pub token_env: String,
    pub project: String,
    pub issue: String,
}
pub fn payload(
    config: &IntegrationConfig,
    run: &RunSnapshot,
) -> Result<(String, serde_json::Value)> {
    let count = run.findings.iter().filter(|f| f.state.confirmed()).count();
    let summary=format!("MetisBLACK {}: {} confirmed findings. Run {}. Review local report for receipt references and limitations.",run.version,count,run.id);
    let base = config.endpoint.trim_end_matches('/');
    let project = percent(&config.project);
    let issue = percent(&config.issue);
    Ok(match config.kind.as_str() {
        "github" => {
            let parts = config.project.split('/').collect::<Vec<_>>();
            ensure!(parts.len() == 2, "GitHub project must be owner/repository");
            (
                format!(
                    "{base}/repos/{}/{}/issues/{issue}/comments",
                    percent(parts[0]),
                    percent(parts[1])
                ),
                json!({"body":summary}),
            )
        }
        "gitlab" => (
            format!("{base}/api/v4/projects/{project}/merge_requests/{issue}/notes"),
            json!({"body":summary}),
        ),
        "jira" => (
            format!("{base}/rest/api/3/issue/{issue}/comment"),
            json!({"body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":summary}]}]}}),
        ),
        _ => anyhow::bail!("unsupported integration"),
    })
}
fn percent(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
pub async fn publish(config: &IntegrationConfig, run: &RunSnapshot) -> Result<()> {
    publish_with_overrides(config, run, None).await
}
pub async fn publish_with_overrides(
    config: &IntegrationConfig,
    run: &RunSnapshot,
    overrides: Option<ExpertOverrides>,
) -> Result<()> {
    let mut run = run.clone();
    if let Some(mut overrides) = overrides {
        overrides.validate()?;
        overrides.timestamp_ms = domain::now_ms();
        overrides.controls = overrides.disabled_controls();
        run.override_history.push(run.config.overrides.clone());
        run.config.overrides = overrides;
    }
    run.config.overrides.validate()?;
    run.updated_ms = domain::now_ms();
    let effective = &run.config.overrides;
    ensure!(
        run.config.authorized || effective.disables(Control::Authorization),
        "integration publication requires authorization or an explicit authorization override"
    );
    let endpoint = url::Url::parse(&config.endpoint)?;
    ensure!(
        endpoint.scheme() == "https" || effective.disables(Control::Network),
        "integration endpoint must use HTTPS unless network is overridden"
    );
    ensure!(
        (endpoint.username().is_empty() && endpoint.password().is_none())
            || effective.disables(Control::SecretExposure),
        "integration URL credentials require secret_exposure override"
    );
    let (url, mut body) = payload(config, &run)?;
    Redactor::with_override(effective).value(&mut body);
    let operation = storage::hash(
        serde_json::to_string(&json!({"url":url,"body":body,"run":run.id}))?.as_bytes(),
    );
    let root = &run.config.output_dir;
    let _lock = storage::RunLock::acquire(root)?;
    let audit_path = root.join(format!("publication-{operation}.json"));
    if audit_path.exists() {
        let previous: serde_json::Value = storage::read_json(&audit_path)?;
        ensure!(
            previous["status"] != "pending",
            "prior publication outcome is unknown; reconcile the remote comment before retrying"
        );
        if previous["status"] == "published" {
            return Ok(());
        }
    }
    let key = std::env::var(&config.token_env).context("integration token unavailable")?;
    let mut builder =
        reqwest::Client::builder()
            .no_proxy()
            .redirect(if effective.disables(Control::Redirects) {
                reqwest::redirect::Policy::custom(|attempt| attempt.follow())
            } else {
                reqwest::redirect::Policy::none()
            });
    if !effective.disables(Control::Timeouts) {
        builder = builder.timeout(std::time::Duration::from_secs(20));
    }
    let client = builder.build()?;
    let mut audit = json!({"operation_id":operation,"run_id":run.id,"endpoint":url,"kind":config.kind,"actor":effective.actor,"timestamp_ms":domain::now_ms(),"expert_override":effective,"disabled_controls":effective.disabled_controls(),"authorized":run.config.authorized,"authorization_override":effective.disables(Control::Authorization),"status":"pending"});
    Redactor::with_override(effective).value(&mut audit);
    storage::write_json(&audit_path, &audit)?;
    reporting::write_all(&run, root)?;
    let response = client
        .post(url)
        .bearer_auth(key)
        .header("User-Agent", "MetisBLACK")
        .header("Idempotency-Key", &operation)
        .json(&body)
        .send()
        .await?;
    audit["http_status"] = json!(response.status().as_u16());
    audit["status"] = json!(if response.status().is_success() {
        "published"
    } else {
        "rejected"
    });
    storage::write_json(&audit_path, &audit)?;
    ensure!(
        response.status().is_success(),
        "integration returned HTTP {}",
        response.status().as_u16()
    );
    Ok(())
}
