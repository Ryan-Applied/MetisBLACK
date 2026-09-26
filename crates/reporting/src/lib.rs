use anyhow::Result;
use domain::{FindingState, RunSnapshot, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Write, path::Path};
use storage::{atomic_write, write_json, Redactor};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Counts {
    pub confirmed: usize,
    pub needs_review: usize,
    pub rejected: usize,
    pub fixed: usize,
    pub operator_accepted: usize,
}
pub fn counts(run: &RunSnapshot) -> Counts {
    let mut c = Counts::default();
    for f in &run.findings {
        if f.state == FindingState::OperatorAccepted {
            c.operator_accepted += 1;
        }
        match f.state {
            FindingState::Confirmed | FindingState::RetestedPresent => c.confirmed += 1,
            FindingState::NeedsReview
            | FindingState::Candidate
            | FindingState::Hypothesis
            | FindingState::Reproduced => c.needs_review += 1,
            FindingState::Rejected => c.rejected += 1,
            FindingState::RetestedFixed => c.fixed += 1,
            FindingState::OperatorAccepted => {}
        }
    }
    c
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn md(s: &str) -> String {
    s.replace('\r', "")
        .replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
pub fn markdown(run: &RunSnapshot) -> String {
    let c = counts(run);
    let mut out=format!("# MetisBLACK {} assessment\n\nRun: `{}` · Generated: {} ms since Unix epoch\n\nStatus: {:?}\n\nConfirmed: {} · Needs review: {} · Rejected: {} · Fixed: {} · Operator-accepted: {}\n\n",run.version,run.id,run.updated_ms,run.status,c.confirmed,c.needs_review,c.rejected,c.fixed,c.operator_accepted);
    if run.config.overrides.active() {
        let _=writeln!(out,"## EXPERT OVERRIDES ACTIVE\n\nActor: {}\n\nReason: {}\n\nControls disabled: {:?}\n\nAcknowledged at: {} ms since Unix epoch\n",md(&run.config.overrides.actor),md(&run.config.overrides.reason),run.config.overrides.disabled_controls(),run.config.overrides.timestamp_ms);
    }
    if !run.override_history.is_empty() {
        out.push_str("## Override history\n\n");
        for entry in &run.override_history {
            let _ = writeln!(
                out,
                "- Actor: {} · Reason: {} · Timestamp: {} · Disabled controls: {:?}\n",
                md(&entry.actor),
                md(&entry.reason),
                entry.timestamp_ms,
                entry.disabled_controls()
            );
        }
    }
    out.push_str("## Scope\n\n");
    for t in &run.config.targets {
        let _ = writeln!(out, "- {}", md(t));
    }
    let mut findings = run.findings.iter().collect::<Vec<_>>();
    findings.sort_by_key(|f| std::cmp::Reverse(f.candidate.severity));
    for state in [
        FindingState::Confirmed,
        FindingState::OperatorAccepted,
        FindingState::RetestedPresent,
        FindingState::NeedsReview,
        FindingState::Rejected,
        FindingState::RetestedFixed,
        FindingState::Candidate,
        FindingState::Hypothesis,
        FindingState::Reproduced,
    ] {
        let section: Vec<_> = findings.iter().filter(|f| f.state == state).collect();
        if section.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n## {state:?}\n");
        for f in section {
            let v = &f.candidate;
            let _=writeln!(out,"### {} — {:?}\n\nID: `{}` · Finder: {}\n\nLocation: {}\n\n{}\n\nImpact: {}\n\nSeverity rationale: {}\n\nAuthentication: {}\n\nRemediation: {}\n\nReview reason: {}\n",md(&v.title),v.severity,f.id,md(&f.finder),md(&v.location),md(&v.description),md(&v.impact),md(&v.severity_justification),md(&v.auth_context),md(&v.remediation),md(&f.review_reason));
            if f.confirmation_override.is_some() {
                out.push_str("**Operator-accepted by explicit override; independent reproduction was not required.**\n\n");
            }
            out.push_str("Receipts:\n\n");
            for id in &v.receipt_ids {
                let _ = writeln!(out, "- [{id}](receipts/{id}.json)");
            }
            for validation in &f.validations {
                let _ = writeln!(
                    out,
                    "\nValidation by {}: {}\n",
                    md(&validation.actor),
                    md(&validation.reason)
                );
                for id in &validation.receipt_ids {
                    let _ = writeln!(out, "- [{id}](receipts/{id}.json)");
                }
            }
        }
    }
    out.push_str("\n## Explicit attack edges\n\n");
    if run.attack_edges.is_empty() {
        out.push_str("No independently evidenced causal edges.\n");
    }
    for e in &run.attack_edges {
        let _ = writeln!(
            out,
            "- `{}` → `{}`: {} (receipts: {})",
            e.from,
            e.to,
            md(&e.explanation),
            e.receipt_ids.join(", ")
        );
    }
    out.push_str("\n## Limitations and untested surfaces\n\n");
    for l in &run.limitations {
        let _ = writeln!(out, "- {}", md(l));
    }
    out.push_str("\n## Test-account cleanup\n\n");
    if run.accounts.is_empty() {
        out.push_str("No test accounts created.\n");
    }
    for a in &run.accounts {
        let _ = writeln!(out, "- {}: {}", md(&a.id), md(&a.cleanup_status));
    }
    out
}
pub fn html(run: &RunSnapshot) -> String {
    let c = counts(run);
    let mut out=format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'\"><title>MetisBLACK assessment</title><style>body{{font:16px system-ui;max-width:1050px;margin:3rem auto;padding:0 1.5rem;line-height:1.6;color:#192134;background:#f4f6fa}}header,article,section{{background:white;padding:1.5rem;margin:1rem 0;border-radius:10px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.warning{{border:3px solid #b45309}}a{{overflow-wrap:anywhere;color:#334db7}}small{{color:#536174}}</style><header><h1>MetisBLACK {}</h1><p>Run {} · {:?}</p><p>{} confirmed · {} needs review · {} rejected · {} fixed</p><small>Generated at {} milliseconds since Unix epoch</small></header>",esc(&run.version),esc(&run.id),run.status,c.confirmed,c.needs_review,c.rejected,c.fixed,run.updated_ms);
    if run.config.overrides.active() {
        let _=write!(out,"<section class=\"warning\"><h2>Expert overrides active</h2><p>Actor: {}</p><p>Reason: {}</p><pre>{:?}</pre></section>",esc(&run.config.overrides.actor),esc(&run.config.overrides.reason),run.config.overrides.disabled_controls());
    }
    let mut findings = run.findings.iter().collect::<Vec<_>>();
    findings.sort_by_key(|f| std::cmp::Reverse(f.candidate.severity));
    for f in findings {
        let v = &f.candidate;
        let _=write!(out,"<article><h2>{}</h2><p>{:?} · {:?}</p><p>{}</p><pre>{}</pre><p><strong>Impact:</strong> {}</p><p><strong>Remediation:</strong> {}</p><p><strong>Review:</strong> {}</p><p>Finder: {} · Authentication: {}</p>",esc(&v.title),v.severity,f.state,esc(&v.location),esc(&v.description),esc(&v.impact),esc(&v.remediation),esc(&f.review_reason),esc(&f.finder),esc(&v.auth_context));
        if f.confirmation_override.is_some() {
            out.push_str("<p class=\"warning\">Operator-accepted by explicit override.</p>");
        }
        for id in v
            .receipt_ids
            .iter()
            .chain(f.validations.iter().flat_map(|v| v.receipt_ids.iter()))
        {
            let _ = write!(
                out,
                "<p><a href=\"receipts/{}.json\">{}</a></p>",
                esc(id),
                esc(id)
            );
        }
        out.push_str("</article>");
    }
    if !run.override_history.is_empty() {
        out.push_str("<section><h2>Override history</h2><ul>");
        for entry in &run.override_history {
            let _ = write!(
                out,
                "<li>Actor: {} · Reason: {} · Timestamp: {} · Disabled controls: {:?}</li>",
                esc(&entry.actor),
                esc(&entry.reason),
                entry.timestamp_ms,
                entry.disabled_controls()
            );
        }
        out.push_str("</ul></section>");
    }
    out.push_str("<section><h2>Limitations and untested surfaces</h2><ul>");
    for l in &run.limitations {
        let _ = write!(out, "<li>{}</li>", esc(l));
    }
    out.push_str("</ul></section></html>");
    out
}
pub fn sarif(run: &RunSnapshot) -> serde_json::Value {
    let results=run.findings.iter().filter(|f|f.state.confirmed()||matches!(f.state,FindingState::NeedsReview|FindingState::OperatorAccepted)).map(|f|{
  let rule=f.candidate.cwe.first().cloned().unwrap_or_else(||"security-review".into());
  let mut result=json!({"ruleId":rule,"level":if f.state==FindingState::OperatorAccepted{"note"}else{match f.candidate.severity{Severity::Critical|Severity::High=>"error",Severity::Medium=>"warning",_=>"note"}},"message":{"text":format!("{} [{:?}]: {}",f.candidate.title,f.state,f.candidate.description)},"partialFingerprints":{"metisblackFinding/v1":f.id},"properties":{"state":f.state,"introduced":f.introduced,"receipts":f.candidate.receipt_ids,"claimReceipts":f.claim_receipts,"validations":f.validations,"empiricallyConfirmed":f.state.confirmed(),"operatorOverride":f.confirmation_override}});
  if let domain::Proof::SourceRule{path,line,..}=&f.candidate.proof{result["locations"]=json!([{"physicalLocation":{"artifactLocation":{"uri":path.to_string_lossy()},"region":{"startLine":line}}}]);}result
 }).collect::<Vec<_>>();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"MetisBLACK","version":run.version,"informationUri":"https://github.com/JoasASantos/MetisBLACK"}},"results":results,"invocations":[{"executionSuccessful":run.status==domain::RunStatus::Complete}],"properties":{"runId":run.id,"expertOverrides":run.config.overrides,"overrideHistory":run.override_history}}]})
}
pub fn write_all(run: &RunSnapshot, root: &Path) -> Result<()> {
    let redactor = Redactor::with_override(&run.config.overrides);
    let run: RunSnapshot = redactor.sanitize(run)?;
    atomic_write(&root.join("report.md"), markdown(&run).as_bytes())?;
    atomic_write(&root.join("report.html"), html(&run).as_bytes())?;
    write_json(
        &root.join("report.json"),
        &json!({"schema_version":1,"version":run.version,"generated_ms":run.updated_ms,"counts":counts(&run),"run":run}),
    )?;
    write_json(&root.join("report.sarif"), &sarif(&run))?;
    write_json(&root.join("findings.json"), &run.findings)?;
    write_json(&root.join("execution-plan.json"), &run.decisions)?;
    write_json(&root.join("account-cleanup.json"), &run.accounts)?;
    write_json(&root.join("run-manifest.json"), &run)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_text_is_escaped_for_report_contexts() {
        assert_eq!(esc("<script>'\"&"), "&lt;script&gt;&#39;&quot;&amp;");
        assert_eq!(md("<tag>|value\r"), "&lt;tag&gt;\\|value");
    }
}
