use anyhow::Result;
use domain::{ExpertOverrides, FindingState, Proof, RunSnapshot, Severity, Validation};
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

fn typed_proof(proof: &Proof) -> String {
    serde_json::to_string(proof)
        .unwrap_or_else(|error| format!(r#"{{"kind":"serialization_error","message":"{error}"}}"#))
}

fn formatted_decision(decision: &serde_json::Value) -> String {
    serde_json::to_string_pretty(decision)
        .unwrap_or_else(|error| format!(r#"{{"kind":"serialization_error","message":"{error}"}}"#))
}

fn validation_result(validation: &Validation) -> &'static str {
    if validation.reproduced {
        "reproduced"
    } else {
        "not reproduced"
    }
}

fn markdown_acceptance(out: &mut String, state: FindingState, override_: &Option<ExpertOverrides>) {
    out.push_str("Acceptance provenance:\n\n");
    match override_ {
        Some(override_) => {
            let _ = writeln!(
                out,
                "- Operator-accepted by: {}\n- Reason: {}\n- Timestamp: {} ms since Unix epoch\n- Acknowledged: {}\n- Disabled controls: {:?}\n",
                md(&override_.actor),
                md(&override_.reason),
                override_.timestamp_ms,
                override_.acknowledged,
                override_.disabled_controls()
            );
        }
        None if state == FindingState::OperatorAccepted => {
            out.push_str("- **Missing confirmation-override provenance. This acceptance is not an empirical confirmation.**\n\n");
        }
        None => out.push_str("- No operator acceptance override.\n\n"),
    }
}

fn sanitized_snapshot(run: &RunSnapshot) -> Result<RunSnapshot> {
    Redactor::with_override(&run.config.overrides).sanitize(run)
}

fn render_markdown(run: &RunSnapshot) -> String {
    let c = counts(run);
    let mut out=format!("# MetisBLACK {} assessment\n\nRun: `{}` · Generated: {} ms since Unix epoch\n\nStatus: {:?}\n\nConfirmed: {} · Needs review: {} · Rejected: {} · Fixed: {} · Operator-accepted: {}\n\n",run.version,run.id,run.updated_ms,run.status,c.confirmed,c.needs_review,c.rejected,c.fixed,c.operator_accepted);
    if run.config.overrides.active() {
        let _=writeln!(out,"## EXPERT OVERRIDES ACTIVE\n\nActor: {}\n\nReason: {}\n\nControls disabled: {:?}\n\nAcknowledged: {}\n\nAcknowledged at: {} ms since Unix epoch\n",md(&run.config.overrides.actor),md(&run.config.overrides.reason),run.config.overrides.disabled_controls(),run.config.overrides.acknowledged,run.config.overrides.timestamp_ms);
    }
    if !run.override_history.is_empty() {
        out.push_str("## Override history\n\n");
        for entry in &run.override_history {
            let _ = writeln!(
                out,
                "- Actor: {} · Reason: {} · Timestamp: {} · Acknowledged: {} · Disabled controls: {:?}\n",
                md(&entry.actor),
                md(&entry.reason),
                entry.timestamp_ms,
                entry.acknowledged,
                entry.disabled_controls()
            );
        }
    }
    out.push_str("## Scope\n\n");
    for t in &run.config.targets {
        let _ = writeln!(out, "- {}", md(t));
    }
    out.push_str("\n## Run decisions and artifacts\n\n");
    out.push_str(
        "These are orchestration decisions and generated artifact references, not findings.\n\n",
    );
    if run.decisions.is_empty() {
        out.push_str("No run decisions or generated artifact references recorded.\n");
    }
    for (index, decision) in run.decisions.iter().enumerate() {
        let _ = writeln!(out, "### Decision {}\n", index + 1);
        for line in formatted_decision(decision).lines() {
            let _ = writeln!(out, "    {}", md(line));
        }
        out.push('\n');
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
            let _=writeln!(out,"### {} — {:?}\n\nID: `{}` · State: `{:?}` · Finder: {}\n\nLocation: {}\n\n{}\n\nImpact: {}\n\nSeverity rationale: {}\n\nAuthentication: {}\n\nRemediation: {}\n\nReview reason: {}\n\nTyped proof:\n\n    {}\n",md(&v.title),v.severity,md(&f.id),f.state,md(&f.finder),md(&v.location),md(&v.description),md(&v.impact),md(&v.severity_justification),md(&v.auth_context),md(&v.remediation),md(&f.review_reason),md(&typed_proof(&v.proof)));
            markdown_acceptance(&mut out, f.state, &f.confirmation_override);
            out.push_str("Receipts:\n\n");
            for id in &v.receipt_ids {
                let id = md(id);
                let _ = writeln!(out, "- [{id}](receipts/{id}.json)");
            }
            if v.receipt_ids.is_empty() {
                out.push_str("- No candidate receipts recorded.\n");
            }
            out.push_str("\nClaim-to-receipt map:\n\n");
            if f.claim_receipts.is_empty() {
                out.push_str("- No claim-to-receipt mappings recorded.\n");
            }
            for (claim, ids) in &f.claim_receipts {
                let ids = if ids.is_empty() {
                    "no receipts".to_owned()
                } else {
                    ids.iter().map(|id| md(id)).collect::<Vec<_>>().join(", ")
                };
                let _ = writeln!(out, "- {} → {}", md(claim), ids);
            }
            out.push_str("\nValidation lineage:\n");
            if f.validations.is_empty() {
                out.push_str("\n- No validation attempts recorded.\n");
            }
            for validation in &f.validations {
                let _ = writeln!(
                    out,
                    "\n- Actor: {} · Result: **{}** · Timestamp: {} ms since Unix epoch\n  Reason: {}\n  Receipt IDs: {}",
                    md(&validation.actor),
                    validation_result(validation),
                    validation.timestamp_ms,
                    md(&validation.reason),
                    if validation.receipt_ids.is_empty() {
                        "none".to_owned()
                    } else {
                        validation
                            .receipt_ids
                            .iter()
                            .map(|id| md(id))
                            .collect::<Vec<_>>()
                        .join(", ")
                    }
                );
                for id in &validation.receipt_ids {
                    let id = md(id);
                    let _ = writeln!(out, "  - [{id}](receipts/{id}.json)");
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

pub fn markdown(run: &RunSnapshot) -> String {
    sanitized_snapshot(run).map_or_else(
        |_| {
            "# MetisBLACK assessment unavailable\n\nReport generation stopped because the snapshot could not be safely redacted.\n"
                .to_owned()
        },
        |run| render_markdown(&run),
    )
}

fn render_html(run: &RunSnapshot) -> String {
    let c = counts(run);
    let mut out=format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'\"><title>MetisBLACK assessment</title><style>body{{font:16px system-ui;max-width:1050px;margin:3rem auto;padding:0 1.5rem;line-height:1.6;color:#192134;background:#f4f6fa}}header,article,section{{background:white;padding:1.5rem;margin:1rem 0;border-radius:10px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.warning{{border:3px solid #b45309}}a{{overflow-wrap:anywhere;color:#334db7}}small{{color:#536174}}dt{{font-weight:700;margin-top:.6rem}}dd{{margin-left:0}}</style><header><h1>MetisBLACK {}</h1><p>Run {} · {:?}</p><p>{} confirmed · {} operator-accepted · {} needs review · {} rejected · {} fixed</p><small>Generated at {} milliseconds since Unix epoch</small></header>",esc(&run.version),esc(&run.id),run.status,c.confirmed,c.operator_accepted,c.needs_review,c.rejected,c.fixed,run.updated_ms);
    if run.config.overrides.active() {
        let controls = format!("{:?}", run.config.overrides.disabled_controls());
        let _=write!(out,"<section class=\"warning\"><h2>Expert overrides active</h2><dl><dt>Actor</dt><dd>{}</dd><dt>Reason</dt><dd>{}</dd><dt>Disabled controls</dt><dd>{}</dd><dt>Acknowledged</dt><dd>{}</dd><dt>Acknowledged at</dt><dd>{} ms since Unix epoch</dd></dl></section>",esc(&run.config.overrides.actor),esc(&run.config.overrides.reason),esc(&controls),run.config.overrides.acknowledged,run.config.overrides.timestamp_ms);
    }
    out.push_str("<section><h2>Run decisions and artifacts</h2><p>These are orchestration decisions and generated artifact references, not findings.</p>");
    if run.decisions.is_empty() {
        out.push_str("<p>No run decisions or generated artifact references recorded.</p>");
    } else {
        out.push_str("<ol>");
        for decision in &run.decisions {
            let _ = write!(
                out,
                "<li><pre>{}</pre></li>",
                esc(&formatted_decision(decision))
            );
        }
        out.push_str("</ol>");
    }
    out.push_str("</section>");
    let mut findings = run.findings.iter().collect::<Vec<_>>();
    findings.sort_by_key(|f| std::cmp::Reverse(f.candidate.severity));
    for f in findings {
        let v = &f.candidate;
        let _=write!(out,"<article><h2>{}</h2><dl><dt>Severity</dt><dd>{:?}</dd><dt>Finding state</dt><dd>{:?}</dd><dt>Finder</dt><dd>{}</dd><dt>Location</dt><dd>{}</dd><dt>Authentication</dt><dd>{}</dd></dl><pre>{}</pre><p><strong>Impact:</strong> {}</p><p><strong>Remediation:</strong> {}</p><p><strong>Review:</strong> {}</p><h3>Typed proof</h3><pre>{}</pre>",esc(&v.title),v.severity,f.state,esc(&f.finder),esc(&v.location),esc(&v.auth_context),esc(&v.description),esc(&v.impact),esc(&v.remediation),esc(&f.review_reason),esc(&typed_proof(&v.proof)));
        out.push_str("<h3>Acceptance provenance</h3>");
        match &f.confirmation_override {
            Some(override_) => {
                let controls = format!("{:?}", override_.disabled_controls());
                let _ = write!(out,"<div class=\"warning\"><p><strong>Operator-accepted by explicit override; this override is not itself empirical confirmation.</strong></p><dl><dt>Actor</dt><dd>{}</dd><dt>Reason</dt><dd>{}</dd><dt>Timestamp</dt><dd>{} ms since Unix epoch</dd><dt>Acknowledged</dt><dd>{}</dd><dt>Disabled controls</dt><dd>{}</dd></dl></div>",esc(&override_.actor),esc(&override_.reason),override_.timestamp_ms,override_.acknowledged,esc(&controls));
            }
            None if f.state == FindingState::OperatorAccepted => out.push_str("<p class=\"warning\"><strong>Missing confirmation-override provenance. This acceptance is not an empirical confirmation.</strong></p>"),
            None => out.push_str("<p>No operator acceptance override.</p>"),
        }
        out.push_str("<h3>Candidate receipts</h3>");
        if v.receipt_ids.is_empty() {
            out.push_str("<p>No candidate receipts recorded.</p>");
        }
        for id in &v.receipt_ids {
            let _ = write!(
                out,
                "<p><a href=\"receipts/{}.json\">{}</a></p>",
                esc(id),
                esc(id)
            );
        }
        out.push_str("<h3>Claim-to-receipt map</h3><dl>");
        if f.claim_receipts.is_empty() {
            out.push_str("<dt>None</dt><dd>No claim-to-receipt mappings recorded.</dd>");
        }
        for (claim, ids) in &f.claim_receipts {
            let receipt_ids = if ids.is_empty() {
                "no receipts".to_owned()
            } else {
                ids.iter().map(|id| esc(id)).collect::<Vec<_>>().join(", ")
            };
            let _ = write!(out, "<dt>{}</dt><dd>{}</dd>", esc(claim), receipt_ids);
        }
        out.push_str("</dl><h3>Validation lineage</h3>");
        if f.validations.is_empty() {
            out.push_str("<p>No validation attempts recorded.</p>");
        }
        for validation in &f.validations {
            let ids = if validation.receipt_ids.is_empty() {
                "none".to_owned()
            } else {
                validation
                    .receipt_ids
                    .iter()
                    .map(|id| esc(id))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _=write!(out,"<dl><dt>Actor</dt><dd>{}</dd><dt>Result</dt><dd>{}</dd><dt>Reason</dt><dd>{}</dd><dt>Timestamp</dt><dd>{} ms since Unix epoch</dd><dt>Receipt IDs</dt><dd>{}</dd></dl>",esc(&validation.actor),validation_result(validation),esc(&validation.reason),validation.timestamp_ms,ids);
            for id in &validation.receipt_ids {
                let _ = write!(
                    out,
                    "<p><a href=\"receipts/{}.json\">Validation receipt: {}</a></p>",
                    esc(id),
                    esc(id)
                );
            }
        }
        out.push_str("</article>");
    }
    if !run.override_history.is_empty() {
        out.push_str("<section><h2>Override history</h2><ul>");
        for entry in &run.override_history {
            let controls = format!("{:?}", entry.disabled_controls());
            let _ = write!(
                out,
                "<li>Actor: {} · Reason: {} · Timestamp: {} · Acknowledged: {} · Disabled controls: {}</li>",
                esc(&entry.actor),
                esc(&entry.reason),
                entry.timestamp_ms,
                entry.acknowledged,
                esc(&controls)
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

pub fn html(run: &RunSnapshot) -> String {
    sanitized_snapshot(run).map_or_else(
        |_| "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"><title>MetisBLACK assessment unavailable</title><h1>Assessment unavailable</h1><p>Report generation stopped because the snapshot could not be safely redacted.</p></html>".to_owned(),
        |run| render_html(&run),
    )
}

fn render_sarif(run: &RunSnapshot) -> serde_json::Value {
    let results=run.findings.iter().filter(|f|f.state.confirmed()||matches!(f.state,FindingState::NeedsReview|FindingState::OperatorAccepted)).map(|f|{
  let rule=f.candidate.cwe.first().cloned().unwrap_or_else(||"security-review".into());
  let mut result=json!({"ruleId":rule,"level":if f.state==FindingState::OperatorAccepted{"note"}else{match f.candidate.severity{Severity::Critical|Severity::High=>"error",Severity::Medium=>"warning",_=>"note"}},"message":{"text":format!("{} [{:?}]: {}",f.candidate.title,f.state,f.candidate.description)},"partialFingerprints":{"metisblackFinding/v1":f.id},"properties":{"findingState":f.state,"state":f.state,"finder":f.finder,"proof":f.candidate.proof,"introduced":f.introduced,"receipts":f.candidate.receipt_ids,"claimReceiptMap":f.claim_receipts,"claimReceipts":f.claim_receipts,"validationLineage":f.validations,"validations":f.validations,"empiricallyConfirmed":f.state.confirmed(),"operatorAccepted":f.state==FindingState::OperatorAccepted,"confirmationOverride":f.confirmation_override,"operatorOverride":f.confirmation_override}});
  if let domain::Proof::SourceRule{path,line,..}=&f.candidate.proof{result["locations"]=json!([{"physicalLocation":{"artifactLocation":{"uri":path.to_string_lossy()},"region":{"startLine":line}}}]);}result
 }).collect::<Vec<_>>();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"MetisBLACK","version":run.version,"informationUri":"https://github.com/JoasASantos/MetisBLACK"}},"results":results,"invocations":[{"executionSuccessful":run.status==domain::RunStatus::Complete}],"properties":{"runId":run.id,"decisions":run.decisions,"expertOverrides":run.config.overrides,"overrideHistory":run.override_history}}]})
}

pub fn sarif(run: &RunSnapshot) -> serde_json::Value {
    sanitized_snapshot(run).map_or_else(
        |_| json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"MetisBLACK"}},"results":[],"invocations":[{"executionSuccessful":false}],"properties":{"reportingError":"snapshot_redaction_failed"}}]}),
        |run| render_sarif(&run),
    )
}

pub fn write_all(run: &RunSnapshot, root: &Path) -> Result<()> {
    let run = sanitized_snapshot(run)?;
    atomic_write(&root.join("report.md"), render_markdown(&run).as_bytes())?;
    atomic_write(&root.join("report.html"), render_html(&run).as_bytes())?;
    write_json(
        &root.join("report.json"),
        &json!({"schema_version":1,"version":run.version,"generated_ms":run.updated_ms,"counts":counts(&run),"run":run}),
    )?;
    write_json(&root.join("report.sarif"), &render_sarif(&run))?;
    write_json(&root.join("findings.json"), &run.findings)?;
    write_json(&root.join("execution-plan.json"), &run.decisions)?;
    write_json(&root.join("account-cleanup.json"), &run.accounts)?;
    write_json(&root.join("run-manifest.json"), &run)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(state: FindingState) -> RunSnapshot {
        let confirmation_override = if state == FindingState::OperatorAccepted {
            json!({
                "controls": ["confirmation"],
                "unsafe_all": false,
                "reason": "Authorized acceptance <review>",
                "actor": "operator <one>",
                "acknowledged": true,
                "timestamp_ms": 44
            })
        } else {
            serde_json::Value::Null
        };
        serde_json::from_value(json!({
            "schema_version": 1,
            "id": "run-report-fixture",
            "version": "0.1.0",
            "created_ms": 1,
            "updated_ms": 2,
            "status": "complete",
            "config": {
                "schema_version": 1,
                "mode": "whitebox",
                "targets": ["fixture <target>"],
                "scope": {},
                "output_dir": std::env::temp_dir(),
                "max_steps": 20,
                "max_model_tokens": 100,
                "authorized": true,
                "overrides": {}
            },
            "findings": [{
                "id": "finding-1",
                "candidate": {
                    "title": "Unsafe <script>alert(1)</script>",
                    "description": "api_key=supersecret <script>alert(2)</script>",
                    "severity": "high",
                    "severity_justification": "Fixture impact",
                    "cwe": ["CWE-79"],
                    "location": "source <location>",
                    "impact": "Fixture impact",
                    "remediation": "Escape <all> output",
                    "confidence": 0.9,
                    "auth_context": "role <admin>",
                    "receipt_ids": ["candidate-receipt"],
                    "proof": {
                        "kind": "manual",
                        "procedure": "api_key=supersecret <proof>"
                    }
                },
                "state": state,
                "finder": "finder <model>",
                "validations": [{
                    "actor": "validator <two>",
                    "receipt_ids": ["validation-receipt"],
                    "reproduced": true,
                    "reason": "password=hunter2 <validated>",
                    "timestamp_ms": 33
                }],
                "review_reason": "review <reason>",
                "introduced": true,
                "claim_receipts": {
                    "response <omits> header": ["candidate-receipt", "validation-receipt"]
                },
                "confirmation_override": confirmation_override
            }],
            "receipt_ids": ["candidate-receipt", "validation-receipt"],
            "decisions": [],
            "limitations": [],
            "accounts": [],
            "attack_edges": [],
            "completed_targets": [],
            "override_history": []
        }))
        .expect("fixture snapshot must deserialize")
    }

    #[test]
    fn untrusted_text_is_escaped_for_report_contexts() {
        assert_eq!(esc("<script>'\"&"), "&lt;script&gt;&#39;&quot;&amp;");
        assert_eq!(md("<tag>|value\r"), "&lt;tag&gt;\\|value");
    }

    #[test]
    fn markdown_and_html_show_typed_lineage_with_html_escaping() {
        let run = fixture(FindingState::Confirmed);
        let markdown = markdown(&run);
        let html = html(&run);

        assert!(markdown.contains("State: `Confirmed` · Finder: finder &lt;model&gt;"));
        assert!(markdown.contains("Typed proof:"));
        assert!(markdown.contains(r#"{"kind":"manual","procedure":"[REDACTED] &lt;proof&gt;"}"#));
        assert!(markdown.contains("Claim-to-receipt map:"));
        assert!(markdown
            .contains("response &lt;omits&gt; header → candidate-receipt, validation-receipt"));
        assert!(markdown.contains("Actor: validator &lt;two&gt; · Result: **reproduced**"));
        assert!(markdown.contains("Receipt IDs: validation-receipt"));

        assert!(!html.contains("<script>alert"));
        assert!(html.contains("Unsafe &lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("<h3>Typed proof</h3>"));
        assert!(html.contains("&quot;kind&quot;:&quot;manual&quot;"));
        assert!(html.contains("<h3>Claim-to-receipt map</h3>"));
        assert!(html.contains("response &lt;omits&gt; header"));
        assert!(html.contains("<h3>Validation lineage</h3>"));
        assert!(html.contains("validator &lt;two&gt;"));
        assert!(html.contains("<dt>Result</dt><dd>reproduced</dd>"));
        assert!(!markdown.contains("supersecret"));
        assert!(!markdown.contains("hunter2"));
        assert!(!html.contains("supersecret"));
        assert!(!html.contains("hunter2"));
    }

    #[test]
    fn operator_acceptance_is_visible_and_never_collapsed_into_confirmation() {
        let run = fixture(FindingState::OperatorAccepted);
        let counts = counts(&run);
        let markdown = markdown(&run);
        let html = html(&run);
        let sarif = sarif(&run);
        let properties = &sarif["runs"][0]["results"][0]["properties"];

        assert_eq!(counts.confirmed, 0);
        assert_eq!(counts.operator_accepted, 1);
        assert!(markdown.contains("Confirmed: 0"));
        assert!(markdown.contains("Operator-accepted: 1"));
        assert!(markdown.contains("Operator-accepted by: operator &lt;one&gt;"));
        assert!(html.contains("0 confirmed · 1 operator-accepted"));
        assert!(html.contains("not itself empirical confirmation"));
        assert_eq!(properties["findingState"], "operator_accepted");
        assert_eq!(properties["empiricallyConfirmed"], false);
        assert_eq!(properties["operatorAccepted"], true);
        assert_eq!(
            properties["confirmationOverride"]["actor"],
            "operator <one>"
        );
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn sarif_and_json_preserve_typed_evidence_lineage_and_artifacts_redact_secrets() {
        let run = fixture(FindingState::Confirmed);
        let sarif = sarif(&run);
        let properties = &sarif["runs"][0]["results"][0]["properties"];
        let sarif_text = serde_json::to_string(&sarif).expect("SARIF serialization");

        assert_eq!(properties["proof"]["kind"], "manual");
        assert_eq!(properties["findingState"], "confirmed");
        assert_eq!(properties["finder"], "finder <model>");
        assert_eq!(
            properties["claimReceiptMap"]["response <omits> header"][0],
            "candidate-receipt"
        );
        assert_eq!(
            properties["validationLineage"][0]["actor"],
            "validator <two>"
        );
        assert_eq!(properties["validationLineage"][0]["reproduced"], true);
        assert_eq!(
            properties["validationLineage"][0]["receipt_ids"][0],
            "validation-receipt"
        );
        assert!(!sarif_text.contains("supersecret"));
        assert!(!sarif_text.contains("hunter2"));
        assert!(sarif_text.contains("[REDACTED]"));

        let root = tempfile::tempdir().expect("temporary report directory");
        write_all(&run, root.path()).expect("report artifacts");
        for name in [
            "report.md",
            "report.html",
            "report.json",
            "report.sarif",
            "findings.json",
        ] {
            let content = fs::read_to_string(root.path().join(name)).expect("report artifact");
            assert!(!content.contains("supersecret"), "{name} exposed API key");
            assert!(!content.contains("hunter2"), "{name} exposed password");
            assert!(
                content.contains("[REDACTED]"),
                "{name} omitted redaction marker"
            );
        }

        let report: serde_json::Value =
            storage::read_json(&root.path().join("report.json")).expect("report JSON");
        let findings: serde_json::Value =
            storage::read_json(&root.path().join("findings.json")).expect("findings JSON");
        assert_eq!(
            report["run"]["findings"][0]["candidate"]["proof"]["kind"],
            "manual"
        );
        assert_eq!(findings[0]["candidate"]["proof"]["kind"], "manual");
        assert_eq!(findings[0]["state"], "confirmed");
        assert_eq!(findings[0]["finder"], "finder <model>");
        assert_eq!(findings[0]["validations"][0]["reproduced"], true);
        assert_eq!(
            findings[0]["validations"][0]["receipt_ids"][0],
            "validation-receipt"
        );
        assert_eq!(
            findings[0]["claim_receipts"]["response <omits> header"][1],
            "validation-receipt"
        );
    }

    #[test]
    fn decisions_and_artifact_references_are_visible_sanitized_and_not_findings() {
        let mut run = fixture(FindingState::Confirmed);
        run.decisions = vec![json!({
            "action": "web_discovery",
            "artifact": "web-discovery/plan-1/artifact.json",
            "artifact_hash": "sha256:fixture",
            "api_key": "decision-secret",
            "label": "untrusted <script>alert(1)</script>"
        })];

        let markdown = markdown(&run);
        let html = html(&run);
        let sarif = sarif(&run);
        let sarif_text = serde_json::to_string(&sarif).expect("SARIF serialization");

        assert!(markdown.contains("## Run decisions and artifacts"));
        assert!(markdown.contains("web-discovery/plan-1/artifact.json"));
        assert!(markdown.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("<h2>Run decisions and artifacts</h2>"));
        assert!(html.contains("web-discovery/plan-1/artifact.json"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert_eq!(
            sarif["runs"][0]["properties"]["decisions"][0]["artifact"],
            "web-discovery/plan-1/artifact.json"
        );
        assert_eq!(
            sarif["runs"][0]["properties"]["decisions"][0]["api_key"],
            "[REDACTED]"
        );
        assert!(!markdown.contains("decision-secret"));
        assert!(!html.contains("decision-secret"));
        assert!(!sarif_text.contains("decision-secret"));
        assert_eq!(
            sarif["runs"][0]["results"].as_array().map(Vec::len),
            Some(1)
        );
    }
}
