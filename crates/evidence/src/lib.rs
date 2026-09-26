use anyhow::{ensure, Result};
use domain::{now_ms, Receipt, ToolOutput, SCHEMA_VERSION};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use storage::{hash, random_id, safe_component, secure_dir, Redactor};

#[derive(Clone)]
pub struct EvidenceStore {
    root: PathBuf,
    run_id: String,
    redactor: Redactor,
}
impl EvidenceStore {
    pub fn new(root: &Path, run_id: &str, redactor: Redactor) -> Result<Self> {
        safe_component(run_id)?;
        secure_dir(root)?;
        Ok(Self {
            root: root.to_owned(),
            run_id: run_id.into(),
            redactor,
        })
    }
    pub fn capture(&self, actor: &str, output: ToolOutput) -> Result<Receipt> {
        self.capture_with_override(actor, output, &domain::ExpertOverrides::default())
    }
    pub fn capture_with_override(
        &self,
        actor: &str,
        output: ToolOutput,
        overrides: &domain::ExpertOverrides,
    ) -> Result<Receipt> {
        overrides.validate()?;
        let output = self.redactor.sanitize(&output)?;
        let content_hash = hash(&serde_json::to_vec(&output)?);
        let mut receipt = Receipt {
            schema_version: SCHEMA_VERSION,
            id: String::new(),
            run_id: self.run_id.clone(),
            actor: actor.into(),
            captured_ms: now_ms(),
            content_hash,
            output,
            expert_override: if overrides.active() {
                let mut expanded = overrides.clone();
                expanded.controls = expanded.disabled_controls();
                Some(expanded)
            } else {
                None
            },
        };
        // Include a random execution identifier so identical independent executions
        // cannot collapse to the same receipt.
        let seed = random_id("execution")?;
        receipt.id = format!("{}-{}", seed, hash(&serde_json::to_vec(&receipt)?));
        let p = self.root.join(format!("{}.json", receipt.id));
        let temporary = self.root.join(format!("{}.pending", random_id("capture")?));
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&temporary)?;
        f.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
        f.sync_all()?;
        drop(f);
        // Atomic publication without replacing an existing receipt. A crash may
        // leave a .pending blob, which is never treated as a valid receipt.
        let result = fs::hard_link(&temporary, &p);
        let _ = fs::remove_file(&temporary);
        result?;
        Ok(receipt)
    }
    pub fn get(&self, id: &str) -> Result<Receipt> {
        safe_component(id)?;
        let p = self.root.join(format!("{id}.json"));
        ensure!(
            !fs::symlink_metadata(&p)?.file_type().is_symlink(),
            "receipt cannot be a symlink"
        );
        let receipt: Receipt = storage::read_json(&p)?;
        ensure!(
            receipt.id == id
                && receipt.run_id == self.run_id
                && receipt.schema_version == SCHEMA_VERSION,
            "receipt provenance mismatch"
        );
        ensure!(
            receipt.content_hash == hash(&serde_json::to_vec(&receipt.output)?),
            "receipt content hash mismatch"
        );
        let (_, stored_hash) = receipt
            .id
            .rsplit_once('-')
            .ok_or_else(|| anyhow::anyhow!("invalid receipt id"))?;
        let mut unhashed = receipt.clone();
        unhashed.id.clear();
        ensure!(
            stored_hash == hash(&serde_json::to_vec(&unhashed)?),
            "receipt metadata hash mismatch"
        );
        Ok(receipt)
    }
    pub fn manifest(&self) -> Result<Vec<Receipt>> {
        let mut out = vec![];
        for e in fs::read_dir(&self.root)? {
            let p = e?.path();
            if p.extension().is_some_and(|e| e == "json") {
                if let Some(id) = p.file_stem().and_then(|s| s.to_str()) {
                    out.push(self.get(id)?);
                }
            }
        }
        out.sort_by_key(|r| r.captured_ms);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::ToolAction;
    #[test]
    fn rejects_fabrication_and_mutation() -> Result<()> {
        let d = tempfile::tempdir()?;
        let s = EvidenceStore::new(d.path(), "run-test", Redactor::default())?;
        assert!(s.get("fake-receipt").is_err());
        let r = s.capture(
            "test",
            ToolOutput {
                action: ToolAction::DnsResolve {
                    host: "localhost".into(),
                },
                successful: true,
                data: serde_json::json!(["127.0.0.1"]),
                truncated: false,
            },
        )?;
        assert!(s.get(&r.id).is_ok());
        let mut changed = r.clone();
        changed.actor = "forged".into();
        storage::write_json(&d.path().join(format!("{}.json", r.id)), &changed)?;
        assert!(s.get(&r.id).is_err());
        Ok(())
    }
}
