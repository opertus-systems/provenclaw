use chrono::{DateTime, Utc};
use provenclaw_core::{ReceiptEnvelope, VerificationStatus, sha256_hex};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("receipt error: {0}")]
    Receipt(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub tool_digest: String,
    pub policy_hash: String,
    pub receipt_hash: String,
    pub decision: String,
    pub reason: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub record_hash: String,
    #[serde(default = "default_verification_status")]
    pub verification_status: VerificationStatus,
}

impl AuditRecord {
    pub fn compute_hash(&self) -> Result<String, AuditError> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        let payload = serde_json::to_vec(&copy)?;
        Ok(sha256_hex(&payload))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainReport {
    pub valid: bool,
    pub checked_records: usize,
    pub first_invalid_seq: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    audit_log_path: PathBuf,
    receipt_dir: PathBuf,
}

impl AuditStore {
    pub fn new(
        audit_log_path: impl Into<PathBuf>,
        receipt_dir: impl Into<PathBuf>,
    ) -> Result<Self, AuditError> {
        let store = Self {
            audit_log_path: audit_log_path.into(),
            receipt_dir: receipt_dir.into(),
        };
        store.ensure_layout()?;
        Ok(store)
    }

    pub fn append_record(&self, record: &AuditRecord) -> Result<AuditRecord, AuditError> {
        let mut finalized = record.clone();

        let (previous_seq, previous_hash) = self.next_chain_metadata()?;

        finalized.seq = if finalized.seq == 0 {
            previous_seq + 1
        } else {
            finalized.seq
        };
        finalized.prev_hash = finalized.prev_hash.clone().or(previous_hash);
        finalized.record_hash = finalized.compute_hash()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_log_path)?;
        let line = serde_json::to_string(&finalized)?;
        writeln!(file, "{line}")?;
        file.sync_data()?;
        Ok(finalized)
    }

    pub fn next_chain_metadata(&self) -> Result<(u64, Option<String>), AuditError> {
        if let Some(last) = self.last_record()? {
            return Ok((last.seq, Some(last.record_hash)));
        }
        Ok((0, None))
    }

    pub fn persist_receipt(&self, receipt: &ReceiptEnvelope) -> Result<PathBuf, AuditError> {
        let receipt_path = self.receipt_path(receipt.id);
        let serialized = serde_json::to_string_pretty(receipt)?;
        fs::write(&receipt_path, serialized)?;
        Ok(receipt_path)
    }

    pub fn load_receipt(&self, id: &str) -> Result<ReceiptEnvelope, AuditError> {
        let parsed_id = Uuid::parse_str(id).map_err(|err| AuditError::Receipt(err.to_string()))?;
        let payload = fs::read_to_string(self.receipt_path(parsed_id))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn verify_receipt(&self, id: &str) -> Result<bool, AuditError> {
        let receipt = self.load_receipt(id)?;
        receipt
            .verify_hash()
            .map_err(|err| AuditError::Receipt(err.to_string()))
    }

    pub fn find_audit_record(&self, id: Uuid) -> Result<Option<AuditRecord>, AuditError> {
        let mut records = self.export_audit()?;
        records.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        Ok(records.into_iter().find(|record| record.id == id))
    }

    pub fn list_receipts(&self) -> Result<Vec<ReceiptSummary>, AuditError> {
        let mut summaries = Vec::new();
        if !self.receipt_dir.exists() {
            return Ok(summaries);
        }

        for entry in fs::read_dir(&self.receipt_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let payload = fs::read_to_string(entry.path())?;
            let receipt: ReceiptEnvelope = serde_json::from_str(&payload)?;
            summaries.push(ReceiptSummary {
                id: receipt.id,
                timestamp: receipt.timestamp,
                decision: receipt.decision,
            });
        }

        summaries.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        Ok(summaries)
    }

    pub fn export_audit(&self) -> Result<Vec<AuditRecord>, AuditError> {
        if !Path::new(&self.audit_log_path).exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&self.audit_log_path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            records.push(serde_json::from_str::<AuditRecord>(&line)?);
        }
        Ok(records)
    }

    pub fn tail_audit(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditRecord>, AuditError> {
        let mut records = self
            .export_audit()?
            .into_iter()
            .filter(|record| record.seq >= from_seq)
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.seq);
        Ok(records.into_iter().take(limit).collect())
    }

    pub fn verify_chain(
        &self,
        seq_range: Option<RangeInclusive<u64>>,
    ) -> Result<AuditChainReport, AuditError> {
        let mut records = self.export_audit()?;
        records.sort_by_key(|record| record.seq);

        let selected = if let Some(range) = seq_range {
            records
                .into_iter()
                .filter(|record| range.contains(&record.seq))
                .collect::<Vec<_>>()
        } else {
            records
        };

        let mut previous_hash: Option<String> = None;
        let mut previous_seq = 0;

        for (index, record) in selected.iter().enumerate() {
            if index == 0 {
                previous_seq = record.seq.saturating_sub(1);
            }

            if record.seq != previous_seq + 1 {
                return Ok(AuditChainReport {
                    valid: false,
                    checked_records: selected.len(),
                    first_invalid_seq: Some(record.seq),
                    reason: Some("non-contiguous sequence number".to_string()),
                });
            }

            if previous_seq > 0 && record.prev_hash != previous_hash {
                return Ok(AuditChainReport {
                    valid: false,
                    checked_records: selected.len(),
                    first_invalid_seq: Some(record.seq),
                    reason: Some("previous hash mismatch".to_string()),
                });
            }

            let computed = record.compute_hash()?;
            if computed != record.record_hash {
                return Ok(AuditChainReport {
                    valid: false,
                    checked_records: selected.len(),
                    first_invalid_seq: Some(record.seq),
                    reason: Some("record hash mismatch".to_string()),
                });
            }

            previous_hash = Some(record.record_hash.clone());
            previous_seq = record.seq;
        }

        Ok(AuditChainReport {
            valid: true,
            checked_records: selected.len(),
            first_invalid_seq: None,
            reason: None,
        })
    }

    fn ensure_layout(&self) -> Result<(), AuditError> {
        if let Some(parent) = self.audit_log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&self.receipt_dir)?;
        if !self.audit_log_path.exists() {
            fs::File::create(&self.audit_log_path)?;
        }
        Ok(())
    }

    fn receipt_path(&self, id: Uuid) -> PathBuf {
        self.receipt_dir.join(format!("{id}.json"))
    }

    fn last_record(&self) -> Result<Option<AuditRecord>, AuditError> {
        let mut records = self.export_audit()?;
        records.sort_by_key(|record| record.seq);
        Ok(records.into_iter().next_back())
    }
}

fn default_verification_status() -> VerificationStatus {
    VerificationStatus::Skipped
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use provenclaw_core::{RiskLevel, VerificationReport};

    #[test]
    fn writes_and_verifies_receipt_and_chain() {
        let root = std::env::temp_dir().join(format!("provenclaw-audit-test-{}", Uuid::new_v4()));
        let audit_log = root.join("audit.ndjson");
        let receipt_dir = root.join("receipts");

        let store = AuditStore::new(&audit_log, &receipt_dir).unwrap();
        let receipt = provenclaw_core::ReceiptEnvelope {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            tool_digest: "sha256:test".to_string(),
            policy_hash: "sha256:policy".to_string(),
            decision: "allow".to_string(),
            reason: "policy-match".to_string(),
            output_hash: "deadbeef".to_string(),
            payload: serde_json::json!({"ok": true}),
            receipt_hash: String::new(),
            signature: None,
            signing_key_id: None,
            verification_report: VerificationReport::default(),
            sequence_number: 0,
            prev_audit_hash: None,
            risk_level: RiskLevel::Medium,
        }
        .finalize()
        .unwrap();

        store.persist_receipt(&receipt).unwrap();
        store
            .append_record(&AuditRecord {
                id: receipt.id,
                timestamp: receipt.timestamp,
                tool_digest: receipt.tool_digest.clone(),
                policy_hash: receipt.policy_hash.clone(),
                receipt_hash: receipt.receipt_hash.clone(),
                decision: receipt.decision.clone(),
                reason: receipt.reason.clone(),
                duration_ms: 10,
                seq: 0,
                prev_hash: None,
                record_hash: String::new(),
                verification_status: VerificationStatus::Pass,
            })
            .unwrap();

        assert!(store.verify_receipt(&receipt.id.to_string()).unwrap());
        assert_eq!(store.list_receipts().unwrap().len(), 1);
        assert_eq!(store.export_audit().unwrap().len(), 1);
        assert!(store.verify_chain(None).unwrap().valid);
    }
}
