mod provenance;
mod runtime;
mod secrets;
mod signing;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use provenance::{ProvenactCliVerifier, Verifier};
use provenclaw_audit::{AuditChainReport, AuditError, AuditRecord, AuditStore, ReceiptSummary};
use provenclaw_control_plane::{
    ControlPlane, ControlPlaneHealth, ControlPlaneProfile, LocalControlPlane,
};
use provenclaw_core::{
    CapabilitySpec, CoreError, EnforcementMode, FsRule, HttpRule, InvocationContext, MainConfig,
    ReceiptEnvelope, RiskLevel, SecurityPosture, ToolRegistration, ToolRegistry,
    VerificationReport, VerificationStatus, sha256_hex,
};
use provenclaw_policy::{
    Decision, PolicyDecision, PolicyEngine, PolicyError, PolicyProfile, PolicySignature,
};
use runtime::{RuntimeError, RuntimeExecutor, WasiLikeExecutor};
use secrets::{SecretProviderStatus, default_provider_status};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use signing::{ReceiptSigner, SigningError};
use std::collections::BTreeMap;
use std::fs;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_POLICY_FILE: &str = "policy.default.json";
const DEFAULT_TRUST_FILE: &str = "trust.json";

#[derive(Debug, Error)]
pub enum HostError {
    #[error("home directory is unavailable")]
    HomeUnavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("signing error: {0}")]
    Signing(#[from] SigningError),
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("bundle verification failed: {0}")]
    Verification(String),
}

#[derive(Debug, Clone)]
pub struct HostPaths {
    pub base_dir: PathBuf,
}

impl HostPaths {
    pub fn discover() -> Result<Self, HostError> {
        if let Ok(value) = std::env::var("PROVENCLAW_HOME") {
            return Ok(Self {
                base_dir: PathBuf::from(value),
            });
        }

        let home = dirs::home_dir().ok_or(HostError::HomeUnavailable)?;
        Ok(Self {
            base_dir: home.join(".provenclaw"),
        })
    }

    pub fn from_base_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn config_path(&self) -> PathBuf {
        self.base_dir.join("config.toml")
    }

    pub fn tools_path(&self) -> PathBuf {
        self.base_dir.join("tools.json")
    }

    pub fn policies_dir(&self) -> PathBuf {
        self.base_dir.join("policies")
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.base_dir.join("audit.ndjson")
    }

    pub fn trust_path(&self) -> PathBuf {
        self.base_dir.join(DEFAULT_TRUST_FILE)
    }

    pub fn metrics_path(&self) -> PathBuf {
        self.base_dir.join("metrics.ndjson")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResponse {
    pub request_id: Uuid,
    pub decision: String,
    pub reason: String,
    pub receipt_id: Uuid,
    pub output: Value,
    pub verification_status: VerificationStatus,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustStore {
    #[serde(default)]
    pub roots: Vec<String>,
    #[serde(default)]
    pub signers: Vec<String>,
    #[serde(default)]
    pub revoked: Vec<String>,
    #[serde(default)]
    pub policy_keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<usize>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReceiptFilters {
    pub decision: Option<String>,
    pub tool_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptListItem {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<Utc>,
    pub decision: String,
    pub tool_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeepReceipt {
    pub receipt: ReceiptEnvelope,
    pub audit_record: Option<AuditRecord>,
    pub hash_valid: bool,
    pub signature_valid: bool,
    pub chain_valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnforcementSloReport {
    pub window_days: u32,
    pub target_pct: f64,
    pub total_runs: usize,
    pub compliant_runs: usize,
    pub compliance_pct: f64,
    pub recommend_enforce: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceRunSummary {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<Utc>,
    pub tool_digest: String,
    pub decision: String,
    pub reason: String,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsReport {
    pub security_posture: SecurityPosture,
    pub secret_provider: SecretProviderStatus,
    pub control_plane: ControlPlaneStatus,
    pub enforcement_slo: EnforcementSloReport,
    pub recent_provenance: Vec<ProvenanceRunSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlPlaneStatus {
    pub profile: ControlPlaneProfile,
    pub health: ControlPlaneHealth,
}

#[derive(Debug, Clone)]
pub struct Host {
    paths: HostPaths,
}

impl Host {
    pub fn discover() -> Result<Self, HostError> {
        Ok(Self {
            paths: HostPaths::discover()?,
        })
    }

    pub fn with_paths(paths: HostPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &HostPaths {
        &self.paths
    }

    pub fn init_layout(&self) -> Result<(), HostError> {
        fs::create_dir_all(&self.paths.base_dir)?;

        let config_path = self.paths.config_path();
        if !config_path.exists() {
            let config = MainConfig::default_for_base(&self.paths.base_dir);
            fs::create_dir_all(&config.workspace_dir)?;
            fs::create_dir_all(&config.policy_dir)?;
            fs::create_dir_all(&config.receipt_dir)?;
            fs::write(config_path, config.to_toml_string()?)?;
        } else {
            let config = self.load_config()?;
            fs::create_dir_all(&config.workspace_dir)?;
            fs::create_dir_all(&config.policy_dir)?;
            fs::create_dir_all(&config.receipt_dir)?;
        }

        let tools_path = self.paths.tools_path();
        if !tools_path.exists() {
            fs::write(
                tools_path,
                serde_json::to_string_pretty(&ToolRegistry::default())?,
            )?;
        }

        let mut trust = if self.paths.trust_path().exists() {
            self.load_trust_store()?
        } else {
            TrustStore {
                roots: vec!["local-root".to_string()],
                signers: vec!["acme.sec".to_string()],
                revoked: Vec::new(),
                policy_keys: BTreeMap::new(),
            }
        };

        let policy_key_id = ensure_policy_key_in_trust(&self.paths.base_dir, &mut trust)?;
        self.save_trust_store(&trust)?;

        let policy_path = self.paths.policies_dir().join(DEFAULT_POLICY_FILE);
        if !policy_path.exists() {
            fs::create_dir_all(self.paths.policies_dir())?;
            let policy = signed_default_policy_json(&self.paths.base_dir, &policy_key_id)?;
            fs::write(&policy_path, policy)?;
        }

        if !self.paths.metrics_path().exists() {
            fs::File::create(self.paths.metrics_path())?;
        }

        let config = self.load_config()?;
        let _store = AuditStore::new(self.paths.audit_log_path(), config.receipt_dir.clone())?;
        let _ = ReceiptSigner::load_or_create(&self.paths.base_dir, &config)?;
        Ok(())
    }

    pub fn load_config(&self) -> Result<MainConfig, HostError> {
        let payload = fs::read_to_string(self.paths.config_path())?;
        Ok(MainConfig::from_toml_str(&payload)?)
    }

    pub fn save_config(&self, config: &MainConfig) -> Result<(), HostError> {
        fs::write(self.paths.config_path(), config.to_toml_string()?)?;
        Ok(())
    }

    pub fn get_security_posture(&self) -> Result<SecurityPosture, HostError> {
        self.init_layout()?;
        let mut posture = self.load_config()?.security_posture();
        let provider = default_provider_status();
        if provider.degraded {
            posture.risk_level = RiskLevel::Degraded;
        }
        Ok(posture)
    }

    pub fn list_tools(&self) -> Result<Vec<ToolRegistration>, HostError> {
        let registry = self.load_registry()?;
        Ok(registry.tools)
    }

    pub fn list_tools_page(
        &self,
        cursor: Option<usize>,
        limit: usize,
    ) -> Result<Page<ToolRegistration>, HostError> {
        let all = self.list_tools()?;
        Ok(paginate(all, cursor, limit.max(1)))
    }

    pub fn add_tool(
        &self,
        digest: String,
        name: Option<String>,
        publisher: String,
        policy: String,
    ) -> Result<ToolRegistration, HostError> {
        self.add_tool_extended(
            digest, name, publisher, policy, None, None, None, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_tool_extended(
        &self,
        digest: String,
        name: Option<String>,
        publisher: String,
        policy: String,
        bundle_path: Option<String>,
        signature_path: Option<String>,
        attestations_path: Option<String>,
        signing_identity: Option<String>,
        verification_profile: Option<String>,
    ) -> Result<ToolRegistration, HostError> {
        self.init_layout()?;
        let mut registry = self.load_registry()?;

        let resolved_name = name.unwrap_or_else(|| default_tool_name_from_digest(&digest));
        let registration = ToolRegistration {
            name: resolved_name,
            digest,
            publisher,
            policy,
            bundle_path,
            signature_path,
            attestations_path,
            signing_identity,
            verification_profile,
        };

        registry.upsert(registration.clone());
        self.save_registry(&registry)?;
        Ok(registration)
    }

    pub fn run_tool(&self, name: &str, input: Value) -> Result<RunResponse, HostError> {
        self.init_layout()?;

        let config = self.load_config()?;
        let trust_store = self.load_trust_store()?;
        let tool = self
            .load_registry()?
            .find_by_name(name)
            .cloned()
            .ok_or_else(|| HostError::UnknownTool(name.to_string()))?;

        let mut verification_report = self.verify_bundle(&config, &trust_store, &tool)?;

        let policy = self.load_policy_profile(&config, &tool.policy)?;
        match self.validate_policy_signature(&config, &trust_store, &policy) {
            Ok(()) => verification_report.push(
                "policy.signature",
                VerificationStatus::Pass,
                "policy signature validated",
            ),
            Err(err) => verification_report.push(
                "policy.signature",
                VerificationStatus::Fail,
                err.to_string(),
            ),
        }

        PolicyEngine::validate_capability_ceilings(&policy, &phase0_capability_ceiling())?;
        let tainted = input
            .get("tainted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let actor = input
            .get("actor")
            .and_then(Value::as_str)
            .unwrap_or("cli")
            .to_string();
        let read_only = input
            .get("read_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let requested = input
            .get("capabilities")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();

        let context = InvocationContext::new(actor, tainted);
        let started_at = Utc::now();
        let policy_decision = PolicyEngine::evaluate(
            &policy,
            &tool.publisher,
            &requested,
            context.tainted,
            config.network_enabled,
        )?;

        let (mut decision, mut reason, mut warnings, should_execute) =
            self.resolve_execution_decision(&config, &policy_decision, &verification_report);

        let output = if should_execute {
            let executor = WasiLikeExecutor;
            match executor.execute(&config, &tool, &requested, &input, read_only) {
                Ok(output) => output,
                Err(err) => {
                    decision = "deny".to_string();
                    reason = format!("runtime-execution-failed:{}", runtime_error_code(&err));
                    warnings.push(format!("runtime execution failed: {err}"));
                    json!({
                        "status": "denied",
                        "reason": reason,
                        "tool": tool.name,
                    })
                }
            }
        } else {
            json!({
                "status": "denied",
                "reason": reason,
                "tool": tool.name,
            })
        };

        let finished_at = Utc::now();
        let output_hash = sha256_hex(&serde_json::to_vec(&output)?);
        let store = self.audit_store(&config)?;
        let (last_seq, prev_hash) = store.next_chain_metadata()?;
        let next_seq = last_seq + 1;

        let signer = if config.receipt_signing_required {
            Some(ReceiptSigner::load_or_create(
                &self.paths.base_dir,
                &config,
            )?)
        } else {
            None
        };

        let mut receipt = ReceiptEnvelope {
            id: context.request_id,
            timestamp: finished_at,
            tool_digest: tool.digest.clone(),
            policy_hash: policy_decision.policy_hash.clone(),
            decision: decision.clone(),
            reason: reason.clone(),
            output_hash,
            payload: output.clone(),
            receipt_hash: String::new(),
            signature: None,
            signing_key_id: signer
                .as_ref()
                .map(|instance| instance.key_id().to_string()),
            verification_report: verification_report.clone(),
            sequence_number: next_seq,
            prev_audit_hash: prev_hash.clone(),
            risk_level: signer
                .as_ref()
                .map(|instance| instance.risk_level().clone())
                .unwrap_or(RiskLevel::Medium),
        }
        .finalize()?;

        if let Some(signer) = &signer {
            let outcome = signer.sign_receipt(&receipt)?;
            receipt.signature = Some(outcome.signature);
        }

        let duration_ms = (finished_at - started_at).num_milliseconds().max(0) as u64;
        let audit_record = AuditRecord {
            id: context.request_id,
            timestamp: finished_at,
            tool_digest: tool.digest,
            policy_hash: policy_decision.policy_hash,
            receipt_hash: receipt.receipt_hash.clone(),
            decision: decision.clone(),
            reason: reason.clone(),
            duration_ms,
            seq: next_seq,
            prev_hash,
            record_hash: String::new(),
            verification_status: verification_report.summary(),
        };

        store.append_record(&audit_record)?;
        store.persist_receipt(&receipt)?;
        self.append_metrics_event(
            &decision,
            verification_report.summary() == VerificationStatus::Pass,
        )?;

        Ok(RunResponse {
            request_id: context.request_id,
            decision,
            reason,
            receipt_id: receipt.id,
            output,
            verification_status: verification_report.summary(),
            warnings,
        })
    }

    pub fn list_receipts(&self) -> Result<Vec<ReceiptSummary>, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let store = self.audit_store(&config)?;
        store.list_receipts().map_err(HostError::from)
    }

    pub fn list_receipts_page(
        &self,
        cursor: Option<usize>,
        limit: usize,
        filters: ReceiptFilters,
    ) -> Result<Page<ReceiptListItem>, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let mut items = load_receipt_items(&config.receipt_dir)?;

        if let Some(decision) = filters.decision {
            items.retain(|item| item.decision == decision);
        }
        if let Some(tool_digest) = filters.tool_digest {
            items.retain(|item| item.tool_digest == tool_digest);
        }

        items.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        Ok(paginate(items, cursor, limit.max(1)))
    }

    pub fn get_receipt_deep(&self, id: &str) -> Result<DeepReceipt, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let store = self.audit_store(&config)?;
        let receipt = store.load_receipt(id)?;
        let hash_valid = receipt.verify_hash()?;

        let signature_valid = if config.receipt_signing_required {
            let signer = ReceiptSigner::load_or_create(&self.paths.base_dir, &config)?;
            signer.verify_receipt(&receipt)?
        } else {
            true
        };

        let audit_record = store.find_audit_record(receipt.id)?;
        let chain_valid = if audit_record.is_some() {
            store.verify_chain(None)?.valid
        } else {
            false
        };

        Ok(DeepReceipt {
            receipt,
            audit_record,
            hash_valid,
            signature_valid,
            chain_valid,
        })
    }

    pub fn verify_receipt(&self, id: &str) -> Result<bool, HostError> {
        let deep = self.get_receipt_deep(id)?;
        Ok(deep.hash_valid && deep.signature_valid && deep.chain_valid)
    }

    pub fn tail_audit(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditRecord>, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let store = self.audit_store(&config)?;
        Ok(store.tail_audit(from_seq, limit)?)
    }

    pub fn verify_audit_chain(
        &self,
        seq_range: Option<RangeInclusive<u64>>,
    ) -> Result<AuditChainReport, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let store = self.audit_store(&config)?;
        Ok(store.verify_chain(seq_range)?)
    }

    pub fn explain_policy(&self, name: &str) -> Result<String, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let trust_store = self.load_trust_store()?;
        let tool = self
            .load_registry()?
            .find_by_name(name)
            .cloned()
            .ok_or_else(|| HostError::UnknownTool(name.to_string()))?;

        let policy = self.load_policy_profile(&config, &tool.policy)?;
        let policy_signature = match self.validate_policy_signature(&config, &trust_store, &policy)
        {
            Ok(()) => "policy_signature=ok".to_string(),
            Err(err) => format!("policy_signature=failed details=\"{err}\""),
        };

        let ceiling_result =
            PolicyEngine::validate_capability_ceilings(&policy, &phase0_capability_ceiling());
        let decision = PolicyEngine::evaluate(
            &policy,
            &tool.publisher,
            &CapabilitySpec::default(),
            false,
            config.network_enabled,
        )?;
        let base = PolicyEngine::explain(&policy, &decision);
        let ceiling = match ceiling_result {
            Ok(()) => "ceiling=ok".to_string(),
            Err(err) => format!("ceiling=violation details=\"{err}\""),
        };
        Ok(format!("{base} {ceiling} {policy_signature}"))
    }

    pub fn evaluate_enforcement_slo(
        &self,
        window_days: u32,
        target_pct: f64,
    ) -> Result<EnforcementSloReport, HostError> {
        self.init_layout()?;
        let records = self.export_audit_json()?;
        let threshold = Utc::now() - Duration::days(i64::from(window_days));

        let in_window = records
            .into_iter()
            .filter(|record| record.timestamp >= threshold)
            .collect::<Vec<_>>();

        let total_runs = in_window.len();
        let compliant_runs = in_window
            .iter()
            .filter(|record| {
                record.decision.starts_with("allow")
                    && record.verification_status == VerificationStatus::Pass
            })
            .count();

        let compliance_pct = if total_runs == 0 {
            0.0
        } else {
            (compliant_runs as f64 * 100.0) / total_runs as f64
        };

        Ok(EnforcementSloReport {
            window_days,
            target_pct,
            total_runs,
            compliant_runs,
            compliance_pct,
            recommend_enforce: total_runs > 0 && compliance_pct >= target_pct,
        })
    }

    pub fn get_provenance_report(
        &self,
        last_n_runs: usize,
    ) -> Result<Vec<ProvenanceRunSummary>, HostError> {
        let mut records = self.export_audit_json()?;
        records.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));

        Ok(records
            .into_iter()
            .take(last_n_runs)
            .map(|record| ProvenanceRunSummary {
                id: record.id,
                timestamp: record.timestamp,
                tool_digest: record.tool_digest,
                decision: record.decision,
                reason: record.reason,
                verification_status: record.verification_status,
            })
            .collect())
    }

    pub fn diagnostics_report(&self) -> Result<DiagnosticsReport, HostError> {
        let config = self.load_config()?;
        Ok(DiagnosticsReport {
            security_posture: self.get_security_posture()?,
            secret_provider: default_provider_status(),
            control_plane: self.get_control_plane_status()?,
            enforcement_slo: self.evaluate_enforcement_slo(
                config.coverage_slo_window_days,
                config.coverage_slo_target,
            )?,
            recent_provenance: self.get_provenance_report(25)?,
        })
    }

    pub fn get_control_plane_status(&self) -> Result<ControlPlaneStatus, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let control_plane = LocalControlPlane::for_local_host(config.enforcement_mode.clone());
        Ok(ControlPlaneStatus {
            profile: control_plane.profile(),
            health: control_plane.health(),
        })
    }

    pub fn list_trust_signers(&self) -> Result<Vec<String>, HostError> {
        self.init_layout()?;
        let trust = self.load_trust_store()?;
        Ok(trust.signers)
    }

    pub fn add_trust_signer(&self, signer: &str) -> Result<(), HostError> {
        self.init_layout()?;
        let mut trust = self.load_trust_store()?;
        if !trust.signers.iter().any(|existing| existing == signer) {
            trust.signers.push(signer.to_string());
            trust.signers.sort();
        }
        self.save_trust_store(&trust)
    }

    pub fn revoke_trust_signer(&self, signer: &str) -> Result<(), HostError> {
        self.init_layout()?;
        let mut trust = self.load_trust_store()?;
        if !trust.revoked.iter().any(|existing| existing == signer) {
            trust.revoked.push(signer.to_string());
            trust.revoked.sort();
        }
        self.save_trust_store(&trust)
    }

    pub fn set_enforcement_mode(&self, mode: EnforcementMode) -> Result<(), HostError> {
        let mut config = self.load_config()?;
        config.enforcement_mode = mode;
        self.save_config(&config)
    }

    pub fn export_audit_json(&self) -> Result<Vec<AuditRecord>, HostError> {
        self.init_layout()?;
        let config = self.load_config()?;
        let store = self.audit_store(&config)?;
        Ok(store.export_audit()?)
    }

    pub fn export_audit_ndjson(&self) -> Result<String, HostError> {
        let records = self.export_audit_json()?;
        let lines = records
            .into_iter()
            .map(|record| serde_json::to_string(&record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(lines.join("\n"))
    }

    fn load_registry(&self) -> Result<ToolRegistry, HostError> {
        let payload = fs::read_to_string(self.paths.tools_path())?;
        Ok(serde_json::from_str(&payload)?)
    }

    fn save_registry(&self, registry: &ToolRegistry) -> Result<(), HostError> {
        fs::write(
            self.paths.tools_path(),
            serde_json::to_string_pretty(registry)?,
        )?;
        Ok(())
    }

    fn load_trust_store(&self) -> Result<TrustStore, HostError> {
        let payload = fs::read_to_string(self.paths.trust_path())?;
        Ok(serde_json::from_str(&payload)?)
    }

    fn save_trust_store(&self, trust_store: &TrustStore) -> Result<(), HostError> {
        fs::write(
            self.paths.trust_path(),
            serde_json::to_string_pretty(trust_store)?,
        )?;
        Ok(())
    }

    fn audit_store(&self, config: &MainConfig) -> Result<AuditStore, HostError> {
        Ok(AuditStore::new(
            self.paths.audit_log_path(),
            &config.receipt_dir,
        )?)
    }

    fn load_policy_profile(
        &self,
        config: &MainConfig,
        policy_reference: &str,
    ) -> Result<PolicyProfile, HostError> {
        let policy_path = resolve_policy_path(config, &self.paths.base_dir, policy_reference);
        let payload = fs::read_to_string(policy_path)?;
        Ok(PolicyEngine::from_json_str(&payload)?)
    }

    fn verify_bundle(
        &self,
        config: &MainConfig,
        trust_store: &TrustStore,
        tool: &ToolRegistration,
    ) -> Result<VerificationReport, HostError> {
        let verifier = ProvenactCliVerifier;
        let mut report = verifier
            .verify(config, tool)
            .map_err(|err| HostError::Verification(err.to_string()))?;

        if trust_store
            .revoked
            .iter()
            .any(|revoked| revoked == &tool.publisher)
        {
            report.push(
                "trust.signer",
                VerificationStatus::Fail,
                format!("signer {} is revoked", tool.publisher),
            );
        } else if trust_store
            .signers
            .iter()
            .any(|signer| signer == &tool.publisher)
        {
            report.push(
                "trust.signer",
                VerificationStatus::Pass,
                format!("signer {} is trusted", tool.publisher),
            );
        } else {
            report.push(
                "trust.signer",
                VerificationStatus::Fail,
                format!("signer {} is not trusted", tool.publisher),
            );
        }

        for check in &mut report.checks {
            if check.check == "signature.artifact"
                && !config.provenance_requirements.require_signature
                && check.status == VerificationStatus::Fail
            {
                check.status = VerificationStatus::Skipped;
                check.detail = "signature requirement disabled by config".to_string();
            }
            if check.check == "attestation.artifact"
                && !config.provenance_requirements.require_attestation
                && check.status == VerificationStatus::Fail
            {
                check.status = VerificationStatus::Skipped;
                check.detail = "attestation requirement disabled by config".to_string();
            }
            if check.check == "digest.format"
                && !config.provenance_requirements.require_digest
                && check.status == VerificationStatus::Fail
            {
                check.status = VerificationStatus::Warn;
                check.detail = "digest format warning in non-strict mode".to_string();
            }
        }

        Ok(report)
    }

    fn validate_policy_signature(
        &self,
        config: &MainConfig,
        trust_store: &TrustStore,
        policy: &PolicyProfile,
    ) -> Result<(), HostError> {
        PolicyEngine::validate_signature_metadata(
            policy,
            config.provenance_requirements.require_signature,
        )?;
        if !config.provenance_requirements.require_signature {
            return Ok(());
        }

        let signature = policy.signature.as_ref().ok_or_else(|| {
            HostError::Verification("missing policy signature metadata".to_string())
        })?;
        let public_key = trust_store
            .policy_keys
            .get(&signature.key_id)
            .ok_or_else(|| {
                HostError::Verification(format!(
                    "missing trusted policy key for key_id={}",
                    signature.key_id
                ))
            })?;
        PolicyEngine::verify_signature(policy, public_key, true)?;
        Ok(())
    }

    fn resolve_execution_decision(
        &self,
        config: &MainConfig,
        policy_decision: &PolicyDecision,
        verification_report: &VerificationReport,
    ) -> (String, String, Vec<String>, bool) {
        let mut warnings = Vec::new();

        if policy_decision.decision == Decision::Deny {
            return (
                "deny".to_string(),
                policy_decision.reason.clone(),
                warnings,
                false,
            );
        }

        let required_failures = required_check_failures(config, verification_report);
        if !required_failures.is_empty() {
            let details = required_failures.join(",");
            return match config.enforcement_mode {
                EnforcementMode::Enforce => (
                    "deny".to_string(),
                    format!("provenance-required-check-failed:{details}"),
                    warnings,
                    false,
                ),
                EnforcementMode::Warn => {
                    warnings.push(format!(
                        "required provenance checks failed but warn mode allowed execution: {details}"
                    ));
                    (
                        "allow_with_warnings".to_string(),
                        "policy-match-with-provenance-warning".to_string(),
                        warnings,
                        true,
                    )
                }
            };
        }

        match verification_report.summary() {
            VerificationStatus::Fail => match config.enforcement_mode {
                EnforcementMode::Enforce => (
                    "deny".to_string(),
                    "provenance-failed".to_string(),
                    warnings,
                    false,
                ),
                EnforcementMode::Warn => {
                    warnings.push(
                        "provenance checks failed but warn mode allowed execution".to_string(),
                    );
                    (
                        "allow_with_warnings".to_string(),
                        "policy-match-with-provenance-warning".to_string(),
                        warnings,
                        true,
                    )
                }
            },
            VerificationStatus::Warn => {
                warnings.push("provenance checks returned warnings".to_string());
                (
                    "allow_with_warnings".to_string(),
                    "policy-match-with-provenance-warning".to_string(),
                    warnings,
                    true,
                )
            }
            _ => (
                "allow".to_string(),
                policy_decision.reason.clone(),
                warnings,
                true,
            ),
        }
    }

    fn append_metrics_event(&self, decision: &str, compliant: bool) -> Result<(), HostError> {
        let line = serde_json::to_string(&json!({
            "timestamp": Utc::now(),
            "decision": decision,
            "compliant": compliant,
        }))?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.paths.metrics_path())?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

fn default_tool_name_from_digest(digest: &str) -> String {
    let compact = digest.trim_start_matches("sha256:");
    let prefix: String = compact.chars().take(12).collect();
    format!("tool-{prefix}")
}

fn phase0_capability_ceiling() -> CapabilitySpec {
    CapabilitySpec {
        net_http: vec![HttpRule {
            host: "api.example.com".to_string(),
            path: "/v1/".to_string(),
            method: "POST".to_string(),
        }],
        fs_read: vec![FsRule {
            path: "/data/".to_string(),
        }],
        fs_write: Vec::new(),
        secrets_materialize: false,
        randomness: false,
    }
}

fn resolve_policy_path(config: &MainConfig, base_dir: &Path, policy_reference: &str) -> PathBuf {
    let candidate = Path::new(policy_reference);
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }

    let direct = config.policy_dir.join(policy_reference);
    if direct.exists() {
        return direct;
    }

    let from_base = base_dir.join(policy_reference);
    if from_base.exists() {
        return from_base;
    }

    let stripped = policy_reference
        .strip_prefix("policies/")
        .unwrap_or(policy_reference);
    config.policy_dir.join(stripped)
}

fn required_check_failures(config: &MainConfig, report: &VerificationReport) -> Vec<String> {
    let mut required = vec!["provenact.cli", "trust.signer", "publisher.identity"];
    if config.provenance_requirements.require_digest {
        required.push("digest.format");
    }
    if config.provenance_requirements.require_signature {
        required.push("signature.artifact");
        required.push("policy.signature");
    }
    if config.provenance_requirements.require_attestation {
        required.push("attestation.artifact");
    }

    required
        .into_iter()
        .filter_map(|check| match latest_check_status(report, check) {
            Some(VerificationStatus::Pass) => None,
            Some(status) => Some(format!("{check}={}", verification_status_label(status))),
            None => Some(format!("{check}=missing")),
        })
        .collect()
}

fn latest_check_status(
    report: &VerificationReport,
    check_name: &str,
) -> Option<VerificationStatus> {
    report
        .checks
        .iter()
        .rev()
        .find(|check| check.check == check_name)
        .map(|check| check.status.clone())
}

fn verification_status_label(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Pass => "pass",
        VerificationStatus::Warn => "warn",
        VerificationStatus::Fail => "fail",
        VerificationStatus::Skipped => "skipped",
    }
}

fn runtime_error_code(err: &RuntimeError) -> &'static str {
    match err {
        RuntimeError::Timeout => "timeout",
        RuntimeError::OutputLimit => "output_limit",
        RuntimeError::CapabilityDenied(_) => "capability_denied",
        RuntimeError::Execution(_) => "execution_error",
    }
}

fn ensure_policy_key_in_trust(
    base_dir: &Path,
    trust_store: &mut TrustStore,
) -> Result<String, HostError> {
    let signing_key = load_or_create_policy_signing_key(base_dir)?;
    let verifying_key = signing_key.verifying_key();
    let key_id = format!(
        "policy-ed25519:{}",
        &sha256_hex(verifying_key.as_bytes())[..16]
    );
    let public_key_b64 = BASE64.encode(verifying_key.as_bytes());
    trust_store
        .policy_keys
        .insert(key_id.clone(), public_key_b64);
    Ok(key_id)
}

fn load_or_create_policy_signing_key(base_dir: &Path) -> Result<SigningKey, HostError> {
    let keys_dir = base_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;
    let key_path = keys_dir.join("policy_signing_key.hex");
    if key_path.exists() {
        let payload = fs::read_to_string(&key_path)?;
        let bytes = hex::decode(payload.trim()).map_err(|err| {
            HostError::Verification(format!("invalid policy signing key encoding: {err}"))
        })?;
        let key_array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            HostError::Verification("policy signing key must be 32 bytes".to_string())
        })?;
        return Ok(SigningKey::from_bytes(&key_array));
    }

    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    fs::write(key_path, hex::encode(key.to_bytes()))?;
    Ok(key)
}

fn signed_default_policy_json(base_dir: &Path, key_id: &str) -> Result<String, HostError> {
    let signing_key = load_or_create_policy_signing_key(base_dir)?;
    let mut policy = PolicyProfile {
        allowed_signers: vec!["acme.sec".to_string()],
        capabilities: provenclaw_policy::PolicyCapabilities {
            net_http: provenclaw_policy::NetworkCapability {
                allow: vec![HttpRule {
                    host: "api.example.com".to_string(),
                    path: "/v1/".to_string(),
                    method: "POST".to_string(),
                }],
            },
            fs_read: provenclaw_policy::FilesystemCapability {
                allow: vec!["/data/".to_string()],
            },
            fs_write: provenclaw_policy::FilesystemCapability::default(),
        },
        secrets: provenclaw_policy::SecretPolicy { materialize: false },
        signature: None,
    };

    let payload = PolicyEngine::canonical_signing_payload(&policy)?;
    let signature = signing_key.sign(&payload);
    policy.signature = Some(PolicySignature {
        key_id: key_id.to_string(),
        algorithm: "ed25519".to_string(),
        signature: BASE64.encode(signature.to_bytes()),
    });

    Ok(serde_json::to_string_pretty(&policy)?)
}

fn paginate<T>(all: Vec<T>, cursor: Option<usize>, limit: usize) -> Page<T> {
    let total = all.len();
    let start = cursor.unwrap_or(0).min(total);
    let end = (start + limit).min(total);
    let mut all = all;
    let items = all.drain(start..end).collect::<Vec<_>>();
    let next_cursor = if end < total { Some(end) } else { None };
    Page {
        items,
        next_cursor,
        total,
    }
}

fn load_receipt_items(receipt_dir: &Path) -> Result<Vec<ReceiptListItem>, HostError> {
    let mut items = Vec::new();
    if !receipt_dir.exists() {
        return Ok(items);
    }

    for entry in fs::read_dir(receipt_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let payload = fs::read_to_string(entry.path())?;
        let receipt: ReceiptEnvelope = serde_json::from_str(&payload)?;
        items.push(ReceiptListItem {
            id: receipt.id,
            timestamp: receipt.timestamp,
            decision: receipt.decision,
            tool_digest: receipt.tool_digest,
        });
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenclaw_control_plane::{ControlPlaneHealth, ControlPlaneMode, TransportKind};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn configure_stubbed_provenact(host: &Host) -> PathBuf {
        let stub = host.paths().base_dir.join("provenact-stub.sh");
        fs::write(
            &stub,
            r#"#!/bin/sh
set -eu
command="${1:-}"
if [ "$command" = "verify" ]; then
  echo '{"verdict":"pass","checks":[{"name":"signature","status":"pass","detail":"signature verified"},{"name":"attestation","status":"pass","detail":"attestation verified"}]}'
  exit 0
fi
if [ "$command" = "run" ]; then
  echo '{"status":"executed","runtime":{"kind":"provenact-cli"},"result":{"ok":true}}'
  exit 0
fi
echo '{"verdict":"fail","reason":"unknown command"}' >&2
exit 1
"#,
        )
        .unwrap();
        let mut perms = fs::metadata(&stub).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&stub, perms).unwrap();

        let mut config = host.load_config().unwrap();
        config.provenact_path = stub.clone();
        host.save_config(&config).unwrap();
        stub
    }

    #[test]
    fn init_add_tool_and_run_golden_path() {
        let root = std::env::temp_dir().join(format!("provenclaw-host-test-{}", Uuid::new_v4()));
        let host = Host::with_paths(HostPaths::from_base_dir(root));
        host.init_layout().unwrap();
        #[cfg(unix)]
        configure_stubbed_provenact(&host);

        let signature_file = host.paths().base_dir.join("sig.json");
        let attest_file = host.paths().base_dir.join("attest.json");
        let bundle_file = host.paths().base_dir.join("bundle.wasm");
        fs::write(&signature_file, "{}").unwrap();
        fs::write(&attest_file, "{}").unwrap();
        fs::write(&bundle_file, b"wasm").unwrap();

        let tool = host
            .add_tool_extended(
                "sha256:1234abcd".to_string(),
                Some("fetch_invoice".to_string()),
                "acme.sec".to_string(),
                "policy.default.json".to_string(),
                Some(bundle_file.display().to_string()),
                Some(signature_file.display().to_string()),
                Some(attest_file.display().to_string()),
                Some("acme.sec".to_string()),
                Some("default".to_string()),
            )
            .unwrap();
        assert_eq!(tool.name, "fetch_invoice");

        let result = host
            .run_tool(
                "fetch_invoice",
                serde_json::json!({"payload": {"invoice": 42}}),
            )
            .unwrap();
        assert!(result.decision.starts_with("allow"));

        let receipts = host.list_receipts().unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(host.verify_receipt(&result.receipt_id.to_string()).unwrap());
    }

    #[test]
    fn policy_outside_ceiling_fails_run() {
        let root = std::env::temp_dir().join(format!("provenclaw-host-test-{}", Uuid::new_v4()));
        let host = Host::with_paths(HostPaths::from_base_dir(root.clone()));
        host.init_layout().unwrap();
        #[cfg(unix)]
        configure_stubbed_provenact(&host);

        let signature_file = host.paths().base_dir.join("sig.json");
        let attest_file = host.paths().base_dir.join("attest.json");
        let bundle_file = host.paths().base_dir.join("bundle.wasm");
        fs::write(&signature_file, "{}").unwrap();
        fs::write(&attest_file, "{}").unwrap();
        fs::write(&bundle_file, b"wasm").unwrap();

        let mut config = host.load_config().unwrap();
        config.provenance_requirements.require_signature = false;
        host.save_config(&config).unwrap();

        let config_path = root.join("policies/outside-ceiling.json");
        fs::write(
            &config_path,
            r#"{
  "allowed_signers": ["acme.sec"],
  "capabilities": {
    "net.http": {
      "allow": [{"host": "bad.example.com", "path": "/", "method": "GET"}]
    }
  },
  "secrets": {"materialize": false},
  "signature": {"key_id": "p", "algorithm": "ed25519", "signature": "s"}
}"#,
        )
        .unwrap();

        host.add_tool_extended(
            "sha256:1234abcd".to_string(),
            Some("bad_tool".to_string()),
            "acme.sec".to_string(),
            "outside-ceiling.json".to_string(),
            Some(bundle_file.display().to_string()),
            Some(signature_file.display().to_string()),
            Some(attest_file.display().to_string()),
            None,
            None,
        )
        .unwrap();

        let err = host
            .run_tool("bad_tool", json!({"payload": {}}))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("policy exceeds capability ceiling")
        );
    }

    #[test]
    fn enforce_mode_denies_required_provenance_failure() {
        let root = std::env::temp_dir().join(format!("provenclaw-host-test-{}", Uuid::new_v4()));
        let host = Host::with_paths(HostPaths::from_base_dir(root));
        host.init_layout().unwrap();

        let signature_file = host.paths().base_dir.join("sig.json");
        let attest_file = host.paths().base_dir.join("attest.json");
        let bundle_file = host.paths().base_dir.join("bundle.wasm");
        fs::write(&signature_file, "{}").unwrap();
        fs::write(&attest_file, "{}").unwrap();
        fs::write(&bundle_file, b"wasm").unwrap();

        let mut config = host.load_config().unwrap();
        config.enforcement_mode = EnforcementMode::Enforce;
        host.save_config(&config).unwrap();

        host.add_tool_extended(
            "sha256:1234abcd".to_string(),
            Some("strict_tool".to_string()),
            "acme.sec".to_string(),
            "policy.default.json".to_string(),
            Some(bundle_file.display().to_string()),
            Some(signature_file.display().to_string()),
            Some(attest_file.display().to_string()),
            None,
            None,
        )
        .unwrap();

        let result = host
            .run_tool("strict_tool", json!({"payload": {"hello": "world"}}))
            .unwrap();
        assert_eq!(result.decision, "deny");
        assert!(result.reason.contains("provenance-required-check-failed"));
    }

    #[test]
    fn warn_mode_runtime_failure_is_audited_as_deny() {
        let root = std::env::temp_dir().join(format!("provenclaw-host-test-{}", Uuid::new_v4()));
        let host = Host::with_paths(HostPaths::from_base_dir(root));
        host.init_layout().unwrap();

        let signature_file = host.paths().base_dir.join("sig.json");
        let attest_file = host.paths().base_dir.join("attest.json");
        let bundle_file = host.paths().base_dir.join("bundle.wasm");
        fs::write(&signature_file, "{}").unwrap();
        fs::write(&attest_file, "{}").unwrap();
        fs::write(&bundle_file, b"wasm").unwrap();

        host.add_tool_extended(
            "sha256:1234abcd".to_string(),
            Some("runtime_failure_tool".to_string()),
            "acme.sec".to_string(),
            "policy.default.json".to_string(),
            Some(bundle_file.display().to_string()),
            Some(signature_file.display().to_string()),
            Some(attest_file.display().to_string()),
            None,
            None,
        )
        .unwrap();

        let result = host
            .run_tool(
                "runtime_failure_tool",
                json!({"payload": {"hello": "world"}}),
            )
            .unwrap();
        assert_eq!(result.decision, "deny");
        assert!(result.reason.starts_with("runtime-execution-failed:"));

        let receipts = host.list_receipts().unwrap();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn diagnostics_report_exposes_local_control_plane_boundary() {
        let root = std::env::temp_dir().join(format!("provenclaw-host-test-{}", Uuid::new_v4()));
        let host = Host::with_paths(HostPaths::from_base_dir(root));
        host.init_layout().unwrap();

        let report = host.diagnostics_report().unwrap();
        assert_eq!(report.control_plane.health, ControlPlaneHealth::Ready);
        assert_eq!(
            report.control_plane.profile.mode,
            ControlPlaneMode::LocalOnly
        );
        assert_eq!(
            report.control_plane.profile.endpoint.transport,
            TransportKind::InProcess
        );
    }
}
