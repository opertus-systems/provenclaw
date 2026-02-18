use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("toml serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Warn,
    Enforce,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Warn
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    Hybrid,
    HardwareOnly,
    SoftwareOnly,
}

impl Default for KeyProviderKind {
    fn default() -> Self {
        Self::Hybrid
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Degraded,
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRequirements {
    #[serde(default = "default_true")]
    pub require_digest: bool,
    #[serde(default = "default_true")]
    pub require_signature: bool,
    #[serde(default = "default_true")]
    pub require_attestation: bool,
    #[serde(default = "default_attestation_max_age_days")]
    pub attestation_max_age_days: u32,
}

impl Default for ProvenanceRequirements {
    fn default() -> Self {
        Self {
            require_digest: true,
            require_signature: true,
            require_attestation: true,
            attestation_max_age_days: default_attestation_max_age_days(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLimits {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_memory_limit_mb")]
    pub memory_limit_mb: u64,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            memory_limit_mb: default_memory_limit_mb(),
            max_output_bytes: default_max_output_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub enforcement_mode: EnforcementMode,
    pub key_provider: KeyProviderKind,
    pub receipt_signing_required: bool,
    pub audit_chain_required: bool,
    pub provenance_requirements: ProvenanceRequirements,
    pub risk_level: RiskLevel,
}

impl SecurityPosture {
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.enforcement_mode, EnforcementMode::Enforce)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRef {
    pub name: String,
    pub digest: String,
    pub publisher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRegistration {
    pub name: String,
    pub digest: String,
    pub publisher: String,
    pub policy: String,
    #[serde(default)]
    pub bundle_path: Option<String>,
    #[serde(default)]
    pub signature_path: Option<String>,
    #[serde(default)]
    pub attestations_path: Option<String>,
    #[serde(default)]
    pub signing_identity: Option<String>,
    #[serde(default)]
    pub verification_profile: Option<String>,
}

impl ToolRegistration {
    pub fn to_tool_ref(&self) -> ToolRef {
        ToolRef {
            name: self.name.clone(),
            digest: self.digest.clone(),
            publisher: self.publisher.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolRegistry {
    pub tools: Vec<ToolRegistration>,
}

impl ToolRegistry {
    pub fn find_by_name(&self, name: &str) -> Option<&ToolRegistration> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    pub fn find_by_digest(&self, digest: &str) -> Option<&ToolRegistration> {
        self.tools.iter().find(|tool| tool.digest == digest)
    }

    pub fn upsert(&mut self, registration: ToolRegistration) {
        if let Some(existing) = self
            .tools
            .iter_mut()
            .find(|tool| tool.name == registration.name)
        {
            *existing = registration;
            return;
        }
        self.tools.push(registration);
        self.tools.sort_by(|left, right| left.name.cmp(&right.name));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainConfig {
    pub workspace_dir: PathBuf,
    pub policy_dir: PathBuf,
    pub receipt_dir: PathBuf,
    pub provenact_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub network_enabled: bool,
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    #[serde(default)]
    pub key_provider: KeyProviderKind,
    #[serde(default)]
    pub provenance_requirements: ProvenanceRequirements,
    #[serde(default = "default_true")]
    pub receipt_signing_required: bool,
    #[serde(default = "default_true")]
    pub audit_chain_required: bool,
    #[serde(default = "default_coverage_slo_target")]
    pub coverage_slo_target: f64,
    #[serde(default = "default_coverage_slo_window_days")]
    pub coverage_slo_window_days: u32,
    #[serde(default)]
    pub runtime_limits: RuntimeLimits,
}

impl MainConfig {
    pub fn default_for_base(base_dir: &Path) -> Self {
        Self {
            workspace_dir: base_dir.join("workspace"),
            policy_dir: base_dir.join("policies"),
            receipt_dir: base_dir.join("receipts"),
            provenact_path: PathBuf::from("provenact"),
            log_level: default_log_level(),
            network_enabled: false,
            enforcement_mode: EnforcementMode::Warn,
            key_provider: KeyProviderKind::Hybrid,
            provenance_requirements: ProvenanceRequirements::default(),
            receipt_signing_required: true,
            audit_chain_required: true,
            coverage_slo_target: default_coverage_slo_target(),
            coverage_slo_window_days: default_coverage_slo_window_days(),
            runtime_limits: RuntimeLimits::default(),
        }
    }

    pub fn from_toml_str(input: &str) -> Result<Self, CoreError> {
        Ok(toml::from_str(input)?)
    }

    pub fn to_toml_string(&self) -> Result<String, CoreError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn security_posture(&self) -> SecurityPosture {
        SecurityPosture {
            enforcement_mode: self.enforcement_mode.clone(),
            key_provider: self.key_provider.clone(),
            receipt_signing_required: self.receipt_signing_required,
            audit_chain_required: self.audit_chain_required,
            provenance_requirements: self.provenance_requirements.clone(),
            risk_level: RiskLevel::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationContext {
    pub request_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub tainted: bool,
    #[serde(default)]
    pub taint_sources: Vec<String>,
}

impl InvocationContext {
    pub fn new(actor: impl Into<String>, tainted: bool) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: actor.into(),
            tainted,
            taint_sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HttpRule {
    pub host: String,
    pub path: String,
    pub method: String,
}

impl HttpRule {
    pub fn normalized_method(&self) -> String {
        self.method.to_ascii_uppercase()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FsRule {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilitySpec {
    #[serde(default)]
    pub net_http: Vec<HttpRule>,
    #[serde(default)]
    pub fs_read: Vec<FsRule>,
    #[serde(default)]
    pub fs_write: Vec<FsRule>,
    #[serde(default)]
    pub secrets_materialize: bool,
    #[serde(default)]
    pub randomness: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub check: String,
    pub status: VerificationStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationReport {
    #[serde(default)]
    pub checks: Vec<VerificationCheck>,
}

impl VerificationReport {
    pub fn summary(&self) -> VerificationStatus {
        if self
            .checks
            .iter()
            .any(|check| check.status == VerificationStatus::Fail)
        {
            return VerificationStatus::Fail;
        }
        if self
            .checks
            .iter()
            .any(|check| check.status == VerificationStatus::Warn)
        {
            return VerificationStatus::Warn;
        }
        if self
            .checks
            .iter()
            .any(|check| check.status == VerificationStatus::Pass)
        {
            return VerificationStatus::Pass;
        }
        VerificationStatus::Skipped
    }

    pub fn push(
        &mut self,
        check: impl Into<String>,
        status: VerificationStatus,
        detail: impl Into<String>,
    ) {
        self.checks.push(VerificationCheck {
            check: check.into(),
            status,
            detail: detail.into(),
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub tool_digest: String,
    pub policy_hash: String,
    pub decision: String,
    pub reason: String,
    pub output_hash: String,
    pub payload: serde_json::Value,
    pub receipt_hash: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub verification_report: VerificationReport,
    #[serde(default)]
    pub sequence_number: u64,
    #[serde(default)]
    pub prev_audit_hash: Option<String>,
    #[serde(default)]
    pub risk_level: RiskLevel,
}

impl ReceiptEnvelope {
    pub fn compute_hash(&self) -> Result<String, CoreError> {
        let mut copy = self.clone();
        copy.receipt_hash.clear();
        copy.signature = None;
        let serialized = serde_json::to_vec(&copy)?;
        Ok(sha256_hex(&serialized))
    }

    pub fn finalize(mut self) -> Result<Self, CoreError> {
        self.receipt_hash = self.compute_hash()?;
        Ok(self)
    }

    pub fn verify_hash(&self) -> Result<bool, CoreError> {
        Ok(self.compute_hash()? == self.receipt_hash)
    }
}

pub fn sha256_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_memory_limit_mb() -> u64 {
    256
}

fn default_max_output_bytes() -> usize {
    1024 * 1024
}

fn default_attestation_max_age_days() -> u32 {
    30
}

fn default_coverage_slo_target() -> f64 {
    99.5
}

fn default_coverage_slo_window_days() -> u32 {
    14
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_replaces_existing_registration() {
        let mut registry = ToolRegistry::default();
        registry.upsert(ToolRegistration {
            name: "fetch_invoice".to_string(),
            digest: "sha256:first".to_string(),
            publisher: "acme.sec".to_string(),
            policy: "policy.default.json".to_string(),
            bundle_path: None,
            signature_path: None,
            attestations_path: None,
            signing_identity: None,
            verification_profile: None,
        });
        registry.upsert(ToolRegistration {
            name: "fetch_invoice".to_string(),
            digest: "sha256:second".to_string(),
            publisher: "acme.sec".to_string(),
            policy: "policy.default.json".to_string(),
            bundle_path: None,
            signature_path: None,
            attestations_path: None,
            signing_identity: None,
            verification_profile: None,
        });

        assert_eq!(registry.tools.len(), 1);
        assert_eq!(
            registry.find_by_name("fetch_invoice").unwrap().digest,
            "sha256:second"
        );
    }

    #[test]
    fn finalized_receipt_hash_verifies() {
        let receipt = ReceiptEnvelope {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            tool_digest: "sha256:abc".to_string(),
            policy_hash: "sha256:def".to_string(),
            decision: "allow".to_string(),
            reason: "policy-match".to_string(),
            output_hash: "out".to_string(),
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

        assert!(receipt.verify_hash().unwrap());
    }

    #[test]
    fn config_defaults_new_security_fields() {
        let cfg = MainConfig::default_for_base(Path::new("/tmp/provenclaw"));
        assert!(matches!(cfg.enforcement_mode, EnforcementMode::Warn));
        assert!(cfg.receipt_signing_required);
        assert!(cfg.audit_chain_required);
    }
}
