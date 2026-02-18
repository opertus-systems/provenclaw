use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use provenclaw_core::{CapabilitySpec, FsRule, HttpRule};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy serialization/parsing failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy exceeds capability ceiling: {0}")]
    CeilingViolation(String),
    #[error("policy signature validation failed: {0}")]
    Signature(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProfile {
    #[serde(default)]
    pub allowed_signers: Vec<String>,
    #[serde(default)]
    pub capabilities: PolicyCapabilities,
    #[serde(default)]
    pub secrets: SecretPolicy,
    #[serde(default)]
    pub signature: Option<PolicySignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySignature {
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyCapabilities {
    #[serde(rename = "net.http", default)]
    pub net_http: NetworkCapability,
    #[serde(rename = "fs.read", default)]
    pub fs_read: FilesystemCapability,
    #[serde(rename = "fs.write", default)]
    pub fs_write: FilesystemCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkCapability {
    #[serde(default)]
    pub allow: Vec<HttpRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemCapability {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    #[serde(default)]
    pub materialize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
    pub policy_hash: String,
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }
}

#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn from_json_str(input: &str) -> Result<PolicyProfile, PolicyError> {
        Ok(serde_json::from_str(input)?)
    }

    pub fn to_hash(policy: &PolicyProfile) -> Result<String, PolicyError> {
        let serialized = serde_json::to_vec(policy)?;
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn validate_signature_metadata(
        policy: &PolicyProfile,
        require_signature: bool,
    ) -> Result<(), PolicyError> {
        if !require_signature {
            return Ok(());
        }

        let Some(signature) = &policy.signature else {
            return Err(PolicyError::Signature(
                "missing policy signature metadata".to_string(),
            ));
        };

        if signature.key_id.trim().is_empty() || signature.signature.trim().is_empty() {
            return Err(PolicyError::Signature(
                "invalid policy signature fields".to_string(),
            ));
        }

        Ok(())
    }

    pub fn canonical_signing_payload(policy: &PolicyProfile) -> Result<Vec<u8>, PolicyError> {
        let mut unsigned = policy.clone();
        unsigned.signature = None;
        Ok(serde_json::to_vec(&unsigned)?)
    }

    pub fn verify_signature(
        policy: &PolicyProfile,
        public_key_b64: &str,
        require_signature: bool,
    ) -> Result<(), PolicyError> {
        Self::validate_signature_metadata(policy, require_signature)?;
        if !require_signature {
            return Ok(());
        }

        let signature = policy.signature.as_ref().ok_or_else(|| {
            PolicyError::Signature("missing policy signature metadata".to_string())
        })?;
        if !signature.algorithm.eq_ignore_ascii_case("ed25519") {
            return Err(PolicyError::Signature(format!(
                "unsupported policy signature algorithm: {}",
                signature.algorithm
            )));
        }

        let public_key_bytes = STANDARD
            .decode(public_key_b64)
            .map_err(|err| PolicyError::Signature(format!("invalid public key encoding: {err}")))?;
        let public_key_array: [u8; 32] = public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PolicyError::Signature("public key must be 32 bytes".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|err| PolicyError::Signature(format!("invalid public key: {err}")))?;

        let signature_bytes = STANDARD
            .decode(&signature.signature)
            .map_err(|err| PolicyError::Signature(format!("invalid signature encoding: {err}")))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|err| PolicyError::Signature(format!("invalid signature bytes: {err}")))?;

        let payload = Self::canonical_signing_payload(policy)?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|err| PolicyError::Signature(format!("signature verification failed: {err}")))
    }

    pub fn validate_capability_ceilings(
        policy: &PolicyProfile,
        ceiling: &CapabilitySpec,
    ) -> Result<(), PolicyError> {
        for allowed_rule in &policy.capabilities.net_http.allow {
            let matches = ceiling.net_http.iter().any(|ceiling_rule| {
                allowed_rule.host == ceiling_rule.host
                    && method_matches(&allowed_rule.method, &ceiling_rule.method)
                    && allowed_rule.path.starts_with(&ceiling_rule.path)
            });
            if !matches {
                return Err(PolicyError::CeilingViolation(format!(
                    "network rule outside ceiling: {} {}{}",
                    allowed_rule.method, allowed_rule.host, allowed_rule.path
                )));
            }
        }

        for allowed_path in &policy.capabilities.fs_read.allow {
            if !path_allowed_by_rules(allowed_path, &ceiling.fs_read) {
                return Err(PolicyError::CeilingViolation(format!(
                    "fs.read path outside ceiling: {allowed_path}"
                )));
            }
        }

        for allowed_path in &policy.capabilities.fs_write.allow {
            if !path_allowed_by_rules(allowed_path, &ceiling.fs_write) {
                return Err(PolicyError::CeilingViolation(format!(
                    "fs.write path outside ceiling: {allowed_path}"
                )));
            }
        }

        if policy.secrets.materialize && !ceiling.secrets_materialize {
            return Err(PolicyError::CeilingViolation(
                "secrets.materialize outside ceiling".to_string(),
            ));
        }

        Ok(())
    }

    pub fn evaluate(
        policy: &PolicyProfile,
        signer: &str,
        requested: &CapabilitySpec,
        tainted: bool,
        network_enabled: bool,
    ) -> Result<PolicyDecision, PolicyError> {
        let policy_hash = Self::to_hash(policy)?;

        if !policy.allowed_signers.is_empty() && !policy.allowed_signers.iter().any(|s| s == signer)
        {
            return Ok(deny("signer-not-allowed", policy_hash));
        }

        if requested.randomness {
            return Ok(deny("randomness-denied-phase0", policy_hash));
        }

        if requested.secrets_materialize && !policy.secrets.materialize {
            return Ok(deny("secret-materialization-denied", policy_hash));
        }

        if tainted && !requested.net_http.is_empty() {
            return Ok(deny("tainted-input-network-downgrade", policy_hash));
        }

        if !network_enabled && !requested.net_http.is_empty() {
            return Ok(deny("network-disabled-in-config", policy_hash));
        }

        for rule in &requested.net_http {
            let allowed = policy.capabilities.net_http.allow.iter().any(|allow_rule| {
                allow_rule.host == rule.host
                    && method_matches(&allow_rule.method, &rule.method)
                    && rule.path.starts_with(&allow_rule.path)
            });
            if !allowed {
                return Ok(deny(
                    &format!(
                        "net.http rule rejected: {} {}{}",
                        rule.method, rule.host, rule.path
                    ),
                    policy_hash,
                ));
            }
        }

        for rule in &requested.fs_read {
            if !path_allowed(&rule.path, &policy.capabilities.fs_read.allow) {
                return Ok(deny(
                    &format!("fs.read rule rejected: {}", rule.path),
                    policy_hash,
                ));
            }
        }

        for rule in &requested.fs_write {
            if !path_allowed(&rule.path, &policy.capabilities.fs_write.allow) {
                return Ok(deny(
                    &format!("fs.write rule rejected: {}", rule.path),
                    policy_hash,
                ));
            }
        }

        Ok(allow("policy-match", policy_hash))
    }

    pub fn explain(policy: &PolicyProfile, decision: &PolicyDecision) -> String {
        format!(
            "decision={} reason={} allowed_signers={} net_http_allow={} fs_read_allow={} fs_write_allow={} secrets_materialize={} policy_signature={}",
            decision_label(&decision.decision),
            decision.reason,
            policy.allowed_signers.len(),
            policy.capabilities.net_http.allow.len(),
            policy.capabilities.fs_read.allow.len(),
            policy.capabilities.fs_write.allow.len(),
            policy.secrets.materialize,
            if policy.signature.is_some() {
                "present"
            } else {
                "missing"
            }
        )
    }
}

fn method_matches(allow_method: &str, request_method: &str) -> bool {
    allow_method == "*" || allow_method.eq_ignore_ascii_case(request_method)
}

fn path_allowed(path: &str, allowed_prefixes: &[String]) -> bool {
    allowed_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn path_allowed_by_rules(path: &str, rules: &[FsRule]) -> bool {
    rules.iter().any(|rule| path.starts_with(&rule.path))
}

fn allow(reason: &str, policy_hash: String) -> PolicyDecision {
    PolicyDecision {
        decision: Decision::Allow,
        reason: reason.to_string(),
        policy_hash,
    }
}

fn deny(reason: &str, policy_hash: String) -> PolicyDecision {
    PolicyDecision {
        decision: Decision::Deny,
        reason: reason.to_string(),
        policy_hash,
    }
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenclaw_core::{CapabilitySpec, FsRule, HttpRule};

    fn sample_policy() -> PolicyProfile {
        PolicyProfile {
            allowed_signers: vec!["acme.sec".to_string()],
            capabilities: PolicyCapabilities {
                net_http: NetworkCapability {
                    allow: vec![HttpRule {
                        host: "api.example.com".to_string(),
                        path: "/v1/".to_string(),
                        method: "POST".to_string(),
                    }],
                },
                fs_read: FilesystemCapability {
                    allow: vec!["/data/".to_string()],
                },
                fs_write: FilesystemCapability::default(),
            },
            secrets: SecretPolicy { materialize: false },
            signature: Some(PolicySignature {
                key_id: "policy-key".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "placeholder".to_string(),
            }),
        }
    }

    #[test]
    fn allows_matching_rules() {
        let policy = sample_policy();
        let requested = CapabilitySpec {
            net_http: vec![HttpRule {
                host: "api.example.com".to_string(),
                path: "/v1/invoices".to_string(),
                method: "POST".to_string(),
            }],
            fs_read: vec![FsRule {
                path: "/data/invoices/2026.json".to_string(),
            }],
            ..CapabilitySpec::default()
        };

        let decision =
            PolicyEngine::evaluate(&policy, "acme.sec", &requested, false, true).unwrap();
        assert!(decision.is_allowed());
    }

    #[test]
    fn denies_tainted_network_use() {
        let policy = sample_policy();
        let requested = CapabilitySpec {
            net_http: vec![HttpRule {
                host: "api.example.com".to_string(),
                path: "/v1/invoices".to_string(),
                method: "POST".to_string(),
            }],
            ..CapabilitySpec::default()
        };

        let decision = PolicyEngine::evaluate(&policy, "acme.sec", &requested, true, true).unwrap();
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason, "tainted-input-network-downgrade");
    }

    #[test]
    fn verifies_cryptographic_signature() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use ed25519_dalek::{Signer, SigningKey};

        let mut policy = sample_policy();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let payload = PolicyEngine::canonical_signing_payload(&policy).unwrap();
        let signature = signing_key.sign(&payload);
        policy.signature = Some(PolicySignature {
            key_id: "policy-key".to_string(),
            algorithm: "ed25519".to_string(),
            signature: BASE64.encode(signature.to_bytes()),
        });

        let pubkey = BASE64.encode(signing_key.verifying_key().as_bytes());
        PolicyEngine::verify_signature(&policy, &pubkey, true).unwrap();
    }
}
