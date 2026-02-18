use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use provenclaw_core::{KeyProviderKind, MainConfig, ReceiptEnvelope, RiskLevel, sha256_hex};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("hardware-backed key required but unavailable")]
    HardwareUnavailable,
    #[error("receipt hashing failed: {0}")]
    Hash(String),
}

#[derive(Debug, Clone)]
pub struct SigningOutcome {
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptSigner {
    signing_key: SigningKey,
    key_id: String,
    risk_level: RiskLevel,
}

impl ReceiptSigner {
    pub fn load_or_create(base_dir: &Path, config: &MainConfig) -> Result<Self, SigningError> {
        let keys_dir = base_dir.join("keys");
        fs::create_dir_all(&keys_dir)?;
        let key_path = keys_dir.join("receipt_signing_key.hex");

        let signing_key = if key_path.exists() {
            let payload = fs::read_to_string(&key_path)?;
            let bytes = hex::decode(payload.trim())
                .map_err(|err| SigningError::InvalidKey(err.to_string()))?;
            let key_bytes: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| SigningError::InvalidKey("expected 32-byte key".to_string()))?;
            SigningKey::from_bytes(&key_bytes)
        } else {
            let signing_key = SigningKey::generate(&mut OsRng);
            fs::write(&key_path, hex::encode(signing_key.to_bytes()))?;
            signing_key
        };

        let hardware_available = std::env::var("PROVENCLAW_HARDWARE_KEY")
            .map(|value| value == "1")
            .unwrap_or(false);

        if matches!(config.key_provider, KeyProviderKind::HardwareOnly) && !hardware_available {
            return Err(SigningError::HardwareUnavailable);
        }

        let risk_level = if hardware_available {
            RiskLevel::Low
        } else {
            match config.key_provider {
                KeyProviderKind::HardwareOnly => RiskLevel::High,
                KeyProviderKind::Hybrid => RiskLevel::Degraded,
                KeyProviderKind::SoftwareOnly => RiskLevel::Medium,
            }
        };

        let verifying_key = signing_key.verifying_key();
        let key_id = format!("ed25519:{}", &sha256_hex(verifying_key.as_bytes())[..16]);

        Ok(Self {
            signing_key,
            key_id,
            risk_level,
        })
    }

    pub fn sign_receipt(&self, receipt: &ReceiptEnvelope) -> Result<SigningOutcome, SigningError> {
        let hash = receipt
            .compute_hash()
            .map_err(|err| SigningError::Hash(err.to_string()))?;
        let signature: Signature = self.signing_key.sign(hash.as_bytes());
        Ok(SigningOutcome {
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }

    pub fn verify_receipt(&self, receipt: &ReceiptEnvelope) -> Result<bool, SigningError> {
        let Some(signature) = &receipt.signature else {
            return Ok(false);
        };

        let signature_bytes = STANDARD
            .decode(signature)
            .map_err(|err| SigningError::InvalidKey(err.to_string()))?;
        let signature: Signature = Signature::from_slice(&signature_bytes)
            .map_err(|err| SigningError::InvalidKey(err.to_string()))?;

        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        let hash = receipt
            .compute_hash()
            .map_err(|err| SigningError::Hash(err.to_string()))?;
        Ok(verifying_key.verify(hash.as_bytes(), &signature).is_ok())
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn risk_level(&self) -> &RiskLevel {
        &self.risk_level
    }
}
