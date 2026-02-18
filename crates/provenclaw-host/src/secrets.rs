use serde::{Deserialize, Serialize};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretProviderStatus {
    pub backend: String,
    pub available: bool,
    pub degraded: bool,
    pub detail: String,
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret backend unavailable: {0}")]
    Unavailable(String),
}

pub trait SecretProvider {
    fn status(&self) -> SecretProviderStatus;
    #[allow(dead_code)]
    fn get_handle(&self, name: &str) -> Result<String, SecretError>;
}

#[derive(Debug, Default)]
pub struct MacOsKeychainProvider;

impl SecretProvider for MacOsKeychainProvider {
    fn status(&self) -> SecretProviderStatus {
        let available = cfg!(target_os = "macos")
            && Command::new("security")
                .arg("help")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
        SecretProviderStatus {
            backend: "macos-keychain".to_string(),
            available,
            degraded: !available,
            detail: if available {
                "security cli available".to_string()
            } else {
                "security cli unavailable".to_string()
            },
        }
    }

    fn get_handle(&self, name: &str) -> Result<String, SecretError> {
        if !self.status().available {
            return Err(SecretError::Unavailable(
                "macOS keychain backend unavailable".to_string(),
            ));
        }
        Ok(format!("secret://macos-keychain/{name}"))
    }
}

#[derive(Debug, Default)]
pub struct LinuxSecretServiceProvider;

impl SecretProvider for LinuxSecretServiceProvider {
    fn status(&self) -> SecretProviderStatus {
        let available = cfg!(target_os = "linux")
            && Command::new("secret-tool")
                .arg("--help")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
        SecretProviderStatus {
            backend: "linux-secret-service".to_string(),
            available,
            degraded: !available,
            detail: if available {
                "secret-tool available".to_string()
            } else {
                "secret-tool unavailable".to_string()
            },
        }
    }

    fn get_handle(&self, name: &str) -> Result<String, SecretError> {
        if !self.status().available {
            return Err(SecretError::Unavailable(
                "Linux secret service backend unavailable".to_string(),
            ));
        }
        Ok(format!("secret://linux-secret-service/{name}"))
    }
}

#[derive(Debug, Default)]
pub struct SoftwareFallbackProvider;

impl SecretProvider for SoftwareFallbackProvider {
    fn status(&self) -> SecretProviderStatus {
        SecretProviderStatus {
            backend: "software-fallback".to_string(),
            available: true,
            degraded: true,
            detail: "software fallback is active".to_string(),
        }
    }

    fn get_handle(&self, name: &str) -> Result<String, SecretError> {
        Ok(format!("secret://software-fallback/{name}"))
    }
}

pub fn default_provider_status() -> SecretProviderStatus {
    if cfg!(target_os = "macos") {
        let provider = MacOsKeychainProvider;
        let status = provider.status();
        if status.available {
            return status;
        }
    }

    if cfg!(target_os = "linux") {
        let provider = LinuxSecretServiceProvider;
        let status = provider.status();
        if status.available {
            return status;
        }
    }

    SoftwareFallbackProvider.status()
}
