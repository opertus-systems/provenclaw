use provenclaw_core::CapabilitySpec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunToolRequest {
    pub tool_name: String,
    #[serde(default)]
    pub input: serde_json::Value,
    #[serde(default)]
    pub capabilities: CapabilitySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunToolResponse {
    pub request_id: String,
    pub decision: String,
    pub reason: String,
    pub receipt_id: String,
    pub output: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuthConfig {
    pub bind_addr: String,
    pub shared_token: String,
}

impl Default for LocalAuthConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:7447".to_string(),
            shared_token: "change-me".to_string(),
        }
    }
}

pub fn is_local_bind_address(bind_addr: &str) -> bool {
    bind_addr.starts_with("127.0.0.1") || bind_addr.starts_with("localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_guard_accepts_loopback() {
        assert!(is_local_bind_address("127.0.0.1:7447"));
        assert!(is_local_bind_address("localhost:7447"));
        assert!(!is_local_bind_address("0.0.0.0:7447"));
    }
}
