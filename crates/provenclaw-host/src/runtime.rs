use provenclaw_core::{CapabilitySpec, MainConfig, ToolRegistration};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime timeout exceeded")]
    Timeout,
    #[error("runtime output exceeded configured limit")]
    OutputLimit,
    #[error("capability denied at runtime boundary: {0}")]
    CapabilityDenied(String),
    #[error("runtime execution error: {0}")]
    Execution(String),
}

pub trait RuntimeExecutor {
    fn execute(
        &self,
        config: &MainConfig,
        tool: &ToolRegistration,
        requested: &CapabilitySpec,
        input: &Value,
        read_only: bool,
    ) -> Result<Value, RuntimeError>;
}

#[derive(Debug, Default)]
pub struct WasiLikeExecutor;

impl RuntimeExecutor for WasiLikeExecutor {
    fn execute(
        &self,
        config: &MainConfig,
        tool: &ToolRegistration,
        requested: &CapabilitySpec,
        input: &Value,
        read_only: bool,
    ) -> Result<Value, RuntimeError> {
        let broker = CapabilityBroker::new(requested, read_only, config.network_enabled);
        broker.preflight()?;
        execute_with_provenact(config, tool, requested, input, read_only)
    }
}

#[derive(Debug)]
struct CapabilityBroker<'a> {
    requested: &'a CapabilitySpec,
    read_only: bool,
    network_enabled: bool,
}

impl<'a> CapabilityBroker<'a> {
    fn new(requested: &'a CapabilitySpec, read_only: bool, network_enabled: bool) -> Self {
        Self {
            requested,
            read_only,
            network_enabled,
        }
    }

    fn preflight(&self) -> Result<(), RuntimeError> {
        if self.requested.randomness {
            return Err(RuntimeError::CapabilityDenied(
                "randomness denied in runtime boundary".to_string(),
            ));
        }

        if self.requested.secrets_materialize {
            return Err(RuntimeError::CapabilityDenied(
                "secret materialization denied in runtime boundary".to_string(),
            ));
        }

        if self.read_only && !self.requested.fs_write.is_empty() {
            return Err(RuntimeError::CapabilityDenied(
                "fs.write denied in read-only mode".to_string(),
            ));
        }

        if !self.network_enabled && !self.requested.net_http.is_empty() {
            return Err(RuntimeError::CapabilityDenied(
                "net.http denied because network is disabled".to_string(),
            ));
        }

        for rule in &self.requested.fs_read {
            if !path_is_sandbox_safe(&rule.path) {
                return Err(RuntimeError::CapabilityDenied(format!(
                    "fs.read path is outside sandbox constraints: {}",
                    rule.path
                )));
            }
        }

        for rule in &self.requested.fs_write {
            if !path_is_sandbox_safe(&rule.path) {
                return Err(RuntimeError::CapabilityDenied(format!(
                    "fs.write path is outside sandbox constraints: {}",
                    rule.path
                )));
            }
        }

        Ok(())
    }
}

fn execute_with_provenact(
    config: &MainConfig,
    tool: &ToolRegistration,
    requested: &CapabilitySpec,
    input: &Value,
    read_only: bool,
) -> Result<Value, RuntimeError> {
    let bundle_path = tool.bundle_path.as_deref().ok_or_else(|| {
        RuntimeError::Execution("bundle path is required for secure execution".to_string())
    })?;
    if !Path::new(bundle_path).exists() {
        return Err(RuntimeError::Execution(format!(
            "bundle path does not exist: {bundle_path}"
        )));
    }

    let request_path = runtime_request_path();
    let request_payload = json!({
        "input": input,
        "capabilities": requested,
        "runtime": {
            "read_only": read_only,
            "network_enabled": config.network_enabled,
            "timeout_ms": config.runtime_limits.timeout_ms,
            "memory_limit_mb": config.runtime_limits.memory_limit_mb,
            "max_output_bytes": config.runtime_limits.max_output_bytes,
        }
    });
    let request_bytes = serde_json::to_vec(&request_payload).map_err(|err| {
        RuntimeError::Execution(format!(
            "failed to serialize runtime request payload: {err}"
        ))
    })?;
    fs::write(&request_path, request_bytes).map_err(|err| {
        RuntimeError::Execution(format!("failed to write runtime payload: {err}"))
    })?;

    let mut cmd = Command::new(&config.provenact_path);
    cmd.arg("run")
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--digest")
        .arg(&tool.digest)
        .arg("--publisher")
        .arg(&tool.publisher)
        .arg("--input")
        .arg(&request_path)
        .arg("--json")
        .arg("--timeout-ms")
        .arg(config.runtime_limits.timeout_ms.to_string())
        .arg("--memory-mb")
        .arg(config.runtime_limits.memory_limit_mb.to_string())
        .arg("--max-output-bytes")
        .arg(config.runtime_limits.max_output_bytes.to_string());

    let output = cmd.output();
    let _ = fs::remove_file(&request_path);

    match output {
        Ok(output) if output.status.success() => {
            if output.stdout.len() > config.runtime_limits.max_output_bytes {
                return Err(RuntimeError::OutputLimit);
            }

            if output.stdout.is_empty() {
                return Ok(json!({
                    "status": "executed",
                    "runtime": {
                        "kind": "provenact-cli",
                        "bundle": bundle_path,
                    },
                    "tool": {
                        "name": tool.name,
                        "digest": tool.digest,
                        "publisher": tool.publisher,
                    }
                }));
            }

            let parsed: Value = serde_json::from_slice(&output.stdout).map_err(|err| {
                RuntimeError::Execution(format!("provenact returned non-json output: {err}"))
            })?;
            let encoded = serde_json::to_vec(&parsed).map_err(|_| RuntimeError::OutputLimit)?;
            if encoded.len() > config.runtime_limits.max_output_bytes {
                return Err(RuntimeError::OutputLimit);
            }
            Ok(parsed)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.to_ascii_lowercase().contains("timeout") {
                return Err(RuntimeError::Timeout);
            }
            Err(RuntimeError::Execution(format!(
                "provenact run failed: {}",
                stderr.trim()
            )))
        }
        Err(err) => Err(RuntimeError::Execution(format!(
            "failed to launch provenact runtime: {err}"
        ))),
    }
}

fn runtime_request_path() -> PathBuf {
    std::env::temp_dir().join(format!("provenclaw-runtime-{}.json", Uuid::new_v4()))
}

fn path_is_sandbox_safe(path: &str) -> bool {
    path.starts_with('/') && !path_has_parent_traversal(path)
}

fn path_has_parent_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenclaw_core::{FsRule, HttpRule, RuntimeLimits};

    fn tool() -> ToolRegistration {
        ToolRegistration {
            name: "t".to_string(),
            digest: "sha256:abc".to_string(),
            publisher: "acme.sec".to_string(),
            policy: "policy.default.json".to_string(),
            bundle_path: None,
            signature_path: None,
            attestations_path: None,
            signing_identity: None,
            verification_profile: None,
        }
    }

    fn test_config() -> MainConfig {
        let base = std::env::temp_dir().join(format!("provenclaw-runtime-{}", Uuid::new_v4()));
        MainConfig {
            runtime_limits: RuntimeLimits {
                timeout_ms: 5_000,
                memory_limit_mb: 64,
                max_output_bytes: 64 * 1024,
            },
            ..MainConfig::default_for_base(&base)
        }
    }

    #[test]
    fn denies_read_only_fs_write() {
        let executor = WasiLikeExecutor;
        let requested = CapabilitySpec {
            fs_write: vec![FsRule {
                path: "/data/out.json".to_string(),
            }],
            ..CapabilitySpec::default()
        };

        let err = executor
            .execute(&test_config(), &tool(), &requested, &json!({}), true)
            .unwrap_err();
        assert!(err.to_string().contains("read-only"));
    }

    #[test]
    fn denies_network_when_disabled() {
        let executor = WasiLikeExecutor;
        let requested = CapabilitySpec {
            net_http: vec![HttpRule {
                host: "api.example.com".to_string(),
                path: "/v1".to_string(),
                method: "POST".to_string(),
            }],
            ..CapabilitySpec::default()
        };

        let err = executor
            .execute(&test_config(), &tool(), &requested, &json!({}), false)
            .unwrap_err();
        assert!(err.to_string().contains("network is disabled"));
    }

    #[test]
    fn denies_unsafe_filesystem_path() {
        let executor = WasiLikeExecutor;
        let requested = CapabilitySpec {
            fs_read: vec![FsRule {
                path: "../etc/passwd".to_string(),
            }],
            ..CapabilitySpec::default()
        };

        let err = executor
            .execute(&test_config(), &tool(), &requested, &json!({}), false)
            .unwrap_err();
        assert!(err.to_string().contains("outside sandbox constraints"));
    }
}
