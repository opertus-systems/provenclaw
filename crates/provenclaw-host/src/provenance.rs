use provenclaw_core::{
    MainConfig, ToolRegistration, VerificationReport, VerificationStatus, sha256_hex,
};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("failed to parse verifier output: {0}")]
    Parse(String),
}

pub trait Verifier {
    fn verify(
        &self,
        config: &MainConfig,
        tool: &ToolRegistration,
    ) -> Result<VerificationReport, VerifierError>;
}

#[derive(Debug, Default)]
pub struct ProvenactCliVerifier;

impl Verifier for ProvenactCliVerifier {
    fn verify(
        &self,
        config: &MainConfig,
        tool: &ToolRegistration,
    ) -> Result<VerificationReport, VerifierError> {
        let mut report = VerificationReport::default();

        if tool.digest.starts_with("sha256:") && tool.digest.len() > "sha256:".len() {
            report.push(
                "digest.format",
                VerificationStatus::Pass,
                "tool digest uses sha256 format",
            );
        } else {
            report.push(
                "digest.format",
                VerificationStatus::Fail,
                "tool digest must use sha256:<hex> format",
            );
        }

        if tool.publisher.trim().is_empty() {
            report.push(
                "publisher.identity",
                VerificationStatus::Fail,
                "publisher must be present",
            );
        } else {
            report.push(
                "publisher.identity",
                VerificationStatus::Pass,
                "publisher identity present",
            );
        }

        match &tool.signature_path {
            Some(path) if Path::new(path).exists() => report.push(
                "signature.artifact",
                VerificationStatus::Pass,
                "signature artifact found",
            ),
            Some(path) => report.push(
                "signature.artifact",
                VerificationStatus::Fail,
                format!("signature artifact missing: {path}"),
            ),
            None => report.push(
                "signature.artifact",
                VerificationStatus::Fail,
                "signature artifact not configured",
            ),
        }

        match &tool.attestations_path {
            Some(path) if Path::new(path).exists() => report.push(
                "attestation.artifact",
                VerificationStatus::Pass,
                "attestation artifact found",
            ),
            Some(path) => report.push(
                "attestation.artifact",
                VerificationStatus::Fail,
                format!("attestation artifact missing: {path}"),
            ),
            None => report.push(
                "attestation.artifact",
                VerificationStatus::Fail,
                "attestation artifact not configured",
            ),
        }

        if config.provenact_path.as_os_str().is_empty() {
            report.push(
                "provenact.cli",
                VerificationStatus::Fail,
                "provenact path is empty",
            );
            return Ok(report);
        }

        let mut cmd = Command::new(&config.provenact_path);
        cmd.arg("verify")
            .arg("--digest")
            .arg(&tool.digest)
            .arg("--publisher")
            .arg(&tool.publisher)
            .arg("--json");

        if let Some(bundle_path) = &tool.bundle_path {
            cmd.arg("--bundle").arg(bundle_path);
        }
        if let Some(signature_path) = &tool.signature_path {
            cmd.arg("--signature").arg(signature_path);
        }
        if let Some(attestation_path) = &tool.attestations_path {
            cmd.arg("--attestation").arg(attestation_path);
        }

        match cmd.output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    let json: Value = serde_json::from_str(&stdout)
                        .map_err(|err| VerifierError::Parse(err.to_string()))?;
                    ingest_machine_readable_report(&json, &mut report);
                } else {
                    report.push(
                        "provenact.cli",
                        VerificationStatus::Pass,
                        "verifier command succeeded",
                    );
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                report.push(
                    "provenact.cli",
                    VerificationStatus::Fail,
                    format!("command failed: {}", stderr.trim()),
                );
            }
            Err(err) => {
                report.push(
                    "provenact.cli",
                    VerificationStatus::Fail,
                    format!("could not execute verifier command: {err}"),
                );
            }
        }

        Ok(report)
    }
}

fn ingest_machine_readable_report(json: &Value, report: &mut VerificationReport) {
    let mut has_cli_verdict = false;

    if let Some(verdict) = json
        .get("verdict")
        .and_then(Value::as_str)
        .or_else(|| json.get("status").and_then(Value::as_str))
    {
        report.push(
            "provenact.cli",
            map_status(verdict),
            format!("verdict={verdict}"),
        );
        has_cli_verdict = true;
    }

    if let Some(checks) = json.get("checks").and_then(Value::as_array) {
        for check in checks {
            let name = check
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| check.get("check").and_then(Value::as_str))
                .unwrap_or("unknown");
            let status = check
                .get("status")
                .and_then(Value::as_str)
                .or_else(|| check.get("result").and_then(Value::as_str))
                .unwrap_or("fail");
            let detail = check
                .get("detail")
                .and_then(Value::as_str)
                .or_else(|| check.get("reason").and_then(Value::as_str))
                .unwrap_or("no details from verifier");
            report.push(format!("provenact.{name}"), map_status(status), detail);
        }
    }

    if let Ok(raw) = serde_json::to_vec(json) {
        report.push(
            "provenact.evidence",
            VerificationStatus::Pass,
            format!("sha256={}", sha256_hex(&raw)),
        );
    }

    if !has_cli_verdict {
        report.push(
            "provenact.cli",
            VerificationStatus::Pass,
            "verifier command succeeded",
        );
    }
}

fn map_status(input: &str) -> VerificationStatus {
    match input.to_ascii_lowercase().as_str() {
        "pass" | "ok" | "success" => VerificationStatus::Pass,
        "warn" | "warning" => VerificationStatus::Warn,
        "skip" | "skipped" => VerificationStatus::Skipped,
        _ => VerificationStatus::Fail,
    }
}
