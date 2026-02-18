use clap::{Parser, Subcommand};
use provenclaw_core::EnforcementMode;
use provenclaw_host::{Host, HostError, ReceiptFilters};
use provenclaw_tui::{TuiOptions, run_tui};
use serde_json::json;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
enum CliError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("host error: {0}")]
    Host(#[from] HostError),
    #[error("tui error: {0}")]
    Tui(#[from] provenclaw_tui::TuiError),
    #[error("{0}")]
    Message(String),
}

#[derive(Parser)]
#[command(name = "provenclaw")]
#[command(about = "Policy-governed runtime for verified tools")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Tui {
        #[arg(long, default_value_t = false)]
        read_only: bool,
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
    Init,
    Tools {
        #[command(subcommand)]
        command: ToolCommands,
    },
    Run {
        name: String,
        #[arg(long)]
        input: PathBuf,
    },
    Chat,
    Receipts {
        #[command(subcommand)]
        command: ReceiptCommands,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },
    Enforcement {
        #[command(subcommand)]
        command: EnforcementCommands,
    },
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticsCommands,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ToolCommands {
    Add {
        digest: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "acme.sec")]
        publisher: String,
        #[arg(long, default_value = "policy.default.json")]
        policy: String,
        #[arg(long)]
        bundle: Option<String>,
        #[arg(long)]
        signature: Option<String>,
        #[arg(long)]
        attestation: Option<String>,
        #[arg(long)]
        signing_identity: Option<String>,
        #[arg(long)]
        verification_profile: Option<String>,
    },
    Ls,
}

#[derive(Subcommand)]
enum ReceiptCommands {
    Ls,
    Verify {
        id: String,
    },
    DeepVerify {
        id: String,
    },
    Export {
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    Explain { tool: String },
}

#[derive(Subcommand)]
enum TrustCommands {
    Init,
    Ls,
    AddSigner { signer: String },
    RevokeSigner { signer: String },
}

#[derive(Subcommand)]
enum EnforcementCommands {
    Status,
    EvaluateSlo {
        #[arg(long)]
        window_days: Option<u32>,
        #[arg(long)]
        target_pct: Option<f64>,
    },
    SetMode {
        mode: String,
    },
}

#[derive(Subcommand)]
enum DiagnosticsCommands {
    SecurityReport,
}

fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            if !std::io::stdout().is_terminal() {
                return Err(CliError::Message(
                    "No subcommand provided and no TTY detected. Use `provenclaw <subcommand>` for automation or run in an interactive terminal for TUI.".to_string(),
                ));
            }
            run_tui(TuiOptions::default())?;
            Ok(())
        }
        Some(Commands::Tui {
            read_only,
            snapshot,
        }) => {
            run_tui(TuiOptions {
                read_only,
                snapshot,
            })?;
            Ok(())
        }
        Some(command) => run_non_interactive(command),
    }
}

fn run_non_interactive(command: Commands) -> Result<(), CliError> {
    let host = Host::discover()?;

    match command {
        Commands::Init => {
            host.init_layout()?;
            println!("initialized {}", host.paths().base_dir.display());
        }
        Commands::Tools { command } => match command {
            ToolCommands::Add {
                digest,
                name,
                publisher,
                policy,
                bundle,
                signature,
                attestation,
                signing_identity,
                verification_profile,
            } => {
                let registration = host.add_tool_extended(
                    digest,
                    name,
                    publisher,
                    policy,
                    bundle,
                    signature,
                    attestation,
                    signing_identity,
                    verification_profile,
                )?;
                println!(
                    "added tool name={} digest={} publisher={} policy={}",
                    registration.name,
                    registration.digest,
                    registration.publisher,
                    registration.policy
                );
            }
            ToolCommands::Ls => {
                let tools = host.list_tools_page(None, 1000)?;
                if tools.items.is_empty() {
                    println!("no tools registered");
                } else {
                    println!("name\tdigest\tpublisher\tpolicy\tbundle\tsignature\tattestation");
                    for tool in tools.items {
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            tool.name,
                            tool.digest,
                            tool.publisher,
                            tool.policy,
                            tool.bundle_path.unwrap_or_else(|| "-".to_string()),
                            tool.signature_path.unwrap_or_else(|| "-".to_string()),
                            tool.attestations_path.unwrap_or_else(|| "-".to_string()),
                        );
                    }
                }
            }
        },
        Commands::Run { name, input } => {
            let payload = fs::read_to_string(&input)?;
            let input_json: serde_json::Value = serde_json::from_str(&payload)?;
            let response = host.run_tool(&name, input_json)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "request_id": response.request_id,
                    "decision": response.decision,
                    "reason": response.reason,
                    "receipt_id": response.receipt_id,
                    "verification_status": response.verification_status,
                    "warnings": response.warnings,
                    "output": response.output,
                }))?
            );
        }
        Commands::Chat => {
            println!(
                "Phase 0.5 uses the TUI as the interactive experience. Run `provenclaw` or `provenclaw tui`."
            );
        }
        Commands::Receipts { command } => match command {
            ReceiptCommands::Ls => {
                let receipts = host.list_receipts_page(None, 1000, ReceiptFilters::default())?;
                if receipts.items.is_empty() {
                    println!("no receipts found");
                } else {
                    println!("id\ttimestamp\tdecision\ttool_digest");
                    for receipt in receipts.items {
                        println!(
                            "{}\t{}\t{}\t{}",
                            receipt.id, receipt.timestamp, receipt.decision, receipt.tool_digest
                        );
                    }
                }
            }
            ReceiptCommands::Verify { id } => {
                let verified = host.verify_receipt(&id)?;
                println!(
                    "receipt {} {}",
                    id,
                    if verified { "valid" } else { "invalid" }
                );
            }
            ReceiptCommands::DeepVerify { id } => {
                let deep = host.get_receipt_deep(&id)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "id": deep.receipt.id,
                        "hash_valid": deep.hash_valid,
                        "signature_valid": deep.signature_valid,
                        "chain_valid": deep.chain_valid,
                        "decision": deep.receipt.decision,
                        "reason": deep.receipt.reason,
                        "verification_summary": deep.receipt.verification_report.summary(),
                    }))?
                );
            }
            ReceiptCommands::Export { format } => match format.as_str() {
                "json" => {
                    let records = host.export_audit_json()?;
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                "ndjson" => {
                    let payload = host.export_audit_ndjson()?;
                    if payload.is_empty() {
                        println!();
                    } else {
                        println!("{payload}");
                    }
                }
                _ => {
                    return Err(CliError::Message(
                        "unsupported format, expected json|ndjson".to_string(),
                    ));
                }
            },
        },
        Commands::Policy { command } => match command {
            PolicyCommands::Explain { tool } => {
                let explanation = host.explain_policy(&tool)?;
                println!("{explanation}");
            }
        },
        Commands::Trust { command } => match command {
            TrustCommands::Init => {
                host.init_layout()?;
                println!(
                    "trust store initialized at {}",
                    host.paths().trust_path().display()
                );
            }
            TrustCommands::Ls => {
                let signers = host.list_trust_signers()?;
                if signers.is_empty() {
                    println!("no trusted signers configured");
                } else {
                    for signer in signers {
                        println!("{signer}");
                    }
                }
            }
            TrustCommands::AddSigner { signer } => {
                host.add_trust_signer(&signer)?;
                println!("added trusted signer {signer}");
            }
            TrustCommands::RevokeSigner { signer } => {
                host.revoke_trust_signer(&signer)?;
                println!("revoked signer {signer}");
            }
        },
        Commands::Enforcement { command } => match command {
            EnforcementCommands::Status => {
                let posture = host.get_security_posture()?;
                println!("{}", serde_json::to_string_pretty(&posture)?);
            }
            EnforcementCommands::EvaluateSlo {
                window_days,
                target_pct,
            } => {
                let config = host.load_config()?;
                let report = host.evaluate_enforcement_slo(
                    window_days.unwrap_or(config.coverage_slo_window_days),
                    target_pct.unwrap_or(config.coverage_slo_target),
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            EnforcementCommands::SetMode { mode } => {
                let mode = parse_mode(&mode)?;
                host.set_enforcement_mode(mode)?;
                println!("enforcement mode updated");
            }
        },
        Commands::Diagnostics { command } => match command {
            DiagnosticsCommands::SecurityReport => {
                let report = host.diagnostics_report()?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Commands::Tui { .. } => unreachable!(),
    }

    Ok(())
}

fn parse_mode(input: &str) -> Result<EnforcementMode, CliError> {
    match input.to_ascii_lowercase().as_str() {
        "warn" => Ok(EnforcementMode::Warn),
        "enforce" => Ok(EnforcementMode::Enforce),
        _ => Err(CliError::Message(
            "invalid mode; expected warn|enforce".to_string(),
        )),
    }
}
