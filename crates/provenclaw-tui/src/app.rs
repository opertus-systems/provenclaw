use crate::actions::UiAction;
use crate::services::HostService;
use crate::state::{AppState, FocusPane, View};
use provenclaw_audit::AuditRecord;
use provenclaw_core::{RiskLevel, ToolRegistration, VerificationStatus};
use provenclaw_host::{DiagnosticsReport, ReceiptListItem};
use serde_json::{Value, json};

pub struct App {
    pub state: AppState,
    service: HostService,
    pub read_only: bool,
    tools: Vec<ToolRegistration>,
    receipts: Vec<ReceiptListItem>,
    audit: Vec<AuditRecord>,
    diagnostics: Option<DiagnosticsReport>,
    trust_signers: Vec<String>,
    last_run_output: Option<Value>,
    policy_explain: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(read_only: bool) -> Result<Self, provenclaw_host::HostError> {
        let mut app = Self {
            state: AppState::default(),
            service: HostService::new()?,
            read_only,
            tools: Vec::new(),
            receipts: Vec::new(),
            audit: Vec::new(),
            diagnostics: None,
            trust_signers: Vec::new(),
            last_run_output: None,
            policy_explain: None,
            should_quit: false,
        };
        app.refresh()?;
        Ok(app)
    }

    pub fn refresh(&mut self) -> Result<(), provenclaw_host::HostError> {
        self.tools = self.service.tools()?;
        self.receipts = self.service.receipts(&self.state.search_query)?;
        self.audit = self.service.audit_tail()?;
        self.trust_signers = self.service.trust_signers()?;
        self.diagnostics = Some(self.service.diagnostics()?);

        if let Some(first_tool) = self.tools.first() {
            self.policy_explain = Some(self.service.policy_explain(&first_tool.name)?);
        }

        self.state.status = format!(
            "view={} tools={} receipts={} audit={} read_only={}",
            self.state.view.title(),
            self.tools.len(),
            self.receipts.len(),
            self.audit.len(),
            self.read_only
        );
        Ok(())
    }

    pub fn palette_items(&self) -> Vec<(&'static str, View)> {
        vec![
            ("Dashboard", View::Dashboard),
            ("Run", View::Run),
            ("Tools", View::Tools),
            ("Policy", View::Policy),
            ("Receipts", View::Receipts),
            ("Audit Stream", View::AuditStream),
            ("Trust", View::Trust),
            ("Diagnostics", View::Diagnostics),
            ("Settings", View::Settings),
        ]
    }

    pub fn handle(&mut self, action: UiAction) -> Result<(), provenclaw_host::HostError> {
        if self.state.search_mode {
            return self.handle_search_mode(action);
        }

        if self.state.show_palette {
            return self.handle_palette_mode(action);
        }

        match action {
            UiAction::Quit => {
                if self.state.show_help {
                    self.state.show_help = false;
                } else {
                    self.should_quit = true;
                }
            }
            UiAction::ToggleHelp => {
                self.state.show_help = !self.state.show_help;
            }
            UiAction::TogglePalette => {
                self.state.show_palette = !self.state.show_palette;
            }
            UiAction::StartSearch => {
                self.state.search_mode = true;
                self.state.status = "search mode: type to filter receipts by digest".to_string();
            }
            UiAction::MoveUp => self.move_selection_up(),
            UiAction::MoveDown => self.move_selection_down(),
            UiAction::Tab => self.state.focus = self.state.focus.next(),
            UiAction::ShiftTab => self.state.focus = self.state.focus.prev(),
            UiAction::Enter => self.primary_action()?,
            UiAction::QuickGoto(view) => self.set_view(view),
            UiAction::DeepVerify => self.deep_verify_selected()?,
            UiAction::Export => self.export_selected()?,
            UiAction::Refresh => self.refresh()?,
            UiAction::MoveLeft | UiAction::MoveRight | UiAction::None => {}
            UiAction::SearchInput(_)
            | UiAction::SearchBackspace
            | UiAction::SearchSubmit
            | UiAction::SearchCancel => {}
        }

        Ok(())
    }

    fn handle_search_mode(&mut self, action: UiAction) -> Result<(), provenclaw_host::HostError> {
        match action {
            UiAction::SearchInput(ch) => self.state.search_query.push(ch),
            UiAction::SearchBackspace => {
                self.state.search_query.pop();
            }
            UiAction::SearchSubmit => {
                self.state.search_mode = false;
                self.refresh()?;
            }
            UiAction::SearchCancel | UiAction::Quit => {
                self.state.search_mode = false;
            }
            _ => {}
        }

        self.state.status = format!("search query={}", self.state.search_query);
        Ok(())
    }

    fn handle_palette_mode(&mut self, action: UiAction) -> Result<(), provenclaw_host::HostError> {
        let len = self.palette_items().len();
        match action {
            UiAction::MoveUp => {
                self.state.palette_index = self.state.palette_index.saturating_sub(1);
            }
            UiAction::MoveDown => {
                self.state.palette_index =
                    (self.state.palette_index + 1).min(len.saturating_sub(1));
            }
            UiAction::Enter => {
                let (_, view) = self.palette_items()[self.state.palette_index];
                self.set_view(view);
                self.state.show_palette = false;
            }
            UiAction::Quit | UiAction::TogglePalette => {
                self.state.show_palette = false;
            }
            UiAction::Refresh => self.refresh()?,
            _ => {}
        }
        Ok(())
    }

    fn move_selection_up(&mut self) {
        match self.state.focus {
            FocusPane::Nav => self.state.nav_index = self.state.nav_index.saturating_sub(1),
            FocusPane::Center => {
                self.state.center_index = self.state.center_index.saturating_sub(1)
            }
            FocusPane::Inspector => {}
        }
    }

    fn move_selection_down(&mut self) {
        match self.state.focus {
            FocusPane::Nav => {
                self.state.nav_index = (self.state.nav_index + 1).min(View::all().len() - 1);
                self.state.view = View::all()[self.state.nav_index];
            }
            FocusPane::Center => {
                self.state.center_index += 1;
            }
            FocusPane::Inspector => {}
        }
    }

    fn set_view(&mut self, view: View) {
        self.state.view = view;
        self.state.nav_index = View::all()
            .iter()
            .position(|candidate| *candidate == view)
            .unwrap_or(0);
        self.state.status = format!("switched to {}", view.title());
    }

    fn primary_action(&mut self) -> Result<(), provenclaw_host::HostError> {
        match self.state.view {
            View::Run => {
                if self.read_only {
                    self.state.status =
                        "read-only mode: run execution is disabled in forensics mode".to_string();
                    return Ok(());
                }
                if let Some(first_tool) = self.tools.first() {
                    let output = self.service.run_tool(
                        &first_tool.name,
                        json!({"payload": {"source": "tui"}, "read_only": self.read_only}),
                    )?;
                    self.last_run_output = Some(output);
                    self.refresh()?;
                } else {
                    self.state.status = "no tool registered".to_string();
                }
            }
            View::Policy => {
                if let Some(first_tool) = self.tools.first() {
                    self.policy_explain = Some(self.service.policy_explain(&first_tool.name)?);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn deep_verify_selected(&mut self) -> Result<(), provenclaw_host::HostError> {
        if self.state.view != View::Receipts {
            self.state.status = "deep verify applies to receipts view".to_string();
            return Ok(());
        }

        let Some(selected) = self
            .receipts
            .get(self.state.center_index % self.receipts.len().max(1))
        else {
            self.state.status = "no receipts available".to_string();
            return Ok(());
        };

        let deep = self.service.deep_verify(&selected.id.to_string())?;
        self.state.status = format!(
            "receipt={} hash={} sig={} chain={}",
            selected.id, deep.hash_valid, deep.signature_valid, deep.chain_valid
        );
        Ok(())
    }

    fn export_selected(&mut self) -> Result<(), provenclaw_host::HostError> {
        let path = std::env::temp_dir().join("provenclaw-export.json");
        let payload = match self.state.view {
            View::Receipts => serde_json::to_string_pretty(&self.receipts).unwrap_or_default(),
            View::Tools => serde_json::to_string_pretty(&self.tools).unwrap_or_default(),
            View::AuditStream => serde_json::to_string_pretty(&self.audit).unwrap_or_default(),
            _ => serde_json::to_string_pretty(&self.diagnostics).unwrap_or_default(),
        };
        std::fs::write(&path, payload)
            .map_err(|err| provenclaw_host::HostError::Verification(err.to_string()))?;
        self.state.status = format!("exported current view to {}", path.display());
        Ok(())
    }

    pub fn center_text(&self) -> String {
        match self.state.view {
            View::Dashboard => {
                if let Some(diagnostics) = &self.diagnostics {
                    format!(
                        "Security posture:\n{}\n\nSLO:\n{}\n\nRecent provenance entries: {}",
                        serde_json::to_string_pretty(&diagnostics.security_posture)
                            .unwrap_or_default(),
                        serde_json::to_string_pretty(&diagnostics.enforcement_slo)
                            .unwrap_or_default(),
                        diagnostics.recent_provenance.len()
                    )
                } else {
                    "no diagnostics loaded".to_string()
                }
            }
            View::Run => {
                if let Some(last) = &self.last_run_output {
                    let decision = last
                        .get("decision")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let reason = last
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let hint = remediation_hint(reason);
                    let warning_count = last
                        .get("warnings")
                        .and_then(Value::as_array)
                        .map(|warnings| warnings.len())
                        .unwrap_or(0);
                    format!(
                        "Press Enter to run first tool with safe default input.\n\nLast run decision={decision} reason={reason} warnings={warning_count}\nRemediation hint: {hint}\n\n{}",
                        serde_json::to_string_pretty(last).unwrap_or_default()
                    )
                } else {
                    "Press Enter to run first tool with safe default input.".to_string()
                }
            }
            View::Tools => serde_json::to_string_pretty(&self.tools).unwrap_or_default(),
            View::Policy => self
                .policy_explain
                .clone()
                .unwrap_or_else(|| "no policy explanation available".to_string()),
            View::Receipts => serde_json::to_string_pretty(&self.receipts).unwrap_or_default(),
            View::AuditStream => serde_json::to_string_pretty(&self.audit).unwrap_or_default(),
            View::Trust => serde_json::to_string_pretty(&self.trust_signers).unwrap_or_default(),
            View::Diagnostics => {
                serde_json::to_string_pretty(&self.diagnostics).unwrap_or_default()
            }
            View::Settings => {
                format!(
                    "read_only={}\nsearch_query={}",
                    self.read_only, self.state.search_query
                )
            }
        }
    }

    pub fn inspector_text(&self) -> String {
        match self.state.view {
            View::Tools => {
                let item = self
                    .tools
                    .get(self.state.center_index % self.tools.len().max(1));
                item.map(|tool| serde_json::to_string_pretty(tool).unwrap_or_default())
                    .unwrap_or_else(|| "no tool selected".to_string())
            }
            View::Receipts => {
                let item = self
                    .receipts
                    .get(self.state.center_index % self.receipts.len().max(1));
                item.map(|receipt| serde_json::to_string_pretty(receipt).unwrap_or_default())
                    .unwrap_or_else(|| "no receipt selected".to_string())
            }
            View::AuditStream => {
                let item = self
                    .audit
                    .get(self.state.center_index % self.audit.len().max(1));
                item.map(|record| serde_json::to_string_pretty(record).unwrap_or_default())
                    .unwrap_or_else(|| "no audit record selected".to_string())
            }
            _ => "Inspector follows focused view and selection.".to_string(),
        }
    }

    pub fn snapshot_text(&self) -> String {
        format!(
            "header=\"{}\" view={} tools={} receipts={} audit={} status={}",
            self.header_text(),
            self.state.view.title(),
            self.tools.len(),
            self.receipts.len(),
            self.audit.len(),
            self.state.status
        )
    }

    pub fn header_text(&self) -> String {
        let Some(diagnostics) = &self.diagnostics else {
            return "provenance=unknown enforcement=unknown risk=unknown".to_string();
        };

        let provenance = diagnostics
            .recent_provenance
            .first()
            .map(|entry| verification_label(&entry.verification_status))
            .unwrap_or("unknown");
        let mode = match diagnostics.security_posture.enforcement_mode {
            provenclaw_core::EnforcementMode::Warn => "warn",
            provenclaw_core::EnforcementMode::Enforce => "enforce",
        };
        let risk = risk_label(&diagnostics.security_posture.risk_level);
        format!("provenance={provenance} enforcement={mode} risk={risk}")
    }

    pub fn risk_level(&self) -> Option<RiskLevel> {
        self.diagnostics
            .as_ref()
            .map(|diagnostics| diagnostics.security_posture.risk_level.clone())
    }
}

fn remediation_hint(reason: &str) -> &'static str {
    if reason.starts_with("provenance-required-check-failed") {
        "Missing required provenance checks. Fix signer trust, signature, attestation, or verifier setup."
    } else if reason.starts_with("runtime-execution-failed") {
        "Runtime failed. Verify bundle path, provenact path, and runtime limits."
    } else if reason == "network-disabled-in-config" {
        "Network is disabled. Enable network or remove network capability requests."
    } else if reason == "tainted-input-network-downgrade" {
        "Input is tainted. Remove taint or avoid outbound network capability."
    } else {
        "Inspect policy explain and verification report for exact failing checks."
    }
}

fn verification_label(status: &VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Pass => "pass",
        VerificationStatus::Warn => "warn",
        VerificationStatus::Fail => "fail",
        VerificationStatus::Skipped => "skipped",
    }
}

fn risk_label(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Degraded => "degraded",
    }
}
