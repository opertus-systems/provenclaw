use provenclaw_audit::AuditRecord;
use provenclaw_host::{
    DeepReceipt, DiagnosticsReport, Host, HostError, ReceiptFilters, ReceiptListItem, TrustStore,
};
use serde_json::Value;

pub struct HostService {
    host: Host,
}

impl HostService {
    pub fn new() -> Result<Self, HostError> {
        let host = Host::discover()?;
        host.init_layout()?;
        Ok(Self { host })
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn tools(&self) -> Result<Vec<provenclaw_core::ToolRegistration>, HostError> {
        self.host.list_tools()
    }

    pub fn receipts(&self, query: &str) -> Result<Vec<ReceiptListItem>, HostError> {
        let filters = ReceiptFilters {
            decision: None,
            tool_digest: if query.is_empty() {
                None
            } else {
                Some(query.to_string())
            },
        };
        Ok(self.host.list_receipts_page(None, 200, filters)?.items)
    }

    pub fn audit_tail(&self) -> Result<Vec<AuditRecord>, HostError> {
        self.host.tail_audit(1, 200)
    }

    pub fn diagnostics(&self) -> Result<DiagnosticsReport, HostError> {
        self.host.diagnostics_report()
    }

    pub fn trust_signers(&self) -> Result<Vec<String>, HostError> {
        self.host.list_trust_signers()
    }

    pub fn policy_explain(&self, tool: &str) -> Result<String, HostError> {
        self.host.explain_policy(tool)
    }

    pub fn run_tool(&self, name: &str, input: Value) -> Result<serde_json::Value, HostError> {
        let result = self.host.run_tool(name, input)?;
        Ok(serde_json::json!({
            "request_id": result.request_id,
            "decision": result.decision,
            "reason": result.reason,
            "receipt_id": result.receipt_id,
            "verification_status": result.verification_status,
            "warnings": result.warnings,
            "output": result.output,
        }))
    }

    pub fn deep_verify(&self, id: &str) -> Result<DeepReceipt, HostError> {
        self.host.get_receipt_deep(id)
    }

    pub fn raw_trust_store(&self) -> Result<TrustStore, HostError> {
        let content = std::fs::read_to_string(self.host.paths().trust_path())?;
        let parsed: TrustStore = serde_json::from_str(&content)
            .map_err(|err| HostError::Verification(err.to_string()))?;
        Ok(parsed)
    }
}
