use provenclaw_core::EnforcementMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unsupported transport endpoint: {0}")]
    UnsupportedTransport(String),
    #[error("authorization denied: {0}")]
    Unauthorized(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneMode {
    LocalOnly,
    Hybrid,
    RemoteOnly,
}

impl Default for ControlPlaneMode {
    fn default() -> Self {
        Self::LocalOnly
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    InProcess,
    UnixSocket,
    LoopbackHttp,
    MtlsHttps,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthnScheme {
    LocalSharedToken,
    OidcBearer,
    MutualTls,
    WorkloadIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookMode {
    Disabled,
    Local,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthnHook {
    pub mode: HookMode,
    #[serde(default)]
    pub accepted_schemes: Vec<AuthnScheme>,
    #[serde(default)]
    pub audience: Option<String>,
}

impl Default for AuthnHook {
    fn default() -> Self {
        Self {
            mode: HookMode::Local,
            accepted_schemes: vec![AuthnScheme::LocalSharedToken],
            audience: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzHook {
    pub mode: HookMode,
    pub policy_source: String,
}

impl Default for AuthzHook {
    fn default() -> Self {
        Self {
            mode: HookMode::Local,
            policy_source: "embedded-rbac".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneEndpoint {
    pub transport: TransportKind,
    pub address: String,
    #[serde(default)]
    pub audience: Option<String>,
}

impl ControlPlaneEndpoint {
    pub fn validate(&self) -> Result<(), ControlPlaneError> {
        match self.transport {
            TransportKind::InProcess => {
                if !self.address.eq_ignore_ascii_case("in-process") {
                    return Err(ControlPlaneError::UnsupportedTransport(
                        "in-process transport requires address=in-process".to_string(),
                    ));
                }
            }
            TransportKind::LoopbackHttp => {
                if !(self.address.starts_with("127.0.0.1:")
                    || self.address.starts_with("localhost:"))
                {
                    return Err(ControlPlaneError::UnsupportedTransport(
                        "loopback HTTP transport requires localhost/127.0.0.1".to_string(),
                    ));
                }
            }
            TransportKind::UnixSocket => {
                if !self.address.starts_with('/') {
                    return Err(ControlPlaneError::UnsupportedTransport(
                        "unix socket transport requires absolute path".to_string(),
                    ));
                }
            }
            TransportKind::MtlsHttps => {
                if !self.address.starts_with("https://") {
                    return Err(ControlPlaneError::UnsupportedTransport(
                        "mTLS HTTPS transport requires https:// endpoint".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneProfile {
    pub mode: ControlPlaneMode,
    pub endpoint: ControlPlaneEndpoint,
    pub authn: AuthnHook,
    pub authz: AuthzHook,
    pub host_enforcement_mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneHealth {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectContext {
    pub subject_id: String,
    #[serde(default)]
    pub roles: BTreeSet<String>,
    pub authn_scheme: AuthnScheme,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationAction {
    RunTool,
    ReadReceipts,
    VerifyReceipts,
    TailAudit,
    ExportDiagnostics,
    ManagePolicy,
    ManageTrust,
    SetEnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceContext {
    pub resource_kind: String,
    pub resource_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub subject: SubjectContext,
    pub action: AuthorizationAction,
    #[serde(default)]
    pub resource: Option<ResourceContext>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub decision: AuthorizationDecision,
    pub reason_code: String,
    pub remediation_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPlaneRequest {
    Health,
    Profile,
    Authorize(AuthorizationRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPlaneResponse {
    Health(ControlPlaneHealth),
    Profile(ControlPlaneProfile),
    Authorize(AuthorizationResponse),
}

pub trait ControlPlane {
    fn profile(&self) -> ControlPlaneProfile;

    fn health(&self) -> ControlPlaneHealth;

    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, ControlPlaneError>;

    fn execute(
        &self,
        request: ControlPlaneRequest,
    ) -> Result<ControlPlaneResponse, ControlPlaneError> {
        match request {
            ControlPlaneRequest::Health => Ok(ControlPlaneResponse::Health(self.health())),
            ControlPlaneRequest::Profile => Ok(ControlPlaneResponse::Profile(self.profile())),
            ControlPlaneRequest::Authorize(request) => {
                Ok(ControlPlaneResponse::Authorize(self.authorize(&request)?))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalControlPlane {
    profile: ControlPlaneProfile,
}

impl LocalControlPlane {
    pub fn for_local_host(enforcement_mode: EnforcementMode) -> Self {
        Self {
            profile: ControlPlaneProfile {
                mode: ControlPlaneMode::LocalOnly,
                endpoint: ControlPlaneEndpoint {
                    transport: TransportKind::InProcess,
                    address: "in-process".to_string(),
                    audience: None,
                },
                authn: AuthnHook::default(),
                authz: AuthzHook::default(),
                host_enforcement_mode: enforcement_mode,
            },
        }
    }

    pub fn with_profile(profile: ControlPlaneProfile) -> Result<Self, ControlPlaneError> {
        profile.endpoint.validate()?;
        Ok(Self { profile })
    }
}

impl ControlPlane for LocalControlPlane {
    fn profile(&self) -> ControlPlaneProfile {
        self.profile.clone()
    }

    fn health(&self) -> ControlPlaneHealth {
        ControlPlaneHealth::Ready
    }

    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, ControlPlaneError> {
        if request.subject.subject_id.trim().is_empty() {
            return Err(ControlPlaneError::InvalidRequest(
                "subject_id is required".to_string(),
            ));
        }

        let required_roles = required_roles(&request.action);
        let has_required_role = required_roles
            .iter()
            .any(|role| request.subject.roles.contains(*role));

        if !has_required_role {
            return Ok(AuthorizationResponse {
                decision: AuthorizationDecision::Deny,
                reason_code: "authz.role-mismatch".to_string(),
                remediation_hint: format!(
                    "grant one of required roles: {}",
                    required_roles.join(",")
                ),
            });
        }

        Ok(AuthorizationResponse {
            decision: AuthorizationDecision::Allow,
            reason_code: "authz.role-match".to_string(),
            remediation_hint: "none".to_string(),
        })
    }
}

fn required_roles(action: &AuthorizationAction) -> &'static [&'static str] {
    match action {
        AuthorizationAction::RunTool
        | AuthorizationAction::ReadReceipts
        | AuthorizationAction::VerifyReceipts
        | AuthorizationAction::TailAudit
        | AuthorizationAction::ExportDiagnostics => &["operator", "auditor", "security-admin"],
        AuthorizationAction::ManagePolicy
        | AuthorizationAction::ManageTrust
        | AuthorizationAction::SetEnforcementMode => &["security-admin"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject_with_roles(roles: &[&str]) -> SubjectContext {
        SubjectContext {
            subject_id: "alice".to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            authn_scheme: AuthnScheme::LocalSharedToken,
            scopes: BTreeSet::new(),
        }
    }

    #[test]
    fn local_profile_defaults_to_in_process_transport() {
        let plane = LocalControlPlane::for_local_host(EnforcementMode::Warn);
        let profile = plane.profile();
        assert_eq!(profile.mode, ControlPlaneMode::LocalOnly);
        assert_eq!(profile.endpoint.transport, TransportKind::InProcess);
        assert_eq!(profile.endpoint.address, "in-process");
    }

    #[test]
    fn authorize_denies_when_subject_lacks_role() {
        let plane = LocalControlPlane::for_local_host(EnforcementMode::Warn);
        let request = AuthorizationRequest {
            subject: subject_with_roles(&["operator"]),
            action: AuthorizationAction::ManageTrust,
            resource: None,
            reason: None,
        };

        let response = plane.authorize(&request).unwrap();
        assert_eq!(response.decision, AuthorizationDecision::Deny);
        assert_eq!(response.reason_code, "authz.role-mismatch");
    }

    #[test]
    fn authorize_allows_when_subject_has_required_role() {
        let plane = LocalControlPlane::for_local_host(EnforcementMode::Warn);
        let request = AuthorizationRequest {
            subject: subject_with_roles(&["security-admin"]),
            action: AuthorizationAction::SetEnforcementMode,
            resource: None,
            reason: None,
        };

        let response = plane.authorize(&request).unwrap();
        assert_eq!(response.decision, AuthorizationDecision::Allow);
    }

    #[test]
    fn endpoint_validation_rejects_non_loopback_http() {
        let profile = ControlPlaneProfile {
            mode: ControlPlaneMode::RemoteOnly,
            endpoint: ControlPlaneEndpoint {
                transport: TransportKind::LoopbackHttp,
                address: "10.0.0.4:7447".to_string(),
                audience: Some("provenclaw-host".to_string()),
            },
            authn: AuthnHook::default(),
            authz: AuthzHook::default(),
            host_enforcement_mode: EnforcementMode::Warn,
        };

        let err = LocalControlPlane::with_profile(profile).unwrap_err();
        assert!(err.to_string().contains("loopback HTTP"));
    }
}
