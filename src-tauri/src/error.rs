use serde::Serialize;
use std::fmt;

/// Error returned to the frontend. Serialized as `{ kind: "...", ... }`.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CmdError {
    Message {
        message: String,
    },
    /// Authentication failed — the UI should ask for a password / passphrase and retry.
    AuthFailed {
        message: String,
    },
    HostKeyUnknown {
        host: String,
        port: u16,
        fingerprint: String,
        key_line: String,
    },
    HostKeyMismatch {
        host: String,
        port: u16,
        fingerprint: String,
        key_line: String,
    },
}

/// Raised from the SSH handler when the server key is not trusted.
#[derive(Debug, Clone)]
pub struct HostKeyProblem {
    pub mismatch: bool,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub key_line: String,
}

impl fmt::Display for HostKeyProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host key problem for {}:{}", self.host, self.port)
    }
}
impl std::error::Error for HostKeyProblem {}

#[derive(Debug)]
pub struct AuthFailed(pub String);

impl fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AuthFailed {}

impl From<anyhow::Error> for CmdError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(p) = e.downcast_ref::<HostKeyProblem>() {
            let p = p.clone();
            return if p.mismatch {
                CmdError::HostKeyMismatch {
                    host: p.host,
                    port: p.port,
                    fingerprint: p.fingerprint,
                    key_line: p.key_line,
                }
            } else {
                CmdError::HostKeyUnknown {
                    host: p.host,
                    port: p.port,
                    fingerprint: p.fingerprint,
                    key_line: p.key_line,
                }
            };
        }
        if let Some(a) = e.downcast_ref::<AuthFailed>() {
            return CmdError::AuthFailed {
                message: a.0.clone(),
            };
        }
        CmdError::Message {
            message: format!("{e:#}"),
        }
    }
}

pub type CmdResult<T> = Result<T, CmdError>;
