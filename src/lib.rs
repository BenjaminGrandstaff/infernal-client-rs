//! Native Rust client for the infernal-law kernel's signed REST contract
//! (ADR-0003). This is the reference implementation for the
//! `infernal-client-*` SDK family (ADR-0012): every other language's SDK is
//! checked for wire-level compatibility against this crate.
//!
//! No request signing or transport is implemented yet. The kernel's
//! governed HTTP routes are still pending (ILK-002 Authority), so there is
//! nothing to sign or send to yet.

/// Configuration for a future signed client. Construction only stores the
/// kernel's base URL until request signing and transport exist.
pub struct Client {
    base_url: String,
}

impl Client {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
