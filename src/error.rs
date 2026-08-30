//! Goal: give every failure mode in this crate one typed, non-secret-leaking
//! error so callers can distinguish malformed input from transport failure.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Eq, PartialEq)]
pub enum ClientError {
    /// A request part (method, authority, path, content type) or a
    /// signature metadata field (timestamps, nonce) failed the same
    /// validation the kernel's verifier applies.
    InvalidRequestPart(&'static str),
    InvalidPublicKey,
    InvalidSignature,
    /// The random source failed. This must never be papered over with a
    /// weaker nonce or key.
    RandomSource,
    /// A network or non-2xx response from a signed HTTP call.
    Transport(String),
    /// A `/v1/kernel-identity` response was missing, malformed, or did not
    /// parse as valid signing key material.
    MalformedKernelIdentity,
    /// An extra trust anchor supplied to [`crate::Client::with_extra_root_certificate`]
    /// was not a valid PEM-encoded certificate.
    InvalidTrustAnchor,
}

impl Display for ClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestPart(field) => write!(formatter, "invalid {field}"),
            Self::InvalidPublicKey => formatter.write_str("public key is not valid Ed25519"),
            Self::InvalidSignature => formatter.write_str("signature verification failed"),
            Self::RandomSource => formatter.write_str("random source failed"),
            Self::Transport(message) => write!(formatter, "transport failed: {message}"),
            Self::MalformedKernelIdentity => {
                formatter.write_str("kernel identity response is malformed")
            }
            Self::InvalidTrustAnchor => {
                formatter.write_str("extra root certificate is not valid PEM")
            }
        }
    }
}

impl Error for ClientError {}
