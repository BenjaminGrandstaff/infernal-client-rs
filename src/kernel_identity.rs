//! Goal: let a caller establish trust in a kernel process's current signing
//! key by fetching its self-published identity (ADR-0014), then verify a
//! message that process signed — without any static configuration that
//! would break the moment the kernel process restarts and rotates its key.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use uuid::Uuid;

use crate::credential::{self, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::error::ClientError;

#[derive(Debug, Deserialize)]
struct KernelIdentityResponse {
    algorithm: String,
    instance_id: String,
    key_id: String,
    public_key: String,
    fingerprint: String,
}

/// A kernel process's current public signing identity, as published at
/// `GET /v1/kernel-identity` (ADR-0014). Fetch once, cache, and re-fetch on
/// a verification failure — that failure is the signal the kernel process
/// restarted and rotated its key, not that the message was forged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelIdentity {
    instance_id: Uuid,
    key_id: Uuid,
    public_key: [u8; PUBLIC_KEY_LENGTH],
    fingerprint: [u8; 32],
}

impl KernelIdentity {
    /// Parses a `GET /v1/kernel-identity` JSON response body.
    pub fn from_json(body: &str) -> Result<Self, ClientError> {
        let response: KernelIdentityResponse =
            serde_json::from_str(body).map_err(|_| ClientError::MalformedKernelIdentity)?;
        if response.algorithm != "ed25519" {
            return Err(ClientError::MalformedKernelIdentity);
        }
        let instance_id = response
            .instance_id
            .parse()
            .map_err(|_| ClientError::MalformedKernelIdentity)?;
        let key_id = response
            .key_id
            .parse()
            .map_err(|_| ClientError::MalformedKernelIdentity)?;
        let public_key = decode_fixed(&response.public_key)?;
        let fingerprint = decode_fixed(&response.fingerprint)?;
        Ok(Self {
            instance_id,
            key_id,
            public_key,
            fingerprint,
        })
    }

    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    pub const fn key_id(&self) -> Uuid {
        self.key_id
    }

    pub const fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }

    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Verifies that `message` was signed by this identity's key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8; SIGNATURE_LENGTH],
    ) -> Result<(), ClientError> {
        credential::verify(&self.public_key, message, signature)
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ClientError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClientError::MalformedKernelIdentity)?;
    decoded
        .try_into()
        .map_err(|_| ClientError::MalformedKernelIdentity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ClientCredential;

    fn response_body(
        algorithm: &str,
        instance_id: Uuid,
        key_id: Uuid,
        key: [u8; 32],
        fp: [u8; 32],
    ) -> String {
        format!(
            r#"{{"algorithm":"{algorithm}","instance_id":"{instance_id}","key_id":"{key_id}","public_key":"{}","fingerprint":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(key),
            URL_SAFE_NO_PAD.encode(fp),
        )
    }

    #[test]
    fn parses_a_well_formed_kernel_identity_response() {
        let body = response_body("ed25519", Uuid::new_v4(), Uuid::new_v4(), [1; 32], [2; 32]);

        let identity = KernelIdentity::from_json(&body).unwrap();

        assert_eq!(identity.public_key_bytes(), &[1_u8; 32]);
        assert_eq!(identity.fingerprint(), &[2_u8; 32]);
    }

    #[test]
    fn rejects_an_unknown_algorithm() {
        let body = response_body("rsa", Uuid::new_v4(), Uuid::new_v4(), [1; 32], [2; 32]);

        assert_eq!(
            KernelIdentity::from_json(&body),
            Err(ClientError::MalformedKernelIdentity)
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(
            KernelIdentity::from_json("not json"),
            Err(ClientError::MalformedKernelIdentity)
        );
    }

    #[test]
    fn a_fetched_identity_verifies_a_message_the_matching_key_signed() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signature = credential.sign(b"kernel says hello");
        let body = response_body(
            "ed25519",
            credential.public_key().instance_id(),
            credential.public_key().key_id(),
            *credential.public_key().public_key_bytes(),
            credential.public_key().fingerprint(),
        );

        let identity = KernelIdentity::from_json(&body).unwrap();

        assert!(identity.verify(b"kernel says hello", &signature).is_ok());
        assert_eq!(
            identity.verify(b"forged", &signature),
            Err(ClientError::InvalidSignature)
        );
    }
}
