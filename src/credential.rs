//! Goal: hold one process's signed-REST identity (ADR-0003) — a service ID
//! plus an ephemeral per-instance Ed25519 keypair — and produce signatures
//! over exactly the bytes the kernel's verifier expects.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ClientError;

pub const ALGORITHM: &str = "ed25519";
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

/// One process's public signing identity: which service it claims to be,
/// which instance/key this is, and the Ed25519 public key itself. Mirrors
/// the kernel's own `InstancePublicKey` field-for-field so wire output is
/// compatible with the kernel's verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientPublicKey {
    service_id: Uuid,
    instance_id: Uuid,
    key_id: Uuid,
    public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ClientPublicKey {
    pub const fn service_id(&self) -> Uuid {
        self.service_id
    }

    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    pub const fn key_id(&self) -> Uuid {
        self.key_id
    }

    pub const fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    pub const fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.public_key).into()
    }
}

/// An ephemeral per-instance credential (ADR-0005): generated fresh for the
/// process's lifetime, never persisted, never reused after restart.
pub struct ClientCredential {
    public_key: ClientPublicKey,
    signing_key: SigningKey,
}

impl ClientCredential {
    /// Generates a fresh instance/key pair for `service_id`. Call once per
    /// process; a restarted process must call this again rather than reuse
    /// a stored key.
    pub fn generate(service_id: Uuid) -> Self {
        let signing_key = SigningKey::generate(&mut UnwrapErr(SysRng));
        let public_key = ClientPublicKey {
            service_id,
            instance_id: Uuid::new_v4(),
            key_id: Uuid::new_v4(),
            public_key: signing_key.verifying_key().to_bytes(),
        };
        Self {
            public_key,
            signing_key,
        }
    }

    pub const fn public_key(&self) -> &ClientPublicKey {
        &self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verifies a signature against a raw Ed25519 public key. Used both to
/// self-check a freshly produced signature and, via [`crate::KernelIdentity`],
/// to verify a message the kernel signed.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LENGTH],
    message: &[u8],
    signature: &[u8; SIGNATURE_LENGTH],
) -> Result<(), ClientError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| ClientError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| ClientError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_distinct_instance_and_key_per_credential() {
        let service_id = Uuid::new_v4();
        let first = ClientCredential::generate(service_id);
        let second = ClientCredential::generate(service_id);

        assert_eq!(first.public_key().service_id(), service_id);
        assert_ne!(
            first.public_key().instance_id(),
            second.public_key().instance_id()
        );
        assert_ne!(first.public_key().key_id(), second.public_key().key_id());
        assert_ne!(
            first.public_key().public_key_bytes(),
            second.public_key().public_key_bytes()
        );
    }

    #[test]
    fn a_signature_verifies_only_the_original_message_under_the_signing_keys_own_public_key() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signature = credential.sign(b"message");

        assert!(
            verify(
                credential.public_key().public_key_bytes(),
                b"message",
                &signature
            )
            .is_ok()
        );
        assert_eq!(
            verify(
                credential.public_key().public_key_bytes(),
                b"altered",
                &signature
            ),
            Err(ClientError::InvalidSignature)
        );

        let other = ClientCredential::generate(Uuid::new_v4());
        assert_eq!(
            verify(
                other.public_key().public_key_bytes(),
                b"message",
                &signature
            ),
            Err(ClientError::InvalidSignature)
        );
    }
}
