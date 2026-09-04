//! Goal: implement the candidate side of ADR-0008 initial enrollment --
//! building and signing the proof a new instance submits to
//! `POST /v1/enrollments`, and parsing the kernel's typed response.
//!
//! There is deliberately no self-service HTTP call here for *requesting* a
//! challenge: infernal-law has no public route for that (any caller could
//! otherwise spam challenge creation for an arbitrary claimed service ID),
//! so a challenge only ever reaches a candidate through a kernel operator's
//! own out-of-band process, the same way authority grants and schema
//! activation are administered outside the kernel's HTTP surface. This
//! module's job starts once a caller already holds a raw challenge value.
//!
//! This crate never links or embeds kernel code, so this mirrors
//! infernal-law's own `kernel::enrollment` module field-for-field (proof
//! message layout, JSON body shape) rather than sharing an implementation
//! -- wire compatibility is proven by a cross-crate test in infernal-law's
//! own repository, the same way ADR-0003 signing compatibility is.
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential::{ALGORITHM, ClientCredential, ClientPublicKey};
use crate::error::ClientError;

const PROOF_CONTEXT: &[u8] = b"infernal-law/enrollment/v1";
pub const CHALLENGE_LENGTH: usize = 32;

/// A signed ADR-0008 enrollment proof, ready to submit via
/// [`crate::Client::submit_enrollment`].
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct EnrollmentSubmission {
    service_id: String,
    instance_id: String,
    key_id: String,
    algorithm: &'static str,
    public_key: String,
    challenge: String,
    endpoint: String,
    pod_uid: String,
    workload_token: String,
    signature: String,
}

impl EnrollmentSubmission {
    /// `challenge` is the raw 32-byte value from a kernel operator's
    /// out-of-band challenge issuance (see this module's own documentation
    /// for why there is no self-service call for this). `workload_token`
    /// is this Pod's own projected ServiceAccount token for the
    /// `infernal-law-enrollment` audience; `pod_uid` is this Pod's own UID,
    /// for example read from the Kubernetes Downward API.
    ///
    /// `endpoint` and `pod_uid` are trimmed before both signing and
    /// transmission, matching the kernel's own field validation exactly --
    /// the kernel recomputes this same proof message from its own trimmed
    /// copies of these fields, so signing over an untrimmed value here
    /// would produce a signature the kernel can never reproduce and so
    /// can never verify.
    pub fn sign(
        credential: &ClientCredential,
        challenge: [u8; CHALLENGE_LENGTH],
        endpoint: &str,
        pod_uid: &str,
        workload_token: String,
    ) -> Result<Self, ClientError> {
        let endpoint = endpoint.trim();
        let pod_uid = pod_uid.trim();
        if endpoint == "https://" || !endpoint.starts_with("https://") {
            return Err(ClientError::InvalidRequestPart("endpoint"));
        }
        if pod_uid.is_empty() {
            return Err(ClientError::InvalidRequestPart("pod_uid"));
        }
        if workload_token.is_empty() {
            return Err(ClientError::InvalidRequestPart("workload_token"));
        }
        let public_key = credential.public_key();
        let message = proof_message(&challenge, public_key, endpoint, pod_uid, &workload_token);
        let signature = credential.sign(&message);
        Ok(Self {
            service_id: public_key.service_id().to_string(),
            instance_id: public_key.instance_id().to_string(),
            key_id: public_key.key_id().to_string(),
            algorithm: ALGORITHM,
            public_key: URL_SAFE_NO_PAD.encode(public_key.public_key_bytes()),
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            endpoint: endpoint.to_owned(),
            pod_uid: pod_uid.to_owned(),
            workload_token,
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }
}

/// The kernel's own successful-enrollment response
/// (`EnrollmentSuccessResponse` on the kernel side), for example to log the
/// granted lease before switching to ordinary signed calls.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EnrolledInstance {
    pub service_id: String,
    pub instance_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub endpoint: String,
    pub registered_at: i64,
    pub lease_expires_at: i64,
    pub lease_revision: i64,
}

/// Requests a challenge from the kernel on the workload's own behalf
/// (`POST /v1/enrollments/challenges`). Deliberately carries no service
/// ID: the kernel derives that from the enrollment binding this token
/// resolves to, so a workload cannot request a challenge for an identity
/// it may not become.
#[derive(Clone, Serialize)]
pub struct ChallengeRequest {
    pub pod_uid: String,
    pub workload_token: String,
}

/// Debug is written by hand: this type carries a bearer token, and the
/// derived form would print it.
impl fmt::Debug for ChallengeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChallengeRequest")
            .field("pod_uid", &self.pod_uid)
            .field("workload_token", &"<redacted>")
            .finish()
    }
}

/// The kernel's `EnrollmentChallengeResponse`. `challenge` is base64url
/// (no padding) over exactly [`CHALLENGE_LENGTH`] bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct IssuedChallenge {
    pub service_id: String,
    pub challenge: String,
    pub audience: String,
    pub expires_at: i64,
}

impl IssuedChallenge {
    /// Decodes the wire form into the raw value [`EnrollmentSubmission::sign`]
    /// expects.
    pub fn challenge_bytes(&self) -> Result<[u8; CHALLENGE_LENGTH], ClientError> {
        URL_SAFE_NO_PAD
            .decode(&self.challenge)
            .map_err(|_| ClientError::MalformedEnrollmentResponse)?
            .try_into()
            .map_err(|_| ClientError::MalformedEnrollmentResponse)
    }
}

/// The kernel's own sanitized enrollment error shape
/// (`EnrollmentErrorResponse` on the kernel side) -- safe to surface
/// as-is, since the kernel never puts proof material, tokens, or raw
/// repository errors into this response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EnrollmentRejection {
    pub code: String,
    pub message: String,
}

fn proof_message(
    challenge: &[u8; CHALLENGE_LENGTH],
    public_key: &ClientPublicKey,
    endpoint: &str,
    pod_uid: &str,
    token: &str,
) -> Vec<u8> {
    let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let service_id = public_key.service_id();
    let instance_id = public_key.instance_id();
    let key_id = public_key.key_id();
    let fields: [&[u8]; 8] = [
        PROOF_CONTEXT,
        challenge,
        service_id.as_bytes(),
        instance_id.as_bytes(),
        key_id.as_bytes(),
        public_key.public_key_bytes(),
        endpoint.as_bytes(),
        pod_uid.as_bytes(),
    ];
    let mut message = Vec::new();
    for field in fields.into_iter().chain([token_digest.as_slice()]) {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field);
    }
    message
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn signs_a_submission_with_the_expected_wire_shape() {
        let credential = ClientCredential::generate(Uuid::new_v4());

        let submission = EnrollmentSubmission::sign(
            &credential,
            [7_u8; CHALLENGE_LENGTH],
            "https://worker.example.test",
            "pod-uid",
            "projected-token".to_owned(),
        )
        .unwrap();

        assert_eq!(
            submission.service_id,
            credential.public_key().service_id().to_string()
        );
        assert_eq!(submission.algorithm, "ed25519");
        assert_eq!(submission.endpoint, "https://worker.example.test");
        assert_eq!(submission.pod_uid, "pod-uid");
        assert_eq!(submission.workload_token, "projected-token");
    }

    #[test]
    fn trims_endpoint_and_pod_uid_before_signing_so_the_kernel_can_reproduce_the_proof() {
        let credential = ClientCredential::generate(Uuid::new_v4());

        let padded = EnrollmentSubmission::sign(
            &credential,
            [3_u8; CHALLENGE_LENGTH],
            "  https://worker.example.test  ",
            "  pod-uid  ",
            "token".to_owned(),
        )
        .unwrap();
        let trimmed = EnrollmentSubmission::sign(
            &credential,
            [3_u8; CHALLENGE_LENGTH],
            "https://worker.example.test",
            "pod-uid",
            "token".to_owned(),
        )
        .unwrap();

        assert_eq!(padded.endpoint, trimmed.endpoint);
        assert_eq!(padded.pod_uid, trimmed.pod_uid);
        assert_eq!(padded.signature, trimmed.signature);
    }

    #[test]
    fn rejects_a_non_https_endpoint() {
        let credential = ClientCredential::generate(Uuid::new_v4());

        assert_eq!(
            EnrollmentSubmission::sign(
                &credential,
                [1_u8; CHALLENGE_LENGTH],
                "http://worker.example.test",
                "pod-uid",
                "token".to_owned(),
            ),
            Err(ClientError::InvalidRequestPart("endpoint"))
        );
    }

    #[test]
    fn rejects_an_empty_workload_token() {
        let credential = ClientCredential::generate(Uuid::new_v4());

        assert_eq!(
            EnrollmentSubmission::sign(
                &credential,
                [1_u8; CHALLENGE_LENGTH],
                "https://worker.example.test",
                "pod-uid",
                String::new(),
            ),
            Err(ClientError::InvalidRequestPart("workload_token"))
        );
    }
}
