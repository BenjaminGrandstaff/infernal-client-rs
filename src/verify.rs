//! Goal: verify an inbound request signed under the ADR-0003 profile — the
//! server-side counterpart to this crate's signing logic — so a Rust
//! service receiving a kernel-originated (or any registered service's)
//! signed call can authenticate it without a second, independent
//! implementation of the same protocol.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

use crate::credential;
use crate::credential::SIGNATURE_LENGTH;
use crate::error::ClientError;
use crate::request::RequestParts;
use crate::wire::{self, SIGNATURE_LABEL};

/// An inbound request's security headers, still unverified. Construct with
/// [`IncomingRequest::from_wire`] from the raw header/body values a server
/// received, then check it with [`verify_incoming`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingRequest {
    parts: RequestParts,
    service_id: Uuid,
    instance_id: Uuid,
    content_digest: String,
    signature_input: String,
    signature: String,
}

impl IncomingRequest {
    pub fn from_wire(
        parts: RequestParts,
        service_id: &str,
        instance_id: &str,
        content_digest: &str,
        signature_input: &str,
        signature: &str,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            parts,
            service_id: service_id
                .parse()
                .map_err(|_| ClientError::InvalidRequestPart("service_id"))?,
            instance_id: instance_id
                .parse()
                .map_err(|_| ClientError::InvalidRequestPart("instance_id"))?,
            content_digest: content_digest.to_owned(),
            signature_input: signature_input.to_owned(),
            signature: signature.to_owned(),
        })
    }

    pub const fn parts(&self) -> &RequestParts {
        &self.parts
    }

    pub const fn service_id(&self) -> Uuid {
        self.service_id
    }

    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }
}

/// The result of successfully verifying an [`IncomingRequest`]: the caller
/// identity and freshness window the signature actually attested to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRequest {
    service_id: Uuid,
    instance_id: Uuid,
    key_id: Uuid,
    request_id: Uuid,
    created: i64,
    expires: i64,
}

impl VerifiedRequest {
    pub const fn service_id(&self) -> Uuid {
        self.service_id
    }

    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    pub const fn key_id(&self) -> Uuid {
        self.key_id
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn created(&self) -> i64 {
        self.created
    }

    pub const fn expires(&self) -> i64 {
        self.expires
    }
}

struct SignatureMetadata {
    parameters: String,
    created: i64,
    expires: i64,
    key_id: Uuid,
}

/// Verifies `request` against `public_key`: that `service_id`/`instance_id`
/// on the wire match the key the caller expects to be the signer, that the
/// content digest matches the body, that the signature is fresh relative to
/// `now`, and that the Ed25519 signature itself is valid over exactly the
/// bytes the kernel's own verifier would compute.
///
/// Callers choose `public_key` themselves — typically a
/// [`crate::KernelIdentity`] fetched from `GET /v1/kernel-identity`, or a
/// registered service's key from wherever the caller keeps that registry.
/// This function does not fetch or cache anything on its own.
pub fn verify_incoming(
    request: &IncomingRequest,
    public_key: &credential::ClientPublicKey,
    now: i64,
) -> Result<VerifiedRequest, ClientError> {
    if request.service_id != public_key.service_id()
        || request.instance_id != public_key.instance_id()
    {
        return Err(ClientError::InvalidRequestPart("service_id"));
    }
    let metadata = parse_signature_input(&request.signature_input)?;
    if metadata.key_id != public_key.key_id() {
        return Err(ClientError::InvalidRequestPart("key_id"));
    }
    validate_signature_time(metadata.created, metadata.expires, now)?;

    let expected_digest = wire::content_digest(request.parts.body());
    if expected_digest != request.content_digest {
        return Err(ClientError::InvalidSignature);
    }

    let signature = parse_signature(&request.signature)?;
    let base = wire::signature_base(
        request.parts.method(),
        &request.parts.target_uri(),
        &request.content_digest,
        request.parts.content_type(),
        request.service_id,
        request.instance_id,
        request.parts.request_id(),
        &metadata.parameters,
    );
    credential::verify(public_key.public_key_bytes(), base.as_bytes(), &signature)?;

    Ok(VerifiedRequest {
        service_id: request.service_id,
        instance_id: request.instance_id,
        key_id: metadata.key_id,
        request_id: request.parts.request_id(),
        created: metadata.created,
        expires: metadata.expires,
    })
}

fn parse_signature_input(value: &str) -> Result<SignatureMetadata, ClientError> {
    let parameters = value
        .strip_prefix(&format!("{SIGNATURE_LABEL}="))
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    let remainder = parameters
        .strip_prefix(wire::COVERED_COMPONENTS)
        .and_then(|value| value.strip_prefix(";created="))
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    let (created, remainder) = remainder
        .split_once(";expires=")
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    let (expires, remainder) = remainder
        .split_once(";nonce=\"")
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    let (nonce, remainder) = remainder
        .split_once("\";keyid=\"")
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    let (key_id, algorithm) = remainder
        .split_once("\";alg=\"")
        .ok_or(ClientError::InvalidRequestPart("signature_input"))?;
    if algorithm != "ed25519\"" {
        return Err(ClientError::InvalidRequestPart("signature_input"));
    }
    let created = parse_timestamp(created)?;
    let expires = parse_timestamp(expires)?;
    wire::validate_signature_metadata(created, expires, nonce)?;
    let key_id = key_id
        .parse()
        .map_err(|_| ClientError::InvalidRequestPart("signature_input"))?;
    Ok(SignatureMetadata {
        parameters: parameters.to_owned(),
        created,
        expires,
        key_id,
    })
}

fn parse_signature(value: &str) -> Result<[u8; SIGNATURE_LENGTH], ClientError> {
    let encoded = value
        .strip_prefix(&format!("{SIGNATURE_LABEL}=:"))
        .and_then(|value| value.strip_suffix(':'))
        .ok_or(ClientError::InvalidRequestPart("signature"))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ClientError::InvalidRequestPart("signature"))?;
    let bytes: [u8; SIGNATURE_LENGTH] = bytes
        .try_into()
        .map_err(|_| ClientError::InvalidRequestPart("signature"))?;
    Ok(bytes)
}

fn parse_timestamp(value: &str) -> Result<i64, ClientError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::InvalidRequestPart("timestamp"));
    }
    value
        .parse()
        .map_err(|_| ClientError::InvalidRequestPart("timestamp"))
}

fn validate_signature_time(created: i64, expires: i64, now: i64) -> Result<(), ClientError> {
    const CLOCK_SKEW_SECONDS: i64 = 5;
    if now < 0
        || created > now.saturating_add(CLOCK_SKEW_SECONDS)
        || expires.saturating_add(CLOCK_SKEW_SECONDS) < now
    {
        return Err(ClientError::InvalidRequestPart("freshness"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ClientCredential;
    use crate::request::SignedRequest;

    fn parts() -> RequestParts {
        RequestParts::new(
            "POST",
            "policy-evaluator.example.test",
            "/v1/authority/evaluate",
            "application/json",
            br#"{"action":"billing.invoice.submit"}"#,
            Uuid::new_v4(),
        )
        .unwrap()
    }

    fn incoming_from(signed: &SignedRequest) -> IncomingRequest {
        IncomingRequest::from_wire(
            signed.parts().clone(),
            &signed.service_id().to_string(),
            &signed.instance_id().to_string(),
            signed.content_digest(),
            signed.signature_input(),
            signed.signature(),
        )
        .unwrap()
    }

    #[test]
    fn a_freshly_signed_request_verifies_against_the_signers_own_public_key() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signed =
            SignedRequest::sign(parts(), &credential, 1_000, 1_020, "verify_test_nonce_01")
                .unwrap();
        let incoming = incoming_from(&signed);

        let verified = verify_incoming(&incoming, credential.public_key(), 1_005).unwrap();

        assert_eq!(verified.service_id(), credential.public_key().service_id());
        assert_eq!(
            verified.instance_id(),
            credential.public_key().instance_id()
        );
        assert_eq!(verified.key_id(), credential.public_key().key_id());
        assert_eq!(verified.request_id(), incoming.parts().request_id());
        assert_eq!(verified.created(), 1_000);
        assert_eq!(verified.expires(), 1_020);
    }

    #[test]
    fn a_request_signed_by_a_different_key_is_rejected() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signed =
            SignedRequest::sign(parts(), &credential, 1_000, 1_020, "verify_test_nonce_02")
                .unwrap();
        let incoming = incoming_from(&signed);

        let impostor = ClientCredential::generate(Uuid::new_v4());
        let result = verify_incoming(&incoming, impostor.public_key(), 1_005);

        assert_eq!(result, Err(ClientError::InvalidRequestPart("service_id")));
    }

    #[test]
    fn a_body_altered_after_signing_fails_the_content_digest_check() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signed =
            SignedRequest::sign(parts(), &credential, 1_000, 1_020, "verify_test_nonce_03")
                .unwrap();
        let tampered_parts = RequestParts::new(
            signed.parts().method(),
            signed.parts().authority(),
            signed.parts().path_and_query(),
            signed.parts().content_type(),
            b"tampered body",
            signed.parts().request_id(),
        )
        .unwrap();
        let incoming = IncomingRequest::from_wire(
            tampered_parts,
            &signed.service_id().to_string(),
            &signed.instance_id().to_string(),
            signed.content_digest(),
            signed.signature_input(),
            signed.signature(),
        )
        .unwrap();

        assert_eq!(
            verify_incoming(&incoming, credential.public_key(), 1_005),
            Err(ClientError::InvalidSignature)
        );
    }

    #[test]
    fn an_expired_signature_is_rejected() {
        let credential = ClientCredential::generate(Uuid::new_v4());
        let signed =
            SignedRequest::sign(parts(), &credential, 1_000, 1_020, "verify_test_nonce_04")
                .unwrap();
        let incoming = incoming_from(&signed);

        let result = verify_incoming(&incoming, credential.public_key(), 2_000);

        assert_eq!(result, Err(ClientError::InvalidRequestPart("freshness")));
    }
}
