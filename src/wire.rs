//! Goal: hold the ADR-0003 wire-format primitives shared between signing
//! (`request.rs`) and verification (`verify.rs`) so there is exactly one
//! implementation of the signature base, not two that could drift apart.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ClientError;

pub(crate) const SIGNATURE_LABEL: &str = "sig1";
pub(crate) const SIGNATURE_VALIDITY_SECONDS: i64 = 30;
pub(crate) const MIN_NONCE_LENGTH: usize = 16;
pub(crate) const MAX_NONCE_LENGTH: usize = 128;

pub(crate) const COVERED_COMPONENTS: &str = "(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\" \"infernal-service-id\" \"infernal-instance-id\" \"infernal-request-id\")";

pub(crate) fn signature_parameters(
    created: i64,
    expires: i64,
    nonce: &str,
    key_id: Uuid,
) -> String {
    format!(
        "{COVERED_COMPONENTS};created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{key_id}\";alg=\"ed25519\""
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn signature_base(
    method: &str,
    target_uri: &str,
    digest: &str,
    content_type: &str,
    service_id: Uuid,
    instance_id: Uuid,
    request_id: Uuid,
    parameters: &str,
) -> String {
    format!(
        "\"@method\": {method}\n\"@target-uri\": {target_uri}\n\"content-digest\": {digest}\n\"content-type\": {content_type}\n\"infernal-service-id\": {service_id}\n\"infernal-instance-id\": {instance_id}\n\"infernal-request-id\": {request_id}\n\"@signature-params\": {parameters}"
    )
}

pub(crate) fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

pub(crate) fn validate_signature_metadata(
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<(), ClientError> {
    if created < 0 {
        return Err(ClientError::InvalidRequestPart("created"));
    }
    if expires <= created || expires - created > SIGNATURE_VALIDITY_SECONDS {
        return Err(ClientError::InvalidRequestPart("expires"));
    }
    if !(MIN_NONCE_LENGTH..=MAX_NONCE_LENGTH).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ClientError::InvalidRequestPart("nonce"));
    }
    Ok(())
}

pub(crate) fn valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

pub(crate) fn valid_uri_value(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

pub(crate) fn encode_signature(signature: &[u8]) -> String {
    format!("{SIGNATURE_LABEL}=:{}:", STANDARD.encode(signature))
}
