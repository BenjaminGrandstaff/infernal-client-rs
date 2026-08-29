//! Goal: construct exactly the signed-HTTP request shape the kernel's
//! verifier expects (ADR-0003) — same covered components, same signature
//! base, same encoding — so a caller only has to supply the parts that vary
//! per call.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::credential::ClientCredential;
use crate::error::ClientError;

pub const SIGNATURE_LABEL: &str = "sig1";
pub const SIGNATURE_VALIDITY_SECONDS: i64 = 30;
pub const MIN_NONCE_LENGTH: usize = 16;
pub const MAX_NONCE_LENGTH: usize = 128;

const COVERED_COMPONENTS: &str = "(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\" \"infernal-service-id\" \"infernal-instance-id\" \"infernal-request-id\")";

/// The caller-supplied, per-call parts of a signed request. Validated up
/// front so a malformed call fails before any network activity or signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestParts {
    method: String,
    authority: String,
    path_and_query: String,
    content_type: String,
    body: Vec<u8>,
    request_id: Uuid,
}

impl RequestParts {
    pub fn new(
        method: &str,
        authority: &str,
        path_and_query: &str,
        content_type: &str,
        body: &[u8],
        request_id: Uuid,
    ) -> Result<Self, ClientError> {
        if method.is_empty() || !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(ClientError::InvalidRequestPart("method"));
        }
        if !valid_uri_value(authority)
            || authority
                .bytes()
                .any(|byte| matches!(byte, b'/' | b'@' | b'?' | b'#'))
        {
            return Err(ClientError::InvalidRequestPart("authority"));
        }
        if !path_and_query.starts_with('/')
            || path_and_query.contains('#')
            || !valid_uri_value(path_and_query)
        {
            return Err(ClientError::InvalidRequestPart("path_and_query"));
        }
        if !valid_header_value(content_type) {
            return Err(ClientError::InvalidRequestPart("content_type"));
        }
        Ok(Self {
            method: method.to_owned(),
            authority: authority.to_owned(),
            path_and_query: path_and_query.to_owned(),
            content_type: content_type.to_owned(),
            body: body.to_vec(),
            request_id,
        })
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn target_uri(&self) -> String {
        format!("https://{}{}", self.authority, self.path_and_query)
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
}

/// A fully signed request, ready to send: every header value the kernel's
/// parser expects is already computed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRequest {
    parts: RequestParts,
    service_id: Uuid,
    instance_id: Uuid,
    content_digest: String,
    signature_input: String,
    signature: String,
}

impl SignedRequest {
    pub fn sign(
        parts: RequestParts,
        credential: &ClientCredential,
        created: i64,
        expires: i64,
        nonce: &str,
    ) -> Result<Self, ClientError> {
        validate_signature_metadata(created, expires, nonce)?;
        let public_key = credential.public_key();
        let content_digest = content_digest(parts.body());
        let signature_parameters =
            signature_parameters(created, expires, nonce, public_key.key_id());
        let base = signature_base(
            &parts,
            public_key.service_id(),
            public_key.instance_id(),
            &content_digest,
            &signature_parameters,
        );
        let signature = credential.sign(base.as_bytes());
        Ok(Self {
            parts,
            service_id: public_key.service_id(),
            instance_id: public_key.instance_id(),
            content_digest,
            signature_input: format!("{SIGNATURE_LABEL}={signature_parameters}"),
            signature: format!("{SIGNATURE_LABEL}=:{}:", STANDARD.encode(signature)),
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

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn signature_input(&self) -> &str {
        &self.signature_input
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// The exact header set the kernel's parser requires, each supplied
    /// exactly once. `Host` is deliberately not included: an HTTP client
    /// sets it from the request URL, which callers must build from
    /// [`RequestParts::target_uri`] so it matches the signed authority.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Content-Type", self.parts.content_type().to_owned()),
            ("Content-Digest", self.content_digest.clone()),
            ("Infernal-Service-Id", self.service_id.to_string()),
            ("Infernal-Instance-Id", self.instance_id.to_string()),
            ("Infernal-Request-Id", self.parts.request_id().to_string()),
            ("Signature-Input", self.signature_input.clone()),
            ("Signature", self.signature.clone()),
        ]
    }
}

/// Generates a fresh nonce from 24 random bytes, URL-safe base64 encoded (32
/// characters, alphanumeric plus `-`/`_`) — comfortably inside the kernel's
/// accepted length and character range.
pub fn generate_nonce() -> Result<String, ClientError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| ClientError::RandomSource)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn signature_parameters(created: i64, expires: i64, nonce: &str, key_id: Uuid) -> String {
    format!(
        "{COVERED_COMPONENTS};created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{key_id}\";alg=\"ed25519\""
    )
}

fn signature_base(
    parts: &RequestParts,
    service_id: Uuid,
    instance_id: Uuid,
    digest: &str,
    parameters: &str,
) -> String {
    format!(
        "\"@method\": {}\n\"@target-uri\": {}\n\"content-digest\": {}\n\"content-type\": {}\n\"infernal-service-id\": {}\n\"infernal-instance-id\": {}\n\"infernal-request-id\": {}\n\"@signature-params\": {}",
        parts.method(),
        parts.target_uri(),
        digest,
        parts.content_type(),
        service_id,
        instance_id,
        parts.request_id(),
        parameters,
    )
}

fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

fn validate_signature_metadata(created: i64, expires: i64, nonce: &str) -> Result<(), ClientError> {
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

fn valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn valid_uri_value(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> ClientCredential {
        ClientCredential::generate(Uuid::new_v4())
    }

    fn parts() -> RequestParts {
        RequestParts::new(
            "POST",
            "kernel.example.test",
            "/v1/subscriptions",
            "application/json",
            b"{}",
            Uuid::new_v4(),
        )
        .unwrap()
    }

    #[test]
    fn signing_produces_the_exact_header_set_the_kernel_parser_requires() {
        let credential = credential();
        let signed = SignedRequest::sign(
            parts(),
            &credential,
            1_000,
            1_020,
            &generate_nonce().unwrap(),
        )
        .unwrap();

        let headers = signed.headers();
        let names: Vec<_> = headers.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "Content-Type",
                "Content-Digest",
                "Infernal-Service-Id",
                "Infernal-Instance-Id",
                "Infernal-Request-Id",
                "Signature-Input",
                "Signature",
            ]
        );
    }

    #[test]
    fn signature_input_carries_the_fixed_covered_components_and_algorithm() {
        let credential = credential();
        let signed = SignedRequest::sign(
            parts(),
            &credential,
            1_000,
            1_020,
            &generate_nonce().unwrap(),
        )
        .unwrap();

        assert!(signed.signature_input().starts_with("sig1=(\"@method\""));
        assert!(signed.signature_input().contains("alg=\"ed25519\""));
    }

    #[test]
    fn generated_nonces_are_unique_and_within_the_accepted_length() {
        let first = generate_nonce().unwrap();
        let second = generate_nonce().unwrap();

        assert_ne!(first, second);
        assert!((MIN_NONCE_LENGTH..=MAX_NONCE_LENGTH).contains(&first.len()));
    }

    #[test]
    fn rejects_a_validity_window_longer_than_the_kernels_limit() {
        let credential = credential();
        let result = SignedRequest::sign(
            parts(),
            &credential,
            1_000,
            1_040,
            &generate_nonce().unwrap(),
        );

        assert_eq!(result, Err(ClientError::InvalidRequestPart("expires")));
    }

    #[test]
    fn rejects_a_malformed_authority() {
        let result = RequestParts::new(
            "GET",
            "kernel.example.test/",
            "/v1/subscriptions",
            "application/json",
            b"",
            Uuid::new_v4(),
        );

        assert_eq!(result, Err(ClientError::InvalidRequestPart("authority")));
    }
}
