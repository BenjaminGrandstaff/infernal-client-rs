//! Goal: construct exactly the signed-HTTP request shape the kernel's
//! verifier expects (ADR-0003) — same covered components, same signature
//! base, same encoding — so a caller only has to supply the parts that vary
//! per call.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use crate::credential::{ClientCredential, ClientPublicKey, SIGNATURE_LENGTH};
use crate::error::ClientError;
use crate::wire::{self, SIGNATURE_LABEL};

/// The caller-supplied, per-call parts of a signed request. Validated up
/// front so a malformed call fails before any network activity or signing.
/// Also used to represent an inbound request's parts for verification
/// (`crate::verify`) — the same shape applies in both directions.
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
        if !wire::valid_uri_value(authority)
            || authority
                .bytes()
                .any(|byte| matches!(byte, b'/' | b'@' | b'?' | b'#'))
        {
            return Err(ClientError::InvalidRequestPart("authority"));
        }
        if !path_and_query.starts_with('/')
            || path_and_query.contains('#')
            || !wire::valid_uri_value(path_and_query)
        {
            return Err(ClientError::InvalidRequestPart("path_and_query"));
        }
        if !wire::valid_header_value(content_type) {
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
    /// Signs `parts` using a credential this crate generated and owns.
    pub fn sign(
        parts: RequestParts,
        credential: &ClientCredential,
        created: i64,
        expires: i64,
        nonce: &str,
    ) -> Result<Self, ClientError> {
        Self::sign_with(parts, credential.public_key(), created, expires, nonce, {
            |message| credential.sign(message)
        })
    }

    /// Signs `parts` using a keypair the caller already holds elsewhere —
    /// for example a host process's own long-lived instance credential —
    /// instead of a `ClientCredential` this crate generated. `signer` must
    /// produce an Ed25519 signature over exactly the bytes it is given,
    /// using the private key matching `public_key`.
    ///
    /// This is what lets a caller keep signing with the *same* key it
    /// publishes elsewhere (for example at `GET /v1/kernel-identity`)
    /// rather than a second, different key that a verifier would never
    /// recognize.
    pub fn sign_with(
        parts: RequestParts,
        public_key: &ClientPublicKey,
        created: i64,
        expires: i64,
        nonce: &str,
        signer: impl FnOnce(&[u8]) -> [u8; SIGNATURE_LENGTH],
    ) -> Result<Self, ClientError> {
        wire::validate_signature_metadata(created, expires, nonce)?;
        let content_digest = wire::content_digest(parts.body());
        let signature_parameters =
            wire::signature_parameters(created, expires, nonce, public_key.key_id());
        let base = wire::signature_base(
            parts.method(),
            &parts.target_uri(),
            &content_digest,
            parts.content_type(),
            public_key.service_id(),
            public_key.instance_id(),
            parts.request_id(),
            &signature_parameters,
        );
        let signature = signer(base.as_bytes());
        Ok(Self {
            parts,
            service_id: public_key.service_id(),
            instance_id: public_key.instance_id(),
            content_digest,
            signature_input: format!("{SIGNATURE_LABEL}={signature_parameters}"),
            signature: wire::encode_signature(&signature),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MAX_NONCE_LENGTH, MIN_NONCE_LENGTH};

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

    #[test]
    fn sign_with_an_externally_held_key_matches_sign_for_the_same_keypair() {
        let credential = credential();
        let nonce = generate_nonce().unwrap();
        let shared_parts = parts();

        let via_sign =
            SignedRequest::sign(shared_parts.clone(), &credential, 1_000, 1_020, &nonce).unwrap();
        let restored = ClientPublicKey::restore(
            credential.public_key().service_id(),
            credential.public_key().instance_id(),
            credential.public_key().key_id(),
            *credential.public_key().public_key_bytes(),
        )
        .unwrap();
        let via_sign_with =
            SignedRequest::sign_with(shared_parts, &restored, 1_000, 1_020, &nonce, |message| {
                credential.sign(message)
            })
            .unwrap();

        assert_eq!(via_sign.signature_input(), via_sign_with.signature_input());
        assert_eq!(via_sign.signature(), via_sign_with.signature());
        assert_eq!(via_sign.content_digest(), via_sign_with.content_digest());
    }
}
