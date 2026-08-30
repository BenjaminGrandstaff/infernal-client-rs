//! Goal: actually perform the network calls a signed request implies —
//! sending it to whatever is verifying the same profile, and fetching a
//! kernel's published identity — using a blocking client so this crate
//! never forces an async runtime on its caller.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::enrollment::{EnrolledInstance, EnrollmentRejection, EnrollmentSubmission};
use crate::error::ClientError;
use crate::kernel_identity::KernelIdentity;
use crate::request::SignedRequest;

const PEM_CERTIFICATE_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERTIFICATE_END: &str = "-----END CERTIFICATE-----";

/// The result of sending a signed request. This crate does not interpret
/// response bodies itself — that is caller-specific (an evaluator's verdict
/// shape, a subscription's JSON DTO, and so on).
pub struct SentResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct Client {
    http: reqwest::blocking::Client,
}

impl Client {
    pub fn new() -> Result<Self, ClientError> {
        let http = reqwest::blocking::Client::builder()
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        Ok(Self { http })
    }

    /// Builds a client that additionally trusts `extra_root_certificate_pem`
    /// -- one PEM-encoded certificate -- alongside this crate's default
    /// public root store. This is what lets a caller reach a peer (a
    /// kernel, or any other signed-REST service this crate calls) whose
    /// TLS certificate chains to a private or self-signed certificate
    /// authority, for example a kernel deployed behind a TLS-terminating
    /// sidecar inside a private cluster network, without weakening
    /// verification for every other host this client might ever call:
    /// [`Client::new`]'s default trust store is untouched for hosts this
    /// extra certificate does not cover.
    pub fn with_extra_root_certificate(
        extra_root_certificate_pem: &[u8],
    ) -> Result<Self, ClientError> {
        validate_pem_certificate(extra_root_certificate_pem)?;
        let certificate = reqwest::Certificate::from_pem(extra_root_certificate_pem)
            .map_err(|_| ClientError::InvalidTrustAnchor)?;
        let http = reqwest::blocking::Client::builder()
            .add_root_certificate(certificate)
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        Ok(Self { http })
    }

    /// Sends a signed request exactly as constructed: same method, same
    /// target URI, same headers, same body — nothing added or reordered
    /// beyond what an HTTP client fills in itself (`Host`, `Content-Length`).
    pub fn send(&self, request: &SignedRequest) -> Result<SentResponse, ClientError> {
        let method = reqwest::Method::from_bytes(request.parts().method().as_bytes())
            .map_err(|_| ClientError::Transport("invalid method".to_owned()))?;
        let mut builder = self
            .http
            .request(method, request.parts().target_uri())
            .body(request.parts().body().to_vec());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let response = builder
            .send()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|error| ClientError::Transport(error.to_string()))?
            .to_vec();
        Ok(SentResponse { status, body })
    }

    /// Fetches and parses `GET /v1/kernel-identity` from `base_url` (for
    /// example `https://kernel.example.test`).
    pub fn fetch_kernel_identity(&self, base_url: &str) -> Result<KernelIdentity, ClientError> {
        let response = self
            .http
            .get(format!("{base_url}/v1/kernel-identity"))
            .send()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ClientError::Transport(format!(
                "kernel identity fetch returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        KernelIdentity::from_json(&body)
    }

    /// Submits a signed ADR-0008 enrollment proof to
    /// `POST {base_url}/v1/enrollments`. Unlike [`Client::send`], this call
    /// is not itself request-signed (ADR-0003 signing requires an already-
    /// registered instance, which is exactly what enrollment is
    /// bootstrapping); the proof embedded in `submission`'s body is what
    /// the kernel authenticates instead.
    pub fn submit_enrollment(
        &self,
        base_url: &str,
        submission: &EnrollmentSubmission,
    ) -> Result<EnrolledInstance, ClientError> {
        let response = self
            .http
            .post(format!("{base_url}/v1/enrollments"))
            .json(submission)
            .send()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        if status.is_success() {
            return serde_json::from_slice(&body)
                .map_err(|_| ClientError::MalformedEnrollmentResponse);
        }
        let rejection: EnrollmentRejection =
            serde_json::from_slice(&body).map_err(|_| ClientError::MalformedEnrollmentResponse)?;
        Err(ClientError::EnrollmentRejected(rejection))
    }
}

/// Rejects a malformed or empty root certificate before it ever reaches
/// `reqwest`. Under this crate's `rustls-tls` backend,
/// `reqwest::Certificate::from_pem` performs no validation at all -- it
/// stores the raw bytes unchecked -- and `ClientBuilder::build` can
/// silently succeed even when the bytes contain zero usable certificates,
/// producing a `Client` that quietly trusts nothing extra instead of
/// failing loudly. A trust-anchor misconfiguration must fail closed at
/// construction time, not surface later as a confusing TLS handshake
/// failure against the very peer this was supposed to make reachable.
fn validate_pem_certificate(pem: &[u8]) -> Result<(), ClientError> {
    let text = std::str::from_utf8(pem).map_err(|_| ClientError::InvalidTrustAnchor)?;
    let after_begin = text
        .find(PEM_CERTIFICATE_BEGIN)
        .map(|index| index + PEM_CERTIFICATE_BEGIN.len())
        .ok_or(ClientError::InvalidTrustAnchor)?;
    let body_len = text[after_begin..]
        .find(PEM_CERTIFICATE_END)
        .ok_or(ClientError::InvalidTrustAnchor)?;
    let body: String = text[after_begin..after_begin + body_len]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let decoded = STANDARD
        .decode(body)
        .map_err(|_| ClientError::InvalidTrustAnchor)?;
    // A minimal DER sanity check: every X.509 certificate is a SEQUENCE
    // (tag 0x30), never empty.
    if decoded.first() != Some(&0x30) {
        return Err(ClientError::InvalidTrustAnchor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn with_extra_root_certificate_rejects_malformed_pem() {
        assert!(matches!(
            Client::with_extra_root_certificate(b"not a certificate"),
            Err(ClientError::InvalidTrustAnchor)
        ));
    }

    #[test]
    fn with_extra_root_certificate_rejects_markers_around_invalid_base64() {
        let pem = b"-----BEGIN CERTIFICATE-----\nnot base64 !!!\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            Client::with_extra_root_certificate(pem),
            Err(ClientError::InvalidTrustAnchor)
        ));
    }

    #[test]
    fn with_extra_root_certificate_accepts_a_real_self_signed_certificate() {
        // A throwaway Ed25519 self-signed certificate (CN=test.example),
        // generated once with `openssl req -x509 -newkey ed25519 ...` --
        // real DER content, not a fixture this test's own code produced,
        // so this proves validate_pem_certificate's sanity check and
        // reqwest's own PEM handling both accept a genuine certificate,
        // not just that they reject garbage.
        const REAL_SELF_SIGNED_CERTIFICATE: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIBQjCB9aADAgECAhRpqM8BLN6ZrntNN+EylrXXRppFfjAFBgMrZXAwFzEVMBMG\n\
A1UEAwwMdGVzdC5leGFtcGxlMB4XDTI2MDgzMDE1MDI1N1oXDTM2MDgyNzE1MDI1\n\
N1owFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCowBQYDK2VwAyEAQos0+A3ENFhQ\n\
/60s4B3ti+Mi3Du0JAFk9kBLqmh8KDOjUzBRMB0GA1UdDgQWBBRManztQrm98Wri\n\
61MjzWkVj91sJTAfBgNVHSMEGDAWgBRManztQrm98Wri61MjzWkVj91sJTAPBgNV\n\
HRMBAf8EBTADAQH/MAUGAytlcANBALhZET94apdND1IVLlWuPqX6o16GhDGQ45YF\n\
bZp8vx1JP4bVywoiLZdIL+IQ5EmolWR3cNzrmWwNIwAGZhEWfgk=\n\
-----END CERTIFICATE-----\n";
        assert!(Client::with_extra_root_certificate(REAL_SELF_SIGNED_CERTIFICATE).is_ok());
    }

    #[test]
    fn fetch_kernel_identity_parses_a_real_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            let body = format!(
                r#"{{"algorithm":"ed25519","instance_id":"{}","key_id":"{}","public_key":"{}","fingerprint":"{}"}}"#,
                Uuid::new_v4(),
                Uuid::new_v4(),
                URL_SAFE_NO_PAD.encode([1_u8; 32]),
                URL_SAFE_NO_PAD.encode([2_u8; 32]),
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let client = Client::new().unwrap();
        let identity = client
            .fetch_kernel_identity(&format!("http://127.0.0.1:{port}"))
            .unwrap();

        assert_eq!(identity.public_key_bytes(), &[1_u8; 32]);
        server.join().unwrap();
    }

    #[test]
    fn fetch_kernel_identity_reports_a_non_success_status_as_a_transport_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });

        let client = Client::new().unwrap();
        let result = client.fetch_kernel_identity(&format!("http://127.0.0.1:{port}"));

        assert!(matches!(result, Err(ClientError::Transport(_))));
        server.join().unwrap();
    }
}
