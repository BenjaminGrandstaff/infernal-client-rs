//! Goal: actually perform the network calls a signed request implies —
//! sending it to whatever is verifying the same profile, and fetching a
//! kernel's published identity — using a blocking client so this crate
//! never forces an async runtime on its caller.

use crate::error::ClientError;
use crate::kernel_identity::KernelIdentity;
use crate::request::SignedRequest;

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
