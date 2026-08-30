# infernal-client-rs

The native Rust client for the
[infernal-law](https://github.com/BenjaminGrandstaff/infernal-law) governance
kernel, and the reference implementation for the `infernal-client-*` SDK
family.

## What this is

infernal-law's kernel exposes exactly one public contract: signed HTTPS REST
using the Ed25519/RFC 9421 HTTP Message Signatures profile with JSON bodies
([ADR-0003](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0003-direct-signed-service-rest.md)).
No caller links kernel code in-process; every language reaches the kernel
only over that network contract
([ADR-0012](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0012-rust-first-client-sdk-family-over-signed-rest.md)).

`infernal-client-rs` implements that contract for Rust callers:

- `RequestParts` + `SignedRequest::sign` — request construction, Ed25519
  signing, and RFC 9421 signature-base construction, ported directly from
  the kernel's own `service_requests.rs` (the same logic the kernel's
  verifier round-trips against in its own contract tests).
- `KernelIdentity` — fetches and verifies against a kernel process's
  self-published signing key
  ([`GET /v1/kernel-identity`](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0014-publish-kernel-identity-endpoint.md)),
  so a caller can trust a kernel-signed message without static
  configuration that breaks on every kernel restart.
- `IncomingRequest` + `verify_incoming` — the server-side counterpart to
  signing: verifies an inbound request against a given public key (a
  `KernelIdentity`, or any other registered service's key). This is what
  lets a Rust service that *receives* kernel-originated signed calls (for
  example a policy evaluator under
  [ADR-0013](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0013-external-stateless-policy-evaluator-for-authority.md))
  authenticate them without a second, independent implementation of the
  same protocol.
- `Client` — a blocking (no async runtime required) transport that sends a
  `SignedRequest` and fetches a kernel's identity.

Every other `infernal-client-*` SDK is checked for wire-level compatibility
against this crate, not against each other.

[`infernal-client-c`](https://github.com/BenjaminGrandstaff/infernal-client-c)
wraps this crate behind a narrow `extern "C"` ABI for callers that need
in-process native integration and cannot conveniently make their own signed
HTTPS calls.

## Status

The signing/verification core is implemented and unit-tested independently
of the kernel. infernal-law now depends on this crate at runtime, not only
in its test suite: `HttpPolicyEvaluator` uses `sign_with` to sign the
kernel's outbound calls to a policy evaluator with the kernel's own
long-lived instance credential. infernal-law's own tests verify, against
its real, unmodified `ServiceRequestVerifier`, that both a request this
crate signs with a `ClientCredential` and a request the kernel signs with
its own credential via `sign_with` are correctly accepted — and that a
tampered body or an unregistered credential is correctly rejected. The
kernel's ILK-010 subscription routes now dispatch to real create/list/disable
handlers rather than a placeholder response, though ILK-002 Authority
evaluation is not yet called from that path. Not yet built: retries,
idempotency-key handling, and typed request/response schemas for specific
kernel operations.

## Development

```sh
cargo build
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
