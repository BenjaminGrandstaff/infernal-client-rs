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
of the kernel, ported field-for-field from the kernel's own
`service_requests.rs` so the wire format matches exactly. The kernel's
governed HTTP routes still return `501` (ILK-002 Authority is not
implemented), so there is no real governed operation to call end-to-end yet.
Not yet built: retries, idempotency-key handling, and typed request/response
schemas for specific kernel operations.

## Development

```sh
cargo build
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
