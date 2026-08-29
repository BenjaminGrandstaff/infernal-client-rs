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

`infernal-client-rs` implements that contract for Rust callers: request
construction, Ed25519 signing, RFC 9421 signature-base construction,
nonce/idempotency handling, retries, and typed request/response schemas.
Every other `infernal-client-*` SDK is checked for wire-level compatibility
against this crate, not against each other.

[`infernal-client-c`](https://github.com/BenjaminGrandstaff/infernal-client-c)
wraps this crate behind a narrow `extern "C"` ABI for callers that need
in-process native integration and cannot conveniently make their own signed
HTTPS calls.

## Status

Early scaffold. The kernel's governed HTTP routes are still pending (ILK-002
Authority is not implemented), so there is no signed request/response
contract to implement against yet. This crate currently only stores client
configuration.

## Development

```sh
cargo build
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
