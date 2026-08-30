//! Native Rust client for the infernal-law kernel's signed REST contract
//! ([ADR-0003](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0003-direct-signed-service-rest.md)).
//! This is the reference implementation for the `infernal-client-*` SDK
//! family ([ADR-0012](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0012-rust-first-client-sdk-family-over-signed-rest.md)):
//! every other language's SDK is checked for wire-level compatibility
//! against this crate.
//!
//! This crate signs and sends requests; it never links or embeds any kernel
//! code. It also verifies messages a kernel process signs, using the kernel
//! process's self-published identity
//! ([ADR-0014](https://github.com/BenjaminGrandstaff/infernal-law/blob/main/docs/architecture/decisions/0014-publish-kernel-identity-endpoint.md))
//! rather than static configuration that would break on every kernel
//! restart — this is what lets a policy evaluator, or any other caller the
//! kernel signs a request to, confirm the request really came from the
//! kernel.
//!
//! No request signing here bypasses the kernel's mediation boundary: this
//! crate only ever produces an ordinary authenticated network call.

mod credential;
mod enrollment;
mod error;
mod kernel_identity;
mod request;
mod transport;
mod verify;
mod wire;

pub use credential::{ClientCredential, ClientPublicKey};
pub use enrollment::{
    CHALLENGE_LENGTH, EnrolledInstance, EnrollmentRejection, EnrollmentSubmission,
};
pub use error::ClientError;
pub use kernel_identity::KernelIdentity;
pub use request::{RequestParts, SignedRequest, generate_nonce};
pub use transport::{Client, SentResponse};
pub use verify::{IncomingRequest, VerifiedRequest, verify_incoming};
