# nitro-attest

[![Rust](https://github.com/yawn/nitro-attest/actions/workflows/rust.yml/badge.svg)](https://github.com/yawn/nitro-attest/actions/workflows/rust.yml)

Attestation document builder, parser and verifier for AWS Nitro Enclaves. Tested to work also in `wasm32-unknown-unknown`.

It performs the following verifications, following the guidance in [AWS Nitro Enclaves documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process):

- Verify root certificate fingerprint is correct, using the official G1 certificate bundle (see `build.rs` for bootstrapping)
- Verify certificate chain signatures
- Verify usage of correct signing algorithm (pinned to `ECDSA_WITH_SHA384`) for certificate chain
- Verify validity fields (not before, not after)
- Verify COSE signature

The crate uses `tracing` with fields appropriate for usage in web contexts such as e.g. logging to end users with `console.log`.  

## Usage for verification

```rust
use nitro_attest::{AttestationDoc, UnparsedAttestationDoc};
use time::OffsetDateTime;

...

let doc: &[u8] = ...;
let doc: UnparsedAttestationDoc = doc.into();
let doc = doc.parse_and_verify(OffsetDateTime::now_utc()).unwrap();

println!("{:?}", doc.public_key);

```
## Usage for testing

When building with the `builder` feature, the crate can generate synthetic attestation documents for testing purposes.

Certificate chains in test attestation documents originate from the "eu-central-1" region. Certificate chains have the following differences when compared to the official certificates:

### Keys and fingerprints

- The root certificate is (obviously) not official and has no matching fingerprints
- Key material is available for all certificates to create valid signatures

### Serial numbers 

- Serial numbers are randomized

### Distinguished names

- All elements in the distinguished name named "aws" or "Amazon" are prefixed with "not-"
- Host and enclave names (in zonal or instance-specific) CN's are randomized
- Distinguished name order can be slightly different due to constraints of the `rcgen` crate

Note: starting from the instance-level certificate, the state name is "Washington" instead of "WA". This is an official inconsistency.

### Validity

- Certificate validity is set to roughly the same ranges as the official certificates
- Validity always starts with "now" as their respective anchor point: the root certificate for example is still valid for 30 years but was created 15 years ago and so forth

### X509v3 extensions

- Extension order can be slightly different due to constraints of the `rcgen` crate
- CRL URIs are subject to the same rules as distinguished names and also have their TLD (".com") replaced by .test
- CRL URI UUIDs are randomized

In leaf certificate the following differences apply:

- Subject Key Identifier extensions are present
- The key usage is marked as "critical"
