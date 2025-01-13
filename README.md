# nitro-attest

Attestation document parser and verifier for AWS Nitro Enclaves. Tested to work also in `wasm32-unknown-unknown`.

It performs the following verifications, following the guidance in [AWS Nitro Enclaves documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process):

- Verify root certificate fingerprint is correct, using the official G1 certificate bundle (see `build.rs` for bootstrapping)
- Verify certificate chain signatures
- Verify usage of correct signing algorithm (pinned to `ECDSA_WITH_SHA384`)
- Verify validity fields (not before, not after)
- Verify COSE signature

The crate uses `tracing` with fields appropriate for usage in web contexts such as e.g. logging to end users with `console.log`.  

## Usage

```rust
use nitro_attest::{AttestationDoc, UnparsedAttestationDoc};
use time::OffsetDateTime;

...

let doc: &[u8] = ...;
let doc: UnparsedAttestationDoc = doc.into();
let doc = doc.parse_and_verify(OffsetDateTime::now_utc()).unwrap();

println!("{:?}", doc.public_key);

```
