use nitro_attest::{Digest, Error, UnparsedAttestationDoc};
use time::OffsetDateTime;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_fixture() {
    let doc: UnparsedAttestationDoc = include_bytes!("../tests/fixtures/attestation.cose")
        .as_slice()
        .into();

    let now = OffsetDateTime::now_utc();

    match doc.parse_and_verify(now).unwrap_err() {
        Error::CertificateExpired { cn, idx, now, then } => {
            assert!(cn.ends_with("eu-central-1.aws.nitro-enclaves"));
            assert!(idx > 0);
            assert_eq!(now, now);
            assert!(then < now);
        }
        e => panic!("{}", e),
    }

    let now = OffsetDateTime::from_unix_timestamp(1736179625).unwrap();

    let res = doc.parse_and_verify(now).unwrap();

    assert_eq!(res.module_id, "i-0bee92034f3d60691-enc01943c5eaab3ad6a");
    assert_eq!(res.digest, Digest::SHA384);

    assert_eq!(res.timestamp, now);
    assert_eq!(res.pcrs.len(), 16);

    for i in 0..16 {
        assert!(res.pcrs.get(&i).is_some());
        assert_eq!(res.pcrs.get(&i).unwrap().len(), 48);
    }

    assert!(res.public_key.is_some());
    assert!(res.user_data.is_none());
    assert!(res.nonce.is_none());
}
