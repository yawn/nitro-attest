use nitro_attest::{Error, UnparsedAttestationDoc};
use time::OffsetDateTime;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_basic_validation() {
    let doc: UnparsedAttestationDoc = include_bytes!("attestation.cose").as_slice().into();

    let now = OffsetDateTime::now_utc();

    let res = doc.parse_and_verify(now);

    assert!(res.is_err());

    if let Err(Error::CertificateExpired { cn, idx, now, then }) = res {
        assert!(cn.ends_with("eu-central-1.aws.nitro-enclaves"));
        assert!(idx > 0);
        assert_eq!(now, now);
        assert!(then < now);
    } else {
        panic!("expected certificate expired error");
    }

    let now = OffsetDateTime::from_unix_timestamp(1736182168).unwrap();

    let res = doc.parse_and_verify(now);

    assert!(res.is_ok());
}
