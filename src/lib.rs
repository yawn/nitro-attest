pub use serde_bytes::ByteBuf;

use ::time::OffsetDateTime;
use coset::{CborSerializable, CoseError, CoseSign1};
use ring::{
    digest::{self, Algorithm, SHA256, SHA384, SHA512},
    signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED},
};
use std::{collections::BTreeMap, iter::once};
use thiserror::Error;
use tracing::debug;
use x509_parser::{
    certificate::X509Certificate,
    oid_registry::{Oid, OID_SIG_ECDSA_WITH_SHA384},
    prelude::*,
    validate::X509StructureValidator,
};

#[derive(Debug)]
pub struct AttestationDoc {
    /// Issuing NSM ID
    pub module_id: String,

    /// Time when document was created-
    pub timestamp: OffsetDateTime,

    /// Map of all locked PCRs at the moment the attestation document was generated-
    pub pcrs: BTreeMap<u16, Digest>,

    /// An optional key the attestation consumer can use to encrypt data with-
    pub public_key: Option<ByteBuf>,

    /// Additional signed user data, as defined by protocol.
    pub user_data: Option<ByteBuf>,

    /// An optional cryptographic nonce provided by the attestation consumer as a proof of
    /// authenticity.
    pub nonce: Option<ByteBuf>,
}

#[derive(Debug)]
pub struct Digest {
    pub algorithm: &'static Algorithm,
    pub value: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("certificate common name is not a string")]
    CommonNameMalformed(#[from] x509_parser::error::X509Error),

    #[error("certificate common name missing")]
    CommonNameMissing,

    #[error("attestation document signature malformed: {0}")]
    CoseSignatureMalformed(#[from] CoseError),

    #[error("attestation document payload missing")]
    CosePayloadMissing,

    #[error("attestation document payload malformed")]
    CosePayloadMalformed {
        #[source]
        source: Option<serde_cbor::error::Error>,
    },

    #[error("certificate {idx} failed to parse")]
    CertificateMalformed {
        idx: usize,
        incomplete: bool,
        #[source]
        source: Option<x509_parser::error::X509Error>,
    },

    #[error("certificate {idx} structure malformed")]
    CertificateMalformedStructure { idx: usize, logger: VecLogger },

    #[error("certificate {idx} ({cn}) unexpected algorithm {oid}")]
    CertificateUnexpectedAlgorithm {
        cn: String,
        idx: usize,
        oid: Oid<'static>,
    },

    #[error("certificate {idx} ({cn}) signature verification failed")]
    CertificateSignatureInvalid {
        cn: String,
        idx: usize,
        #[source]
        source: x509_parser::error::X509Error,
    },

    #[error("root certificate fingerprint mismatch")]
    CertificateRootInvalid { have: String, want: String },

    #[error("certificate {idx} ({cn}) expired")]
    CertificateExpired {
        cn: String,
        idx: usize,
        now: OffsetDateTime,
        then: OffsetDateTime,
    },

    #[error("certificate {idx} ({cn}) not yet valid")]
    CertificateNotYetValid {
        cn: String,
        idx: usize,
        now: OffsetDateTime,
        then: OffsetDateTime,
    },

    #[error("no certificates found in attestation document")]
    NoCertificatesFound,

    #[error("cose signature verification failed")]
    CoseSignatureVerificationFailed(),

    #[error("cose timestamp invalid")]
    CoseTimestampInvalid {
        #[source]
        source: ::time::error::ComponentRange,
        timestamp: u64,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
struct Cert<'a> {
    cert: &'a [u8],
    idx: usize,
    x509: X509Certificate<'a>,
}

impl AsRef<[u8]> for Cert<'_> {
    fn as_ref(&self) -> &[u8] {
        self.cert
    }
}

impl<'a> Cert<'a> {
    const ROOT_FINGERPRINT: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/root.pem.sha256"));

    /// Get the common name of the certificate.
    fn cn(&'a self) -> Result<&'a str> {
        let cn = self
            .x509
            .subject()
            .iter_common_name()
            .next()
            .ok_or(Error::CommonNameMissing)?;

        let cn = cn.as_str().map_err(Error::CommonNameMalformed)?;

        Ok(cn)
    }

    /// Calculate the SHA256 fingerprint of the certificate.
    fn fingerprint(&self) -> ring::digest::Digest {
        digest::digest(&SHA256, self.cert)
    }

    /// Check if the certificate is the root certificate by comparing fingerprints.
    fn is_root(&self) -> bool {
        self.fingerprint().as_ref() == Self::ROOT_FINGERPRINT
    }

    /// Parse the certificate from DER encoded bytes.
    fn parse(cert: &'a [u8], idx: usize) -> Result<Self> {
        let (_, x509) = X509Certificate::from_der(cert).map_err(|e| match e {
            x509_parser::nom::Err::Incomplete(_) => Error::CertificateMalformed {
                idx,
                incomplete: true,
                source: None,
            },
            x509_parser::nom::Err::Error(e) => Error::CertificateMalformed {
                idx,
                incomplete: false,
                source: Some(e),
            },
            x509_parser::nom::Err::Failure(e) => Error::CertificateMalformed {
                idx,
                incomplete: false,
                source: Some(e),
            },
        })?;

        let mut logger = VecLogger::default();
        let ok = X509StructureValidator.validate(&x509, &mut logger);

        if !ok {
            return Err(Error::CertificateMalformedStructure { idx, logger });
        }

        Ok(Self { cert, idx, x509 })
    }

    fn public_key(&'a self) -> &'a SubjectPublicKeyInfo<'a> {
        self.x509.public_key()
    }

    fn validate(self, now: OffsetDateTime) -> Result<Self> {
        let cn = self.cn()?.into();
        let idx = self.idx;

        let not_after = self.x509.validity.not_after.to_datetime();

        if now > not_after {
            return Err(Error::CertificateExpired {
                cn,
                idx,
                now,
                then: not_after,
            });
        }

        let not_before = self.x509.validity.not_before.to_datetime();

        if now < not_before {
            return Err(Error::CertificateNotYetValid {
                cn,
                idx,
                now,
                then: not_before,
            });
        }

        Ok(self)
    }

    /// Verify the certificate by checking the signature of the parent certificate or
    /// by checking is_root() for root certificates.
    fn verify(self, parent: Option<&Cert>) -> Result<Self> {
        // TODO: potentially return verified cert variant - expose tracing fields in struct itself

        let cn = self.cn()?;
        let cert = hex::encode(self.cert); // we use hex to make it simpler to copy & paste when logging via console.log
        let idx = self.idx;

        // ensure algorithm before doing signature checks
        let alg = self.x509.signature_algorithm.oid();

        if alg != &OID_SIG_ECDSA_WITH_SHA384 {
            return Err(Error::CertificateUnexpectedAlgorithm {
                cn: cn.into(),
                idx,
                oid: alg.to_owned(),
            });
        }
        match parent {
            Some(parent) => {
                debug!(
                    cert,
                    cn,
                    parent_cn = parent.cn()?,
                    idx,
                    "validating certificate by parent signature"
                );

                // TODO: test what happens if no signature and / or public key is present
                self.x509
                    .verify_signature(Some(parent.public_key()))
                    .map_err(|e| Error::CertificateSignatureInvalid {
                        cn: cn.into(),
                        idx,
                        source: e,
                    })?;
            }
            None => {
                debug!(
                    cert,
                    cn, idx, "validating root certificate by embedded fingerprint"
                );

                if !self.is_root() {
                    return Err(Error::CertificateRootInvalid {
                        have: hex::encode(self.fingerprint().as_ref()),
                        want: hex::encode(Self::ROOT_FINGERPRINT),
                    });
                }
            }
        }

        Ok(self)
    }
}

pub struct UnparsedAttestationDoc<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for UnparsedAttestationDoc<'a> {
    fn from(val: &'a [u8]) -> Self {
        UnparsedAttestationDoc(val)
    }
}

impl UnparsedAttestationDoc<'_> {
    pub fn parse_and_verify(&self, now: OffsetDateTime) -> Result<AttestationDoc> {
        let document = CoseSign1::from_slice(self.0).map_err(Error::CoseSignatureMalformed)?;

        let payload = document.payload.as_ref().ok_or(Error::CosePayloadMissing)?;

        let doc = aws_nitro_enclaves_nsm_api::api::AttestationDoc::from_binary(payload.as_slice())
            .map_err(|e| match e {
                aws_nitro_enclaves_nsm_api::api::Error::Cbor(e) => {
                    Error::CosePayloadMalformed { source: Some(e) }
                }
                _ => Error::CosePayloadMalformed { source: None },
            })?;

        // verify offline by inspecting with openssl (e.g. xxd -r -p | openssl x509 -inform DER -text -noout)
        debug!("decode and verify certificates");

        let certs = doc
            .cabundle
            .iter()
            .chain(once(&doc.certificate))
            .enumerate()
            .map(|(idx, cert)| Cert::parse(cert, idx))
            .collect::<Result<Vec<_>>>()?;

        let cert = certs
            .into_iter()
            .try_fold::<Option<Cert>, _, Result<_>>(None, |parent, cert| {
                let cert = cert.verify(parent.as_ref())?;
                let cert = cert.validate(now)?;

                Ok(Some(cert))
            })?
            .ok_or(Error::NoCertificatesFound)?;

        debug!("verifying cose signature");

        let public_key = &cert.public_key().subject_public_key.as_ref();
        let aad = &[];

        document.verify_signature(aad, |sig, data| {
            let public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &public_key);

            public_key
                .verify(data, sig)
                .map_err(|_| Error::CoseSignatureVerificationFailed())
        })?;

        let timestamp = doc.timestamp / 1000;
        let timestamp = OffsetDateTime::from_unix_timestamp(timestamp as i64).map_err(|e| {
            Error::CoseTimestampInvalid {
                source: e,
                timestamp: doc.timestamp,
            }
        })?;

        let alg = match doc.digest {
            aws_nitro_enclaves_nsm_api::api::Digest::SHA256 => &SHA256,
            aws_nitro_enclaves_nsm_api::api::Digest::SHA384 => &SHA384,
            aws_nitro_enclaves_nsm_api::api::Digest::SHA512 => &SHA512,
        };

        let pcrs = doc
            .pcrs
            .into_iter()
            .filter(|(_, digest)| !digest.iter().all(|e| e == &0))
            .map(|(idx, digest)| {
                (
                    idx as u16,
                    Digest {
                        algorithm: alg,
                        value: digest.to_vec(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let doc = AttestationDoc {
            module_id: doc.module_id,
            nonce: doc.nonce,
            pcrs,
            public_key: doc.public_key,
            timestamp,
            user_data: doc.user_data,
        };

        Ok(doc)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ::time::Duration;
    use rcgen::{CertificateParams, DnType, KeyPair};

    const C0: &[u8] = include_bytes!("../tests/fixtures/0.der");
    const C1: &[u8] = include_bytes!("../tests/fixtures/1.der");
    const C2: &[u8] = include_bytes!("../tests/fixtures/2.der");
    const C3: &[u8] = include_bytes!("../tests/fixtures/3.der");
    const C4: &[u8] = include_bytes!("../tests/fixtures/4.der");

    fn cert(params: &CertificateParams) -> Result<Cert<'static>> {
        let keypair = KeyPair::generate().unwrap();
        let cert = params.clone().self_signed(&keypair).unwrap();
        let der = Box::leak(cert.der().to_vec().into_boxed_slice());

        Cert::parse(der, 0)
    }

    fn certs() -> Vec<Cert<'static>> {
        [C0, C1, C2, C3, C4]
            .iter()
            .enumerate()
            .map(|(idx, cert)| Cert::parse(cert, idx))
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn test_cn() {
        let certs = certs();
        assert_eq!(certs[0].cn().unwrap(), "aws.nitro-enclaves");
        assert_eq!(
            certs[1].cn().unwrap(),
            "4c2ecc4dee288943.eu-central-1.aws.nitro-enclaves"
        );
        assert_eq!(
            certs[2].cn().unwrap(),
            "edbf01d65003f42f.zonal.eu-central-1.aws.nitro-enclaves"
        );
        assert_eq!(
            certs[3].cn().unwrap(),
            "i-0bee92034f3d60691.eu-central-1.aws.nitro-enclaves"
        );
        assert_eq!(
            certs[4].cn().unwrap(),
            "i-0bee92034f3d60691-enc01943c5eaab3ad6a.eu-central-1.aws"
        );

        let mut params = CertificateParams::default();
        params.distinguished_name.remove(DnType::CommonName);

        let c = cert(&params).unwrap();
        let cn = c.cn();

        match cn.unwrap_err() {
            Error::CommonNameMissing => (),
            e => panic!("{}", e),
        }
    }

    #[test]
    fn test_fingerprint() {
        let certs = certs();

        assert_eq!(
            certs[0].fingerprint().as_ref(),
            ring::test::from_hex(
                "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_is_root() {
        let certs = certs();

        assert!(certs[0].is_root());

        for cert in &certs[1..] {
            assert!(!cert.is_root());
        }
    }

    #[test]
    fn test_parse() {
        let params = CertificateParams::default();
        let c = cert(&params).unwrap();

        let der = c.cert.to_vec();

        match Cert::parse(der[0..0].as_ref(), 0).unwrap_err() {
            Error::CertificateMalformed {
                idx,
                incomplete,
                source,
            } => {
                assert_eq!(idx, 0);
                assert_eq!(incomplete, true);
                assert!(source.is_none());
            }
            e => panic!("{}", e),
        }

        match Cert::parse(der[0..10].as_ref(), 0).unwrap_err() {
            Error::CertificateMalformed {
                idx,
                incomplete,
                source,
            } => {
                assert_eq!(idx, 0);
                assert_eq!(incomplete, false);
                assert!(source.is_some());
            }
            e => panic!("{}", e),
        }
    }

    #[test]
    fn test_validate() {
        let now = OffsetDateTime::now_utc();
        let then = now + Duration::seconds(10);

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "foo");
        params.not_before = then;

        let c = cert(&params).unwrap();

        match c.validate(now).unwrap_err() {
            Error::CertificateNotYetValid { cn, idx, now, then } => {
                assert_eq!(cn, "foo");
                assert_eq!(idx, 0);
                assert_eq!(now, now);
                assert_eq!(then, then);
            }
            e => panic!("{}", e),
        }

        params.not_before = now;
        params.not_after = now;

        let c = cert(&params).unwrap();

        match c.validate(now).unwrap_err() {
            Error::CertificateExpired { cn, idx, now, then } => {
                assert_eq!(cn, "foo");
                assert_eq!(idx, 0);
                assert_eq!(now, now);
                assert_eq!(then, then);
            }
            e => panic!("{}", e),
        }
    }

    #[test]
    fn test_verify() {
        let certs = certs();

        assert!(certs[0].clone().verify(None).is_ok());

        match certs[1].clone().verify(None).unwrap_err() {
            Error::CertificateRootInvalid { .. } => {}
            e => panic!("{}", e),
        }

        match certs[2].clone().verify(Some(&certs[0])).unwrap_err() {
            Error::CertificateSignatureInvalid { cn, idx, .. } => {
                assert_eq!(cn, "edbf01d65003f42f.zonal.eu-central-1.aws.nitro-enclaves");
                assert_eq!(idx, 2);
            }
            e => panic!("{}", e),
        }
    }
}
