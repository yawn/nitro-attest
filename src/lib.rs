pub use serde_bytes::ByteBuf;

use ::time::OffsetDateTime;
use coset::{CborSerializable, CoseError, CoseSign1};
use ring::{
    digest::{self, SHA256},
    signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED},
};
use std::collections::BTreeMap;
use std::iter::once;
use thiserror::Error;
use tracing::debug;
use x509_parser::{
    certificate::X509Certificate,
    oid_registry::{Oid, OID_SIG_ECDSA_WITH_SHA384},
    prelude::*,
    validate::X509StructureValidator,
};

const ROOT_FINGERPRINT: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/AWS_NitroEnclaves_Root-G1.zip.root.pem.sha256" // TODO: better naming
));

#[derive(Debug)]
pub enum Digest {
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug)]
pub struct AttestationDoc {
    // /// Issuing NSM ID
    pub module_id: String,

    // /// The digest function used for calculating the register values
    // /// Can be: "SHA256" | "SHA512"
    pub digest: Digest,

    /// Time when document was created
    pub timestamp: OffsetDateTime,

    /// Map of all locked PCRs at the moment the attestation document was generated
    pub pcrs: BTreeMap<usize, ByteBuf>,

    /// An optional DER-encoded key the attestation consumer can use to encrypt data with
    pub public_key: Option<ByteBuf>,

    /// Additional signed user data, as defined by protocol.
    pub user_data: Option<ByteBuf>,

    /// An optional cryptographic nonce provided by the attestation consumer as a proof of
    /// authenticity.
    pub nonce: Option<ByteBuf>,
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
}

pub type Result<T> = std::result::Result<T, Error>;

struct Cert<'a> {
    cert: &'a [u8],
    idx: usize,
    x509: X509Certificate<'a>,
}

impl<'a> AsRef<[u8]> for Cert<'a> {
    fn as_ref(&self) -> &[u8] {
        self.cert
    }
}

impl<'a> Cert<'a> {
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

    // TODO: move root here
    fn fingerprint(&self) -> ring::digest::Digest {
        digest::digest(&SHA256, self.cert)
    }

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

    fn validate(&self, now: OffsetDateTime) -> Result<()> {
        let not_after = self.x509.validity.not_after.to_datetime();

        if now > not_after {
            return Err(Error::CertificateExpired {
                cn: self.cn()?.into(),
                idx: self.idx,
                now,
                then: not_after,
            });
        }

        let not_before = self.x509.validity.not_before.to_datetime();

        if now < not_before {
            return Err(Error::CertificateNotYetValid {
                cn: self.cn()?.into(),
                idx: self.idx,
                now,
                then: not_before,
            });
        }

        Ok(())
    }

    fn verify(&self, parent: Option<&Cert>) -> Result<()> {
        let cn = self.cn()?;
        let cert = self.cert;
        let idx = self.idx;

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
                        idx: self.idx,
                        source: e,
                    })?;
            }
            None => {
                debug!(
                    cert,
                    cn, idx, "validating root certificate by embedded fingerprint"
                );

                let want = ROOT_FINGERPRINT;
                let have = self.fingerprint(); // TODO: fix usage of contents equivalent

                if have.as_ref() != want {
                    return Err(Error::CertificateRootInvalid {
                        have: hex::encode(have.as_ref()),
                        want: hex::encode(want),
                    });
                }
            }
        }

        Ok(())
    }
}

pub struct UnparsedAttestationDoc<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for UnparsedAttestationDoc<'a> {
    fn from(val: &'a [u8]) -> Self {
        UnparsedAttestationDoc(val)
    }
}

impl UnparsedAttestationDoc<'_> {
    /// Convert a bundle of DER encoded certificates and a DER encoded leaf certificate into a vector of
    /// X509Certificate objects.
    fn parse_certificates<'a>(
        cabundle: &'a [ByteBuf],
        cert: &'a ByteBuf,
    ) -> Result<Vec<X509Certificate<'a>>> {
        let bundle = cabundle
            .iter()
            .chain(once(cert))
            .enumerate()
            .map(|(idx, cert)| {
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

                // validate integrity before any other checks
                let mut logger = VecLogger::default();

                // validate integrity before any other checks
                let mut logger = VecLogger::default();
                let ok = X509StructureValidator.validate(&x509, &mut logger);

                if !ok {
                    return Err(Error::CertificateMalformedStructure { idx, logger });
                }

                Ok(x509)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(bundle)
    }

    fn parse_cn<'a>(x509: &'a X509Certificate) -> Result<&'a str> {
        let cn = x509
            .subject()
            .iter_common_name()
            .next()
            .ok_or(Error::CommonNameMissing)?;

        let cn = cn.as_str().map_err(Error::CommonNameMalformed)?;

        Ok(cn)
    }

    fn verify_certificate_signature(
        parent: Option<&X509Certificate>,
        x509: &X509Certificate,
        idx: usize,
    ) -> Result<()> {
        // ensure algorithm before doing signature checks
        let alg = x509.signature_algorithm.oid();

        if alg != &OID_SIG_ECDSA_WITH_SHA384 {
            return Err(Error::CertificateUnexpectedAlgorithm {
                cn: Self::parse_cn(&x509)?.into(),
                idx,
                oid: alg.to_owned(),
            });
        }

        // we use hex to make it simpler to copy & paste when logging via console.log
        let cert = hex::encode(x509.as_ref());
        let cn = Self::parse_cn(&x509)?; // TODO: flag this in trace keys

        match parent {
            Some(parent) => {
                let parent_cn = Self::parse_cn(&parent)?;

                debug!(
                    cert = cert,
                    cn = debug(cn),
                    parent_cn = debug(parent_cn),
                    idx = idx,
                    "validating certificate by parent signature"
                );

                // TODO: test what happens if no signature and / or public key is present
                x509.verify_signature(Some(parent.public_key()))
                    .map_err(|e| Error::CertificateSignatureInvalid {
                        cn: cn.into(),
                        idx,
                        source: e,
                    })?;
            }
            None => {
                debug!(
                    cert,
                    cn = debug(cn),
                    idx,
                    "validating root certificate by embedded fingerprint"
                );

                // let want = ROOT_FINGERPRINT;
                // let have = digest::digest(&SHA256, x509.as_ref()); // TODO: fix usage of contents equivalent

                // if have.as_ref() != want {
                //     return Err(Error::CertificateRootInvalid {
                //         have: hex::encode(have.as_ref()),
                //         want: hex::encode(want),
                //     });
                // }
            }
        }

        Ok(())
    }

    fn verify_certificate_validity(
        x509: &X509Certificate,
        idx: usize,
        now: OffsetDateTime,
    ) -> Result<()> {
        let not_after = x509.validity.not_after.to_datetime();

        if now > not_after {
            return Err(Error::CertificateExpired {
                cn: Self::parse_cn(x509)?.into(),
                idx,
                now,
                then: not_after,
            });
        }

        let not_before = x509.validity.not_before.to_datetime();

        if now < not_before {
            return Err(Error::CertificateNotYetValid {
                cn: Self::parse_cn(x509)?.into(),
                idx,
                now,
                then: not_before,
            });
        }

        Ok(())
    }

    pub fn parse_and_verify<'a>(&'a self, now: OffsetDateTime) -> Result<AttestationDoc> {
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

        let certs = Self::parse_certificates(&doc.cabundle, &doc.certificate)?;

        let cert = certs
            .into_iter()
            .enumerate()
            .try_fold::<Option<X509Certificate>, _, Result<_>>(None, |parent, (idx, x509)| {
                Self::verify_certificate_signature(parent.as_ref(), &x509, idx)?;
                Self::verify_certificate_validity(&x509, idx, now)?;
                std::fs::write(format!("{}.der", idx), x509.as_ref()).unwrap();

                println!("wrote {}.der", idx);

                Ok(Some(x509))
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

        let doc = AttestationDoc {
            module_id: doc.module_id,
            digest: match doc.digest {
                aws_nitro_enclaves_nsm_api::api::Digest::SHA256 => Digest::SHA256,
                aws_nitro_enclaves_nsm_api::api::Digest::SHA384 => Digest::SHA384,
                aws_nitro_enclaves_nsm_api::api::Digest::SHA512 => Digest::SHA512,
            },
            timestamp: OffsetDateTime::from_unix_timestamp(doc.timestamp as i64).unwrap(), // TODO: add an error
            pcrs: doc.pcrs,
            public_key: doc.public_key,
            user_data: doc.user_data,
            nonce: doc.nonce,
        };

        Ok(doc)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn init() -> () {}

    #[test]
    fn test_parse_ca() {

        // let cert= X509Certificate {
        //     tbs_certificate: TbsCertificate {}
        // }:

        // // TODO: add entire bundle from attestation.cose

        // let cabundle = vec![];

        // let cert = ByteBuf::from(CERTIFICATE);

        // let certs = UnparsedAttestationDoc::parse_certificates(&cabundle, &cert).unwrap();

        // assert_eq!(certs.len(), 1);
        // assert_eq!(certs[0].subject().to_string(), "C=US, ST=Washington, L=Seattle, O=Amazon, OU=AWS, CN=i-0bee92034f3d60691-enc01943c5eaab3ad6a.eu-central-1.aws");
        // assert_eq!(
        //     UnparsedAttestationDoc::parse_cn(&certs[0]).unwrap(),
        //     "i-0bee92034f3d60691-enc01943c5eaab3ad6a.eu-central-1.aws"
        // );
    }
}
