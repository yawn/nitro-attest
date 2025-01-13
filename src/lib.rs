use ::time::OffsetDateTime;
pub use aws_nitro_enclaves_nsm_api::api::AttestationDoc; // TODO: internalize this and expose the X509 certificate
use coset::{CborSerializable, CoseError, CoseSign1};
use ring::{
    digest::{self, SHA256},
    signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED},
};
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
    "/AWS_NitroEnclaves_Root-G1.zip.root.pem.sha256"
));

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

#[derive(Debug)]
pub struct UnparsedAttestationDoc<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for UnparsedAttestationDoc<'a> {
    fn from(val: &'a [u8]) -> Self {
        UnparsedAttestationDoc(val)
    }
}

impl UnparsedAttestationDoc<'_> {
    fn cn<'a>(x509: &'a X509Certificate) -> Result<&'a str> {
        let cn = x509
            .subject()
            .iter_common_name()
            .next()
            .ok_or(Error::CommonNameMissing)?;

        let cn = cn.as_str().map_err(|e| Error::CommonNameMalformed(e))?;

        Ok(cn)
    }

    pub fn parse_and_verify(&self, now: OffsetDateTime) -> Result<AttestationDoc> {
        let document =
            CoseSign1::from_slice(self.0).map_err(|e| Error::CoseSignatureMalformed(e))?;

        let payload = document.payload.as_ref().ok_or(Error::CosePayloadMissing)?;

        let doc = AttestationDoc::from_binary(payload).map_err(|e| match e {
            aws_nitro_enclaves_nsm_api::api::Error::Cbor(e) => {
                Error::CosePayloadMalformed { source: Some(e) }
            }
            _ => Error::CosePayloadMalformed { source: None },
        })?;

        // verify offline by inspecting with openssl (e.g. xxd -r -p | openssl x509 -inform DER -text -noout)
        debug!("decode and verify certificates");

        let cert = doc
            .cabundle
            .iter()
            .chain(vec![&doc.certificate])
            .enumerate()
            .try_fold(None, |parent, (idx, cert)| {
                let (_, x509) = X509Certificate::from_der(cert).map_err(|e| match e {
                    x509_parser::nom::Err::Incomplete(_) => Error::CertificateMalformed {
                        idx: idx,
                        incomplete: true,
                        source: None,
                    },
                    x509_parser::nom::Err::Error(e) => Error::CertificateMalformed {
                        idx: idx,
                        incomplete: false,
                        source: Some(e),
                    },
                    x509_parser::nom::Err::Failure(e) => Error::CertificateMalformed {
                        idx: idx,
                        incomplete: false,
                        source: Some(e),
                    },
                })?;

                // validate integrity before any other checks
                let mut logger = VecLogger::default();
                let ok = X509StructureValidator.validate(&x509, &mut logger);

                if !ok {
                    return Err(Error::CertificateMalformedStructure { idx, logger });
                }

                // this is just for information purposes - the cn is not validated yet
                // TODO: potentially flag this in the tracing keys
                let cn = Self::cn(&x509)?;

                // ensure algorithm before doing signature checks
                let alg = x509.signature_algorithm.oid();

                if alg != &OID_SIG_ECDSA_WITH_SHA384 {
                    return Err(Error::CertificateUnexpectedAlgorithm {
                        cn: cn.to_owned(),
                        idx: idx,
                        oid: alg.to_owned(),
                    });
                }

                // we use hex to make it simpler to copy & paste when logging via console.log
                match parent {
                    Some(parent) => {
                        debug!(
                            cert = hex::encode(cert),
                            cn = debug(cn),
                            parent_cn = debug(Self::cn(&parent)?),
                            idx = idx,
                            "validating certificate by parent signature"
                        );

                        // TODO: test what happens if no signature and / or public key is present
                        x509.verify_signature(Some(parent.public_key()))
                            .map_err(|e| Error::CertificateSignatureInvalid {
                                cn: cn.to_string(),
                                idx: idx,
                                source: e,
                            })?;
                    }
                    None => {
                        debug!(
                            cert = hex::encode(cert),
                            cn = debug(cn),
                            idx = idx,
                            "validating root certificate by embedded fingerprint"
                        );

                        let want = ROOT_FINGERPRINT;
                        let have = digest::digest(&SHA256, cert);

                        if have.as_ref() != want {
                            return Err(Error::CertificateRootInvalid {
                                have: hex::encode(have.as_ref()),
                                want: hex::encode(want),
                            });
                        }
                    }
                }

                // check for validity after signature check to allow a chance to debug
                let not_after = x509.validity.not_after.to_datetime();

                if now > not_after {
                    return Err(Error::CertificateExpired {
                        cn: cn.to_string(),
                        idx: idx,
                        now: now,
                        then: not_after,
                    });
                }

                let not_before = x509.validity.not_before.to_datetime();

                if now < not_before {
                    return Err(Error::CertificateNotYetValid {
                        cn: cn.to_string(),
                        idx: idx,
                        now: now,
                        then: not_before,
                    });
                }

                let next = Some(x509);

                Ok::<Option<X509Certificate<'_>>, Error>(next)
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

        Ok(doc)
    }
}
