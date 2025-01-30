use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CrlDistributionPoint, DistinguishedName,
    DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct HostNames {
    rng: SystemRandom,
}

impl HostNames {
    fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    fn crl(&self, fqdn: &str) -> String {
        format!("http://{}/crl/{}.crl", fqdn, Uuid::new_v4())
    }

    fn random(&self, len: usize) -> String {
        let mut buf = vec![0u8; len / 2];
        self.rng.fill(&mut buf).unwrap();

        hex::encode(buf)
    }

    fn regional(&self) -> String {
        format!("{}.eu-central-1.aws.nitro-enclaves", self.random(16))
    }

    fn zonal(&self) -> String {
        format!("{}.zonal.eu-central-1.aws.nitro-enclaves", self.random(16))
    }

    fn instance(&self) -> String {
        format!("i-{}.eu-central-1.aws.nitro-enclaves", self.random(16))
    }

    fn enclave(&self) -> String {
        format!(
            "i-{}-enc{}.eu-central-1.aws",
            self.random(16),
            self.random(16)
        )
    }
}

pub struct Cert {
    pub cert: Certificate,
    pub keys: KeyPair,
}

impl Cert {
    fn new(
        lifetime: Duration,
        dn_elements: Vec<(DnType, &str)>,
        ca: IsCa,
        crl_fqdn: Option<&str>,
        parent: Option<&Cert>,
    ) -> Self {
        let mut params = CertificateParams::default();

        let now = OffsetDateTime::now_utc();

        params.not_before = now - lifetime / 2;
        params.not_after = now + lifetime / 2;

        let mut dn = DistinguishedName::new();

        dn.push(DnType::CountryName, "US");
        dn.push(DnType::OrganizationName, Self::censor("Amazon"));
        dn.push(DnType::OrganizationalUnitName, Self::censor("AWS"));

        for (k, v) in dn_elements {
            dn.push(k, Self::censor(v));
        }

        params.distinguished_name = dn;

        match ca {
            IsCa::Ca(BasicConstraints::Unconstrained) => {
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::CrlSign,
                ];
            }
            IsCa::Ca(BasicConstraints::Constrained(n)) => {
                params.use_authority_key_identifier_extension = true;

                if n > 0 {
                    params.key_usages = vec![
                        KeyUsagePurpose::DigitalSignature,
                        KeyUsagePurpose::KeyCertSign,
                        KeyUsagePurpose::CrlSign,
                    ];
                } else {
                    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
                }
            }
            IsCa::ExplicitNoCa => {
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::ContentCommitment,
                ];
            }
            IsCa::NoCa => {
                panic!("no ca is not supported");
            }
        }

        params.is_ca = ca;

        if let Some(crl_fqdn) = crl_fqdn {
            params.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![Self::censor(crl_fqdn)],
            }];
        }

        let keys = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("failed to generate keys");

        let cert = if let Some(parent) = parent {
            params
                .signed_by(&keys, &parent.cert, &parent.keys)
                .expect("failed to sign certificate")
        } else {
            params
                .self_signed(&keys)
                .expect("failed to self sign certificate")
        };

        Self { cert, keys }
    }

    fn censor(name: &str) -> String {
        name.replace("Amazon", "not-Amazon")
            .replace("amazon", "not-amazon")
            .replace("AWS", "not-AWS")
            .replace("aws", "not-aws")
            .replace(".com", ".test")
    }
}

/// Builds a nitro enclave compatible certificate chain for usage in attestation documents.
pub fn chain() -> Vec<Cert> {
    let hostnames = HostNames::new();

    let root = Cert::new(
        Duration::days(30 * 365),
        vec![(DnType::CommonName, "aws.nitro-enclaves")],
        IsCa::Ca(BasicConstraints::Unconstrained),
        None,
        None,
    );

    let l1 = Cert::new(
        Duration::hours(481),
        vec![(DnType::CommonName, &hostnames.regional())],
        IsCa::Ca(BasicConstraints::Constrained(2)),
        Some(&hostnames.crl("aws-nitro-enclaves-crl.s3.amazonaws.com")),
        Some(&root),
    );

    let l2 = Cert::new(
        Duration::hours(135),
        vec![
            (DnType::CommonName, &hostnames.zonal()),
            (DnType::StateOrProvinceName, "WA"),
            (DnType::LocalityName, "Seattle"),
        ],
        IsCa::Ca(BasicConstraints::Constrained(1)),
        Some(&hostnames.crl("crl-eu-central-1-aws-nitro-enclaves.s3.eu-central-1.amazonaws.com")),
        Some(&l1),
    );

    let l3 = Cert::new(
        Duration::hours(24),
        vec![
            (DnType::CommonName, &hostnames.instance()),
            (DnType::StateOrProvinceName, "Washington"),
            (DnType::LocalityName, "Seattle"),
        ],
        IsCa::Ca(BasicConstraints::Constrained(0)),
        None,
        Some(&l2),
    );

    let leaf = Cert::new(
        Duration::hours(3),
        vec![
            (DnType::CommonName, &hostnames.enclave()),
            (DnType::StateOrProvinceName, "Washington"),
            (DnType::LocalityName, "Seattle"),
        ],
        IsCa::ExplicitNoCa,
        None,
        Some(&l3),
    );

    vec![root, l1, l2, l3, leaf]
}
