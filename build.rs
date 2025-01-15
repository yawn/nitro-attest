use ring::{
    digest::{self, SHA256},
    test,
};
use std::{
    env, fs,
    io::{Cursor, Read},
    path::Path,
};
use x509_parser::pem;
use zip::ZipArchive;

macro_rules! src {
    () => {
        "src/AWS_NitroEnclaves_Root-G1.zip"
    };
}

const FINGERPRINT_PATH: &str = "root.pem.sha256";

fn main() {
    println!("cargo:rerun-if-changed={}", src!());

    let g1 = include_bytes!(src!());

    // see https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process
    let want =
        test::from_hex("8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c").unwrap();
    let have = digest::digest(&SHA256, g1);

    if have.as_ref() != want {
        panic!("unexpected hash");
    }

    let mut archive = ZipArchive::new(Cursor::new(g1)).expect("failed to open archive");

    let mut root = archive
        .by_name("root.pem")
        .expect("failed to find root.pem");

    let mut data = Vec::new();
    root.read_to_end(&mut data)
        .expect("failed ro read root.pem bytes");

    let out = env::var("OUT_DIR").unwrap();

    let (_, pem) = pem::parse_x509_pem(&data).expect("failed to parse root.pem");

    // 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
    let have = digest::digest(&SHA256, pem.contents.as_ref());

    fs::write(Path::new(&out).join(FINGERPRINT_PATH), have).unwrap();
}
