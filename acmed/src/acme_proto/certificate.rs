use crate::certificate::{Algorithm, Certificate};
use crate::storage;
use acme_common::error::Error;
use acme_common::{b64_encode, gen};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509ReqBuilder;
use serde_json::json;

fn gen_key_pair(cert: &Certificate) -> Result<(PKey<Private>, PKey<Public>), Error> {
    let (priv_key, pub_key) = match cert.algo {
        Algorithm::Rsa2048 => gen::rsa2048(),
        Algorithm::Rsa4096 => gen::rsa4096(),
        Algorithm::EcdsaP256 => gen::p256(),
        Algorithm::EcdsaP384 => gen::p384(),
    }?;
    storage::set_priv_key(cert, &priv_key)?;
    Ok((priv_key, pub_key))
}

fn read_key_pair(cert: &Certificate) -> Result<(PKey<Private>, PKey<Public>), Error> {
    let priv_key = storage::get_priv_key(cert)?;
    let pub_key = storage::get_pub_key(cert)?;
    Ok((priv_key, pub_key))
}

pub fn get_key_pair(cert: &Certificate) -> Result<(PKey<Private>, PKey<Public>), Error> {
    if cert.kp_reuse {
        match read_key_pair(cert) {
            Ok((priv_key, pub_key)) => Ok((priv_key, pub_key)),
            Err(_) => gen_key_pair(cert),
        }
    } else {
        gen_key_pair(cert)
    }
}

pub fn generate_csr(
    cert: &Certificate,
    priv_key: &PKey<Private>,
    pub_key: &PKey<Public>,
) -> Result<String, Error> {
    let mut builder = X509ReqBuilder::new()?;
    builder.set_pubkey(pub_key)?;
    let ctx = builder.x509v3_context(None);
    let mut san = SubjectAlternativeName::new();
    for c in cert.domains.iter() {
        san.dns(&c.dns);
    }
    let san = san.build(&ctx)?;
    let mut ext_stack = Stack::new()?;
    ext_stack.push(san)?;
    builder.add_extensions(&ext_stack)?;
    builder.sign(priv_key, MessageDigest::sha256())?;
    let csr = builder.build();
    let csr = csr.to_der()?;
    let csr = b64_encode(&csr);
    let csr = json!({ "csr": csr });
    Ok(csr.to_string())
}
