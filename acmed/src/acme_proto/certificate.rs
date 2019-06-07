use crate::certificate::{Algorithm, Certificate};
use crate::storage;
use acme_common::b64_encode;
use acme_common::crypto::{gen_keypair, KeyType, PrivateKey, PublicKey};
use acme_common::error::Error;
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509ReqBuilder;
use serde_json::json;

fn gen_key_pair(cert: &Certificate) -> Result<(PublicKey, PrivateKey), Error> {
    let key_type = match cert.algo {
        Algorithm::Rsa2048 => KeyType::Rsa2048,
        Algorithm::Rsa4096 => KeyType::Rsa4096,
        Algorithm::EcdsaP256 => KeyType::EcdsaP256,
        Algorithm::EcdsaP384 => KeyType::EcdsaP384,
    };
    let (pub_key, priv_key) = gen_keypair(key_type)?;
    storage::set_priv_key(cert, &priv_key)?;
    Ok((pub_key, priv_key))
}

fn read_key_pair(cert: &Certificate) -> Result<(PublicKey, PrivateKey), Error> {
    let pub_key = storage::get_pub_key(cert)?;
    let priv_key = storage::get_priv_key(cert)?;
    Ok((pub_key, priv_key))
}

pub fn get_key_pair(cert: &Certificate) -> Result<(PublicKey, PrivateKey), Error> {
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
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
) -> Result<String, Error> {
    let mut builder = X509ReqBuilder::new()?;
    builder.set_pubkey(&pub_key.inner_key)?;
    let ctx = builder.x509v3_context(None);
    let mut san = SubjectAlternativeName::new();
    for c in cert.domains.iter() {
        san.dns(&c.dns);
    }
    let san = san.build(&ctx)?;
    let mut ext_stack = Stack::new()?;
    ext_stack.push(san)?;
    builder.add_extensions(&ext_stack)?;
    builder.sign(&priv_key.inner_key, MessageDigest::sha256())?;
    let csr = builder.build();
    let csr = csr.to_der()?;
    let csr = b64_encode(&csr);
    let csr = json!({ "csr": csr });
    Ok(csr.to_string())
}
