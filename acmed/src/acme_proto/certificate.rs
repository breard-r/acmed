use crate::certificate::{Algorithm, Certificate};
use crate::storage;
use acme_common::crypto::{gen_keypair, KeyPair, KeyType};
use acme_common::error::Error;

fn gen_key_pair(cert: &Certificate) -> Result<KeyPair, Error> {
    let key_type = match cert.algo {
        Algorithm::Rsa2048 => KeyType::Rsa2048,
        Algorithm::Rsa4096 => KeyType::Rsa4096,
        Algorithm::EcdsaP256 => KeyType::EcdsaP256,
        Algorithm::EcdsaP384 => KeyType::EcdsaP384,
    };
    let key_pair = gen_keypair(key_type)?;
    storage::set_keypair(cert, &key_pair)?;
    Ok(key_pair)
}

fn read_key_pair(cert: &Certificate) -> Result<KeyPair, Error> {
    storage::get_keypair(cert)
}

pub fn get_key_pair(cert: &Certificate) -> Result<KeyPair, Error> {
    if cert.kp_reuse {
        match read_key_pair(cert) {
            Ok(key_pair) => Ok(key_pair),
            Err(_) => gen_key_pair(cert),
        }
    } else {
        gen_key_pair(cert)
    }
}
