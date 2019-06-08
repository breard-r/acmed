use crate::certificate::{Algorithm, Certificate};
use crate::storage;
use acme_common::crypto::{gen_keypair, KeyType, PrivateKey, PublicKey};
use acme_common::error::Error;

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
