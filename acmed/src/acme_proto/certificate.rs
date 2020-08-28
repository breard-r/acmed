use crate::certificate::Certificate;
use crate::storage;
use acme_common::crypto::{gen_keypair, KeyPair};
use acme_common::error::Error;

fn gen_key_pair(cert: &Certificate) -> Result<KeyPair, Error> {
    let key_pair = gen_keypair(cert.key_type)?;
    storage::set_keypair(&cert.file_manager, &key_pair)?;
    Ok(key_pair)
}

fn read_key_pair(cert: &Certificate) -> Result<KeyPair, Error> {
    storage::get_keypair(&cert.file_manager)
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
