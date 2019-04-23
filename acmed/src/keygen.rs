use crate::error::Error;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;

fn gen_ec_pair(nid: Nid) -> Result<(PKey<Private>, PKey<Public>), Error> {
    let group = EcGroup::from_curve_name(nid).unwrap();
    let ec_priv_key = EcKey::generate(&group).unwrap();
    let public_key_point = ec_priv_key.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key_point).unwrap();
    Ok((
        PKey::from_ec_key(ec_priv_key).unwrap(),
        PKey::from_ec_key(ec_pub_key).unwrap(),
    ))
}

pub fn p256() -> Result<(PKey<Private>, PKey<Public>), Error> {
    gen_ec_pair(Nid::X9_62_PRIME256V1)
}

pub fn p384() -> Result<(PKey<Private>, PKey<Public>), Error> {
    gen_ec_pair(Nid::SECP384R1)
}

fn gen_rsa_pair(nb_bits: u32) -> Result<(PKey<Private>, PKey<Public>), Error> {
    let priv_key = Rsa::generate(nb_bits).unwrap();
    let pub_key = Rsa::from_public_components(
        priv_key.n().to_owned().unwrap(),
        priv_key.e().to_owned().unwrap(),
    )
    .unwrap();
    Ok((
        PKey::from_rsa(priv_key).unwrap(),
        PKey::from_rsa(pub_key).unwrap(),
    ))
}

pub fn rsa2048() -> Result<(PKey<Private>, PKey<Public>), Error> {
    gen_rsa_pair(2048)
}

pub fn rsa4096() -> Result<(PKey<Private>, PKey<Public>), Error> {
    gen_rsa_pair(4096)
}
