use crate::crypto::{gen_keypair, JwsSignatureAlgorithm, KeyType};

const TEST_DATA: &'static [u8] = &[72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33];

#[test]
fn test_rs256_sign_rsa2048() {
    let k = gen_keypair(KeyType::Rsa2048).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Rs256, TEST_DATA).unwrap();
}

#[test]
fn test_rs256_sign_rsa4096() {
    let k = gen_keypair(KeyType::Rsa4096).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Rs256, TEST_DATA).unwrap();
}

#[test]
fn test_rs256_sign_ecdsa() {
    let k = gen_keypair(KeyType::EcdsaP256).unwrap();
    let res = k.sign(&JwsSignatureAlgorithm::Rs256, TEST_DATA);
    assert!(res.is_err());
}

#[test]
fn test_es256_sign_p256() {
    let k = gen_keypair(KeyType::EcdsaP256).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Es256, TEST_DATA).unwrap();
}

#[test]
fn test_es256_sign_p384() {
    let k = gen_keypair(KeyType::EcdsaP384).unwrap();
    let res = k.sign(&JwsSignatureAlgorithm::Es256, TEST_DATA);
    assert!(res.is_err());
}

#[test]
fn test_es384_sign_p384() {
    let k = gen_keypair(KeyType::EcdsaP384).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Es384, TEST_DATA).unwrap();
}

#[test]
fn test_es384_sign_p256() {
    let k = gen_keypair(KeyType::EcdsaP256).unwrap();
    let res = k.sign(&JwsSignatureAlgorithm::Es384, TEST_DATA);
    assert!(res.is_err());
}

#[cfg(ed25519)]
#[test]
fn test_ed25519_sign() {
    let k = gen_keypair(KeyType::Ed25519).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Ed25519, TEST_DATA).unwrap();
}

#[cfg(ed448)]
#[test]
fn test_ed448_sign() {
    let k = gen_keypair(KeyType::Ed448).unwrap();
    let _ = k.sign(&JwsSignatureAlgorithm::Ed448, TEST_DATA).unwrap();
}
