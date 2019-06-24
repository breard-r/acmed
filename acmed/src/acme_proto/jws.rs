use crate::acme_proto::jws::algorithms::{EdDsaVariant, SignatureAlgorithm};
use acme_common::b64_encode;
use acme_common::crypto::{sha256, KeyPair};
use acme_common::error::Error;
use serde::Serialize;

pub mod algorithms;
mod jwk;

#[derive(Serialize)]
struct JwsData {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct JwsProtectedHeaderJwk {
    alg: String,
    jwk: jwk::Jwk,
    nonce: String,
    url: String,
}

#[derive(Serialize)]
struct JwsProtectedHeaderKid {
    alg: String,
    kid: String,
    nonce: String,
    url: String,
}

fn get_data(key_pair: &KeyPair, protected: &str, payload: &[u8]) -> Result<String, Error> {
    let protected = b64_encode(protected);
    let payload = b64_encode(payload);
    let signing_input = format!("{}.{}", protected, payload);
    let fingerprint = sha256(signing_input.as_bytes());
    let signature = key_pair.sign(&fingerprint)?;
    let signature = b64_encode(&signature);
    let data = JwsData {
        protected,
        payload,
        signature,
    };
    let str_data = serde_json::to_string(&data)?;
    Ok(str_data)
}

pub fn encode_jwk(
    key_pair: &KeyPair,
    payload: &[u8],
    url: &str,
    nonce: &str,
) -> Result<String, Error> {
    let sign_alg = SignatureAlgorithm::from_pkey(key_pair)?;
    let protected = JwsProtectedHeaderJwk {
        alg: sign_alg.to_string(),
        jwk: sign_alg.get_jwk(key_pair)?,
        nonce: nonce.into(),
        url: url.into(),
    };
    let protected = serde_json::to_string(&protected)?;
    get_data(key_pair, &protected, payload)
}

pub fn encode_kid(
    key_pair: &KeyPair,
    key_id: &str,
    payload: &[u8],
    url: &str,
    nonce: &str,
) -> Result<String, Error> {
    let sign_alg = SignatureAlgorithm::from_pkey(key_pair)?;
    let protected = JwsProtectedHeaderKid {
        alg: sign_alg.to_string(),
        kid: key_id.to_string(),
        nonce: nonce.into(),
        url: url.into(),
    };
    let protected = serde_json::to_string(&protected)?;
    get_data(key_pair, &protected, payload)
}

#[cfg(test)]
mod tests {
    use super::{encode_jwk, encode_kid};
    use acme_common::crypto::{gen_keypair, KeyType};

    #[test]
    fn test_default_jwk() {
        let (_, priv_key) = gen_keypair(KeyType::EcdsaP256).unwrap();
        let payload = "Dummy payload 1";
        let payload_b64 = "RHVtbXkgcGF5bG9hZCAx";
        let s = encode_jwk(&priv_key, payload.as_bytes(), "", "");
        assert!(s.is_ok());
        let s = s.unwrap();
        assert!(s.contains("\"protected\""));
        assert!(s.contains("\"payload\""));
        assert!(s.contains("\"signature\""));
        assert!(s.contains(payload_b64));
    }

    #[test]
    fn test_default_nopad_jwk() {
        let (_, priv_key) = gen_keypair(KeyType::EcdsaP256).unwrap();
        let payload = "Dummy payload";
        let payload_b64 = "RHVtbXkgcGF5bG9hZA";
        let payload_b64_pad = "RHVtbXkgcGF5bG9hZA==";
        let s = encode_jwk(&priv_key, payload.as_bytes(), "", "");
        assert!(s.is_ok());
        let s = s.unwrap();
        assert!(s.contains("\"protected\""));
        assert!(s.contains("\"payload\""));
        assert!(s.contains("\"signature\""));
        assert!(s.contains(payload_b64));
        assert!(!s.contains(payload_b64_pad));
    }

    #[test]
    fn test_default_kid() {
        let (_, priv_key) = gen_keypair(KeyType::EcdsaP256).unwrap();
        let payload = "Dummy payload 1";
        let payload_b64 = "RHVtbXkgcGF5bG9hZCAx";
        let key_id = "0x2a";
        let s = encode_kid(&priv_key, key_id, payload.as_bytes(), "", "");
        assert!(s.is_ok());
        let s = s.unwrap();
        assert!(s.contains("\"protected\""));
        assert!(s.contains("\"payload\""));
        assert!(s.contains("\"signature\""));
        assert!(s.contains(payload_b64));
    }
}
