use crate::acme_proto::b64_encode;
use crate::acme_proto::jws::algorithms::{EdDsaVariant, SignatureAlgorithm};
use crate::error::Error;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
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

fn es256_sign(data: &[u8], private_key: &PKey<Private>) -> Result<String, Error> {
    let signature = EcdsaSig::sign(data, private_key.ec_key()?.as_ref())?;
    let r = signature.r().to_vec();
    let mut s = signature.s().to_vec();
    let mut signature = r;
    signature.append(&mut s);
    let signature = b64_encode(&signature);
    Ok(signature)
}

fn eddsa_ed25519_sign(_data: &[u8], _private_key: &PKey<Private>) -> Result<String, Error> {
    // TODO: implement
    Err("EdDSA not implemented.".into())
}

fn get_data(
    private_key: &PKey<Private>,
    protected: &str,
    payload: &[u8],
    sign_alg: SignatureAlgorithm,
) -> Result<String, Error> {
    let protected = b64_encode(protected);
    let payload = b64_encode(payload);
    let signing_input = format!("{}.{}", protected, payload);
    let fingerprint = sha256(signing_input.as_bytes());
    let signature = match sign_alg {
        SignatureAlgorithm::Es256 => es256_sign(&fingerprint, private_key)?,
        SignatureAlgorithm::EdDsa(variant) => match variant {
            EdDsaVariant::Ed25519 => eddsa_ed25519_sign(&fingerprint, private_key)?,
        },
    };
    let data = JwsData {
        protected,
        payload,
        signature,
    };
    let str_data = serde_json::to_string(&data)?;
    Ok(str_data)
}

pub fn encode_jwk(
    private_key: &PKey<Private>,
    payload: &[u8],
    url: &str,
    nonce: &str,
) -> Result<String, Error> {
    let sign_alg = SignatureAlgorithm::from_pkey(private_key)?;
    let protected = JwsProtectedHeaderJwk {
        alg: sign_alg.to_string(),
        jwk: sign_alg.get_jwk(private_key)?,
        nonce: nonce.into(),
        url: url.into(),
    };
    let protected = serde_json::to_string(&protected)?;
    get_data(private_key, &protected, payload, sign_alg)
}

pub fn encode_kid(
    private_key: &PKey<Private>,
    key_id: &str,
    payload: &[u8],
    url: &str,
    nonce: &str,
) -> Result<String, Error> {
    let sign_alg = SignatureAlgorithm::from_pkey(private_key)?;
    let protected = JwsProtectedHeaderKid {
        alg: sign_alg.to_string(),
        kid: key_id.to_string(),
        nonce: nonce.into(),
        url: url.into(),
    };
    let protected = serde_json::to_string(&protected)?;
    get_data(private_key, &protected, payload, sign_alg)
}

#[cfg(test)]
mod tests {
    use super::{encode_jwk, encode_kid};

    #[test]
    fn test_default_jwk() {
        let (priv_key, _) = crate::keygen::p256().unwrap();
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
        let (priv_key, _) = crate::keygen::p256().unwrap();
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
        let (priv_key, _) = crate::keygen::p256().unwrap();
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
