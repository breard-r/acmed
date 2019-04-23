use super::jwk::{EdDsaEd25519Jwk, Es256Jwk, Jwk};
use crate::acme_proto::b64_encode;
use crate::error::Error;
use crate::keygen;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use serde_json::json;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub enum EdDsaVariant {
    Ed25519,
}

impl fmt::Display for EdDsaVariant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            EdDsaVariant::Ed25519 => "Ed25519",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
    EdDsa(EdDsaVariant),
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SignatureAlgorithm::Es256 => "ES256",
            SignatureAlgorithm::EdDsa(_) => "EdDSA",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        match data.to_lowercase().as_str() {
            "es256" => Ok(SignatureAlgorithm::Es256),
            "eddsa-ed25519" => Ok(SignatureAlgorithm::EdDsa(EdDsaVariant::Ed25519)),
            _ => Err(format!("{}: unknown signature algorithm", data).into()),
        }
    }
}

impl SignatureAlgorithm {
    pub fn from_pkey(private_key: &PKey<Private>) -> Result<Self, Error> {
        match private_key.id() {
            Id::EC => match private_key.ec_key()?.group().curve_name() {
                Some(nid) => {
                    if nid == Nid::X9_62_PRIME256V1 {
                        Ok(SignatureAlgorithm::Es256)
                    // TODO: add support for Ed25519 keys
                    } else {
                        Err(format!("{}: unsupported EC key type", nid.as_raw()).into())
                    }
                }
                None => Err("EC curve: name not found".into()),
            },
            _ => Err(format!("{}: unsupported key id", private_key.id().as_raw()).into()),
        }
    }

    fn get_p256_coordinates(private_key: &PKey<Private>) -> Result<(String, String), Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        private_key
            .ec_key()
            .unwrap()
            .public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        let x = b64_encode(&x.to_vec());
        let y = b64_encode(&y.to_vec());
        Ok((x, y))
    }

    pub fn get_jwk_thumbprint(&self, private_key: &PKey<Private>) -> Result<String, Error> {
        let jwk = match self {
            SignatureAlgorithm::Es256 => {
                let (x, y) = SignatureAlgorithm::get_p256_coordinates(private_key)?;
                json!({
                    "crv": "P-256",
                    "kty": "EC",
                    "x": x,
                    "y": y,
                })
            }
            SignatureAlgorithm::EdDsa(_crv) => json!({
                // TODO: implement EdDsa
            }),
        };
        Ok(jwk.to_string())
    }

    pub fn get_jwk(&self, private_key: &PKey<Private>) -> Result<Jwk, Error> {
        let jwk = match self {
            SignatureAlgorithm::Es256 => {
                let (x, y) = SignatureAlgorithm::get_p256_coordinates(private_key)?;
                Jwk::Es256(Es256Jwk::new(&x, &y))
            }
            // TODO: implement EdDsa
            SignatureAlgorithm::EdDsa(_crv) => Jwk::EdDsaEd25519(EdDsaEd25519Jwk::new()),
        };
        Ok(jwk)
    }

    pub fn gen_key_pair(&self) -> Result<(PKey<Private>, PKey<Public>), Error> {
        match self {
            SignatureAlgorithm::Es256 => keygen::p256(),
            SignatureAlgorithm::EdDsa(EdDsaVariant::Ed25519) => Err("Not implemented".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EdDsaVariant, SignatureAlgorithm};
    use openssl::ec::EcKey;
    use openssl::pkey::PKey;
    use std::str::FromStr;

    #[test]
    fn test_es256_from_str() {
        let variants = ["ES256", "Es256", "es256"];
        for v in variants.iter() {
            let a = SignatureAlgorithm::from_str(v);
            assert!(a.is_ok());
            let a = a.unwrap();
            assert_eq!(a, SignatureAlgorithm::Es256);
        }
    }

    #[test]
    fn test_es256_to_str() {
        let a = SignatureAlgorithm::Es256;
        assert_eq!(a.to_string().as_str(), "ES256");
    }

    #[test]
    fn test_eddsa_ed25519_from_str() {
        let variants = ["ES256", "Es256", "es256"];
        for v in variants.iter() {
            let a = SignatureAlgorithm::from_str(v);
            assert!(a.is_ok());
            let a = a.unwrap();
            assert_eq!(a, SignatureAlgorithm::Es256);
        }
    }

    #[test]
    fn test_eddsa_ed25519_to_str() {
        let a = SignatureAlgorithm::EdDsa(EdDsaVariant::Ed25519);
        assert_eq!(a.to_string().as_str(), "EdDSA");
    }

    #[test]
    fn test_from_p256() {
        let pem = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6To1BW8qTehGhPca
0eMcW8iQU4yA02dvtKkuqfny4HChRANCAAQwxx+j3wYGzD5LSFNBTLlT7J+7rWrq
4BGdR8705iwpBeOQgMpLj+9vuFutlVtmoYpJSYa9+49Hxz8aCe1AQeWt
-----END PRIVATE KEY-----";
        let ek = EcKey::private_key_from_pem(pem).unwrap();
        let k = PKey::from_ec_key(ek).unwrap();
        let s = SignatureAlgorithm::from_pkey(&k);
        assert!(s.is_ok());
        let s = s.unwrap();
        assert_eq!(s, SignatureAlgorithm::Es256)
    }
}
