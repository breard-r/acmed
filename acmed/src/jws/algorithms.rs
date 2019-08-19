use acme_common::crypto::{gen_keypair, KeyPair, KeyType};
use acme_common::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Es256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SignatureAlgorithm::Es256 => "ES256",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        match data.to_lowercase().as_str() {
            "es256" => Ok(SignatureAlgorithm::Es256),
            _ => Err(format!("{}: unknown signature algorithm", data).into()),
        }
    }
}

impl SignatureAlgorithm {
    pub fn from_pkey(key_pair: &KeyPair) -> Result<Self, Error> {
        match key_pair.key_type {
            KeyType::EcdsaP256 => Ok(SignatureAlgorithm::Es256),
            t => Err(format!("{}: unsupported key type", t).into()),
        }
    }

    pub fn gen_key_pair(&self) -> Result<KeyPair, Error> {
        match self {
            SignatureAlgorithm::Es256 => gen_keypair(KeyType::EcdsaP256),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SignatureAlgorithm;
    use acme_common::crypto::KeyPair;
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
    fn test_from_p256() {
        let pem = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6To1BW8qTehGhPca
0eMcW8iQU4yA02dvtKkuqfny4HChRANCAAQwxx+j3wYGzD5LSFNBTLlT7J+7rWrq
4BGdR8705iwpBeOQgMpLj+9vuFutlVtmoYpJSYa9+49Hxz8aCe1AQeWt
-----END PRIVATE KEY-----";
        let k = KeyPair::from_pem(pem).unwrap();
        let s = SignatureAlgorithm::from_pkey(&k);
        assert!(s.is_ok());
        let s = s.unwrap();
        assert_eq!(s, SignatureAlgorithm::Es256)
    }
}
