use crate::crypto::JwsSignatureAlgorithm;
use crate::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    #[cfg(feature = "ed25519")]
    Ed25519,
}

impl KeyType {
    pub fn get_default_signature_alg(&self) -> JwsSignatureAlgorithm {
        match self {
            KeyType::Rsa2048 | KeyType::Rsa4096 => JwsSignatureAlgorithm::Rs256,
            KeyType::EcdsaP256 => JwsSignatureAlgorithm::Es256,
            KeyType::EcdsaP384 => JwsSignatureAlgorithm::Es384,
            #[cfg(feature = "ed25519")]
            KeyType::Ed25519 => JwsSignatureAlgorithm::Ed25519,
        }
    }

    pub fn check_alg_compatibility(&self, alg: &JwsSignatureAlgorithm) -> Result<(), Error> {
        let ok = match self {
            KeyType::Rsa2048 | KeyType::Rsa4096 => *alg == JwsSignatureAlgorithm::Rs256,
            KeyType::EcdsaP256 | KeyType::EcdsaP384 => *alg == self.get_default_signature_alg(),
            #[cfg(feature = "ed25519")]
            KeyType::Ed25519 => *alg == self.get_default_signature_alg(),
        };
        if ok {
            Ok(())
        } else {
            let err_msg = format!(
                "Incompatible signature algorithm: {} cannot be used with an {} key.",
                alg, self
            );
            Err(err_msg.into())
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "rsa2048" => Ok(KeyType::Rsa2048),
            "rsa4096" => Ok(KeyType::Rsa4096),
            "ecdsa_p256" => Ok(KeyType::EcdsaP256),
            "ecdsa_p384" => Ok(KeyType::EcdsaP384),
            #[cfg(feature = "ed25519")]
            "ed25519" => Ok(KeyType::Ed25519),
            _ => Err(format!("{}: unknown algorithm.", s).into()),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa4096 => "rsa4096",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            #[cfg(feature = "ed25519")]
            KeyType::Ed25519 => "ed25519",
        };
        write!(f, "{}", s)
    }
}
