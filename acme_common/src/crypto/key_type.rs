use crate::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    Curve25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(KeyType::Curve25519),
            "ecdsa_p256" => Ok(KeyType::EcdsaP256),
            "ecdsa_p384" => Ok(KeyType::EcdsaP384),
            "rsa2048" => Ok(KeyType::Rsa2048),
            "rsa4096" => Ok(KeyType::Rsa4096),
            _ => Err(format!("{}: unknown algorithm.", s).into()),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            KeyType::Curve25519 => "ed25519",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa4096 => "rsa4096",
        };
        write!(f, "{}", s)
    }
}
