use crate::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JwsSignatureAlgorithm {
    Rs256,
    Es256,
    Es384,
    Ed25519,
}

impl FromStr for JwsSignatureAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "rs256" => Ok(JwsSignatureAlgorithm::Rs256),
            "es256" => Ok(JwsSignatureAlgorithm::Es256),
            "es384" => Ok(JwsSignatureAlgorithm::Es384),
            "ed25519" => Ok(JwsSignatureAlgorithm::Ed25519),
            _ => Err(format!("{}: unknown algorithm.", s).into()),
        }
    }
}

impl fmt::Display for JwsSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            JwsSignatureAlgorithm::Rs256 => "RS256",
            JwsSignatureAlgorithm::Es256 => "ES256",
            JwsSignatureAlgorithm::Es384 => "ES384",
            JwsSignatureAlgorithm::Ed25519 => "Ed25519",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::JwsSignatureAlgorithm;
    use std::str::FromStr;

    #[test]
    fn test_es256_from_str() {
        let variants = ["ES256", "Es256", "es256"];
        for v in variants.iter() {
            let a = JwsSignatureAlgorithm::from_str(v);
            assert!(a.is_ok());
            let a = a.unwrap();
            assert_eq!(a, JwsSignatureAlgorithm::Es256);
        }
    }

    #[test]
    fn test_es256_to_str() {
        let a = JwsSignatureAlgorithm::Es256;
        assert_eq!(a.to_string().as_str(), "ES256");
    }
}
