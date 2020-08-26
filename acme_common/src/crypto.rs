use crate::error::Error;
use std::fmt;
use std::str::FromStr;

mod jws_signature_algorithm;
mod key_type;
mod openssl_certificate;
mod openssl_hash;
mod openssl_keys;

pub const DEFAULT_ALGO: &str = "rsa2048";
pub const TLS_LIB_NAME: &str = env!("ACMED_TLS_LIB_NAME");
pub const TLS_LIB_VERSION: &str = env!("ACMED_TLS_LIB_VERSION");

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BaseHashFunction {
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for BaseHashFunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.to_lowercase().replace("-", "").replace("_", "");
        match s.as_str() {
            "sha256" => Ok(BaseHashFunction::Sha256),
            "sha384" => Ok(BaseHashFunction::Sha384),
            "sha512" => Ok(BaseHashFunction::Sha512),
            _ => Err(format!("{}: unknown hash function.", s).into()),
        }
    }
}

impl fmt::Display for BaseHashFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            BaseHashFunction::Sha256 => "sha256",
            BaseHashFunction::Sha384 => "sha384",
            BaseHashFunction::Sha512 => "sha512",
        };
        write!(f, "{}", s)
    }
}

pub use jws_signature_algorithm::JwsSignatureAlgorithm;
pub use key_type::KeyType;
pub use openssl_certificate::{Csr, X509Certificate};
pub use openssl_hash::HashFunction;
pub use openssl_keys::{gen_keypair, KeyPair};
