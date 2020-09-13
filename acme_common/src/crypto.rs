use crate::error::Error;
use std::fmt;
use std::str::FromStr;

mod jws_signature_algorithm;
mod key_type;
mod openssl_certificate;
mod openssl_hash;
mod openssl_keys;
mod openssl_version;

pub const CRT_NB_DAYS_VALIDITY: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BaseHashFunction {
    Sha256,
    Sha384,
    Sha512,
}

impl BaseHashFunction {
    pub fn list_possible_values() -> Vec<&'static str> {
        vec!["sha256", "sha384", "sha512"]
    }
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
pub use openssl_version::{get_lib_name, get_lib_version};
