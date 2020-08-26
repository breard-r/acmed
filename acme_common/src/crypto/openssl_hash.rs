use openssl::hash::MessageDigest;
use openssl::sha::{sha256, sha384, sha512};

pub type HashFunction = super::BaseHashFunction;

impl HashFunction {
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashFunction::Sha256 => sha256(data).to_vec(),
            HashFunction::Sha384 => sha384(data).to_vec(),
            HashFunction::Sha512 => sha512(data).to_vec(),
        }
    }

    pub(crate) fn native_digest(&self) -> MessageDigest {
        match self {
            HashFunction::Sha256 => MessageDigest::sha256(),
            HashFunction::Sha384 => MessageDigest::sha384(),
            HashFunction::Sha512 => MessageDigest::sha512(),
        }
    }
}
