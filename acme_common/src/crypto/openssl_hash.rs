use crate::error::Error;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sha::{sha256, sha384, sha512};
use openssl::sign::Signer;

pub type HashFunction = super::BaseHashFunction;

impl HashFunction {
	pub fn hash(&self, data: &[u8]) -> Vec<u8> {
		match self {
			HashFunction::Sha256 => sha256(data).to_vec(),
			HashFunction::Sha384 => sha384(data).to_vec(),
			HashFunction::Sha512 => sha512(data).to_vec(),
		}
	}

	pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
		let key = PKey::hmac(key)?;
		let h_func = self.native_digest();
		let mut signer = Signer::new(h_func, &key)?;
		signer.update(data)?;
		let res = signer.sign_to_vec()?;
		Ok(res)
	}

	pub(crate) fn native_digest(&self) -> MessageDigest {
		match self {
			HashFunction::Sha256 => MessageDigest::sha256(),
			HashFunction::Sha384 => MessageDigest::sha384(),
			HashFunction::Sha512 => MessageDigest::sha512(),
		}
	}
}
