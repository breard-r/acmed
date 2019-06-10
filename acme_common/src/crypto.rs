mod openssl_certificate;

#[cfg(not(feature = "standalone"))]
mod openssl_hash;
#[cfg(feature = "standalone")]
mod standalone_hash;

mod openssl_keys;

pub const DEFAULT_ALGO: &str = "rsa2048";

pub use openssl_certificate::{Csr, X509Certificate};

#[cfg(not(feature = "standalone"))]
pub use openssl_hash::sha256;
#[cfg(feature = "standalone")]
pub use standalone_hash::sha256;

pub use openssl_keys::{gen_keypair, KeyType, PrivateKey, PublicKey};
