mod openssl_keys;
pub use openssl_keys::{gen_keypair, KeyType, PrivateKey, PublicKey};
pub const DEFAULT_ALGO: &str = "rsa2048";
