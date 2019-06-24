use acme_common::crypto::{KeyPair, X509Certificate};
use acme_common::error::Error;

pub fn start(
    listen_addr: &str,
    certificate: &X509Certificate,
    key_pair: &KeyPair,
) -> Result<(), Error> {
    Err("The standalone server is not implemented yet.".into())
}
