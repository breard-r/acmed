use acme_common::crypto::{PrivateKey, X509Certificate};
use acme_common::error::Error;

pub fn start(
    listen_addr: &str,
    certificate: &X509Certificate,
    private_key: &PrivateKey,
) -> Result<(), Error> {
    Err("The standalone server is not implemented yet.".into())
}
