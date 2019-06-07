use acme_common::crypto::{gen_keypair, KeyType, PrivateKey, PublicKey};
use acme_common::error::Error;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509};

const X509_VERSION: i32 = 0x02;
const CRT_SERIAL_NB_BITS: i32 = 32;
const CRT_NB_DAYS_VALIDITY: u32 = 7;
const INVALID_EXT_MSG: &str = "Invalid acmeIdentifier extension.";

fn get_certificate(
    domain: &str,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    acme_ext: &str,
) -> Result<X509, Error> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("O", crate::APP_ORG)?;
    let ca_name = format!("{} TLS-ALPN-01 Authority", crate::APP_NAME);
    x509_name.append_entry_by_text("CN", &ca_name)?;
    let x509_name = x509_name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(X509_VERSION)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(CRT_SERIAL_NB_BITS - 1, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    builder.set_serial_number(&serial_number)?;
    builder.set_subject_name(&x509_name)?;
    builder.set_issuer_name(&x509_name)?;
    builder.set_pubkey(&public_key.inner_key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(CRT_NB_DAYS_VALIDITY)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().build()?)?;
    let ctx = builder.x509v3_context(None, None);
    let san_ext = SubjectAlternativeName::new().dns(domain).build(&ctx)?;
    builder.append_extension(san_ext)?;

    let ctx = builder.x509v3_context(None, None);
    let mut v: Vec<&str> = acme_ext.split('=').collect();
    let value = v.pop().ok_or_else(|| Error::from(INVALID_EXT_MSG))?;
    let acme_ext_name = v.pop().ok_or_else(|| Error::from(INVALID_EXT_MSG))?;
    if !v.is_empty() {
        return Err(Error::from(INVALID_EXT_MSG));
    }
    let acme_ext = X509Extension::new(None, Some(&ctx), &acme_ext_name, &value)
        .map_err(|_| Error::from(INVALID_EXT_MSG))?;
    builder
        .append_extension(acme_ext)
        .map_err(|_| Error::from(INVALID_EXT_MSG))?;
    builder.sign(&private_key.inner_key, MessageDigest::sha256())?;
    let cert = builder.build();
    Ok(cert)
}

pub fn gen_certificate(domain: &str, acme_ext: &str) -> Result<(PrivateKey, X509), Error> {
    let (pub_key, priv_key) = gen_keypair(KeyType::EcdsaP256)?;
    let cert = get_certificate(domain, &pub_key, &priv_key, acme_ext)?;
    Ok((priv_key, cert))
}
