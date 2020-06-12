use super::{gen_keypair, KeyPair, KeyType};
use crate::b64_encode;
use crate::error::Error;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APP_ORG: &str = "ACMEd";
const APP_NAME: &str = "ACMEd";
const X509_VERSION: i32 = 0x02;
const CRT_SERIAL_NB_BITS: i32 = 32;
const CRT_NB_DAYS_VALIDITY: u32 = 7;
const INVALID_EXT_MSG: &str = "Invalid acmeIdentifier extension.";

pub struct Csr {
    inner_csr: X509Req,
}

impl Csr {
    pub fn new(key_pair: &KeyPair, domains: &[String]) -> Result<Self, Error> {
        let mut builder = X509ReqBuilder::new()?;
        builder.set_pubkey(&key_pair.inner_key)?;
        let ctx = builder.x509v3_context(None);
        let mut san = SubjectAlternativeName::new();
        for dns in domains.iter() {
            san.dns(&dns);
        }
        let san = san.build(&ctx)?;
        let mut ext_stack = Stack::new()?;
        ext_stack.push(san)?;
        builder.add_extensions(&ext_stack)?;
        builder.sign(&key_pair.inner_key, MessageDigest::sha256())?;
        Ok(Csr {
            inner_csr: builder.build(),
        })
    }

    pub fn to_der_base64(&self) -> Result<String, Error> {
        let csr = self.inner_csr.to_der()?;
        let csr = b64_encode(&csr);
        Ok(csr)
    }
}

pub struct X509Certificate {
    pub inner_cert: X509,
}

impl X509Certificate {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, Error> {
        Ok(X509Certificate {
            inner_cert: X509::from_pem(pem_data)?,
        })
    }

    pub fn from_acme_ext(domain: &str, acme_ext: &str) -> Result<(KeyPair, Self), Error> {
        let key_pair = gen_keypair(KeyType::EcdsaP256)?;
        let inner_cert = gen_certificate(domain, &key_pair, acme_ext)?;
        let cert = X509Certificate { inner_cert };
        Ok((key_pair, cert))
    }

    pub fn expires_in(&self) -> Result<Duration, Error> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let now = Asn1Time::from_unix(timestamp)?;
        let not_after = self.inner_cert.not_after();
        let diff = now.diff(not_after)?;
        let nb_secs = diff.days * 24 * 60 * 60 + diff.secs;
        let nb_secs = if nb_secs > 0 { nb_secs as u64 } else { 0 };
        Ok(Duration::from_secs(nb_secs))
    }

    pub fn subject_alt_names(&self) -> HashSet<String> {
        match self.inner_cert.subject_alt_names() {
            Some(s) => s
                .iter()
                .filter(|v| v.dnsname().is_some())
                .map(|v| v.dnsname().unwrap().to_string())
                .collect(),
            None => HashSet::new(),
        }
    }
}

fn gen_certificate(domain: &str, key_pair: &KeyPair, acme_ext: &str) -> Result<X509, Error> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("O", APP_ORG)?;
    let ca_name = format!("{} TLS-ALPN-01 Authority", APP_NAME);
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
    builder.set_pubkey(&key_pair.inner_key)?;
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
    builder.sign(&key_pair.inner_key, MessageDigest::sha256())?;
    let cert = builder.build();
    Ok(cert)
}
