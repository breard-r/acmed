use super::{gen_keypair, KeyPair, KeyType, SubjectAttribute};
use crate::b64_encode;
use crate::crypto::HashFunction;
use crate::error::Error;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

fn get_digest(digest: HashFunction, key_pair: &KeyPair) -> MessageDigest {
	#[cfg(not(any(ed25519, ed448)))]
	let digest = digest.native_digest();
	let _ = key_pair;
	#[cfg(any(ed25519, ed448))]
	let digest = match key_pair.key_type {
		#[cfg(ed25519)]
		KeyType::Ed25519 => MessageDigest::null(),
		#[cfg(ed448)]
		KeyType::Ed448 => MessageDigest::null(),
		_ => digest.native_digest(),
	};
	digest
}

pub struct Csr {
	inner_csr: X509Req,
}

impl Csr {
	pub fn new(
		key_pair: &KeyPair,
		digest: HashFunction,
		domains: &[String],
		ips: &[String],
		subject_attributes: &HashMap<SubjectAttribute, String>,
	) -> Result<Self, Error> {
		let mut builder = X509ReqBuilder::new()?;
		builder.set_pubkey(&key_pair.inner_key)?;
		if !subject_attributes.is_empty() {
			let mut snb = X509NameBuilder::new()?;
			for (sattr, val) in subject_attributes.iter() {
				snb.append_entry_by_nid(sattr.get_nid(), val)?;
			}
			let name = snb.build();
			builder.set_subject_name(&name)?;
		}
		let ctx = builder.x509v3_context(None);
		let mut san = SubjectAlternativeName::new();
		for dns in domains.iter() {
			san.dns(dns);
		}
		for ip in ips.iter() {
			san.ip(ip);
		}
		let san = san.build(&ctx)?;
		let mut ext_stack = Stack::new()?;
		ext_stack.push(san)?;
		builder.add_extensions(&ext_stack)?;
		let digest = get_digest(digest, key_pair);
		builder.sign(&key_pair.inner_key, digest)?;
		Ok(Csr {
			inner_csr: builder.build(),
		})
	}

	pub fn to_der_base64(&self) -> Result<String, Error> {
		let csr = self.inner_csr.to_der()?;
		let csr = b64_encode(&csr);
		Ok(csr)
	}

	pub fn to_pem(&self) -> Result<String, Error> {
		let csr = self.inner_csr.to_pem()?;
		Ok(String::from_utf8(csr)?)
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

	pub fn from_pem_native(pem_data: &[u8]) -> Result<native_tls::Certificate, Error> {
		Ok(native_tls::Certificate::from_pem(pem_data)?)
	}

	pub fn from_acme_ext(
		domain: &str,
		acme_ext: &str,
		key_type: KeyType,
		digest: HashFunction,
	) -> Result<(KeyPair, Self), Error> {
		let key_pair = gen_keypair(key_type)?;
		let digest = get_digest(digest, &key_pair);
		let inner_cert = gen_certificate(domain, &key_pair, &digest, acme_ext)?;
		let cert = X509Certificate { inner_cert };
		Ok((key_pair, cert))
	}

	pub fn expires_in(&self) -> Result<Duration, Error> {
		let now = Asn1Time::days_from_now(0)?;
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
				.filter(|v| v.dnsname().is_some() || v.ipaddress().is_some())
				.map(|v| match v.dnsname() {
					Some(d) => d.to_string(),
					None => match v.ipaddress() {
						Some(i) => match i.len() {
							4 => {
								let ipv4: [u8; 4] = [i[0], i[1], i[2], i[3]];
								IpAddr::from(ipv4).to_string()
							}
							16 => {
								let ipv6: [u8; 16] = [
									i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9],
									i[10], i[11], i[12], i[13], i[14], i[15],
								];
								IpAddr::from(ipv6).to_string()
							}
							_ => String::new(),
						},
						None => String::new(),
					},
				})
				.collect(),
			None => HashSet::new(),
		}
	}
}

fn gen_certificate(
	domain: &str,
	key_pair: &KeyPair,
	digest: &MessageDigest,
	acme_ext: &str,
) -> Result<X509, Error> {
	let mut x509_name = X509NameBuilder::new()?;
	x509_name.append_entry_by_text("O", super::APP_ORG)?;
	let ca_name = format!("{} TLS-ALPN-01 Authority", super::APP_NAME);
	x509_name.append_entry_by_text("CN", &ca_name)?;
	let x509_name = x509_name.build();

	let mut builder = X509Builder::new()?;
	builder.set_version(super::X509_VERSION)?;
	let serial_number = {
		let mut serial = BigNum::new()?;
		serial.rand(super::CRT_SERIAL_NB_BITS - 1, MsbOption::MAYBE_ZERO, false)?;
		serial.to_asn1_integer()?
	};
	builder.set_serial_number(&serial_number)?;
	builder.set_subject_name(&x509_name)?;
	builder.set_issuer_name(&x509_name)?;
	builder.set_pubkey(&key_pair.inner_key)?;
	let not_before = Asn1Time::days_from_now(0)?;
	builder.set_not_before(&not_before)?;
	let not_after = Asn1Time::days_from_now(super::CRT_NB_DAYS_VALIDITY)?;
	builder.set_not_after(&not_after)?;

	builder.append_extension(BasicConstraints::new().build()?)?;
	let ctx = builder.x509v3_context(None, None);
	let san_ext = SubjectAlternativeName::new().dns(domain).build(&ctx)?;
	builder.append_extension(san_ext)?;

	if !acme_ext.is_empty() {
		let ctx = builder.x509v3_context(None, None);
		let mut v: Vec<&str> = acme_ext.split('=').collect();
		let value = v.pop().ok_or_else(|| Error::from(super::INVALID_EXT_MSG))?;
		let acme_ext_name = v.pop().ok_or_else(|| Error::from(super::INVALID_EXT_MSG))?;
		if !v.is_empty() {
			return Err(Error::from(super::INVALID_EXT_MSG));
		}
		let acme_ext = X509Extension::new(None, Some(&ctx), acme_ext_name, value)
			.map_err(|_| Error::from(super::INVALID_EXT_MSG))?;
		builder
			.append_extension(acme_ext)
			.map_err(|_| Error::from(super::INVALID_EXT_MSG))?;
	}

	builder.sign(&key_pair.inner_key, *digest)?;
	let cert = builder.build();
	Ok(cert)
}
