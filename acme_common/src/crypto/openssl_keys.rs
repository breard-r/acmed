use crate::b64_encode;
use crate::crypto::{HashFunction, JwsSignatureAlgorithm, KeyType};
use crate::error::Error;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use serde_json::json;
use serde_json::value::Value;

macro_rules! get_key_type {
	($key: expr) => {
		match $key.id() {
			Id::RSA => match $key.rsa()?.size() {
				256 => KeyType::Rsa2048,
				512 => KeyType::Rsa4096,
				s => {
					return Err(format!("{}: unsupported RSA key size", s * 8).into());
				}
			},
			Id::EC => match $key.ec_key()?.group().curve_name() {
				Some(Nid::X9_62_PRIME256V1) => KeyType::EcdsaP256,
				Some(Nid::SECP384R1) => KeyType::EcdsaP384,
				Some(Nid::SECP521R1) => KeyType::EcdsaP521,
				Some(nid) => {
					return Err(format!("{:?}: unsupported EC key", nid).into());
				}
				None => {
					return Err("unsupported EC key".into());
				}
			},
			#[cfg(ed25519)]
			Id::ED25519 => KeyType::Ed25519,
			#[cfg(ed448)]
			Id::ED448 => KeyType::Ed448,
			_ => {
				return Err("unsupported key type".into());
			}
		}
	};
}

macro_rules! get_ecdsa_sig_part {
	($part: expr, $size: ident) => {{
		let mut p = $part.to_vec();
		let length = p.len();
		if length != $size {
			let mut s: Vec<u8> = Vec::with_capacity($size);
			s.resize_with($size - length, || 0);
			s.append(&mut p);
			s
		} else {
			p
		}
	}};
}

#[derive(Clone, Debug)]
pub struct KeyPair {
	pub key_type: KeyType,
	pub inner_key: PKey<Private>,
}

impl KeyPair {
	pub fn from_der(der_data: &[u8]) -> Result<Self, Error> {
		let inner_key = PKey::private_key_from_der(der_data)?;
		let key_type = get_key_type!(inner_key);
		Ok(KeyPair {
			key_type,
			inner_key,
		})
	}

	pub fn from_pem(pem_data: &[u8]) -> Result<Self, Error> {
		let inner_key = PKey::private_key_from_pem(pem_data)?;
		let key_type = get_key_type!(inner_key);
		Ok(KeyPair {
			key_type,
			inner_key,
		})
	}

	pub fn private_key_to_der(&self) -> Result<Vec<u8>, Error> {
		self.inner_key.private_key_to_der().map_err(Error::from)
	}

	pub fn private_key_to_pem(&self) -> Result<Vec<u8>, Error> {
		self.inner_key
			.private_key_to_pem_pkcs8()
			.map_err(Error::from)
	}

	pub fn public_key_to_pem(&self) -> Result<Vec<u8>, Error> {
		self.inner_key.public_key_to_pem().map_err(Error::from)
	}

	pub fn sign(&self, alg: &JwsSignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
		self.key_type.check_alg_compatibility(alg)?;
		match alg {
			JwsSignatureAlgorithm::Hs256
			| JwsSignatureAlgorithm::Hs384
			| JwsSignatureAlgorithm::Hs512 => Err(format!(
				"{} key pair cannot be used for the {alg} signature algorithm",
				self.key_type
			)
			.into()),
			JwsSignatureAlgorithm::Rs256 => self.sign_rsa(&MessageDigest::sha256(), data),
			JwsSignatureAlgorithm::Es256 => self.sign_ecdsa(&HashFunction::Sha256, data),
			JwsSignatureAlgorithm::Es384 => self.sign_ecdsa(&HashFunction::Sha384, data),
			JwsSignatureAlgorithm::Es512 => self.sign_ecdsa(&HashFunction::Sha512, data),
			#[cfg(ed25519)]
			JwsSignatureAlgorithm::Ed25519 => self.sign_eddsa(data),
			#[cfg(ed448)]
			JwsSignatureAlgorithm::Ed448 => self.sign_eddsa(data),
		}
	}

	fn sign_rsa(&self, hash_func: &MessageDigest, data: &[u8]) -> Result<Vec<u8>, Error> {
		let mut signer = Signer::new(*hash_func, &self.inner_key)?;
		signer.update(data)?;
		let signature = signer.sign_to_vec()?;
		Ok(signature)
	}

	fn sign_ecdsa(&self, hash_func: &HashFunction, data: &[u8]) -> Result<Vec<u8>, Error> {
		let fingerprint = hash_func.hash(data);
		let signature = EcdsaSig::sign(&fingerprint, self.inner_key.ec_key()?.as_ref())?;
		let sig_size = match self.key_type {
			KeyType::EcdsaP256 => 32,
			KeyType::EcdsaP384 => 48,
			KeyType::EcdsaP521 => 66,
			_ => {
				return Err("not an ecdsa key".into());
			}
		};
		let r = get_ecdsa_sig_part!(signature.r(), sig_size);
		let mut s = get_ecdsa_sig_part!(signature.s(), sig_size);
		let mut signature = r;
		signature.append(&mut s);
		Ok(signature)
	}

	#[cfg(any(ed25519, ed448))]
	fn sign_eddsa(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
		let mut signer = Signer::new_without_digest(&self.inner_key)?;
		let signature = signer.sign_oneshot_to_vec(data)?;
		Ok(signature)
	}

	pub fn jwk_public_key(&self) -> Result<Value, Error> {
		self.get_jwk_public_key(false)
	}

	pub fn jwk_public_key_thumbprint(&self) -> Result<Value, Error> {
		self.get_jwk_public_key(true)
	}

	fn get_jwk_public_key(&self, thumbprint: bool) -> Result<Value, Error> {
		match self.key_type {
			KeyType::Rsa2048 | KeyType::Rsa4096 => self.get_rsa_jwk(thumbprint),
			KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
				self.get_ecdsa_jwk(thumbprint)
			}
			#[cfg(ed25519)]
			KeyType::Ed25519 => self.get_eddsa_jwk(thumbprint),
			#[cfg(ed448)]
			KeyType::Ed448 => self.get_eddsa_jwk(thumbprint),
		}
	}

	fn get_rsa_jwk(&self, thumbprint: bool) -> Result<Value, Error> {
		let rsa = self.inner_key.rsa().unwrap();
		let e = rsa.e();
		let n = rsa.n();
		let e = b64_encode(&e.to_vec());
		let n = b64_encode(&n.to_vec());
		let jwk = if thumbprint {
			json!({
				"kty": "RSA",
				"e": e,
				"n": n,
			})
		} else {
			json!({
				"alg": "RS256",
				"kty": "RSA",
				"use": "sig",
				"e": e,
				"n": n,
			})
		};
		Ok(jwk)
	}

	fn get_ecdsa_jwk(&self, thumbprint: bool) -> Result<Value, Error> {
		let (crv, alg, size, curve) = match self.key_type {
			KeyType::EcdsaP256 => ("P-256", "ES256", 32, Nid::X9_62_PRIME256V1),
			KeyType::EcdsaP384 => ("P-384", "ES384", 48, Nid::SECP384R1),
			KeyType::EcdsaP521 => ("P-521", "ES512", 66, Nid::SECP521R1),
			_ => {
				return Err("not an ECDSA elliptic curve".into());
			}
		};
		let group = EcGroup::from_curve_name(curve).unwrap();
		let mut ctx = BigNumContext::new().unwrap();
		let mut x = BigNum::new().unwrap();
		let mut y = BigNum::new().unwrap();
		self.inner_key
			.ec_key()
			.unwrap()
			.public_key()
			.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
		let x = b64_encode(&x.to_vec_padded(size)?);
		let y = b64_encode(&y.to_vec_padded(size)?);
		let jwk = if thumbprint {
			json!({
				"crv": crv,
				"kty": "EC",
				"x": x,
				"y": y,
			})
		} else {
			json!({
				"alg": alg,
				"crv": crv,
				"kty": "EC",
				"use": "sig",
				"x": x,
				"y": y,
			})
		};
		Ok(jwk)
	}

	#[cfg(any(ed25519, ed448))]
	fn get_eddsa_jwk(&self, thumbprint: bool) -> Result<Value, Error> {
		let crv = match self.key_type {
			#[cfg(ed25519)]
			KeyType::Ed25519 => "Ed25519",
			#[cfg(ed448)]
			KeyType::Ed448 => "Ed448",
			_ => {
				return Err("not an EdDSA elliptic curve".into());
			}
		};

		/*
		 * /!\ WARNING: HAZARDOUS AND UGLY CODE /!\
		 *
		 * I couldn't find a way to get the value of `x` using the OpenSSL
		 * interface, therefore I had to hack my way arround.
		 *
		 * The idea behind this hack is to export the public key in PEM, then
		 * get the PEM base64 part, convert it to base64url without padding
		 * and finally truncate the first part so only the value of `x`
		 * remains.
		 */

		// -----BEGIN UGLY-----
		let mut x = String::new();
		let public_pem = self.public_key_to_pem()?;
		let public_pem = String::from_utf8(public_pem)?;
		for pem_line in public_pem.lines() {
			if !pem_line.is_empty() && !pem_line.starts_with("-----") {
				x += &pem_line
					.trim()
					.trim_end_matches('=')
					.replace('/', "_")
					.replace('+', "-");
			}
		}
		x.replace_range(..16, "");
		// -----END UGLY-----

		let jwk = if thumbprint {
			json!({
				"crv": crv,
				"kty": "OKP",
				"x": &x,
			})
		} else {
			json!({
				"alg": "EdDSA",
				"crv": crv,
				"kty": "OKP",
				"use": "sig",
				"x": &x,
			})
		};
		Ok(jwk)
	}
}

fn gen_rsa_pair(nb_bits: u32) -> Result<PKey<Private>, Error> {
	let priv_key = Rsa::generate(nb_bits)?;
	let pk = PKey::from_rsa(priv_key).map_err(|_| Error::from(""))?;
	Ok(pk)
}

fn gen_ec_pair(nid: Nid) -> Result<PKey<Private>, Error> {
	let mut group = EcGroup::from_curve_name(nid)?;

	// Use NAMED_CURVE format; OpenSSL 1.0.1 and 1.0.2 default to EXPLICIT_CURVE which won't work (see #9)
	group.set_asn1_flag(Asn1Flag::NAMED_CURVE);

	let ec_priv_key = EcKey::generate(&group).map_err(|_| Error::from(""))?;
	let pk = PKey::from_ec_key(ec_priv_key).map_err(|_| Error::from(""))?;
	Ok(pk)
}

#[cfg(ed25519)]
fn gen_ed25519_pair() -> Result<PKey<Private>, Error> {
	let pk = PKey::generate_ed25519().map_err(|_| Error::from(""))?;
	Ok(pk)
}

#[cfg(ed448)]
fn gen_ed448_pair() -> Result<PKey<Private>, Error> {
	let pk = PKey::generate_ed448().map_err(|_| Error::from(""))?;
	Ok(pk)
}

pub fn gen_keypair(key_type: KeyType) -> Result<KeyPair, Error> {
	let priv_key = match key_type {
		KeyType::Rsa2048 => gen_rsa_pair(2048),
		KeyType::Rsa4096 => gen_rsa_pair(4096),
		KeyType::EcdsaP256 => gen_ec_pair(Nid::X9_62_PRIME256V1),
		KeyType::EcdsaP384 => gen_ec_pair(Nid::SECP384R1),
		KeyType::EcdsaP521 => gen_ec_pair(Nid::SECP521R1),
		#[cfg(ed25519)]
		KeyType::Ed25519 => gen_ed25519_pair(),
		#[cfg(ed448)]
		KeyType::Ed448 => gen_ed448_pair(),
	}
	.map_err(|_| Error::from(format!("unable to generate a {key_type} key pair")))?;
	let key_pair = KeyPair {
		key_type,
		inner_key: priv_key,
	};
	Ok(key_pair)
}
