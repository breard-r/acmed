use acme_common::b64_encode;
use acme_common::crypto::{HashFunction, JwsSignatureAlgorithm, KeyPair};
use acme_common::error::Error;
use serde::Serialize;
use serde_json::value::Value;

#[derive(Serialize)]
struct JwsData {
	protected: String,
	payload: String,
	signature: String,
}

#[derive(Serialize)]
struct JwsProtectedHeader {
	alg: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	jwk: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	kid: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	nonce: Option<String>,
	url: String,
}

fn get_jws_data(
	key_pair: &KeyPair,
	sign_alg: &JwsSignatureAlgorithm,
	protected: &str,
	payload: &[u8],
) -> Result<String, Error> {
	let protected = b64_encode(protected);
	let payload = b64_encode(payload);
	let signing_input = format!("{protected}.{payload}");
	let signature = key_pair.sign(sign_alg, signing_input.as_bytes())?;
	let signature = b64_encode(&signature);
	let data = JwsData {
		protected,
		payload,
		signature,
	};
	let str_data = serde_json::to_string(&data)?;
	Ok(str_data)
}

pub fn encode_jwk(
	key_pair: &KeyPair,
	sign_alg: &JwsSignatureAlgorithm,
	payload: &[u8],
	url: &str,
	nonce: Option<String>,
) -> Result<String, Error> {
	let protected = JwsProtectedHeader {
		alg: sign_alg.to_string(),
		jwk: Some(key_pair.jwk_public_key()?),
		kid: None,
		nonce,
		url: url.into(),
	};
	let protected = serde_json::to_string(&protected)?;
	get_jws_data(key_pair, sign_alg, &protected, payload)
}

pub fn encode_kid(
	key_pair: &KeyPair,
	sign_alg: &JwsSignatureAlgorithm,
	key_id: &str,
	payload: &[u8],
	url: &str,
	nonce: &str,
) -> Result<String, Error> {
	let protected = JwsProtectedHeader {
		alg: sign_alg.to_string(),
		jwk: None,
		kid: Some(key_id.to_string()),
		nonce: Some(nonce.into()),
		url: url.into(),
	};
	let protected = serde_json::to_string(&protected)?;
	get_jws_data(key_pair, sign_alg, &protected, payload)
}

pub fn encode_kid_mac(
	key: &[u8],
	sign_alg: &JwsSignatureAlgorithm,
	key_id: &str,
	payload: &[u8],
	url: &str,
) -> Result<String, Error> {
	let protected = JwsProtectedHeader {
		alg: sign_alg.to_string(),
		jwk: None,
		kid: Some(key_id.to_string()),
		nonce: None,
		url: url.into(),
	};
	let protected = serde_json::to_string(&protected)?;
	let protected = b64_encode(&protected);
	let payload = b64_encode(payload);
	let signing_input = format!("{protected}.{payload}");
	let hash_func = match sign_alg {
		JwsSignatureAlgorithm::Hs256 => HashFunction::Sha256,
		JwsSignatureAlgorithm::Hs384 => HashFunction::Sha384,
		JwsSignatureAlgorithm::Hs512 => HashFunction::Sha512,
		_ => {
			return Err(format!("{sign_alg}: not a HMAC-based signature algorithm").into());
		}
	};
	let signature = hash_func.hmac(key, signing_input.as_bytes())?;
	let signature = b64_encode(&signature);
	let data = JwsData {
		protected,
		payload,
		signature,
	};
	let str_data = serde_json::to_string(&data)?;
	Ok(str_data)
}

#[cfg(test)]
mod tests {
	use super::{encode_jwk, encode_kid};
	use acme_common::crypto::{gen_keypair, KeyType};

	#[test]
	fn test_default_jwk() {
		let key_type = KeyType::EcdsaP256;
		let key_pair = gen_keypair(key_type).unwrap();
		let payload = "Dummy payload 1";
		let payload_b64 = "RHVtbXkgcGF5bG9hZCAx";
		let s = encode_jwk(
			&key_pair,
			&key_type.get_default_signature_alg(),
			payload.as_bytes(),
			"",
			Some(String::new()),
		);
		assert!(s.is_ok());
		let s = s.unwrap();
		assert!(s.contains("\"protected\""));
		assert!(s.contains("\"payload\""));
		assert!(s.contains("\"signature\""));
		assert!(s.contains(payload_b64));
	}

	#[test]
	fn test_default_nopad_jwk() {
		let key_type = KeyType::EcdsaP256;
		let key_pair = gen_keypair(key_type).unwrap();
		let payload = "Dummy payload";
		let payload_b64 = "RHVtbXkgcGF5bG9hZA";
		let payload_b64_pad = "RHVtbXkgcGF5bG9hZA==";
		let s = encode_jwk(
			&key_pair,
			&key_type.get_default_signature_alg(),
			payload.as_bytes(),
			"",
			Some(String::new()),
		);
		assert!(s.is_ok());
		let s = s.unwrap();
		assert!(s.contains("\"protected\""));
		assert!(s.contains("\"payload\""));
		assert!(s.contains("\"signature\""));
		assert!(s.contains(payload_b64));
		assert!(!s.contains(payload_b64_pad));
	}

	#[test]
	fn test_default_kid() {
		let key_type = KeyType::EcdsaP256;
		let key_pair = gen_keypair(key_type).unwrap();
		let payload = "Dummy payload 1";
		let payload_b64 = "RHVtbXkgcGF5bG9hZCAx";
		let key_id = "0x2a";
		let s = encode_kid(
			&key_pair,
			&key_type.get_default_signature_alg(),
			key_id,
			payload.as_bytes(),
			"",
			"",
		);
		assert!(s.is_ok());
		let s = s.unwrap();
		assert!(s.contains("\"protected\""));
		assert!(s.contains("\"payload\""));
		assert!(s.contains("\"signature\""));
		assert!(s.contains(payload_b64));
	}
}
