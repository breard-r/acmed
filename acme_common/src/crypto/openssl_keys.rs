use crate::b64_encode;
use crate::crypto::{JwsSignatureAlgorithm, KeyType};
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
                    return Err(format!("{}: unsupported RSA key size", s).into());
                }
            },
            Id::EC => match $key.ec_key()?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => KeyType::EcdsaP256,
                Some(Nid::SECP384R1) => KeyType::EcdsaP384,
                Some(nid) => {
                    return Err(format!("{:?}: Unsupported EC key.", nid).into());
                }
                None => {
                    return Err("None: Unsupported EC key".into());
                }
            },
            _ => {
                return Err("Unsupported key type".into());
            }
        }
    };
}

pub struct KeyPair {
    pub key_type: KeyType,
    pub inner_key: PKey<Private>,
}

impl KeyPair {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, Error> {
        let inner_key = PKey::private_key_from_pem(pem_data)?;
        let key_type = get_key_type!(inner_key);
        Ok(KeyPair {
            key_type,
            inner_key,
        })
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
        let _ = self.key_type.check_alg_compatibility(alg)?;
        match alg {
            JwsSignatureAlgorithm::Rs256 => self.sign_rsa(&MessageDigest::sha256(), data),
            JwsSignatureAlgorithm::Es256 => self.sign_ecdsa(&crate::crypto::sha256, data),
            JwsSignatureAlgorithm::Es384 => self.sign_ecdsa(&crate::crypto::sha384, data),
        }
    }

    fn sign_rsa(&self, hash_func: &MessageDigest, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signer = Signer::new(*hash_func, &self.inner_key)?;
        signer.update(data)?;
        let signature = signer.sign_to_vec()?;
        Ok(signature)
    }

    fn sign_ecdsa(
        &self,
        hash_func: &dyn Fn(&[u8]) -> Vec<u8>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let fingerprint = hash_func(data);
        let signature = EcdsaSig::sign(&fingerprint, self.inner_key.ec_key()?.as_ref())?;
        let r = signature.r().to_vec();
        let mut s = signature.s().to_vec();
        let mut signature = r;
        signature.append(&mut s);
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
            KeyType::EcdsaP256 | KeyType::EcdsaP384 => self.get_nist_ec_jwk(thumbprint),
            KeyType::Rsa2048 | KeyType::Rsa4096 => self.get_rsa_jwk(thumbprint),
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

    fn get_nist_ec_jwk(&self, thumbprint: bool) -> Result<Value, Error> {
        let (crv, alg, curve) = match self.key_type {
            KeyType::EcdsaP256 => ("P-256", "ES256", Nid::X9_62_PRIME256V1),
            KeyType::EcdsaP384 => ("P-384", "ES384", Nid::SECP384R1),
            _ => {
                return Err("Not a NIST elliptic curve.".into());
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
        let x = b64_encode(&x.to_vec());
        let y = b64_encode(&y.to_vec());
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

pub fn gen_keypair(key_type: KeyType) -> Result<KeyPair, Error> {
    let priv_key = match key_type {
        KeyType::EcdsaP256 => gen_ec_pair(Nid::X9_62_PRIME256V1),
        KeyType::EcdsaP384 => gen_ec_pair(Nid::SECP384R1),
        KeyType::Rsa2048 => gen_rsa_pair(2048),
        KeyType::Rsa4096 => gen_rsa_pair(4096),
    }
    .map_err(|_| Error::from(format!("Unable to generate a {} key pair.", key_type)))?;
    let key_pair = KeyPair {
        key_type,
        inner_key: priv_key,
    };
    Ok(key_pair)
}
