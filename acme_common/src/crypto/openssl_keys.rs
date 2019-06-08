use crate::b64_encode;
use crate::error::Error;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use serde_json::json;
use std::fmt;
use std::str::FromStr;

macro_rules! get_key_type {
    ($key: expr) => {
        match $key.id() {
            Id::RSA => match $key.rsa()?.size() {
                2048 => KeyType::Rsa2048,
                4096 => KeyType::Rsa4096,
                s => {
                    return Err(format!("{}: unsupported RSA key size", s).into());
                }
            },
            Id::EC => match $key.ec_key()?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => KeyType::EcdsaP256,
                Some(Nid::SECP384R1) => KeyType::EcdsaP384,
                _ => {
                    return Err("Unsupported EC key".into());
                }
            },
            _ => {
                return Err("Unsupported key type".into());
            }
        }
    };
}

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "rsa2048" => Ok(KeyType::Rsa2048),
            "rsa4096" => Ok(KeyType::Rsa4096),
            "ecdsa_p256" => Ok(KeyType::EcdsaP256),
            "ecdsa_p384" => Ok(KeyType::EcdsaP384),
            _ => Err(format!("{}: unknown algorithm.", s).into()),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa4096 => "rsa4096",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
        };
        write!(f, "{}", s)
    }
}

pub struct PublicKey {
    pub key_type: KeyType,
    pub inner_key: PKey<Public>,
}

impl PublicKey {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, Error> {
        let inner_key = PKey::public_key_from_pem(pem_data)?;
        let key_type = get_key_type!(inner_key);
        Ok(PublicKey {
            key_type,
            inner_key,
        })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>, Error> {
        self.inner_key.public_key_to_pem().map_err(Error::from)
    }
}

pub struct PrivateKey {
    pub key_type: KeyType,
    pub inner_key: PKey<Private>,
}

impl PrivateKey {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, Error> {
        let inner_key = PKey::private_key_from_pem(pem_data)?;
        let key_type = get_key_type!(inner_key);
        Ok(PrivateKey {
            key_type,
            inner_key,
        })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>, Error> {
        self.inner_key
            .private_key_to_pem_pkcs8()
            .map_err(Error::from)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self.key_type {
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                // TODO: implement RSA signatures
                Err("RSA signatures are not implemented yet".into())
            }
            KeyType::EcdsaP256 | KeyType::EcdsaP384 => {
                let signature = EcdsaSig::sign(data, self.inner_key.ec_key()?.as_ref())?;
                let r = signature.r().to_vec();
                let mut s = signature.s().to_vec();
                let mut signature = r;
                signature.append(&mut s);
                Ok(signature)
            }
        }
    }

    pub fn get_jwk_thumbprint(&self) -> Result<String, Error> {
        match self.key_type {
            KeyType::EcdsaP256 | KeyType::EcdsaP384 => self.get_nist_ec_jwk(),
            // TODO: implement RSA JWK thumbprint
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                Err("RSA jwk thumbprint are not implemented yet".into())
            }
        }
    }

    fn get_nist_ec_jwk(&self) -> Result<String, Error> {
        let (x, y) = self.get_nist_ec_coordinates()?;
        let crv = match self.key_type {
            KeyType::EcdsaP256 => "P-256",
            KeyType::EcdsaP384 => "P-384",
            _ => {
                return Err("Not a NIST elliptic curve.".into());
            }
        };
        let jwk = json!({
            "crv": crv,
            "kty": "EC",
            "x": x,
            "y": y,
        });
        Ok(jwk.to_string())
    }

    pub fn get_nist_ec_coordinates(&self) -> Result<(String, String), Error> {
        let curve = match self.key_type {
            KeyType::EcdsaP256 => Nid::X9_62_PRIME256V1,
            KeyType::EcdsaP384 => Nid::SECP384R1,
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
        Ok((x, y))
    }
}

fn gen_rsa_pair(nb_bits: u32) -> Result<(PKey<Public>, PKey<Private>), Error> {
    let priv_key = Rsa::generate(nb_bits).unwrap();
    let pub_key = Rsa::from_public_components(
        priv_key.n().to_owned().unwrap(),
        priv_key.e().to_owned().unwrap(),
    )
    .unwrap();
    Ok((
        PKey::from_rsa(pub_key).unwrap(),
        PKey::from_rsa(priv_key).unwrap(),
    ))
}

fn gen_ec_pair(nid: Nid) -> Result<(PKey<Public>, PKey<Private>), Error> {
    let group = EcGroup::from_curve_name(nid).unwrap();
    let ec_priv_key = EcKey::generate(&group).unwrap();
    let public_key_point = ec_priv_key.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key_point).unwrap();
    Ok((
        PKey::from_ec_key(ec_pub_key).unwrap(),
        PKey::from_ec_key(ec_priv_key).unwrap(),
    ))
}

pub fn gen_keypair(key_type: KeyType) -> Result<(PublicKey, PrivateKey), Error> {
    let (pub_key, priv_key) = match key_type {
        KeyType::Rsa2048 => gen_rsa_pair(2048),
        KeyType::Rsa4096 => gen_rsa_pair(4096),
        KeyType::EcdsaP256 => gen_ec_pair(Nid::X9_62_PRIME256V1),
        KeyType::EcdsaP384 => gen_ec_pair(Nid::SECP384R1),
    }
    .map_err(|_| Error::from(format!("Unable to generate a {} key pair.", key_type)))?;
    let pub_key = PublicKey {
        key_type,
        inner_key: pub_key,
    };
    let priv_key = PrivateKey {
        key_type,
        inner_key: priv_key,
    };
    Ok((pub_key, priv_key))
}
