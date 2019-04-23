use serde::Serialize;

#[derive(Serialize)]
#[serde(untagged)]
pub enum Jwk {
    Es256(Es256Jwk),
    EdDsaEd25519(EdDsaEd25519Jwk),
}

#[derive(Serialize)]
pub struct Es256Jwk {
    kty: String,
    #[serde(rename = "use")]
    jwk_use: String,
    crv: String,
    alg: String,
    x: String,
    y: String,
}

impl Es256Jwk {
    pub fn new(x: &str, y: &str) -> Self {
        Es256Jwk {
            kty: "EC".into(),
            jwk_use: "sig".into(),
            crv: "P-256".into(),
            alg: "ES256".into(),
            x: x.to_string(),
            y: y.to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct EdDsaEd25519Jwk {
    // TODO: implement
}

impl EdDsaEd25519Jwk {
    pub fn new() -> Self {
        EdDsaEd25519Jwk {}
    }
}
