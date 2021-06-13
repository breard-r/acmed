use crate::crypto::KeyPair;

const KEY_RSA_2048_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzfwZGF8zKNAg2
9mdZ9ieE7V2clY3oeI+2V7eV5kUwOGqhhpDaDyDmju+l0dKFwF8xeDeeGmTSED10
e38ZsHqJF0cZqKDrB3hOeDAsn7Z6stHf/RZozQO5sAmZpN7g0P0lhXJnyAr+WL58
X41kWuufiPVbvURQv/tK3yN2K+rC6MdZ2lLsLemKiwAlbyGrPfUzuVc6dXrU8JvX
kkwuIpAyEEJ7OTXdBaT4VAHHtm2YDWIwW+34Otyp2FvbSJYsIwJjC00t7Phmah9b
MjiypCZB6OknZV7WAZ55jaF/rypARB/zzTieSyn4Qi/VjipWE7nO/GjubyzrJtQm
q+o7Pm71AgMBAAECggEAVAXEFA+UB5svtTrGym/Vs/3A8kl3sjitXTfWck7mWFow
YAgzyj+GsSZ7u+1qVL3mUavqrRHB3CtJ+TrOFmJsGbxRxgsPuLU4ddMBCgKBUxJd
+DHqyYgelE95TvjEdAygU24STc5whvtXv7Si5TVCUt2zrQv97KbRpQyq9ug77pxp
iQGiZ4spUH47TrYtw85HqU1Vb+hJamvcwLv1jv6sKOKv4A4nF3OsqJOqH1FAcFf7
f2Co2Zz83LV6WZ+yFAVG4C1OFMYJABHb3Sq+a5BOipkcCqQqK016NBcIsPvMGTuK
sHUBa2Reh9jLdOehfUa3p+Ir9ZALD+gs5jStRxFqCQKBgQD6Vcpsspsrl069fIJ2
gWd37saM0b0DTqf5Pb3JFKyD5yCyRQD0UtgrUSP8wPxhRtJN0Jku+X1IW3FjLPeg
S/VWEp2nmRTpvHGZ1KYD0gn3RQne8mbt43+f9AwlEfjhvrWDUQhb1TOdCwa/9/xY
HPRM0xV4UiYJG+GVLla4Rbs60wKBgQC3jtvZh/Nd8DwtuS8wXMHQxTLjiHdd6r5n
Lm1m6236NHs7NMA3NlcH9lOP+YfU3I0Ti4CnYI8YWyIrJAbck6maCzLlzUluSzeo
kJ+Ax0/H7DOM0ix7EMkUMCU8m5qi684qg1yngmWobd0Y3aCWjPgQa0oG04+uXb0A
w+GbrB+CFwKBgQDGfF1a4CauYnMZRO7AfYwHiPg+0VH3nFcNBQpEtDKxBwJittmx
3zns5pINJws1Kg03i6zZlRHj3DVEOHRC0dc9ntcH+xWc2kCMgxH6t4AVYdUYw8Qe
3KHltoAmqGBYxXhwHUDuZ1ZcL1DzxvF6/8IoY7mDREdKM6QiP7KcuxVf5wKBgHx/
NnnqDZRvNkHE0k64+vPAbG2Kx3s5lf6hrK4bjDIhmltjweMwxgKufaqvEgO7uyvA
eHgNs8BPP3OHMeg1dtj2M4VNoTpfZda8kJJlnKT6fVRL0MN/dQJuTTM4Tr+ls+V9
x0AN3ylHqqgM2biC0FVCj6jloRQgm+qC8OgG7C/tAoGAeMToPctEvifliZkiyA6P
INrBwWyg3d0Kk3Wlyne3HP9PwS5KrtbKqwkAXsFWNW0HMpG7lMkedvoYjmL71i/5
jIkjfccxlH1fRp/YOZ0wJ4ZWS6G/QgfqmvTeIpEcbokOmBGvHeuFLA8pyzfZa9rP
hEeZwTjgMoKYaVZ4q+23m/0=
-----END PRIVATE KEY-----"#;
const KEY_RSA_4096_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
yr9E4nQyE5YlYlPUK6iIRBu9j1N2MhY=
-----END PRIVATE KEY-----"#;
const KEY_ECDSA_P256_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCQc9OXwvygYqOFT4fN
NpXynr1lu+1sSplFdYoWu7hE4g==
-----END PRIVATE KEY-----"#;
const KEY_ECDSA_P384_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCMsN9kHPueLABk+0PKi7WO
PO2/53dpt/yV5zOPrYPEoKs4t973nbt46IUN19lLF/s=
-----END PRIVATE KEY-----"#;
#[cfg(ed25519)]
const KEY_ECDSA_ED25519_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhpRNsiUzoWqNkpJKCtKV5++Tttz3locu1gQKkQnrOa
-----END PRIVATE KEY-----"#;
#[cfg(ed25519)]
const KEY_ECDSA_ED25519_PEM_BIS: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKa3WD0qeUToPQKSwa9cTsLPgCovqAtXMhlMX2KYBz0o
-----END PRIVATE KEY-----"#;
#[cfg(ed448)]
const KEY_ECDSA_ED448_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOcFBwsH4zU7u5RgFh48MgJPzXyjN5uXxDapZv4rG6opU
uMXco2JR1CSjKWgqgu1CAKadJIYiv2EgIw==
-----END PRIVATE KEY-----"#;

#[test]
fn test_rsa_2048_jwk() {
    let k = KeyPair::from_pem(KEY_RSA_2048_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 5);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("e"));
    assert!(jwk.contains_key("n"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "RSA");
    assert_eq!(jwk.get("e").unwrap(), "AQAB");
    assert_eq!(jwk.get("n").unwrap(), "s38GRhfMyjQINvZnWfYnhO1dnJWN6HiPtle3leZFMDhqoYaQ2g8g5o7vpdHShcBfMXg3nhpk0hA9dHt_GbB6iRdHGaig6wd4TngwLJ-2erLR3_0WaM0DubAJmaTe4ND9JYVyZ8gK_li-fF-NZFrrn4j1W71EUL_7St8jdivqwujHWdpS7C3piosAJW8hqz31M7lXOnV61PCb15JMLiKQMhBCezk13QWk-FQBx7ZtmA1iMFvt-Drcqdhb20iWLCMCYwtNLez4ZmofWzI4sqQmQejpJ2Ve1gGeeY2hf68qQEQf8804nksp-EIv1Y4qVhO5zvxo7m8s6ybUJqvqOz5u9Q");
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "RS256");
}

#[test]
fn test_rsa_2048_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_RSA_2048_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 3);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("e"));
    assert!(jwk.contains_key("n"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "RSA");
    assert_eq!(jwk.get("e").unwrap(), "AQAB");
    assert_eq!(jwk.get("n").unwrap(), "s38GRhfMyjQINvZnWfYnhO1dnJWN6HiPtle3leZFMDhqoYaQ2g8g5o7vpdHShcBfMXg3nhpk0hA9dHt_GbB6iRdHGaig6wd4TngwLJ-2erLR3_0WaM0DubAJmaTe4ND9JYVyZ8gK_li-fF-NZFrrn4j1W71EUL_7St8jdivqwujHWdpS7C3piosAJW8hqz31M7lXOnV61PCb15JMLiKQMhBCezk13QWk-FQBx7ZtmA1iMFvt-Drcqdhb20iWLCMCYwtNLez4ZmofWzI4sqQmQejpJ2Ve1gGeeY2hf68qQEQf8804nksp-EIv1Y4qVhO5zvxo7m8s6ybUJqvqOz5u9Q");
}

#[test]
fn test_rsa_4096_jwk() {
    let k = KeyPair::from_pem(KEY_RSA_4096_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 5);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("e"));
    assert!(jwk.contains_key("n"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "RSA");
    assert_eq!(jwk.get("e").unwrap(), "AQAB");
    assert_eq!(jwk.get("n").unwrap(), "jm0Jh8Zk-aRqUxME0yLeHhBtdDFq6IvVesr_ffFwGqtlI4tIa6MqYuuOE5qlqoBrxt1fpccqGF82j47JqeoWerkNdZxYh1uKGQa9G2vB4OBOFHxYujT-NNPPlwnVPrp1_pjxK0hiOGzZRliNhO65lMbEueQCaLbQ6wstr4aVsWKiw8O4MG8Cc2ZegkWlYg0ZHOAn-uJlAt17NJfX8x576XRwX2KCssPYeyiwBukRne3ahVVqrc35EmV9JH3CxDaG9MeBLo7FUV5P1GNOIs313cbAgdMYV6Ahr2LvsaLucFvhSwmHh42--meDui-0wdFILjrz7MsITZy4xXjl8_zqMZ2dBaO38wP5o9VCfCXaVlD3IYB9A4-Y9IQ6wEVeodzGloPQyddUZ70kZ7O3E1kYu0tBKhoAL1VcKiUvOj1ABGooqf8QIAWCiAWqDqkZJ5HiR61NC9lJ3MH-aqYXzeHUuOxdlfr3oWPQKlRyYoUW93xD4dXjHQyHsIS4gWYE9ZJ9aIomNHj93UPNfR8ScxQTQBJV9Ttgl_vOUdmlasTmo0OXbTLMexzWCVISvUuoBoTcTY4DXCFeYHz3EE3ijJ9fnDkX3SsvV43x8X58py9rEyAQnRxfeahpWEoxW6TA5qBxg1GMBQu6CY2MupqsmI0XHTXzy8xCt4Pqd_a5zP6Wh_E");
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "RS256");
}

#[test]
fn test_rsa_4096_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_RSA_4096_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 3);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("e"));
    assert!(jwk.contains_key("n"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "RSA");
    assert_eq!(jwk.get("e").unwrap(), "AQAB");
    assert_eq!(jwk.get("n").unwrap(), "jm0Jh8Zk-aRqUxME0yLeHhBtdDFq6IvVesr_ffFwGqtlI4tIa6MqYuuOE5qlqoBrxt1fpccqGF82j47JqeoWerkNdZxYh1uKGQa9G2vB4OBOFHxYujT-NNPPlwnVPrp1_pjxK0hiOGzZRliNhO65lMbEueQCaLbQ6wstr4aVsWKiw8O4MG8Cc2ZegkWlYg0ZHOAn-uJlAt17NJfX8x576XRwX2KCssPYeyiwBukRne3ahVVqrc35EmV9JH3CxDaG9MeBLo7FUV5P1GNOIs313cbAgdMYV6Ahr2LvsaLucFvhSwmHh42--meDui-0wdFILjrz7MsITZy4xXjl8_zqMZ2dBaO38wP5o9VCfCXaVlD3IYB9A4-Y9IQ6wEVeodzGloPQyddUZ70kZ7O3E1kYu0tBKhoAL1VcKiUvOj1ABGooqf8QIAWCiAWqDqkZJ5HiR61NC9lJ3MH-aqYXzeHUuOxdlfr3oWPQKlRyYoUW93xD4dXjHQyHsIS4gWYE9ZJ9aIomNHj93UPNfR8ScxQTQBJV9Ttgl_vOUdmlasTmo0OXbTLMexzWCVISvUuoBoTcTY4DXCFeYHz3EE3ijJ9fnDkX3SsvV43x8X58py9rEyAQnRxfeahpWEoxW6TA5qBxg1GMBQu6CY2MupqsmI0XHTXzy8xCt4Pqd_a5zP6Wh_E");
}

#[test]
fn test_ecdsa_p256_jwk() {
    let k = KeyPair::from_pem(KEY_ECDSA_P256_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 6);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("y"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-256");
    assert_eq!(
        jwk.get("x").unwrap(),
        "VpJrz2a8rASzmbHStuDxNCjQc8ZiDnrGvVeRayNskrQ"
    );
    assert_eq!(
        jwk.get("y").unwrap(),
        "GrVCHhF5hN68efEgdoYS7acUT88qhMKQbULVcBgPBUg"
    );
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "ES256");
}

#[test]
fn test_ecdsa_p256_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_ECDSA_P256_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 4);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("y"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-256");
    assert_eq!(
        jwk.get("x").unwrap(),
        "VpJrz2a8rASzmbHStuDxNCjQc8ZiDnrGvVeRayNskrQ"
    );
    assert_eq!(
        jwk.get("y").unwrap(),
        "GrVCHhF5hN68efEgdoYS7acUT88qhMKQbULVcBgPBUg"
    );
}

#[test]
fn test_ecdsa_p384_jwk() {
    let k = KeyPair::from_pem(KEY_ECDSA_P384_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 6);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("y"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-384");
    assert_eq!(
        jwk.get("x").unwrap(),
        "N7TmS8prIp0DAGvwg1saML4UK61oe2PPJTeGLJt0iW-PMNcetFPcMF4WCa0ez80a"
    );
    assert_eq!(
        jwk.get("y").unwrap(),
        "RE5dtMDKV9Y8hsKf3fqLzMx75WORJaGswqC68xkRNjo0HcTar4tCB9VF9eSFfTMU"
    );
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "ES384");
}

#[test]
fn test_ecdsa_p384_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_ECDSA_P384_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 4);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("y"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-384");
    assert_eq!(
        jwk.get("x").unwrap(),
        "N7TmS8prIp0DAGvwg1saML4UK61oe2PPJTeGLJt0iW-PMNcetFPcMF4WCa0ez80a"
    );
    assert_eq!(
        jwk.get("y").unwrap(),
        "RE5dtMDKV9Y8hsKf3fqLzMx75WORJaGswqC68xkRNjo0HcTar4tCB9VF9eSFfTMU"
    );
}

#[cfg(ed25519)]
#[test]
fn test_ed25519_jwk() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED25519_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 5);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed25519");
    assert_eq!(
        jwk.get("x").unwrap(),
        "DUX9ja8pq2wfkxuIaHzmhkdcVXMav_3rk5Y5ozOcp4o"
    );
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "EdDSA");
}

#[cfg(ed25519)]
#[test]
fn test_ed25519_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED25519_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 3);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed25519");
    assert_eq!(
        jwk.get("x").unwrap(),
        "DUX9ja8pq2wfkxuIaHzmhkdcVXMav_3rk5Y5ozOcp4o"
    );
}

#[cfg(ed25519)]
#[test]
fn test_ed25519_jwk_bis() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED25519_PEM_BIS.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 5);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed25519");
    assert_eq!(
        jwk.get("x").unwrap(),
        "i9K0eV5qOJ_l_TWjWFLm8R-JbyGdlqFFeL_J0eEXFnc"
    );
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "EdDSA");
}

#[cfg(ed25519)]
#[test]
fn test_ed25519_jwk_thumbprint_bis() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED25519_PEM_BIS.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 3);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed25519");
    assert_eq!(
        jwk.get("x").unwrap(),
        "i9K0eV5qOJ_l_TWjWFLm8R-JbyGdlqFFeL_J0eEXFnc"
    );
}

#[cfg(ed448)]
#[test]
fn test_ed448_jwk() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED448_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 5);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("use"));
    assert!(jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed448");
    assert_eq!(
        jwk.get("x").unwrap(),
        "b9GZ8b1hip3UMzkkNBdMF4JWBTZojxsNHK-jQBH94SY3boVs4Oeo291E1dGXz7RUMqIXjkSbU4EA"
    );
    assert_eq!(jwk.get("use").unwrap(), "sig");
    assert_eq!(jwk.get("alg").unwrap(), "EdDSA");
}

#[cfg(ed448)]
#[test]
fn test_ed448_jwk_thumbprint() {
    let k = KeyPair::from_pem(KEY_ECDSA_ED448_PEM.as_bytes()).unwrap();
    let jwk = k.jwk_public_key_thumbprint().unwrap();
    assert!(jwk.is_object());
    let jwk = jwk.as_object().unwrap();
    assert_eq!(jwk.len(), 3);
    assert!(jwk.contains_key("kty"));
    assert!(jwk.contains_key("crv"));
    assert!(jwk.contains_key("x"));
    assert!(!jwk.contains_key("use"));
    assert!(!jwk.contains_key("alg"));
    assert_eq!(jwk.get("kty").unwrap(), "OKP");
    assert_eq!(jwk.get("crv").unwrap(), "Ed448");
    assert_eq!(
        jwk.get("x").unwrap(),
        "b9GZ8b1hip3UMzkkNBdMF4JWBTZojxsNHK-jQBH94SY3boVs4Oeo291E1dGXz7RUMqIXjkSbU4EA"
    );
}
