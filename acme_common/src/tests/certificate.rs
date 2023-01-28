use crate::crypto::{HashFunction, KeyType, X509Certificate, CRT_NB_DAYS_VALIDITY};
use std::collections::HashSet;
use std::iter::FromIterator;

const CERTIFICATE_P256_DOMAINS_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICtDCCAZygAwIBAgIIf5BEPlNrrYkwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAyZDE2ODgwHhcNMjAwODI1MTMwMzE3
WhcNMjUwODI1MTMwMzE3WjAYMRYwFAYDVQQDEw1sb2NhbC53aGF0LnRmMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE0c/unUqpoOMxxc8e1pkpPQTSsh2irQruOJgd
ITN9WLC4mzFSJ/ad64TFi4HsCFNd7mv/QRH6rW1s3LbocEvBuqOBvDCBuTAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud
EwEB/wQCMAAwHQYDVR0OBBYEFGjf1TWIZyE+QP9SGkBN6dfviIsaMB8GA1UdIwQY
MBaAFLgD5DMU2ijpIxlxaAv82sQvb5ofMDoGA1UdEQQzMDGCDWxvY2FsLndoYXQu
dGaCDzEubG9jYWwud2hhdC50ZoIPMi5sb2NhbC53aGF0LnRmMA0GCSqGSIb3DQEB
CwUAA4IBAQDREOAU2JwHfSPGt4SYlQ3OmFl4HHI2f+XyNE/09uZVteM0aChkntgX
rAZltuAAX+coSlgv3a04hJBqioDG1R9MFtf4LZBhfkgZwbzucMt8Ga3QL3XFXOkn
FlOwb/ZEIjFsBFQWt1ZSA85WxIVkGsgMfQeGpu/p8gEmJAE5l0qHEVFP9cYNsIqg
wsUGwZzPZFLsBXurM2cEA7cTt2HryVXlQWl8QI5YFpIpa43itYaerfMldfIfNdJ9
8GLZPEfJb6t/UYYexXEkpQY9wGZkaTWvYeItuC0YlPY9RUCAl48Q85Yjf37Wbm5z
f810HGl+/c6ttyoHKmLfY/GcX07AUcLc
-----END CERTIFICATE-----"#;
const CERTIFICATE_P256_IP_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICkTCCAXmgAwIBAgIIMW1X7DjQOFgwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAxYWM3MzcwHhcNMjAwODI1MTQzMjQw
WhcNMjUwODI1MTQzMjQwWjAOMQwwCgYDVQQDEwM6OjEwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASF+MvxX7GBAVe3McuAc+0emdFpBfAQG4mt9j8417qT76qHHyJ6
oIHRNXAUxh4J78ihrvyph8TvqND73Nxk8Jj9o4GjMIGgMA4GA1UdDwEB/wQEAwIF
oDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAd
BgNVHQ4EFgQU5R7EGzjpZqrs2o/ZwuBqNHlMB2AwHwYDVR0jBBgwFoAUhEUnWREW
GoAScr1wv/aXHTGOVoswIQYDVR0RBBowGIcQAAAAAAAAAAAAAAAAAAAAAYcEfwAA
ATANBgkqhkiG9w0BAQsFAAOCAQEAS8oRpjGakUU+KRtXCGoVlXgKYFe3u/G2aFMF
soApjvwd3L1W9b3bsT4FquF7F5qB6TGBwiXoNBoDAeVhRcUsHbmN8GZRUaq2TEsm
MwpPr8L4rqeRIuxY85AqmbGfMuFUie6r4FbwelnBniO0eMQkTW/XY41rbhGZ+lmj
DTQy08oj0892py2U/YbkL3JnCBwBba//f/Ji7nnSKdJl4Yd1iguA0nbdElcWaKk3
ij3t17FSNeI5uMOI3TRBr4k4bu3ZMnuN2DYFPnL6GiSEhyNrxaiac8xKuOXBICmJ
oyO7pZVvc5cDcP/USPcWJYcnR9gvuL8snQdFpWND8H19eZ+i0g==
-----END CERTIFICATE-----"#;
const CERTIFICATE_P256_DOMAINS_IP_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICzDCCAbSgAwIBAgIIff0SyxJBhtMwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAxYWM3MzcwHhcNMjAwODI1MTQzNjE1
WhcNMjUwODI1MTQzNjE1WjAYMRYwFAYDVQQDEw1sb2NhbC53aGF0LnRmMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7Jp4AmF0TTcYfUy4TtZhN4bXn4DXWnqF0I6i
Yvz4kc0r2L01nrUrICg2bmCFM7BU9pr9fcCDodH3ZuhlRqBAf6OB1DCB0TAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud
EwEB/wQCMAAwHQYDVR0OBBYEFHV0lnh55aQGfljcsjNkzZa4lTG6MB8GA1UdIwQY
MBaAFIRFJ1kRFhqAEnK9cL/2lx0xjlaLMFIGA1UdEQRLMEmCDWxvY2FsLndoYXQu
dGaCDzEubG9jYWwud2hhdC50ZoIPMi5sb2NhbC53aGF0LnRmhwR/AAABhxAAAAAA
AAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBAQC3VmoTlrrTCWCd4eUB4RSB
+080uco6Jl7VMqcY5F+eG1S7p4Kqz6kc1wiiKB8ILA94hdP1qTbfphdGllYiEvbs
urj0x62cm5URahEDx4xn+dQkmh4XiiZgZVw2ccphjqJqJa28GsuR2zAxSkKMDnB7
eX1G4/Av0XE7RqJ3Frq8qa5EjjLJTw0iEaWS5NGtZxMqWEIetCgb0IDZNxNvbeAv
mmH6qnF3xQPx5FkwP/Yw4d9T4KhSHNf2/tImIlbuk3SEsOglGbKNY1juor8uw+J2
5XsUZxD5QiDbCFd3dGmH58XmkiQHXs8hhIbhu9ZLgp+fNv0enVMHTTI1gGpZ5MPm
-----END CERTIFICATE-----"#;
const CERTIFICATE_EXPIRED_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIEsTCCA5mgAwIBAgISBApMImYflPdX7BYLjinQ+ErUMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTExMzAxODQxNTZaFw0y
MDAyMjgxODQxNTZaMBExDzANBgNVBAMTBmJ6aC50ZjB2MBAGByqGSM49AgEGBSuB
BAAiA2IABLSEIYJpT2SM+F9mEzFypkqbBm64dgX0KnyZuYGB2qHHsBLIBBK5Ev9Y
vPvYb8lzX3uJFHPn0JwPpGR0YBzPHBspyvwrhedokt8pNFEDC1eE4BH9XVN35utt
EGP1ZT92mKOCAnYwggJyMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOALpvHYbvHbQ
GcrtL0I4s/W/S58wHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYI
KwYBBQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0
c2VuY3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0
c2VuY3J5cHQub3JnLzAtBgNVHREEJjAkggZiemgudGaCDm10YS1zdHMuYnpoLnRm
ggp3d3cuYnpoLnRmMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEB
MCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBAwYK
KwYBBAHWeQIEAgSB9ASB8QDvAHYAb1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2y
CJo32RMAAAFuvdWC7QAABAMARzBFAiBgCoazSI4unyx09P8KYxdIfMZsG/fMtzkF
ciBDB9gcJQIhAPZMsnjqr4IqpyHyvauqrWoGqlFBcBCmogZCuhQXAnv5AHUAB7dc
G+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohwAAAFuvdWC7gAABAMARjBEAiAO
z7sHUA42VEQkicrWb5A4WjNGWV7NxpSDdb2XQ2Q1OwIgRaiEMrHfyT797O7Fvbk2
cL6rnnmDJOyxIAC4Dxe7NVwwDQYJKoZIhvcNAQELBQADggEBAFaNvfsGKqBuJ9m7
qRNqVmC7UHzGym+TPBLiXncwFIaWt0ncRHb6qfGCCETeAplhPv8uoOrzQQwTKwr3
eMDtdmK+9smnQZ4AjUsscsrbkGwMWOOmIRm/tCwQZ0dFnl1ySZDuaoCG7v/uRE4A
HXtNAeVOKuE7BOISvvssFajxLifmFixifWRwEnimTffjnIX6xqol+2bcxMuLWxt9
HmjTgcY4JMMcOAiNk3roJK9ayMi7jn0Cd097BFnvx08+oWSMOZ29hFHMHp3KCSzT
bQg4DAU6E9VT+pvyGsc1NNyREKxOlDkam3CqfYc0oAowjn11MmDac2aKP8Pyt4pk
ehm+yKg=
-----END CERTIFICATE-----"#;

#[test]
fn test_san_domains() {
	let san = vec!["local.what.tf", "1.local.what.tf", "2.local.what.tf"];
	let san = HashSet::from_iter(san.iter().map(|v| v.to_string()));
	let crt = X509Certificate::from_pem(CERTIFICATE_P256_DOMAINS_PEM.as_bytes()).unwrap();
	assert_eq!(crt.subject_alt_names(), san);
}

#[test]
fn test_san_ip() {
	let san = vec!["127.0.0.1", "::1"];
	let san = HashSet::from_iter(san.iter().map(|v| v.to_string()));
	let crt = X509Certificate::from_pem(CERTIFICATE_P256_IP_PEM.as_bytes()).unwrap();
	assert_eq!(crt.subject_alt_names(), san);
}

#[test]
fn test_san_domains_and_ip() {
	let san = vec![
		"127.0.0.1",
		"::1",
		"local.what.tf",
		"1.local.what.tf",
		"2.local.what.tf",
	];
	let san = HashSet::from_iter(san.iter().map(|v| v.to_string()));
	let crt = X509Certificate::from_pem(CERTIFICATE_P256_DOMAINS_IP_PEM.as_bytes()).unwrap();
	assert_eq!(crt.subject_alt_names(), san);
}

#[test]
fn generate_rsa2048_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::Rsa2048, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::Rsa2048);
}

#[test]
fn generate_rsa4096_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::Rsa4096, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::Rsa4096);
}

#[test]
fn generate_ecdsa_p256_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::EcdsaP256, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::EcdsaP256);
}

#[test]
fn generate_ecdsa_p384_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::EcdsaP384, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::EcdsaP384);
}

#[cfg(ed25519)]
#[test]
fn generate_ed25519_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::Ed25519, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::Ed25519);
}

#[cfg(ed448)]
#[test]
fn generate_ed448_certificate() {
	let (kp, _) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::Ed448, HashFunction::Sha256)
			.unwrap();
	assert_eq!(kp.key_type, KeyType::Ed448);
}

#[test]
fn cert_expiration_date_future() {
	let (_, crt) =
		X509Certificate::from_acme_ext("example.org", "", KeyType::EcdsaP256, HashFunction::Sha256)
			.unwrap();
	let duration = crt.expires_in().unwrap().as_secs();
	let validity_sec = CRT_NB_DAYS_VALIDITY as u64 * 24 * 60 * 60;
	let delta = 60;
	assert!(duration > validity_sec - delta);
	assert!(duration < validity_sec + delta);
}

#[test]
fn cert_expiration_date_past() {
	let crt = X509Certificate::from_pem(CERTIFICATE_EXPIRED_PEM.as_bytes()).unwrap();
	let duration = crt.expires_in().unwrap().as_secs();
	assert_eq!(duration, 0);
}
