use acme_lib::Error;
use acme_lib::persist::PersistKind;
use crate::acmed::Format;
use log::debug;
use pem::{encode, Pem};

enum ConversionType {
    PemToDer,
    DerToPem,
    None,
}

impl ConversionType {
    fn get(from: &Format, to: &Format) -> Self {
        match from {
            Format::Pem => match to {
                Format::Pem => ConversionType::None,
                Format::Der => ConversionType::PemToDer,
            },
            Format::Der => match to {
                Format::Pem => ConversionType::DerToPem,
                Format::Der => ConversionType::None,
            },
        }
    }
}

fn pem_to_der(data: &[u8]) -> Result<Vec<u8>, Error> {
    // We need to convert all CRLF into LF since x509_parser only supports the later.
    let mut data = data.to_vec();
    data.retain(|&c| c != 0x0d);
    match x509_parser::pem::pem_to_der(&data) {
        Ok((_, cert)) => Ok(cert.contents),
        Err(_) => Err(Error::Other("invalid PEM certificate".to_string())),
    }
}

fn der_to_pem(data: &[u8], kind: PersistKind) -> Result<Vec<u8>, Error> {
    // TODO: allow the user to specify if we should use CRLF or LF (default is CRLF).
    let tag_str = match kind {
        PersistKind::AccountPrivateKey => "PRIVATE KEY",
        PersistKind::PrivateKey => "PRIVATE KEY",
        PersistKind::Certificate => "CERTIFICATE",
    };
    let pem = Pem {
        tag: String::from(tag_str),
        contents: data.to_vec(),
    };
    let res = encode(&pem);
    Ok(res.into_bytes())
}

/// Convert a certificate encoded in a format into another format.
///
/// Warning: if the data contains multiple certificates (eg: a PEM
/// certificate chain), converting to DER will only include the first
/// certificate, the others will be lost.
pub fn convert(
    data: &[u8],
    from: &Format,
    to: &Format,
    kind: PersistKind,
) -> Result<Vec<u8>, Error> {
    debug!("Converting a certificate from {} to {}", from, to);
    match ConversionType::get(from, to) {
        ConversionType::PemToDer => pem_to_der(data),
        ConversionType::DerToPem => der_to_pem(data, kind),
        ConversionType::None => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use acme_lib::persist::PersistKind;
    use crate::acmed::Format;
    use super::convert;

    // Test data generated using:
    //
    // openssl req -x509 -nodes -newkey ED25519 -keyout key.pem -out cert.pem -days 365
    // openssl pkey -inform PEM -outform DER -in key.pem -out key.der
    // openssl x509 -inform PEM -outform DER -in cert.pem -out cert.der
    pub const PK_PEM: &'static [u8] = b"-----BEGIN PRIVATE KEY-----\r
MC4CAQAwBQYDK2VwBCIEIJRKGvS3yKtxf+zjzvDTHx2dIcDXz0LKeBLnqE0H8ALb\r
-----END PRIVATE KEY-----\r\n";
    pub const PK_DER: &'static [u8] = b"\x30\x2E\x02\x01\x00\x30\x05\x06\x03\
\x2B\x65\x70\x04\x22\x04\x20\x94\x4A\x1A\xF4\xB7\xC8\xAB\x71\x7F\xEC\xE3\xCE\
\xF0\xD3\x1F\x1D\x9D\x21\xC0\xD7\xCF\x42\xCA\x78\x12\xE7\xA8\x4D\x07\xF0\x02\
\xDB";
    pub const CERT_PEM: &'static [u8] = b"-----BEGIN CERTIFICATE-----\r
MIICLzCCAeGgAwIBAgIUdlMenq7MVkx5b1lFrvaBwvjlIEQwBQYDK2VwMIGMMQsw\r
CQYDVQQGEwJGUjEZMBcGA1UECAwQw4PCjmxlLWRlLUZyYW5jZTEOMAwGA1UEBwwF\r
UGFyaXMxDjAMBgNVBAoMBUFDTUVkMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUub3Jn\r
MScwJQYJKoZIhvcNAQkBFhhpbnZhbGlkQHRlc3QuZXhhbXBsZS5vcmcwHhcNMTkw\r
MzE0MTE0NDI1WhcNMjAwMzEzMTE0NDI1WjCBjDELMAkGA1UEBhMCRlIxGTAXBgNV\r
BAgMEMODwo5sZS1kZS1GcmFuY2UxDjAMBgNVBAcMBVBhcmlzMQ4wDAYDVQQKDAVB\r
Q01FZDEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLm9yZzEnMCUGCSqGSIb3DQEJARYY\r
aW52YWxpZEB0ZXN0LmV4YW1wbGUub3JnMCowBQYDK2VwAyEAboP+S9yfoP3euk+C\r
FgMIZ9J/Q6KxLwteCAvJSkbWTwKjUzBRMB0GA1UdDgQWBBT49UVSayhFWUaRiyiB\r
oXkSoRgynTAfBgNVHSMEGDAWgBT49UVSayhFWUaRiyiBoXkSoRgynTAPBgNVHRMB\r
Af8EBTADAQH/MAUGAytlcANBAPITjbIYNioMcpMDMvbyzHf2IqPFiNW/Ce3KTS8T\r
zseNNFkN0oOc55UAd2ECe6gGOXB0r4MycFOM9ccR2t8ttwE=\r
-----END CERTIFICATE-----\r\n";
    pub const CERT_DER: &'static [u8] = b"\x30\x82\x02\x2F\x30\x82\x01\xE1\xA0\
\x03\x02\x01\x02\x02\x14\x76\x53\x1E\x9E\xAE\xCC\x56\x4C\x79\x6F\x59\x45\xAE\
\xF6\x81\xC2\xF8\xE5\x20\x44\x30\x05\x06\x03\x2B\x65\x70\x30\x81\x8C\x31\x0B\
\x30\x09\x06\x03\x55\x04\x06\x13\x02\x46\x52\x31\x19\x30\x17\x06\x03\x55\x04\
\x08\x0C\x10\xC3\x83\xC2\x8E\x6C\x65\x2D\x64\x65\x2D\x46\x72\x61\x6E\x63\x65\
\x31\x0E\x30\x0C\x06\x03\x55\x04\x07\x0C\x05\x50\x61\x72\x69\x73\x31\x0E\x30\
\x0C\x06\x03\x55\x04\x0A\x0C\x05\x41\x43\x4D\x45\x64\x31\x19\x30\x17\x06\x03\
\x55\x04\x03\x0C\x10\x74\x65\x73\x74\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x6F\
\x72\x67\x31\x27\x30\x25\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x18\
\x69\x6E\x76\x61\x6C\x69\x64\x40\x74\x65\x73\x74\x2E\x65\x78\x61\x6D\x70\x6C\
\x65\x2E\x6F\x72\x67\x30\x1E\x17\x0D\x31\x39\x30\x33\x31\x34\x31\x31\x34\x34\
\x32\x35\x5A\x17\x0D\x32\x30\x30\x33\x31\x33\x31\x31\x34\x34\x32\x35\x5A\x30\
\x81\x8C\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x46\x52\x31\x19\x30\x17\
\x06\x03\x55\x04\x08\x0C\x10\xC3\x83\xC2\x8E\x6C\x65\x2D\x64\x65\x2D\x46\x72\
\x61\x6E\x63\x65\x31\x0E\x30\x0C\x06\x03\x55\x04\x07\x0C\x05\x50\x61\x72\x69\
\x73\x31\x0E\x30\x0C\x06\x03\x55\x04\x0A\x0C\x05\x41\x43\x4D\x45\x64\x31\x19\
\x30\x17\x06\x03\x55\x04\x03\x0C\x10\x74\x65\x73\x74\x2E\x65\x78\x61\x6D\x70\
\x6C\x65\x2E\x6F\x72\x67\x31\x27\x30\x25\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\
\x09\x01\x16\x18\x69\x6E\x76\x61\x6C\x69\x64\x40\x74\x65\x73\x74\x2E\x65\x78\
\x61\x6D\x70\x6C\x65\x2E\x6F\x72\x67\x30\x2A\x30\x05\x06\x03\x2B\x65\x70\x03\
\x21\x00\x6E\x83\xFE\x4B\xDC\x9F\xA0\xFD\xDE\xBA\x4F\x82\x16\x03\x08\x67\xD2\
\x7F\x43\xA2\xB1\x2F\x0B\x5E\x08\x0B\xC9\x4A\x46\xD6\x4F\x02\xA3\x53\x30\x51\
\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\xF8\xF5\x45\x52\x6B\x28\x45\x59\
\x46\x91\x8B\x28\x81\xA1\x79\x12\xA1\x18\x32\x9D\x30\x1F\x06\x03\x55\x1D\x23\
\x04\x18\x30\x16\x80\x14\xF8\xF5\x45\x52\x6B\x28\x45\x59\x46\x91\x8B\x28\x81\
\xA1\x79\x12\xA1\x18\x32\x9D\x30\x0F\x06\x03\x55\x1D\x13\x01\x01\xFF\x04\x05\
\x30\x03\x01\x01\xFF\x30\x05\x06\x03\x2B\x65\x70\x03\x41\x00\xF2\x13\x8D\xB2\
\x18\x36\x2A\x0C\x72\x93\x03\x32\xF6\xF2\xCC\x77\xF6\x22\xA3\xC5\x88\xD5\xBF\
\x09\xED\xCA\x4D\x2F\x13\xCE\xC7\x8D\x34\x59\x0D\xD2\x83\x9C\xE7\x95\x00\x77\
\x61\x02\x7B\xA8\x06\x39\x70\x74\xAF\x83\x32\x70\x53\x8C\xF5\xC7\x11\xDA\xDF\
\x2D\xB7\x01";

    #[test]
    fn test_der_to_der() {
        let res = convert(
            &CERT_DER,
            &Format::Der,
            &Format::Der,
            PersistKind::Certificate,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(CERT_DER, res.as_slice());
    }

    #[test]
    fn test_pem_to_pem() {
        let res = convert(
            &CERT_PEM,
            &Format::Pem,
            &Format::Pem,
            PersistKind::Certificate,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(CERT_PEM, res.as_slice());
    }

    #[test]
    fn test_der_to_pem_pk() {
        let res = convert(&PK_DER, &Format::Der, &Format::Pem, PersistKind::PrivateKey);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(PK_PEM, res.as_slice());
    }

    #[test]
    fn test_der_to_pem_crt() {
        let res = convert(
            &CERT_DER,
            &Format::Der,
            &Format::Pem,
            PersistKind::Certificate,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(CERT_PEM, res.as_slice());
    }

    #[test]
    fn test_pem_to_der_crt() {
        let res = convert(
            &CERT_PEM,
            &Format::Pem,
            &Format::Der,
            PersistKind::Certificate,
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(CERT_DER, res.as_slice());
    }

    #[test]
    fn test_pem_to_der_pk() {
        let res = convert(&PK_PEM, &Format::Pem, &Format::Der, PersistKind::PrivateKey);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(PK_DER, res.as_slice());
    }
}
