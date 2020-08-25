use crate::acme_proto::Challenge;
use acme_common::error::Error;
use acme_common::to_idna;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

// RFC 3596, section 2.5
fn u8_to_nibbles_string(value: &u8) -> String {
    let bytes = value.to_ne_bytes();
    let first = bytes[0] & 0x0f;
    let second = (bytes[0] >> 4) & 0x0f;
    format!("{:x}.{:x}", first, second)
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum IdentifierType {
    #[serde(rename = "dns")]
    Dns,
    #[serde(rename = "ip")]
    Ip,
}

impl IdentifierType {
    pub fn supported_challenges(&self) -> Vec<Challenge> {
        match self {
            IdentifierType::Dns => vec![Challenge::Http01, Challenge::Dns01, Challenge::TlsAlpn01],
            IdentifierType::Ip => vec![Challenge::Http01, Challenge::TlsAlpn01],
        }
    }
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            IdentifierType::Dns => "dns",
            IdentifierType::Ip => "ip",
        };
        write!(f, "{}", name)
    }
}

#[derive(Clone, Debug)]
pub struct Identifier {
    pub id_type: IdentifierType,
    pub value: String,
    pub challenge: Challenge,
    pub env: HashMap<String, String>,
}

impl Identifier {
    pub fn new(
        id_type: IdentifierType,
        value: &str,
        challenge: &str,
        env: &HashMap<String, String>,
    ) -> Result<Self, Error> {
        let value = match id_type {
            IdentifierType::Dns => to_idna(value)?,
            IdentifierType::Ip => IpAddr::from_str(value)?.to_string(),
        };
        let challenge = Challenge::from_str(challenge)?;
        if !id_type.supported_challenges().contains(&challenge) {
            let msg = format!(
                "Challenge {} cannot be used with identifier of type {}",
                challenge, id_type
            );
            return Err(msg.into());
        }
        Ok(Identifier {
            id_type,
            value,
            challenge,
            env: env.clone(),
        })
    }

    pub fn get_tls_alpn_name(&self) -> Result<String, Error> {
        match &self.id_type {
            IdentifierType::Dns => Ok(self.value.to_owned()),
            IdentifierType::Ip => match IpAddr::from_str(&self.value)? {
                IpAddr::V4(ip) => {
                    let dn = ip
                        .octets()
                        .iter()
                        .rev()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>()
                        .join(".");
                    let dn = format!("{}.in-addr.arpa", dn);
                    Ok(dn)
                }
                IpAddr::V6(ip) => {
                    let dn = ip
                        .octets()
                        .iter()
                        .rev()
                        .map(u8_to_nibbles_string)
                        .collect::<Vec<String>>()
                        .join(".");
                    let dn = format!("{}.ip6.arpa", dn);
                    Ok(dn)
                }
            },
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {} ({})", self.id_type, self.value, self.challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_ipv4_tls_alpn_name() {
        let env = HashMap::new();
        let id = Identifier::new(IdentifierType::Ip, "203.0.113.1", "http-01", &env).unwrap();
        assert_eq!(&id.get_tls_alpn_name().unwrap(), "1.113.0.203.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_tls_alpn_name() {
        let env = HashMap::new();
        let id = Identifier::new(IdentifierType::Ip, "2001:db8::1", "http-01", &env).unwrap();
        assert_eq!(
            &id.get_tls_alpn_name().unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        let id = Identifier::new(
            IdentifierType::Ip,
            "4321:0:1:2:3:4:567:89ab",
            "http-01",
            &env,
        )
        .unwrap();
        assert_eq!(
            &id.get_tls_alpn_name().unwrap(),
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa"
        );
    }
}
