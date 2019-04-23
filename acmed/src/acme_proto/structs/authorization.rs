use crate::acme_proto::b64_encode;
use crate::acme_proto::jws::algorithms::SignatureAlgorithm;
use crate::acme_proto::structs::Identifier;
use crate::error::Error;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use serde::Deserialize;
use std::fmt;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

impl FromStr for Authorization {
    type Err = Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        let mut res: Self = serde_json::from_str(data)?;
        res.challenges.retain(|c| *c != Challenge::Unknown);
        Ok(res)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            AuthorizationStatus::Pending => "pending",
            AuthorizationStatus::Valid => "valid",
            AuthorizationStatus::Invalid => "invalid",
            AuthorizationStatus::Deactivated => "deactivated",
            AuthorizationStatus::Expired => "expired",
            AuthorizationStatus::Revoked => "revoked",
        };
        write!(f, "{}", s)
    }
}

#[derive(PartialEq, Deserialize)]
#[serde(tag = "type")]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01(TokenChallenge),
    #[serde(rename = "dns-01")]
    Dns01(TokenChallenge),
    // TODO: tls-alpn-01
    #[serde(other)]
    Unknown,
}

deserialize_from_str!(Challenge);

impl Challenge {
    pub fn get_url(&self) -> String {
        match self {
            Challenge::Http01(tc) | Challenge::Dns01(tc) => tc.url.to_owned(),
            Challenge::Unknown => String::new(),
        }
    }

    pub fn get_proof(&self, private_key: &PKey<Private>) -> Result<String, Error> {
        match self {
            Challenge::Http01(tc) => tc.key_authorization(private_key),
            Challenge::Dns01(tc) => {
                let ka = tc.key_authorization(private_key)?;
                let a = sha256(ka.as_bytes());
                let a = b64_encode(&a);
                Ok(a)
            }
            Challenge::Unknown => Ok(String::new()),
        }
    }

    pub fn get_file_name(&self) -> String {
        match self {
            Challenge::Http01(tc) => tc.token.to_owned(),
            Challenge::Dns01(_) => String::new(),
            Challenge::Unknown => String::new(),
        }
    }
}

#[derive(PartialEq, Deserialize)]
pub struct TokenChallenge {
    pub url: String,
    pub status: Option<ChallengeStatus>,
    pub validated: Option<String>,
    pub error: Option<String>, // TODO: set the correct object
    pub token: String,
}

impl TokenChallenge {
    fn key_authorization(&self, private_key: &PKey<Private>) -> Result<String, Error> {
        let sa = SignatureAlgorithm::from_pkey(private_key)?;
        let thumbprint = sa.get_jwk_thumbprint(private_key)?;
        let thumbprint = sha256(thumbprint.as_bytes());
        let thumbprint = b64_encode(&thumbprint);
        let auth = format!("{}.{}", self.token, thumbprint);
        Ok(auth)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::{Authorization, AuthorizationStatus, Challenge, ChallengeStatus};
    use crate::acme_proto::structs::IdentifierType;
    use std::str::FromStr;

    #[test]
    fn test_authorization() {
        let data = "{
    \"status\": \"pending\",
    \"identifier\": {
        \"type\": \"dns\",
        \"value\": \"example.com\"
    },
    \"challenges\": []
}";
        let a = Authorization::from_str(data);
        assert!(a.is_ok());
        let a = a.unwrap();
        assert_eq!(a.status, AuthorizationStatus::Pending);
        assert!(a.challenges.is_empty());
        let i = a.identifier;
        assert_eq!(i.id_type, IdentifierType::Dns);
        assert_eq!(i.value, "example.com".to_string());
    }

    #[test]
    fn test_authorization_challenge() {
        let data = "{
    \"status\": \"pending\",
    \"identifier\": {
        \"type\": \"dns\",
        \"value\": \"example.com\"
    },
    \"challenges\": [
        {
            \"type\": \"dns-01\",
            \"status\": \"pending\",
            \"url\": \"https://example.com/chall/jYWxob3N0OjE\",
            \"token\": \"1y9UVMUvkqQVljCsnwlRLsbJcwN9nx-qDd6JHzXQQsw\"
        }
    ]
}";
        let a = Authorization::from_str(data);
        assert!(a.is_ok());
        let a = a.unwrap();
        assert_eq!(a.status, AuthorizationStatus::Pending);
        assert_eq!(a.challenges.len(), 1);
        let i = a.identifier;
        assert_eq!(i.id_type, IdentifierType::Dns);
        assert_eq!(i.value, "example.com".to_string());
    }

    #[test]
    fn test_authorization_unknown_challenge() {
        let data = "{
    \"status\": \"pending\",
    \"identifier\": {
        \"type\": \"dns\",
        \"value\": \"example.com\"
    },
    \"challenges\": [
        {
            \"type\": \"invalid-challenge-01\",
            \"status\": \"pending\",
            \"url\": \"https://example.com/chall/jYWxob3N0OjE\",
            \"token\": \"1y9UVMUvkqQVljCsnwlRLsbJcwN9nx-qDd6JHzXQQsw\"
        }
    ]
}";
        let a = Authorization::from_str(data);
        assert!(a.is_ok());
        let a = a.unwrap();
        assert_eq!(a.status, AuthorizationStatus::Pending);
        assert!(a.challenges.is_empty());
        let i = a.identifier;
        assert_eq!(i.id_type, IdentifierType::Dns);
        assert_eq!(i.value, "example.com".to_string());
    }

    #[test]
    fn test_invalid_authorization() {
        let data = "{
    \"status\": \"pending\",
    \"identifier\": {
        \"type\": \"foo\",
        \"value\": \"bar\"
    },
    \"challenges\": []
}";
        let a = Authorization::from_str(data);
        assert!(a.is_err());
    }

    #[test]
    fn test_http01_challenge() {
        let data = "{
    \"type\": \"http-01\",
    \"url\": \"https://example.com/acme/chall/prV_B7yEyA4\",
    \"status\": \"pending\",
    \"token\": \"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\"
}";
        let challenge = Challenge::from_str(data);
        assert!(challenge.is_ok());
        let challenge = challenge.unwrap();
        let c = match challenge {
            Challenge::Http01(c) => c,
            _ => {
                assert!(false);
                return;
            }
        };
        assert_eq!(
            c.url,
            "https://example.com/acme/chall/prV_B7yEyA4".to_string()
        );
        assert_eq!(c.status, Some(ChallengeStatus::Pending));
        assert_eq!(
            c.token,
            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0".to_string()
        );
        assert!(c.validated.is_none());
        assert!(c.error.is_none());
    }

    #[test]
    fn test_dns01_challenge() {
        let data = "{
    \"type\": \"http-01\",
    \"url\": \"https://example.com/acme/chall/prV_B7yEyA4\",
    \"status\": \"valid\",
    \"token\": \"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\"
}";
        let challenge = Challenge::from_str(data);
        assert!(challenge.is_ok());
        let challenge = challenge.unwrap();
        let c = match challenge {
            Challenge::Http01(c) => c,
            _ => {
                assert!(false);
                return;
            }
        };
        assert_eq!(
            c.url,
            "https://example.com/acme/chall/prV_B7yEyA4".to_string()
        );
        assert_eq!(c.status, Some(ChallengeStatus::Valid));
        assert_eq!(
            c.token,
            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0".to_string()
        );
        assert!(c.validated.is_none());
        assert!(c.error.is_none());
    }

    #[test]
    fn test_unknown_challenge_type() {
        let data = "{
    \"type\": \"invalid-01\",
    \"url\": \"https://example.com/acme/chall/prV_B7yEyA4\",
    \"status\": \"pending\",
    \"token\": \"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\"
}";
        let challenge = Challenge::from_str(data);
        assert!(challenge.is_ok());
        match challenge.unwrap() {
            Challenge::Unknown => assert!(true),
            _ => assert!(false),
        }
    }
}
