use acme_common::error::Error;
use serde::Deserialize;
use std::fmt;
use std::str::FromStr;

pub trait ApiError {
    fn get_error(&self) -> Option<Error>;
}

#[derive(PartialEq)]
pub enum AcmeError {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCSR,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    Caa,
    Compound,
    Connection,
    Dns,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Tls,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
    Unknown,
}

impl From<String> for AcmeError {
    fn from(error: String) -> Self {
        match error.as_str() {
            "urn:ietf:params:acme:error:accountDoesNotExist" => AcmeError::AccountDoesNotExist,
            "urn:ietf:params:acme:error:alreadyRevoked" => AcmeError::AlreadyRevoked,
            "urn:ietf:params:acme:error:badCSR" => AcmeError::BadCSR,
            "urn:ietf:params:acme:error:badNonce" => AcmeError::BadNonce,
            "urn:ietf:params:acme:error:badPublicKey" => AcmeError::BadPublicKey,
            "urn:ietf:params:acme:error:badRevocationReason" => AcmeError::BadRevocationReason,
            "urn:ietf:params:acme:error:badSignatureAlgorithm" => AcmeError::BadSignatureAlgorithm,
            "urn:ietf:params:acme:error:caa" => AcmeError::Caa,
            "urn:ietf:params:acme:error:compound" => AcmeError::Compound,
            "urn:ietf:params:acme:error:connection" => AcmeError::Connection,
            "urn:ietf:params:acme:error:dns" => AcmeError::Dns,
            "urn:ietf:params:acme:error:externalAccountRequired" => {
                AcmeError::ExternalAccountRequired
            }
            "urn:ietf:params:acme:error:incorrectResponse" => AcmeError::IncorrectResponse,
            "urn:ietf:params:acme:error:invalidContact" => AcmeError::InvalidContact,
            "urn:ietf:params:acme:error:malformed" => AcmeError::Malformed,
            "urn:ietf:params:acme:error:orderNotReady" => AcmeError::OrderNotReady,
            "urn:ietf:params:acme:error:rateLimited" => AcmeError::RateLimited,
            "urn:ietf:params:acme:error:rejectedIdentifier" => AcmeError::RejectedIdentifier,
            "urn:ietf:params:acme:error:serverInternal" => AcmeError::ServerInternal,
            "urn:ietf:params:acme:error:tls" => AcmeError::Tls,
            "urn:ietf:params:acme:error:unauthorized" => AcmeError::Unauthorized,
            "urn:ietf:params:acme:error:unsupportedContact" => AcmeError::UnsupportedContact,
            "urn:ietf:params:acme:error:unsupportedIdentifier" => AcmeError::UnsupportedIdentifier,
            "urn:ietf:params:acme:error:userActionRequired" => AcmeError::UserActionRequired,
            _ => AcmeError::Unknown,
        }
    }
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            AcmeError::AccountDoesNotExist => "The request specified an account that does not exist",
            AcmeError::AlreadyRevoked => "The request specified a certificate to be revoked that has already been revoked",
            AcmeError::BadCSR => "The CSR is unacceptable (e.g., due to a short key)",
            AcmeError::BadNonce => "The client sent an unacceptable anti-replay nonce",
            AcmeError::BadPublicKey => "The JWS was signed by a public key the server does not support",
            AcmeError::BadRevocationReason => "The revocation reason provided is not allowed by the server",
            AcmeError::BadSignatureAlgorithm => "The JWS was signed with an algorithm the server does not support",
            AcmeError::Caa => "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate",
            AcmeError::Compound => "Specific error conditions are indicated in the \"subproblems\" array",
            AcmeError::Connection => "The server could not connect to validation target",
            AcmeError::Dns => "There was a problem with a DNS query during identifier validation",
            AcmeError::ExternalAccountRequired => "The request must include a value for the \"externalAccountBinding\" field",
            AcmeError::IncorrectResponse => "Response received didn't match the challenge's requirements",
            AcmeError::InvalidContact => "A contact URL for an account was invalid",
            AcmeError::Malformed => "The request message was malformed",
            AcmeError::OrderNotReady => "The request attempted to finalize an order that is not ready to be finalized",
            AcmeError::RateLimited => "The request exceeds a rate limit",
            AcmeError::RejectedIdentifier => "The server will not issue certificates for the identifier",
            AcmeError::ServerInternal => "The server experienced an internal error",
            AcmeError::Tls => "The server received a TLS error during validation",
            AcmeError::Unauthorized => "The client lacks sufficient authorization",
            AcmeError::UnsupportedContact => "A contact URL for an account used an unsupported protocol scheme",
            AcmeError::UnsupportedIdentifier => "An identifier is of an unsupported type",
            AcmeError::UserActionRequired => "Visit the \"instance\" URL and take actions specified there",
            AcmeError::Unknown => "Unknown error",
        };
        write!(f, "{}", msg)
    }
}

impl AcmeError {
    pub fn is_recoverable(&self) -> bool {
        *self == AcmeError::BadNonce
            || *self == AcmeError::Connection
            || *self == AcmeError::Dns
            || *self == AcmeError::Malformed
            || *self == AcmeError::RateLimited
            || *self == AcmeError::ServerInternal
            || *self == AcmeError::Tls
    }
}

impl From<Error> for AcmeError {
    fn from(_error: Error) -> Self {
        AcmeError::Unknown
    }
}

impl From<AcmeError> for Error {
    fn from(error: AcmeError) -> Self {
        error.to_string().into()
    }
}

#[derive(Clone, PartialEq, Deserialize)]
pub struct HttpApiError {
    #[serde(rename = "type")]
    error_type: Option<String>,
    // title: Option<String>,
    status: Option<usize>,
    detail: Option<String>,
    // instance: Option<String>,
    // TODO: implement subproblems
}

crate::acme_proto::structs::deserialize_from_str!(HttpApiError);

impl fmt::Display for HttpApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = self
            .detail
            .to_owned()
            .unwrap_or_else(|| self.get_acme_type().to_string());
        let msg = match self.status {
            Some(s) => format!("Status {}: {}", s, msg),
            None => msg,
        };
        write!(f, "{}", msg)
    }
}

impl HttpApiError {
    pub fn get_type(&self) -> String {
        self.error_type
            .to_owned()
            .unwrap_or_else(|| String::from("about:blank"))
    }

    pub fn get_acme_type(&self) -> AcmeError {
        self.get_type().into()
    }
}

impl From<HttpApiError> for Error {
    fn from(error: HttpApiError) -> Self {
        error.to_string().into()
    }
}
