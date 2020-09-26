use crate::acme_proto::structs::HttpApiError;
use crate::endpoint::Endpoint;
use acme_common::crypto::X509Certificate;
use acme_common::error::Error;
use attohttpc::{charsets, header, Response, Session};
use std::fs::File;
use std::io::prelude::*;
use std::{thread, time};

pub const CONTENT_TYPE_JOSE: &str = "application/jose+json";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_PEM: &str = "application/pem-certificate-chain";
pub const HEADER_NONCE: &str = "Replay-Nonce";
pub const HEADER_LOCATION: &str = "Location";

pub struct ValidHttpResponse {
    headers: attohttpc::header::HeaderMap,
    pub body: String,
}

impl ValidHttpResponse {
    pub fn get_header(&self, name: &str) -> Option<String> {
        match self.headers.get(name) {
            Some(r) => match header_to_string(r) {
                Ok(h) => Some(h),
                Err(_) => None,
            },
            None => None,
        }
    }

    pub fn json<T>(&self) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_str(&self.body).map_err(Error::from)
    }

    fn from_response(response: Response) -> Result<Self, Error> {
        let (_status, headers, body) = response.split();
        let body = body.text()?;
        log::trace!("HTTP response headers: {:?}", headers);
        log::trace!("HTTP response body: {}", body);
        Ok(ValidHttpResponse { headers, body })
    }
}

#[derive(Clone, Debug)]
pub enum HttpError {
    ApiError(HttpApiError),
    GenericError(Error),
}

impl HttpError {
    pub fn in_err(error: HttpError) -> Error {
        match error {
            HttpError::ApiError(e) => e.to_string().into(),
            HttpError::GenericError(e) => e,
        }
    }
}

impl From<Error> for HttpError {
    fn from(error: Error) -> Self {
        HttpError::GenericError(error)
    }
}

impl From<HttpApiError> for HttpError {
    fn from(error: HttpApiError) -> Self {
        HttpError::ApiError(error)
    }
}

impl From<&str> for HttpError {
    fn from(error: &str) -> Self {
        HttpError::GenericError(error.into())
    }
}

impl From<String> for HttpError {
    fn from(error: String) -> Self {
        HttpError::GenericError(error.into())
    }
}

impl From<attohttpc::Error> for HttpError {
    fn from(error: attohttpc::Error) -> Self {
        HttpError::GenericError(error.into())
    }
}

fn is_nonce(data: &str) -> bool {
    !data.is_empty()
        && data
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn new_nonce(endpoint: &mut Endpoint, root_certs: &[String]) -> Result<(), HttpError> {
    rate_limit(endpoint);
    let url = endpoint.dir.new_nonce.clone();
    let _ = get(endpoint, root_certs, &url)?;
    Ok(())
}

fn update_nonce(endpoint: &mut Endpoint, response: &Response) -> Result<(), Error> {
    if let Some(nonce) = response.headers().get(HEADER_NONCE) {
        let nonce = header_to_string(&nonce)?;
        if !is_nonce(&nonce) {
            let msg = format!("{}: invalid nonce.", &nonce);
            return Err(msg.into());
        }
        endpoint.nonce = Some(nonce);
    }
    Ok(())
}

fn check_status(response: &Response) -> Result<(), Error> {
    if !response.is_success() {
        let status = response.status();
        let msg = format!("HTTP error: {}: {}", status.as_u16(), status.as_str());
        return Err(msg.into());
    }
    Ok(())
}

fn rate_limit(endpoint: &mut Endpoint) {
    endpoint.rl.block_until_allowed();
}

fn header_to_string(header_value: &header::HeaderValue) -> Result<String, Error> {
    let s = header_value
        .to_str()
        .map_err(|_| Error::from("invalid header format"))?;
    Ok(s.to_string())
}

fn get_session(root_certs: &[String]) -> Result<Session, Error> {
    let useragent = format!(
        "{}/{} ({}) {}",
        crate::APP_NAME,
        crate::APP_VERSION,
        env!("ACMED_TARGET"),
        env!("ACMED_HTTP_LIB_AGENT")
    );
    // TODO: allow to change the language
    let mut session = Session::new();
    session.default_charset(Some(charsets::UTF_8));
    session.try_header(header::ACCEPT_LANGUAGE, "en-US,en;q=0.5")?;
    session.try_header(header::USER_AGENT, &useragent)?;
    for crt_file in root_certs.iter() {
        let mut buff = Vec::new();
        File::open(crt_file)?.read_to_end(&mut buff)?;
        let crt = X509Certificate::from_pem_native(&buff)?;
        session.add_root_certificate(crt);
    }
    Ok(session)
}

pub fn get(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    url: &str,
) -> Result<ValidHttpResponse, HttpError> {
    let mut session = get_session(root_certs)?;
    session.try_header(header::ACCEPT, CONTENT_TYPE_JSON)?;
    rate_limit(endpoint);
    let response = session.get(url).send()?;
    update_nonce(endpoint, &response)?;
    check_status(&response)?;
    ValidHttpResponse::from_response(response).map_err(HttpError::from)
}

pub fn post<F>(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    url: &str,
    data_builder: &F,
    content_type: &str,
    accept: &str,
) -> Result<ValidHttpResponse, HttpError>
where
    F: Fn(&str, &str) -> Result<String, Error>,
{
    let mut session = get_session(root_certs)?;
    session.try_header(header::ACCEPT, accept)?;
    session.try_header(header::CONTENT_TYPE, content_type)?;
    if endpoint.nonce.is_none() {
        let _ = new_nonce(endpoint, root_certs);
    }
    for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
        let nonce = &endpoint.nonce.clone().unwrap_or_default();
        let body = data_builder(&nonce, url)?;
        rate_limit(endpoint);
        log::trace!("POST request body: {}", body);
        let response = session.post(url).text(&body).send()?;
        update_nonce(endpoint, &response)?;
        match check_status(&response) {
            Ok(_) => {
                return ValidHttpResponse::from_response(response).map_err(HttpError::from);
            }
            Err(_) => {
                let resp = ValidHttpResponse::from_response(response)?;
                let api_err = resp.json::<HttpApiError>()?;
                let acme_err = api_err.get_acme_type();
                if !acme_err.is_recoverable() {
                    return Err(api_err.into());
                }
            }
        }
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_HTTP_FAIL_WAIT_SEC));
    }
    Err("too much errors, will not retry".into())
}

pub fn post_jose<F>(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    url: &str,
    data_builder: &F,
) -> Result<ValidHttpResponse, HttpError>
where
    F: Fn(&str, &str) -> Result<String, Error>,
{
    post(
        endpoint,
        root_certs,
        url,
        data_builder,
        CONTENT_TYPE_JOSE,
        CONTENT_TYPE_JSON,
    )
}

#[cfg(test)]
mod tests {
    use super::is_nonce;

    #[test]
    fn test_nonce_valid() {
        let lst = [
            "XFHw3qcgFNZAdw",
            "XFHw3qcg-NZAdw",
            "XFHw3qcg_NZAdw",
            "XFHw3qcg-_ZAdw",
            "a",
            "1",
            "-",
            "_",
        ];
        for n in lst.iter() {
            assert!(is_nonce(n));
        }
    }

    #[test]
    fn test_nonce_invalid() {
        let lst = [
            "",
            "rdo9x8gS4K/mZg==",
            "rdo9x8gS4K/mZg",
            "rdo9x8gS4K+mZg",
            "৬",
            "京",
        ];
        for n in lst.iter() {
            assert!(!is_nonce(n));
        }
    }
}
