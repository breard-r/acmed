use crate::acme_proto::structs::HttpApiError;
use crate::endpoint::Endpoint;
use acme_common::error::Error;
use reqwest::blocking::{Client, Response};
use reqwest::header::{self, HeaderMap, HeaderValue};
use std::fs::File;
use std::io::prelude::*;
use std::{thread, time};

pub const CONTENT_TYPE_JOSE: &str = "application/jose+json";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_PEM: &str = "application/pem-certificate-chain";
pub const HEADER_NONCE: &str = "Replay-Nonce";
pub const HEADER_LOCATION: &str = "Location";

fn is_nonce(data: &str) -> bool {
    !data.is_empty()
        && data
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn new_nonce(endpoint: &mut Endpoint, root_certs: &[String]) -> Result<(), Error> {
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
    let status = response.status();
    if !status.is_success() {
        let msg = status
            .canonical_reason()
            .unwrap_or("<no description provided>");
        let msg = format!("HTTP error: {}: {}", status.as_u16(), msg);
        return Err(msg.into());
    }
    Ok(())
}

fn rate_limit(endpoint: &mut Endpoint) {
    endpoint.rl.block_until_allowed();
}

pub fn header_to_string(header_value: &HeaderValue) -> Result<String, Error> {
    let s = header_value
        .to_str()
        .map_err(|_| Error::from("Invalid nonce format."))?;
    Ok(s.to_string())
}

fn get_client(root_certs: &[String]) -> Result<Client, Error> {
    let useragent = format!(
        "{}/{} ({}) {}",
        crate::APP_NAME,
        crate::APP_VERSION,
        env!("ACMED_TARGET"),
        env!("ACMED_HTTP_LIB_AGENT")
    );
    let mut headers = HeaderMap::with_capacity(2);
    // TODO: allow to change the language
    headers.insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.5"),
    );
    headers.insert(header::USER_AGENT, HeaderValue::from_str(&useragent)?);
    let mut client_builder = Client::builder().default_headers(headers).referer(false);
    for crt_file in root_certs.iter() {
        let mut buff = Vec::new();
        File::open(crt_file)?.read_to_end(&mut buff)?;
        let crt = reqwest::Certificate::from_pem(&buff)?;
        client_builder = client_builder.add_root_certificate(crt);
    }
    let client = client_builder.build()?;
    Ok(client)
}

pub fn get(endpoint: &mut Endpoint, root_certs: &[String], url: &str) -> Result<Response, Error> {
    let client = get_client(root_certs)?;
    rate_limit(endpoint);
    let response = client
        .get(url)
        .header(header::ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON))
        .send()?;
    update_nonce(endpoint, &response)?;
    check_status(&response)?;
    Ok(response)
}

pub fn post<F>(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    url: &str,
    data_builder: &F,
    content_type: &str,
    accept: &str,
) -> Result<Response, Error>
where
    F: Fn(&str, &str) -> Result<String, Error>,
{
    let client = get_client(root_certs)?;
    if endpoint.nonce.is_none() {
        let _ = new_nonce(endpoint, root_certs);
    }
    for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
        let nonce = &endpoint.nonce.clone().unwrap();
        let body = data_builder(&nonce, url)?.into_bytes();
        rate_limit(endpoint);
        let response = client
            .post(url)
            .body(body)
            .header(header::ACCEPT, HeaderValue::from_str(accept)?)
            .header(header::CONTENT_TYPE, HeaderValue::from_str(content_type)?)
            .send()?;
        update_nonce(endpoint, &response)?;
        match check_status(&response) {
            Ok(_) => {
                return Ok(response);
            }
            Err(e) => {
                let api_err = response.json::<HttpApiError>()?;
                let acme_err = api_err.get_acme_type();
                if !acme_err.is_recoverable() {
                    return Err(e);
                }
            }
        }
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_HTTP_FAIL_WAIT_SEC));
    }
    Err("Too much errors, will not retry".into())
}

pub fn post_jose<F>(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    url: &str,
    data_builder: &F,
) -> Result<Response, Error>
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
