use crate::acme_proto::structs::{AcmeError, ApiError, Directory, HttpApiError};
use crate::certificate::Certificate;
use crate::rate_limits;
use acme_common::error::Error;
use http_req::request::{self, Method};
use http_req::response::Response;
use http_req::uri::Uri;
use std::path::Path;
use std::str::FromStr;
use std::{thread, time};

const CONTENT_TYPE_JOSE: &str = "application/jose+json";
const CONTENT_TYPE_JSON: &str = "application/json";

struct Request<'a> {
    r: request::Request<'a>,
    uri: &'a Uri,
    method: Method,
}

struct DummyString {
    pub content: String,
}

impl FromStr for DummyString {
    type Err = Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        Ok(DummyString {
            content: data.to_string(),
        })
    }
}

fn new_request<'a>(root_certs: &'a [String], uri: &'a Uri, method: Method) -> Request<'a> {
    let useragent = format!(
        "{}/{} ({}) {}",
        crate::APP_NAME,
        crate::APP_VERSION,
        env!("ACMED_TARGET"),
        env!("ACMED_HTTP_LIB_AGENT")
    );
    let mut rb = request::Request::new(uri);
    for file_name in root_certs.iter() {
        rb.root_cert_file_pem(&Path::new(file_name));
    }
    rb.method(method.to_owned());
    rb.header("User-Agent", &useragent);
    // TODO: allow to configure the language
    rb.header("Accept-Language", "en-US,en;q=0.5");
    Request { r: rb, method, uri }
}

fn send_request(cert: &Certificate, request: &Request) -> Result<(Response, String), Error> {
    let mut buffer = Vec::new();
    cert.https_throttle
        .send(rate_limits::Request::HttpsRequest)
        .unwrap();
    cert.debug(&format!("{}: {}", request.method, request.uri));
    let res = request.r.send(&mut buffer)?;
    let res_str = String::from_utf8(buffer)?;
    Ok((res, res_str))
}

fn send_request_retry(cert: &Certificate, request: &Request) -> Result<(Response, String), Error> {
    for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
        let (res, res_body) = send_request(cert, request)?;
        match check_response(&res, &res_body) {
            Ok(()) => {
                return Ok((res, res_body));
            }
            Err(e) => {
                if !e.is_recoverable() {
                    let msg = format!("HTTP error: {}: {}", res.status_code(), res.reason());
                    return Err(msg.into());
                }
                cert.warn(&format!("{}", e));
            }
        };
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_HTTP_FAIL_WAIT_SEC));
    }
    Err("Too much errors, will not retry".into())
}

fn get_header(res: &Response, name: &str) -> Result<String, Error> {
    match res.headers().get(name) {
        Some(v) => Ok(v.to_string()),
        None => Err(format!("{}: header not found.", name).into()),
    }
}

fn is_nonce(data: &str) -> bool {
    !data.is_empty()
        && data
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn nonce_from_response(cert: &Certificate, res: &Response) -> Result<String, Error> {
    let nonce = get_header(res, "Replay-Nonce")?;
    if is_nonce(&nonce) {
        cert.trace(&format!("New nonce: {}", nonce));
        Ok(nonce)
    } else {
        let msg = format!("{}: invalid nonce.", nonce);
        Err(msg.into())
    }
}

fn post_jose_type(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data: &[u8],
    accept_type: &str,
) -> Result<(Response, String), Error> {
    let uri = url.parse::<Uri>()?;
    let mut request = new_request(root_certs, &uri, Method::POST);
    request.r.header("Content-Type", CONTENT_TYPE_JOSE);
    request.r.header("Content-Length", &data.len().to_string());
    request.r.header("Accept", accept_type);
    request.r.body(data);
    let rstr = String::from_utf8_lossy(data);
    cert.trace(&format!("request body: {}", rstr));
    let (res, res_body) = send_request(cert, &request)?;
    let lpos = res_body.find('{').unwrap_or(0);
    let res_body = if lpos == 0 {
        res_body
    } else {
        res_body.chars().skip(lpos).collect::<String>()
    };
    let rpos = res_body.rfind('}').unwrap_or(0);
    let res_body = if rpos == 0 {
        res_body
    } else {
        res_body.chars().take(rpos + 1).collect::<String>()
    };
    cert.trace(&format!("response body: {}", res_body));
    Ok((res, res_body))
}

fn check_response(res: &Response, body: &str) -> Result<(), AcmeError> {
    if res.status_code().is_success() {
        Ok(())
    } else {
        Err(HttpApiError::from_str(body)?.get_acme_type())
    }
}

fn fetch_obj_type<T, G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
    accept_type: &str,
) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    let mut nonce = nonce.to_string();
    for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
        let data = data_builder(&nonce)?;
        let (res, res_body) = post_jose_type(cert, root_certs, url, data.as_bytes(), accept_type)?;
        nonce = nonce_from_response(cert, &res)?;

        match check_response(&res, &res_body) {
            Ok(()) => {
                let obj = T::from_str(&res_body)?;
                let location = get_header(&res, "Location").unwrap_or_else(|_| String::new());
                return Ok((obj, location, nonce));
            }
            Err(e) => {
                if !e.is_recoverable() {
                    let msg = format!("HTTP error: {}: {}", res.status_code(), res.reason());
                    return Err(msg.into());
                }
                cert.warn(&format!("{}", e));
            }
        };
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_HTTP_FAIL_WAIT_SEC));
    }
    Err("Too much errors, will not retry".into())
}

fn fetch_obj<T, G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    fetch_obj_type(
        cert,
        root_certs,
        url,
        data_builder,
        nonce,
        CONTENT_TYPE_JSON,
    )
}

pub fn get_obj_loc<T, G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    let (obj, location, nonce) = fetch_obj(cert, root_certs, url, data_builder, nonce)?;
    if location.is_empty() {
        Err("Location header not found.".into())
    } else {
        Ok((obj, location, nonce))
    }
}

pub fn get_obj<T, G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(T, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    let (obj, _, nonce) = fetch_obj(cert, root_certs, url, data_builder, nonce)?;
    Ok((obj, nonce))
}

pub fn pool_obj<T, G, S>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    break_fn: &S,
    nonce: &str,
) -> Result<(T, String), Error>
where
    T: std::str::FromStr<Err = Error> + ApiError,
    G: Fn(&str) -> Result<String, Error>,
    S: Fn(&T) -> bool,
{
    let mut nonce: String = nonce.to_string();
    for _ in 0..crate::DEFAULT_POOL_NB_TRIES {
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_POOL_WAIT_SEC));
        let (obj, _, new_nonce) = fetch_obj(cert, root_certs, url, data_builder, &nonce)?;
        if break_fn(&obj) {
            return Ok((obj, new_nonce));
        }
        if let Some(e) = obj.get_error() {
            cert.warn(&e.prefix("Error").message);
        }
        nonce = new_nonce;
    }
    let msg = format!("Pooling failed for {}", url);
    Err(msg.into())
}

pub fn post_challenge_response<G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<String, Error>
where
    G: Fn(&str) -> Result<String, Error>,
{
    let (_, _, nonce): (DummyString, String, String) =
        fetch_obj(cert, root_certs, url, data_builder, nonce)?;
    Ok(nonce)
}

pub fn get_certificate<G>(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(String, String), Error>
where
    G: Fn(&str) -> Result<String, Error>,
{
    let (res_body, _, nonce): (DummyString, String, String) =
        fetch_obj(cert, root_certs, url, data_builder, nonce)?;
    Ok((res_body.content, nonce))
}

pub fn get_directory(
    cert: &Certificate,
    root_certs: &[String],
    url: &str,
) -> Result<Directory, Error> {
    let uri = url.parse::<Uri>()?;
    let mut request = new_request(root_certs, &uri, Method::GET);
    request.r.header("Accept", CONTENT_TYPE_JSON);
    let (r, s) = send_request_retry(cert, &request)?;
    check_response(&r, &s)?;
    Directory::from_str(&s)
}

pub fn get_nonce(cert: &Certificate, root_certs: &[String], url: &str) -> Result<String, Error> {
    let uri = url.parse::<Uri>()?;
    let request = new_request(root_certs, &uri, Method::HEAD);
    let (res, res_body) = send_request_retry(cert, &request)?;
    check_response(&res, &res_body)?;
    nonce_from_response(cert, &res)
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
