use crate::acme_proto::structs::Directory;
use crate::error::{AcmeError, Error, HttpApiError};
use http_req::request::{Method, Request};
use http_req::response::Response;
use http_req::uri::Uri;
use log::{debug, trace, warn};
use std::str::FromStr;
use std::{thread, time};

const CONTENT_TYPE_JOSE: &str = "application/jose+json";
const CONTENT_TYPE_JSON: &str = "application/json";

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

fn new_request(uri: &Uri, method: Method) -> Request {
    debug!("{}: {}", method, uri);
    let useragent = format!(
        "{}/{} ({}) {}",
        crate::APP_NAME,
        crate::APP_VERSION,
        env!("ACMED_TARGET"),
        env!("ACMED_HTTP_LIB_AGENT")
    );
    let mut rb = Request::new(uri);
    rb.method(method);
    rb.header("User-Agent", &useragent);
    // TODO: allow to configure the language
    rb.header("Accept-Language", "en-US,en;q=0.5");
    rb
}

fn send_request(request: &Request) -> Result<(Response, String), Error> {
    let mut buffer = Vec::new();
    let res = request.send(&mut buffer)?;
    let res_str = String::from_utf8(buffer)?;
    Ok((res, res_str))
}

fn send_request_retry(request: &Request) -> Result<(Response, String), Error> {
    for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
        let (res, res_body) = send_request(request)?;
        match check_response(&res, &res_body) {
            Ok(()) => {
                return Ok((res, res_body));
            }
            Err(e) => {
                if !e.is_recoverable() {
                    let msg = format!("HTTP error: {}: {}", res.status_code(), res.reason());
                    return Err(msg.into());
                }
                warn!("{}", e);
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

fn nonce_from_response(res: &Response) -> Result<String, Error> {
    let nonce = get_header(res, "Replay-Nonce")?;
    if is_nonce(&nonce) {
        trace!("New nonce: {}", nonce);
        Ok(nonce.to_string())
    } else {
        let msg = format!("{}: invalid nonce.", nonce);
        Err(msg.into())
    }
}

fn post_jose_type(url: &str, data: &[u8], accept_type: &str) -> Result<(Response, String), Error> {
    let uri = url.parse::<Uri>()?;
    let mut request = new_request(&uri, Method::POST);
    request.header("Content-Type", CONTENT_TYPE_JOSE);
    request.header("Content-Length", &data.len().to_string());
    request.header("Accept", accept_type);
    request.body(data);
    let rstr = String::from_utf8_lossy(data);
    trace!("request body: {}", rstr);
    let (res, res_body) = send_request(&request)?;
    trace!("response body: {}", res_body);
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
        let (res, res_body) = post_jose_type(url, data.as_bytes(), accept_type)?;
        nonce = nonce_from_response(&res)?;

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
                warn!("{}", e);
            }
        };
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_HTTP_FAIL_WAIT_SEC));
    }
    Err("Too much errors, will not retry".into())
}

fn fetch_obj<T, G>(url: &str, data_builder: &G, nonce: &str) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    fetch_obj_type(url, data_builder, nonce, CONTENT_TYPE_JSON)
}

pub fn get_obj_loc<T, G>(
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    let (obj, location, nonce) = fetch_obj(url, data_builder, nonce)?;
    if location.is_empty() {
        Err("Location header not found.".into())
    } else {
        Ok((obj, location, nonce))
    }
}

pub fn get_obj<T, G>(url: &str, data_builder: &G, nonce: &str) -> Result<(T, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
{
    let (obj, _, nonce) = fetch_obj(url, data_builder, nonce)?;
    Ok((obj, nonce))
}

pub fn pool_obj<T, G, S>(
    url: &str,
    data_builder: &G,
    break_fn: &S,
    nonce: &str,
) -> Result<(T, String), Error>
where
    T: std::str::FromStr<Err = Error>,
    G: Fn(&str) -> Result<String, Error>,
    S: Fn(&T) -> bool,
{
    let mut nonce: String = nonce.to_string();
    for _ in 0..crate::DEFAULT_POOL_NB_TRIES {
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_POOL_WAIT_SEC));
        let (obj, _, new_nonce) = fetch_obj(url, data_builder, &nonce)?;
        if break_fn(&obj) {
            return Ok((obj, new_nonce));
        }
        nonce = new_nonce;
    }
    let msg = format!("Pooling failed for {}", url);
    Err(msg.into())
}

pub fn post_challenge_response<G>(url: &str, data_builder: &G, nonce: &str) -> Result<String, Error>
where
    G: Fn(&str) -> Result<String, Error>,
{
    let (_, _, nonce): (DummyString, String, String) = fetch_obj(url, data_builder, nonce)?;
    Ok(nonce)
}

pub fn get_certificate<G>(
    url: &str,
    data_builder: &G,
    nonce: &str,
) -> Result<(String, String), Error>
where
    G: Fn(&str) -> Result<String, Error>,
{
    let (res_body, _, nonce): (DummyString, String, String) = fetch_obj(url, data_builder, nonce)?;
    Ok((res_body.content, nonce))
}

pub fn get_directory(url: &str) -> Result<Directory, Error> {
    let uri = url.parse::<Uri>()?;
    let mut request = new_request(&uri, Method::GET);
    request.header("Accept", CONTENT_TYPE_JSON);
    let (r, s) = send_request_retry(&request)?;
    check_response(&r, &s)?;
    Directory::from_str(&s)
}

pub fn get_nonce(url: &str) -> Result<String, Error> {
    let uri = url.parse::<Uri>()?;
    let request = new_request(&uri, Method::HEAD);
    let (res, res_body) = send_request_retry(&request)?;
    check_response(&res, &res_body)?;
    nonce_from_response(&res)
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
