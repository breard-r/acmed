use crate::acme_proto::structs::Directory;
use crate::error::Error;
use http_req::request::{Method, Request};
use http_req::response::Response;
use http_req::uri::Uri;
use log::{debug, trace};
use std::str::FromStr;

const CONTENT_TYPE_JOSE: &str = "application/jose+json";
const CONTENT_TYPE_JSON: &str = "application/json";

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
    if !res.status_code().is_success() {
        debug!("Response: {}", res_str);
        let msg = format!("HTTP error: {}: {}", res.status_code(), res.reason());
        return Err(msg.into());
    }
    Ok((res, res_str))
}

fn check_response(_res: &Response) -> Result<(), Error> {
    // TODO: implement
    Ok(())
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
    trace!("post_jose: request body: {}", rstr);
    let (res, res_body) = send_request(&request)?;
    trace!("post_jose: response body: {}", res_body);
    check_response(&res)?;
    Ok((res, res_body))
}

fn post_jose(url: &str, data: &[u8]) -> Result<(Response, String), Error> {
    post_jose_type(url, data, CONTENT_TYPE_JSON)
}

pub fn get_directory(url: &str) -> Result<Directory, Error> {
    let uri = url.parse::<Uri>()?;
    let mut request = new_request(&uri, Method::GET);
    request.header("Accept", CONTENT_TYPE_JSON);
    let (r, s) = send_request(&request)?;
    check_response(&r)?;
    Directory::from_str(&s)
}

pub fn get_nonce(url: &str) -> Result<String, Error> {
    let uri = url.parse::<Uri>()?;
    let request = new_request(&uri, Method::HEAD);
    let (res, _) = send_request(&request)?;
    check_response(&res)?;
    nonce_from_response(&res)
}

pub fn get_obj<T>(url: &str, data: &[u8]) -> Result<(T, String), Error>
where
    T: std::str::FromStr<Err = Error>,
{
    let (res, res_body) = post_jose(url, data)?;
    let obj = T::from_str(&res_body)?;
    let nonce = nonce_from_response(&res)?;
    Ok((obj, nonce))
}

pub fn get_obj_loc<T>(url: &str, data: &[u8]) -> Result<(T, String, String), Error>
where
    T: std::str::FromStr<Err = Error>,
{
    let (res, res_body) = post_jose(url, data)?;
    let obj = T::from_str(&res_body)?;
    let location = get_header(&res, "Location")?;
    let nonce = nonce_from_response(&res)?;
    Ok((obj, location, nonce))
}

pub fn post_challenge_response(url: &str, data: &[u8]) -> Result<String, Error> {
    let (res, _) = post_jose(url, data)?;
    let nonce = nonce_from_response(&res)?;
    Ok(nonce)
}

pub fn get_certificate(url: &str, data: &[u8]) -> Result<(String, String), Error> {
    let (res, res_body) = post_jose_type(url, data, CONTENT_TYPE_JSON)?;
    let nonce = nonce_from_response(&res)?;
    Ok((res_body, nonce))
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
