use crate::acme_proto::structs::{AcmeError, HttpApiError};
use crate::config::NamedAcmeResource;
use crate::endpoint::Endpoint;
#[cfg(feature = "crypto_openssl")]
use acme_common::error::Error;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header, Client, ClientBuilder, Response};
use std::fs::File;
#[cfg(feature = "crypto_openssl")]
use std::io::prelude::*;
use std::{thread, time};

pub const CONTENT_TYPE_JOSE: &str = "application/jose+json";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_PEM: &str = "application/pem-certificate-chain";
pub const HEADER_NONCE: &str = "Replay-Nonce";
pub const HEADER_LOCATION: &str = "Location";

pub struct ValidHttpResponse {
	headers: HeaderMap,
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

	async fn from_response(response: Response) -> Result<Self, Error> {
		let headers = response.headers().clone();
		let body = response.text().await?;
		log::trace!("HTTP response headers: {headers:?}");
		log::trace!("HTTP response body: {body}");
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

	pub fn is_acme_err(&self, acme_error: AcmeError) -> bool {
		match self {
			HttpError::ApiError(aerr) => aerr.get_acme_type() == acme_error,
			HttpError::GenericError(_) => false,
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

impl From<reqwest::Error> for HttpError {
	fn from(error: reqwest::Error) -> Self {
		HttpError::GenericError(error.into())
	}
}

fn is_nonce(data: &str) -> bool {
	!data.is_empty()
		&& data
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

async fn new_nonce(endpoint: &mut Endpoint) -> Result<(), HttpError> {
	let url = endpoint.dir.new_nonce.clone();
	let _ = get(endpoint, &url, Some(NamedAcmeResource::NewNonce)).await?;
	Ok(())
}

fn update_nonce(endpoint: &mut Endpoint, response: &Response) -> Result<(), Error> {
	if let Some(nonce) = response.headers().get(HEADER_NONCE) {
		let nonce = header_to_string(nonce)?;
		if !is_nonce(&nonce) {
			let msg = format!("{nonce}: invalid nonce.");
			return Err(msg.into());
		}
		endpoint.nonce = Some(nonce);
	}
	Ok(())
}

fn check_status(response: &Response) -> Result<(), Error> {
	if !response.status().is_success() {
		let status = response.status();
		let msg = format!("HTTP error: {}: {}", status.as_u16(), status.as_str());
		return Err(msg.into());
	}
	Ok(())
}

async fn rate_limit(endpoint: &mut Endpoint, resource: Option<NamedAcmeResource>, path: &str) {
	endpoint.rl.block_until_allowed(resource, path).await;
}

fn header_to_string(header_value: &HeaderValue) -> Result<String, Error> {
	let s = header_value
		.to_str()
		.map_err(|_| Error::from("invalid header format"))?;
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
	// TODO: allow to change the language
	let mut client_builder = ClientBuilder::new();
	let mut default_headers = HeaderMap::new();
	default_headers.append(header::ACCEPT_LANGUAGE, "en-US,en;q=0.5".parse().unwrap());
	default_headers.append(header::USER_AGENT, useragent.parse().unwrap());
	client_builder = client_builder.default_headers(default_headers);
	for crt_file in root_certs.iter() {
		#[cfg(feature = "crypto_openssl")]
		{
			let mut buff = Vec::new();
			File::open(crt_file)
				.map_err(|e| Error::from(e).prefix(crt_file))?
				.read_to_end(&mut buff)?;
			let crt = reqwest::Certificate::from_pem(&buff)?;
			client_builder = client_builder.add_root_certificate(crt);
		}
	}
	Ok(client_builder.build()?)
}

pub async fn get(
	endpoint: &mut Endpoint,
	url: &str,
	resource: Option<NamedAcmeResource>,
) -> Result<ValidHttpResponse, HttpError> {
	let client = get_client(&endpoint.root_certificates)?;
	rate_limit(endpoint, resource, url).await;
	let response = client
		.get(url)
		.header(header::ACCEPT, CONTENT_TYPE_JSON)
		.send()
		.await?;
	update_nonce(endpoint, &response)?;
	check_status(&response)?;
	ValidHttpResponse::from_response(response)
		.await
		.map_err(HttpError::from)
}

pub async fn post<F>(
	endpoint: &mut Endpoint,
	url: &str,
	resource: Option<NamedAcmeResource>,
	data_builder: &F,
	content_type: &str,
	accept: &str,
) -> Result<ValidHttpResponse, HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let client = get_client(&endpoint.root_certificates)?;
	if endpoint.nonce.is_none() {
		let _ = new_nonce(endpoint).await;
	}
	for _ in 0..crate::DEFAULT_HTTP_FAIL_NB_RETRY {
		let mut request = client.post(url);
		request = request.header(header::ACCEPT, accept);
		request = request.header(header::CONTENT_TYPE, content_type);
		let nonce = &endpoint.nonce.clone().unwrap_or_default();
		let body = data_builder(nonce, url)?;
		rate_limit(endpoint, resource, url).await;
		log::trace!("POST request body: {body}");
		let response = request.body(body).send().await?;
		update_nonce(endpoint, &response)?;
		match check_status(&response) {
			Ok(_) => {
				return ValidHttpResponse::from_response(response)
					.await
					.map_err(HttpError::from);
			}
			Err(_) => {
				let resp = ValidHttpResponse::from_response(response).await?;
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

pub async fn post_jose<F>(
	endpoint: &mut Endpoint,
	url: &str,
	resource: Option<NamedAcmeResource>,
	data_builder: &F,
) -> Result<ValidHttpResponse, HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	post(
		endpoint,
		url,
		resource,
		data_builder,
		CONTENT_TYPE_JOSE,
		CONTENT_TYPE_JSON,
	)
	.await
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
