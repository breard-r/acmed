use crate::config::AcmedConfig;
use anyhow::Result;
use reqwest::header::HeaderMap;
use reqwest::{header, Certificate, Client, ClientBuilder, Request, Response};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
struct RawRequest {
	request: Request,
	endpoint: String,
	tx: oneshot::Sender<Result<Response, reqwest::Error>>,
}

#[derive(Clone, Debug)]
pub struct HttpClient {
	tx: mpsc::UnboundedSender<RawRequest>,
}

impl HttpClient {
	#[tracing::instrument(skip(self), level = "trace", err(Debug))]
	pub async fn send<S: AsRef<str> + std::fmt::Debug>(
		&self,
		endpoint: S,
		request: Request,
	) -> Result<Response> {
		let (tx, rx) = oneshot::channel();
		let raw_req = RawRequest {
			request,
			endpoint: endpoint.as_ref().to_string(),
			tx,
		};
		self.tx.send(raw_req)?;
		Ok(rx.await??)
	}
}

#[derive(Debug)]
struct HttpEndpoint {
	client: Client,
}

#[derive(Debug)]
pub(super) struct HttpRoutine {
	tx: mpsc::UnboundedSender<RawRequest>,
	rx: mpsc::UnboundedReceiver<RawRequest>,
	endpoints: HashMap<String, HttpEndpoint>,
}

impl HttpRoutine {
	#[tracing::instrument(skip_all, level = "trace")]
	pub(super) fn new(config: &AcmedConfig) -> Self {
		let (tx, rx) = mpsc::unbounded_channel();
		let mut endpoints = HashMap::with_capacity(config.endpoint.len());
		for (name, edp) in &config.endpoint {
			tracing::debug!(name, "loading endpoint");
			let client = get_http_client(config.get_global_root_certs(), &edp.root_certificates);
			let endpoint = HttpEndpoint { client };
			endpoints.insert(name.to_owned(), endpoint);
		}
		Self { tx, rx, endpoints }
	}

	pub(super) fn get_client(&self) -> HttpClient {
		HttpClient {
			tx: self.tx.clone(),
		}
	}

	#[tracing::instrument(skip_all, level = "trace")]
	pub(super) async fn run(mut self) {
		tracing::trace!("starting the http routine");
		while let Some(raw_req) = self.rx.recv().await {
			tracing::debug!(request = ?raw_req.request, "new http request");
			match self.endpoints.get(&raw_req.endpoint) {
				Some(edp) => {
					let ret = edp.client.execute(raw_req.request).await;
					let _ = raw_req.tx.send(ret);
				}
				None => {
					tracing::error!(endpoint = raw_req.endpoint, "endpoint not found");
				}
			}
		}
		tracing::error!("the http routine has stopped");
	}
}

macro_rules! add_root_cert {
	($builder: ident, $iter: ident) => {
		for cert_path in $iter {
			match get_cert_pem(cert_path) {
				Ok(cert) => {
					$builder = $builder.add_root_certificate(cert);
					tracing::debug!(?cert_path, "root certificate loaded");
				}
				Err(e) => tracing::error!(?cert_path, "{e:#?}",),
			}
		}
	};
}

#[tracing::instrument(level = "trace")]
fn get_http_client(base_certs_opt: Option<&[PathBuf]>, end_certs: &[PathBuf]) -> Client {
	let useragent = format!(
		"{}/{} ({}) {}",
		env!("CARGO_BIN_NAME"),
		env!("CARGO_PKG_VERSION"),
		env!("ACMED_TARGET"),
		env!("ACMED_HTTP_LIB_AGENT")
	);
	let mut client_builder = ClientBuilder::new();
	let mut default_headers = HeaderMap::new();
	default_headers.append(header::ACCEPT_LANGUAGE, "en-US,en;q=0.5".parse().unwrap());
	default_headers.append(header::USER_AGENT, useragent.parse().unwrap());
	client_builder = client_builder.default_headers(default_headers);
	if let Some(base_certs) = base_certs_opt {
		add_root_cert!(client_builder, base_certs);
	}
	add_root_cert!(client_builder, end_certs);
	client_builder.build().unwrap()
}

fn get_cert_pem(cert_path: &Path) -> Result<Certificate> {
	let mut buff = Vec::new();
	File::open(cert_path)?.read_to_end(&mut buff)?;
	let crt = reqwest::Certificate::from_pem(&buff)?;
	Ok(crt)
}
