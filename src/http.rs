use crate::config::AcmedConfig;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header, Client, ClientBuilder, Request, Response};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
struct RawRequest {
	request: Request,
	tx: oneshot::Sender<Result<Response, reqwest::Error>>,
}

#[derive(Clone, Debug)]
pub struct HttpClient {
	tx: mpsc::UnboundedSender<RawRequest>,
}

impl HttpClient {
	pub async fn send(&self, request: Request) -> Result<Response> {
		let (tx, rx) = oneshot::channel();
		let raw_req = RawRequest { request, tx };
		self.tx.send(raw_req)?;
		let ret = rx.await?;
		if let Err(ref e) = ret {
			tracing::error!("http error: {e:#?}");
		}
		Ok(ret?)
	}
}

#[derive(Debug)]
pub(super) struct HttpRoutine {
	tx: mpsc::UnboundedSender<RawRequest>,
	rx: mpsc::UnboundedReceiver<RawRequest>,
}

impl HttpRoutine {
	pub(super) fn new(config: &AcmedConfig) -> Self {
		let (tx, mut rx) = mpsc::unbounded_channel();
		Self { tx, rx }
	}

	pub(super) fn get_client(&self) -> HttpClient {
		HttpClient {
			tx: self.tx.clone(),
		}
	}

	pub(super) async fn run(mut self) {
		tracing::trace!("starting the http routine");
		let client = self.get_http_client();
		while let Some(raw_req) = self.rx.recv().await {
			tracing::debug!("new http request: {:?}", raw_req.request);
			let ret = client.execute(raw_req.request).await;
			let _ = raw_req.tx.send(ret);
		}
		tracing::warn!("the http routine has stopped");
	}

	fn get_http_client(&self) -> Client {
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
		client_builder.build().unwrap()
	}
}
