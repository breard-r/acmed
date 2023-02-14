use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::logs::HasLogger;
use crate::{AccountSync, EndpointSync};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct CertificateManager {
	cert: Certificate,
}

impl CertificateManager {
	pub fn new(cert: Certificate) -> Self {
		Self { cert }
	}

	pub fn get_id(&self) -> String {
		self.cert.get_id()
	}

	pub fn get_account_name(&self) -> String {
		self.cert.account_name.clone()
	}

	pub fn get_endpoint_name(&self) -> String {
		self.cert.endpoint_name.clone()
	}

	pub async fn renew(
		&mut self,
		account_s: AccountSync,
		endpoint_s: EndpointSync,
	) -> (&mut Self, AccountSync, EndpointSync) {
		loop {
			match self.cert.should_renew() {
				Ok(true) => break,
				Ok(false) => {}
				Err(e) => {
					self.cert.warn(&e.message);
				}
			}
			sleep(Duration::from_secs(crate::DEFAULT_SLEEP_TIME)).await;
		}
		let mut account = account_s.write().await;
		let mut endpoint = endpoint_s.write().await;
		let (status, is_success) =
			match request_certificate(&self.cert, &mut endpoint, &mut account) {
				Ok(_) => ("success".to_string(), true),
				Err(e) => {
					let e = e.prefix("unable to renew the certificate");
					self.cert.warn(&e.message);
					(e.message, false)
				}
			};
		match self.cert.call_post_operation_hooks(&status, is_success) {
			Ok(_) => {}
			Err(e) => {
				let e = e.prefix("post-operation hook error");
				self.cert.warn(&e.message);
			}
		};
		(self, account_s.clone(), endpoint_s.clone())
	}
}
