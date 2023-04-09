use crate::account::Account;
use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::config;
use crate::endpoint::Endpoint;
use crate::hooks::HookType;
use crate::logs::HasLogger;
use crate::storage::FileManager;
use crate::{AccountSync, EndpointSync};
use acme_common::error::Error;
use async_lock::RwLock;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub struct MainEventLoop {
	certificates: HashMap<String, Certificate>,
	accounts: HashMap<String, AccountSync>,
	endpoints: HashMap<String, EndpointSync>,
}

impl MainEventLoop {
	pub async fn new(config_file: &str, root_certs: &[&str]) -> Result<Self, Error> {
		let cnf = config::from_file(config_file)?;
		let file_hooks = vec![
			HookType::FilePreCreate,
			HookType::FilePostCreate,
			HookType::FilePreEdit,
			HookType::FilePostEdit,
		]
		.into_iter()
		.collect();
		let cert_hooks = vec![
			HookType::ChallengeHttp01,
			HookType::ChallengeHttp01Clean,
			HookType::ChallengeDns01,
			HookType::ChallengeDns01Clean,
			HookType::ChallengeTlsAlpn01,
			HookType::ChallengeTlsAlpn01Clean,
			HookType::PostOperation,
		]
		.into_iter()
		.collect();

		let mut accounts: HashMap<String, Account> = HashMap::new();
		for acc in &cnf.account {
			let fm = FileManager {
				account_directory: cnf.get_account_dir(),
				account_name: acc.name.clone(),
				crt_name: String::new(),
				crt_name_format: String::new(),
				crt_directory: String::new(),
				crt_key_type: String::new(),
				cert_file_mode: cnf.get_cert_file_mode(),
				cert_file_owner: cnf.get_cert_file_user(),
				cert_file_group: cnf.get_cert_file_group(),
				pk_file_mode: cnf.get_pk_file_mode(),
				pk_file_owner: cnf.get_pk_file_user(),
				pk_file_group: cnf.get_pk_file_group(),
				hooks: acc
					.get_hooks(&cnf)?
					.iter()
					.filter(|h| !h.hook_type.is_disjoint(&file_hooks))
					.map(|e| e.to_owned())
					.collect(),
				env: acc.env.clone(),
			};
			let account = acc.to_generic(&fm).await?;
			let name = acc.name.clone();
			accounts.insert(name, account);
		}

		let mut endpoints: HashMap<String, Endpoint> = HashMap::new();
		let mut certificates: HashMap<String, Certificate> = HashMap::new();
		for crt in cnf.certificate.iter() {
			let endpoint = crt.get_endpoint(&cnf, root_certs)?;
			let endpoint_name = endpoint.name.clone();
			let crt_name = crt.get_crt_name()?;
			let key_type = crt.get_key_type()?;
			let hooks = crt.get_hooks(&cnf)?;
			let fm = FileManager {
				account_directory: cnf.get_account_dir(),
				account_name: crt.account.clone(),
				crt_name: crt_name.clone(),
				crt_name_format: crt.get_crt_name_format(&cnf)?,
				crt_directory: crt.get_crt_dir(&cnf),
				crt_key_type: key_type.to_string(),
				cert_file_mode: cnf.get_cert_file_mode(),
				cert_file_owner: cnf.get_cert_file_user(),
				cert_file_group: cnf.get_cert_file_group(),
				pk_file_mode: cnf.get_pk_file_mode(),
				pk_file_owner: cnf.get_pk_file_user(),
				pk_file_group: cnf.get_pk_file_group(),
				hooks: hooks
					.iter()
					.filter(|h| !h.hook_type.is_disjoint(&file_hooks))
					.map(|e| e.to_owned())
					.collect(),
				env: crt.env.clone(),
			};
			let cert = Certificate {
				account_name: crt.account.clone(),
				identifiers: crt.get_identifiers()?,
				subject_attributes: crt.subject_attributes.to_generic(),
				key_type,
				csr_digest: crt.get_csr_digest()?,
				kp_reuse: crt.get_kp_reuse(),
				endpoint_name: endpoint_name.clone(),
				hooks: hooks
					.iter()
					.filter(|h| !h.hook_type.is_disjoint(&cert_hooks))
					.map(|e| e.to_owned())
					.collect(),
				crt_name,
				env: crt.env.to_owned(),
				random_early_renew: crt.get_random_early_renew(&cnf)?,
				renew_delay: crt.get_renew_delay(&cnf)?,
				file_manager: fm,
			};
			let crt_id = cert.get_id();
			if certificates.contains_key(&crt_id) {
				let msg = format!("{crt_id}: duplicate certificate id");
				return Err(msg.into());
			}
			match accounts.get_mut(&crt.account) {
				Some(acc) => acc.add_endpoint_name(&endpoint_name),
				None => {
					let msg = format!("{}: account not found", &crt.account);
					return Err(msg.into());
				}
			};
			if !endpoints.contains_key(&endpoint.name) {
				endpoints.insert(endpoint.name.clone(), endpoint);
			}
			certificates.insert(crt_id, cert);
		}

		Ok(MainEventLoop {
			certificates,
			accounts: accounts
				.into_iter()
				.map(|(k, v)| (k, Arc::new(RwLock::new(v))))
				.collect(),
			endpoints: endpoints
				.into_iter()
				.map(|(k, v)| (k, Arc::new(RwLock::new(v))))
				.collect(),
		})
	}

	pub async fn run(&mut self) {
		let mut renewals = FuturesUnordered::new();
		for (_, crt) in self.certificates.iter_mut() {
			log::trace!("Adding certificate: {}", crt.get_id());
			if let Some(acc) = self.accounts.get(&crt.account_name) {
				if let Some(ept) = self.endpoints.get(&crt.endpoint_name) {
					renewals.push(renew_certificate(crt, acc.clone(), ept.clone()));
				} else {
				}
			} else {
			}
		}
		loop {
			if renewals.is_empty() {
				log::error!("No certificate found.");
				return;
			}
			if let Some((crt, acc, ept)) = renewals.next().await {
				renewals.push(renew_certificate(crt, acc, ept));
			}
		}
	}
}

async fn renew_certificate(
	certificate: &mut Certificate,
	account_s: AccountSync,
	endpoint_s: EndpointSync,
) -> (&mut Certificate, AccountSync, EndpointSync) {
	let backoff = [60, 10 * 60, 100 * 60, 24 * 60 * 60];
	let mut scheduling_retries = 0;
	loop {
		match certificate.schedule_renewal().await {
			Ok(duration) => {
				sleep(duration).await;
				break;
			}
			Err(e) => {
				certificate.warn(&e.message);
				sleep(Duration::from_secs(
					backoff[scheduling_retries.min(backoff.len() - 1)],
				))
				.await;
				scheduling_retries += 1;
			}
		}
	}
	let (status, is_success) =
		match request_certificate(certificate, account_s.clone(), endpoint_s.clone()).await {
			Ok(_) => ("success".to_string(), true),
			Err(e) => {
				let e = e.prefix("unable to renew the certificate");
				certificate.warn(&e.message);
				(e.message, false)
			}
		};
	match certificate
		.call_post_operation_hooks(&status, is_success)
		.await
	{
		Ok(_) => {}
		Err(e) => {
			let e = e.prefix("post-operation hook error");
			certificate.warn(&e.message);
		}
	};
	(certificate, account_s.clone(), endpoint_s.clone())
}
