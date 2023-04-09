use crate::acme_proto::structs::{
	AcmeError, ApiError, Authorization, AuthorizationStatus, NewOrder, Order, OrderStatus,
};
use crate::certificate::Certificate;
use crate::http::HttpError;
use crate::identifier::IdentifierType;
use crate::jws::encode_kid;
use crate::logs::HasLogger;
use crate::storage;
use crate::{AccountSync, EndpointSync};
use acme_common::crypto::Csr;
use acme_common::error::Error;
use serde_json::json;
use std::fmt;

pub mod account;
mod certificate;
mod http;
pub mod structs;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Challenge {
	Http01,
	Dns01,
	TlsAlpn01,
}

impl Challenge {
	pub fn from_str(s: &str) -> Result<Self, Error> {
		match s.to_lowercase().as_str() {
			"http-01" => Ok(Challenge::Http01),
			"dns-01" => Ok(Challenge::Dns01),
			"tls-alpn-01" => Ok(Challenge::TlsAlpn01),
			_ => Err(format!("{s}: unknown challenge.").into()),
		}
	}
}

impl fmt::Display for Challenge {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let s = match self {
			Challenge::Http01 => "http-01",
			Challenge::Dns01 => "dns-01",
			Challenge::TlsAlpn01 => "tls-alpn-01",
		};
		write!(f, "{s}")
	}
}

impl PartialEq<structs::Challenge> for Challenge {
	fn eq(&self, other: &structs::Challenge) -> bool {
		matches!(
			(self, other),
			(Challenge::Http01, structs::Challenge::Http01(_))
				| (Challenge::Dns01, structs::Challenge::Dns01(_))
				| (Challenge::TlsAlpn01, structs::Challenge::TlsAlpn01(_))
		)
	}
}

#[macro_export]
macro_rules! set_data_builder_sync {
	($account: ident, $endpoint_name: ident, $data: expr) => {{
		let endpoint_name = &$endpoint_name;
		move |n: &str, url: &str| {
			encode_kid(
				&$account.current_key.key,
				&$account.current_key.signature_algorithm,
				&($account.get_endpoint(endpoint_name)?.account_url),
				$data,
				url,
				n,
			)
		}
	}};
}

#[macro_export]
macro_rules! set_data_builder {
	($account: ident, $endpoint_name: ident, $data: expr) => {
		async {
			let account = $account.read().await;
			set_data_builder_sync!(account, $endpoint_name, $data)
		}
	};
}

pub async fn request_certificate(
	cert: &Certificate,
	account_s: AccountSync,
	endpoint_s: EndpointSync,
) -> Result<(), Error> {
	let mut hook_datas = vec![];
	let endpoint_name = endpoint_s.read().await.name.clone();

	// Refresh the directory
	http::refresh_directory(&mut *(endpoint_s.write().await))
		.await
		.map_err(HttpError::in_err)?;

	// Synchronize the account
	account_s
		.write()
		.await
		.synchronize(&mut *(endpoint_s.write().await))
		.await?;

	// Create a new order
	let mut new_reg = false;
	let (order, order_url) = loop {
		let new_order = NewOrder::new(&cert.identifiers);
		let new_order = serde_json::to_string(&new_order)?;
		let data_builder = set_data_builder!(account_s, endpoint_name, new_order.as_bytes()).await;
		match http::new_order(&mut *(endpoint_s.write().await), &data_builder).await {
			Ok((order, order_url)) => {
				if let Some(e) = order.get_error() {
					cert.warn(&e.prefix("Error").message);
				}
				break (order, order_url);
			}
			Err(e) => {
				if !new_reg && e.is_acme_err(AcmeError::AccountDoesNotExist) {
					drop(data_builder);
					account_s
						.write()
						.await
						.register(&mut *(endpoint_s.write().await))
						.await?;
					new_reg = true;
				} else {
					return Err(HttpError::in_err(e));
				}
			}
		};
	};

	// Begin iter over authorizations
	for auth_url in order.authorizations.iter() {
		// Fetch the authorization
		let data_builder = set_data_builder!(account_s, endpoint_name, b"").await;
		let auth =
			http::get_authorization(&mut *(endpoint_s.write().await), &data_builder, auth_url)
				.await
				.map_err(HttpError::in_err)?;
		drop(data_builder);
		if let Some(e) = auth.get_error() {
			cert.warn(&e.prefix("error").message);
		}
		if auth.status == AuthorizationStatus::Valid {
			continue;
		}
		if auth.status != AuthorizationStatus::Pending {
			let msg = format!(
				"{}: authorization status is {}",
				auth.identifier, auth.status
			);
			return Err(msg.into());
		}

		// Fetch the associated challenges
		let current_identifier = cert.get_identifier_from_str(&auth.identifier.value)?;
		let current_challenge = current_identifier.challenge;
		for challenge in auth.challenges.iter() {
			if current_challenge == *challenge {
				let proof = challenge.get_proof(&account_s.read().await.current_key.key)?;
				let file_name = challenge.get_file_name();
				let identifier = auth.identifier.value.to_owned();

				// Call the challenge hook in order to complete it
				let mut data = cert
					.call_challenge_hooks(&file_name, &proof, &identifier)
					.await?;
				data.0.is_clean_hook = true;
				hook_datas.push(data);

				// Tell the server the challenge has been completed
				let chall_url = challenge.get_url();
				let data_builder = set_data_builder!(account_s, endpoint_name, b"{}").await;
				http::post_jose_no_response(
					&mut *(endpoint_s.write().await),
					&data_builder,
					&chall_url,
					None,
				)
				.await
				.map_err(HttpError::in_err)?;
				drop(data_builder);
			}
		}

		// Pool the authorization in order to see whether or not it is valid
		let data_builder = set_data_builder!(account_s, endpoint_name, b"").await;
		let break_fn = |a: &Authorization| a.status == AuthorizationStatus::Valid;
		let _ = http::pool_authorization(
			&mut *(endpoint_s.write().await),
			&data_builder,
			&break_fn,
			auth_url,
		)
		.await
		.map_err(HttpError::in_err)?;
		drop(data_builder);
		for (data, hook_type) in hook_datas.iter() {
			cert.call_challenge_hooks_clean(data, (*hook_type).to_owned())
				.await?;
		}
		hook_datas.clear();
	}
	// End iter over authorizations

	// Pool the order in order to see whether or not it is ready
	let data_builder = set_data_builder!(account_s, endpoint_name, b"").await;
	let break_fn = |o: &Order| o.status == OrderStatus::Ready;
	let order = http::pool_order(
		&mut *(endpoint_s.write().await),
		&data_builder,
		&break_fn,
		&order_url,
	)
	.await
	.map_err(HttpError::in_err)?;
	drop(data_builder);

	// Finalize the order by sending the CSR
	let key_pair = certificate::get_key_pair(cert).await?;
	let domains: Vec<String> = cert
		.identifiers
		.iter()
		.filter(|e| e.id_type == IdentifierType::Dns)
		.map(|e| e.value.to_owned())
		.collect();
	let ips: Vec<String> = cert
		.identifiers
		.iter()
		.filter(|e| e.id_type == IdentifierType::Ip)
		.map(|e| e.value.to_owned())
		.collect();
	let csr = Csr::new(
		&key_pair,
		cert.csr_digest,
		domains.as_slice(),
		ips.as_slice(),
		&cert.subject_attributes,
	)?;
	cert.trace(&format!("new CSR:\n{}", csr.to_pem()?));
	let csr = json!({
		"csr": csr.to_der_base64()?,
	});
	let csr = csr.to_string();
	let data_builder = set_data_builder!(account_s, endpoint_name, csr.as_bytes()).await;
	let order = http::finalize_order(
		&mut *(endpoint_s.write().await),
		&data_builder,
		&order.finalize,
	)
	.await
	.map_err(HttpError::in_err)?;
	drop(data_builder);
	if let Some(e) = order.get_error() {
		cert.warn(&e.prefix("error").message);
	}

	// Pool the order in order to see whether or not it is valid
	let data_builder = set_data_builder!(account_s, endpoint_name, b"").await;
	let break_fn = |o: &Order| o.status == OrderStatus::Valid;
	let order = http::pool_order(
		&mut *(endpoint_s.write().await),
		&data_builder,
		&break_fn,
		&order_url,
	)
	.await
	.map_err(HttpError::in_err)?;
	drop(data_builder);

	// Download the certificate
	let crt_url = order
		.certificate
		.ok_or_else(|| Error::from("no certificate available for download"))?;
	let data_builder = set_data_builder!(account_s, endpoint_name, b"").await;
	let crt = http::get_certificate(&mut *(endpoint_s.write().await), &data_builder, &crt_url)
		.await
		.map_err(HttpError::in_err)?;
	drop(data_builder);
	storage::write_certificate(&cert.file_manager, crt.as_bytes()).await?;

	cert.info(&format!(
		"certificate renewed (identifiers: {})",
		cert.identifier_list()
	));
	Ok(())
}
