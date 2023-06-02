use crate::account::Account as BaseAccount;
use crate::acme_proto::http;
use crate::acme_proto::structs::{Account, AccountKeyRollover, AccountUpdate, AcmeError};
use crate::endpoint::Endpoint;
use crate::http::HttpError;
use crate::jws::{encode_jwk, encode_kid};
use crate::logs::HasLogger;
use crate::set_data_builder_sync;
use acme_common::error::Error;

macro_rules! create_account_if_does_not_exist {
	($e: expr, $endpoint: ident, $account: ident) => {
		match $e {
			Ok(r) => Ok(r),
			Err(he) => match he {
				HttpError::ApiError(ref e) => match e.get_acme_type() {
					AcmeError::AccountDoesNotExist => {
						let msg = format!(
							"account has been dropped by endpoint \"{}\"",
							$endpoint.name
						);
						$account.debug(&msg);
						return register_account($endpoint, $account).await;
					}
					_ => Err(HttpError::in_err(he.to_owned())),
				},
				HttpError::GenericError(e) => Err(e),
			},
		}
	};
}

pub async fn register_account(
	endpoint: &mut Endpoint,
	account: &mut BaseAccount,
) -> Result<(), Error> {
	account.debug(&format!(
		"creating account on endpoint \"{}\"...",
		&endpoint.name
	));
	let account_struct = Account::new(account, endpoint)?;
	let account_struct = serde_json::to_string(&account_struct)?;
	let acc_ref = &account_struct;
	let kp_ref = &account.current_key.key;
	let signature_algorithm = &account.current_key.signature_algorithm;
	let data_builder = |n: &str, url: &str| {
		encode_jwk(
			kp_ref,
			signature_algorithm,
			acc_ref.as_bytes(),
			url,
			Some(n.to_string()),
		)
	};
	let (acc_rep, account_url) = http::new_account(endpoint, &data_builder)
		.await
		.map_err(HttpError::in_err)?;
	account.set_account_url(&endpoint.name, &account_url)?;
	let orders_url = match acc_rep.orders {
		Some(url) => url,
		None => {
			let msg = format!(
				"endpoint \"{}\": account \"{}\": the server has not provided an order URL upon account creation",
				&endpoint.name,
				&account.name
			);
			account.warn(&msg);
			String::new()
		}
	};
	account.set_orders_url(&endpoint.name, &orders_url)?;
	account.update_key_hash(&endpoint.name)?;
	account.update_contacts_hash(&endpoint.name)?;
	account.update_external_account_hash(&endpoint.name)?;
	account.save().await?;
	account.info(&format!(
		"account created on endpoint \"{}\"",
		&endpoint.name
	));
	Ok(())
}

pub async fn update_account_contacts(
	endpoint: &mut Endpoint,
	account: &mut BaseAccount,
) -> Result<(), Error> {
	let endpoint_name = endpoint.name.clone();
	account.debug(&format!(
		"updating account contacts on endpoint \"{endpoint_name}\"..."
	));
	let new_contacts: Vec<String> = account.contacts.iter().map(|c| c.to_string()).collect();
	let acc_up_struct = AccountUpdate::new(&new_contacts);
	let acc_up_struct = serde_json::to_string(&acc_up_struct)?;
	let account_owned = account.clone();
	let data_builder =
		set_data_builder_sync!(account_owned, endpoint_name, acc_up_struct.as_bytes());
	let url = account.get_endpoint(&endpoint_name)?.account_url.clone();
	create_account_if_does_not_exist!(
		http::post_jose_no_response(endpoint, &data_builder, &url, None).await,
		endpoint,
		account
	)?;
	account.update_contacts_hash(&endpoint_name)?;
	account.save().await?;
	account.info(&format!(
		"account contacts updated on endpoint \"{endpoint_name}\""
	));
	Ok(())
}

pub async fn update_account_key(
	endpoint: &mut Endpoint,
	account: &mut BaseAccount,
) -> Result<(), Error> {
	let endpoint_name = endpoint.name.clone();
	account.debug(&format!(
		"updating account key on endpoint \"{endpoint_name}\"..."
	));
	let url = endpoint.dir.key_change.clone();
	let ep = account.get_endpoint(&endpoint_name)?;
	let old_account_key = account.get_past_key(&ep.key_hash)?;
	let old_key = &old_account_key.key;
	let account_url = account.get_endpoint(&endpoint_name)?.account_url.clone();
	let rollover_struct = AccountKeyRollover::new(&account_url, old_key)?;
	let rollover_struct = serde_json::to_string(&rollover_struct)?;
	let rollover_payload = encode_jwk(
		&account.current_key.key,
		&account.current_key.signature_algorithm,
		rollover_struct.as_bytes(),
		&url,
		None,
	)?;
	let data_builder = |n: &str, url: &str| {
		encode_kid(
			old_key,
			&old_account_key.signature_algorithm,
			&account_url,
			rollover_payload.as_bytes(),
			url,
			n,
		)
	};
	create_account_if_does_not_exist!(
		http::post_jose_no_response(endpoint, &data_builder, &url, None).await,
		endpoint,
		account
	)?;
	account.update_key_hash(&endpoint_name)?;
	account.save().await?;
	account.info(&format!(
		"account key updated on endpoint \"{endpoint_name}\""
	));
	Ok(())
}
