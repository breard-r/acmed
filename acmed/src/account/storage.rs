use crate::account::contact::AccountContact;
use crate::account::{Account, AccountEndpoint, AccountKey, ExternalAccount};
use crate::storage::{account_files_exists, get_account_data, set_account_data, FileManager};
use acme_common::crypto::KeyPair;
use acme_common::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ExternalAccountStorage {
	pub identifier: String,
	pub key: Vec<u8>,
	pub signature_algorithm: String,
}

impl ExternalAccountStorage {
	fn new(external_account: &ExternalAccount) -> Self {
		ExternalAccountStorage {
			identifier: external_account.identifier.to_owned(),
			key: external_account.key.to_owned(),
			signature_algorithm: external_account.signature_algorithm.to_string(),
		}
	}

	fn to_generic(&self) -> Result<ExternalAccount, Error> {
		Ok(ExternalAccount {
			identifier: self.identifier.to_owned(),
			key: self.key.to_owned(),
			signature_algorithm: self.signature_algorithm.parse()?,
		})
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AccountKeyStorage {
	creation_date: SystemTime,
	key: Vec<u8>,
	signature_algorithm: String,
}

impl AccountKeyStorage {
	fn new(key: &AccountKey) -> Result<Self, Error> {
		Ok(AccountKeyStorage {
			creation_date: key.creation_date,
			key: key.key.private_key_to_der()?,
			signature_algorithm: key.signature_algorithm.to_string(),
		})
	}

	fn to_generic(&self) -> Result<AccountKey, Error> {
		Ok(AccountKey {
			creation_date: self.creation_date,
			key: KeyPair::from_der(&self.key)?,
			signature_algorithm: self.signature_algorithm.parse()?,
		})
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AccountEndpointStorage {
	creation_date: SystemTime,
	account_url: String,
	orders_url: String,
	key_hash: Vec<u8>,
	contacts_hash: Vec<u8>,
	external_account_hash: Vec<u8>,
}

impl AccountEndpointStorage {
	fn new(account_endpoint: &AccountEndpoint) -> Self {
		AccountEndpointStorage {
			creation_date: account_endpoint.creation_date,
			account_url: account_endpoint.account_url.clone(),
			orders_url: account_endpoint.orders_url.clone(),
			key_hash: account_endpoint.key_hash.clone(),
			contacts_hash: account_endpoint.contacts_hash.clone(),
			external_account_hash: account_endpoint.external_account_hash.clone(),
		}
	}

	fn to_generic(&self) -> AccountEndpoint {
		AccountEndpoint {
			creation_date: self.creation_date,
			account_url: self.account_url.clone(),
			orders_url: self.orders_url.clone(),
			key_hash: self.key_hash.clone(),
			contacts_hash: self.contacts_hash.clone(),
			external_account_hash: self.external_account_hash.clone(),
		}
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AccountStorage {
	name: String,
	endpoints: HashMap<String, AccountEndpointStorage>,
	contacts: Vec<(String, String)>,
	current_key: AccountKeyStorage,
	past_keys: Vec<AccountKeyStorage>,
	external_account: Option<ExternalAccountStorage>,
}

fn do_fetch(file_manager: &FileManager, name: &str) -> Result<Option<Account>, Error> {
	if account_files_exists(file_manager) {
		let data = get_account_data(file_manager)?;
		let obj: AccountStorage = bincode::deserialize(&data[..])
			.map_err(|e| Error::from(&e.to_string()).prefix(name))?;
		let endpoints = obj
			.endpoints
			.iter()
			.map(|(k, v)| (k.clone(), v.to_generic()))
			.collect();
		let contacts = obj
			.contacts
			.iter()
			.map(|(t, v)| AccountContact::new(t, v))
			.collect::<Result<Vec<AccountContact>, Error>>()?;
		let current_key = obj.current_key.to_generic()?;
		let past_keys = obj
			.past_keys
			.iter()
			.map(|k| k.to_generic())
			.collect::<Result<Vec<AccountKey>, Error>>()?;
		let external_account = match obj.external_account {
			Some(a) => Some(a.to_generic()?),
			None => None,
		};
		Ok(Some(Account {
			name: obj.name,
			endpoints,
			contacts,
			current_key,
			past_keys,
			file_manager: file_manager.clone(),
			external_account,
		}))
	} else {
		Ok(None)
	}
}

fn do_save(file_manager: &FileManager, account: &Account) -> Result<(), Error> {
	let endpoints: HashMap<String, AccountEndpointStorage> = account
		.endpoints
		.iter()
		.map(|(k, v)| (k.to_owned(), AccountEndpointStorage::new(v)))
		.collect();
	let contacts: Vec<(String, String)> = account
		.contacts
		.iter()
		.map(|c| (c.contact_type.to_string(), c.value.to_owned()))
		.collect();
	let past_keys = account
		.past_keys
		.iter()
		.map(AccountKeyStorage::new)
		.collect::<Result<Vec<AccountKeyStorage>, Error>>()?;
	let external_account = account
		.external_account
		.as_ref()
		.map(ExternalAccountStorage::new);
	let account_storage = AccountStorage {
		name: account.name.to_owned(),
		endpoints,
		contacts,
		current_key: AccountKeyStorage::new(&account.current_key)?,
		past_keys,
		external_account,
	};
	let encoded: Vec<u8> = bincode::serialize(&account_storage)
		.map_err(|e| Error::from(&e.to_string()).prefix(&account.name))?;
	set_account_data(file_manager, &encoded)
}

pub fn fetch(file_manager: &FileManager, name: &str) -> Result<Option<Account>, Error> {
	do_fetch(file_manager, name).map_err(|_| {
		format!("account \"{name}\": unable to load account file: file may be corrupted").into()
	})
}

pub fn save(file_manager: &FileManager, account: &Account) -> Result<(), Error> {
	do_save(file_manager, account).map_err(|e| format!("unable to save account file: {e}").into())
}
