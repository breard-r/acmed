use crate::acme_proto::account::{register_account, update_account_contacts, update_account_key};
use crate::endpoint::Endpoint;
use crate::logs::HasLogger;
use crate::storage::FileManager;
use acme_common::crypto::{gen_keypair, HashFunction, JwsSignatureAlgorithm, KeyPair, KeyType};
use acme_common::error::Error;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

mod contact;
mod storage;

#[derive(Clone, Debug)]
pub struct ExternalAccount {
	pub identifier: String,
	pub key: Vec<u8>,
	pub signature_algorithm: JwsSignatureAlgorithm,
}

#[derive(Clone, Debug)]
pub enum AccountContactType {
	Mailfrom,
}

impl FromStr for AccountContactType {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Error> {
		match s.to_lowercase().as_str() {
			"mailfrom" => Ok(AccountContactType::Mailfrom),
			_ => Err(format!("{s}: unknown contact type.").into()),
		}
	}
}

impl fmt::Display for AccountContactType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let s = match self {
			AccountContactType::Mailfrom => "mailfrom",
		};
		write!(f, "{s}")
	}
}

#[derive(Clone, Debug)]
pub struct AccountKey {
	pub creation_date: SystemTime,
	pub key: KeyPair,
	pub signature_algorithm: JwsSignatureAlgorithm,
}

impl AccountKey {
	fn new(key_type: KeyType, signature_algorithm: JwsSignatureAlgorithm) -> Result<Self, Error> {
		Ok(AccountKey {
			creation_date: SystemTime::now(),
			key: gen_keypair(key_type)?,
			signature_algorithm,
		})
	}
}

#[derive(Clone, Debug, Hash)]
pub struct AccountEndpoint {
	pub creation_date: SystemTime,
	pub account_url: String,
	pub orders_url: String,
	pub key_hash: Vec<u8>,
	pub contacts_hash: Vec<u8>,
	pub external_account_hash: Vec<u8>,
}

impl AccountEndpoint {
	pub fn new() -> Self {
		AccountEndpoint {
			creation_date: SystemTime::UNIX_EPOCH,
			account_url: String::new(),
			orders_url: String::new(),
			key_hash: Vec::new(),
			contacts_hash: Vec::new(),
			external_account_hash: Vec::new(),
		}
	}
}

#[derive(Clone, Debug)]
pub struct Account {
	pub name: String,
	pub endpoints: HashMap<String, AccountEndpoint>,
	pub contacts: Vec<contact::AccountContact>,
	pub current_key: AccountKey,
	pub past_keys: Vec<AccountKey>,
	pub file_manager: FileManager,
	pub external_account: Option<ExternalAccount>,
}

impl HasLogger for Account {
	fn warn(&self, msg: &str) {
		log::warn!("account \"{}\": {msg}", &self.name);
	}

	fn info(&self, msg: &str) {
		log::info!("account \"{}\": {msg}", &self.name);
	}

	fn debug(&self, msg: &str) {
		log::debug!("account \"{}\": {msg}", &self.name);
	}

	fn trace(&self, msg: &str) {
		log::trace!("account \"{}\": {msg}", &self.name);
	}
}

impl Account {
	pub fn get_endpoint_mut(&mut self, endpoint_name: &str) -> Result<&mut AccountEndpoint, Error> {
		match self.endpoints.get_mut(endpoint_name) {
			Some(ep) => Ok(ep),
			None => {
				let msg = format!(
					"\"{}\": unknown endpoint for account \"{}\"",
					endpoint_name, self.name
				);
				Err(msg.into())
			}
		}
	}

	pub fn get_endpoint(&self, endpoint_name: &str) -> Result<&AccountEndpoint, Error> {
		match self.endpoints.get(endpoint_name) {
			Some(ep) => Ok(ep),
			None => {
				let msg = format!(
					"\"{}\": unknown endpoint for account \"{}\"",
					endpoint_name, self.name
				);
				Err(msg.into())
			}
		}
	}

	pub fn get_past_key(&self, key_hash: &[u8]) -> Result<&AccountKey, Error> {
		let key_hash = key_hash.to_vec();
		for key in &self.past_keys {
			let past_key_hash = hash_key(key)?;
			if past_key_hash == key_hash {
				return Ok(key);
			}
		}
		Err("key not found".into())
	}

	pub fn load(
		file_manager: &FileManager,
		name: &str,
		contacts: &[(String, String)],
		key_type: &Option<String>,
		signature_algorithm: &Option<String>,
		external_account: &Option<ExternalAccount>,
	) -> Result<Self, Error> {
		let contacts = contacts
			.iter()
			.map(|(k, v)| contact::AccountContact::new(k, v))
			.collect::<Result<Vec<contact::AccountContact>, Error>>()?;
		let key_type = match key_type {
			Some(kt) => kt.parse()?,
			None => crate::DEFAULT_ACCOUNT_KEY_TYPE,
		};
		let signature_algorithm = match signature_algorithm {
			Some(sa) => sa.parse()?,
			None => key_type.get_default_signature_alg(),
		};
		key_type.check_alg_compatibility(&signature_algorithm)?;
		let account = match storage::fetch(file_manager, name)? {
			Some(mut a) => {
				a.update_keys(key_type, signature_algorithm)?;
				a.contacts = contacts;
				a.external_account = external_account.to_owned();
				a
			}
			None => {
				let account = Account {
					name: name.to_string(),
					endpoints: HashMap::new(),
					contacts,
					current_key: AccountKey::new(key_type, signature_algorithm)?,
					past_keys: Vec::new(),
					file_manager: file_manager.clone(),
					external_account: external_account.to_owned(),
				};
				account.debug("initializing a new account");
				account
			}
		};
		Ok(account)
	}

	pub fn add_endpoint_name(&mut self, endpoint_name: &str) {
		self.endpoints
			.entry(endpoint_name.to_string())
			.or_insert_with(AccountEndpoint::new);
	}

	pub fn synchronize(&mut self, endpoint: &mut Endpoint) -> Result<(), Error> {
		let acc_ep = self.get_endpoint(&endpoint.name)?;
		if !acc_ep.account_url.is_empty() {
			if let Some(ec) = &self.external_account {
				let external_account_hash = hash_external_account(ec);
				if external_account_hash != acc_ep.external_account_hash {
					let msg = format!(
						"external account changed on endpoint \"{}\"",
						&endpoint.name
					);
					self.info(&msg);
					register_account(endpoint, self)?;
					return Ok(());
				}
			}
			let ct_hash = hash_contacts(&self.contacts);
			let key_hash = hash_key(&self.current_key)?;
			let contacts_changed = ct_hash != acc_ep.contacts_hash;
			let key_changed = key_hash != acc_ep.key_hash;
			if contacts_changed {
				update_account_contacts(endpoint, self)?;
			}
			if key_changed {
				update_account_key(endpoint, self)?;
			}
		} else {
			register_account(endpoint, self)?;
		}
		Ok(())
	}

	pub fn register(&mut self, endpoint: &mut Endpoint) -> Result<(), Error> {
		register_account(endpoint, self)
	}

	pub fn save(&self) -> Result<(), Error> {
		storage::save(&self.file_manager, self)
	}

	pub fn set_account_url(&mut self, endpoint_name: &str, account_url: &str) -> Result<(), Error> {
		let mut ep = self.get_endpoint_mut(endpoint_name)?;
		ep.account_url = account_url.to_string();
		Ok(())
	}

	pub fn set_orders_url(&mut self, endpoint_name: &str, orders_url: &str) -> Result<(), Error> {
		let mut ep = self.get_endpoint_mut(endpoint_name)?;
		ep.orders_url = orders_url.to_string();
		Ok(())
	}

	pub fn update_key_hash(&mut self, endpoint_name: &str) -> Result<(), Error> {
		let key = self.current_key.clone();
		let mut ep = self.get_endpoint_mut(endpoint_name)?;
		ep.key_hash = hash_key(&key)?;
		Ok(())
	}

	pub fn update_contacts_hash(&mut self, endpoint_name: &str) -> Result<(), Error> {
		let ct = self.contacts.clone();
		let mut ep = self.get_endpoint_mut(endpoint_name)?;
		ep.contacts_hash = hash_contacts(&ct);
		Ok(())
	}

	pub fn update_external_account_hash(&mut self, endpoint_name: &str) -> Result<(), Error> {
		if let Some(ec) = &self.external_account {
			let ec = ec.clone();
			let mut ep = self.get_endpoint_mut(endpoint_name)?;
			ep.external_account_hash = hash_external_account(&ec);
		}
		Ok(())
	}

	fn update_keys(
		&mut self,
		key_type: KeyType,
		signature_algorithm: JwsSignatureAlgorithm,
	) -> Result<(), Error> {
		if self.current_key.key.key_type != key_type
			|| self.current_key.signature_algorithm != signature_algorithm
		{
			self.debug("account key has been changed in the configuration, creating a new one...");
			self.past_keys.push(self.current_key.to_owned());
			self.current_key = AccountKey::new(key_type, signature_algorithm)?;
			self.save()?;
			let msg = format!("new {key_type} account key created, using {signature_algorithm} as signing algorithm");
			self.info(&msg);
		} else {
			self.trace("account key is up to date");
		}
		Ok(())
	}
}

fn hash_contacts(contacts: &[contact::AccountContact]) -> Vec<u8> {
	let msg = contacts
		.iter()
		.map(|v| v.to_string())
		.collect::<Vec<String>>()
		.join("")
		.into_bytes();
	HashFunction::Sha256.hash(&msg)
}

fn hash_key(key: &AccountKey) -> Result<Vec<u8>, Error> {
	let pem = key.key.public_key_to_pem()?;
	Ok(HashFunction::Sha256.hash(&pem))
}

fn hash_external_account(ec: &ExternalAccount) -> Vec<u8> {
	let mut msg = ec.key.clone();
	msg.extend(ec.identifier.as_bytes());
	HashFunction::Sha256.hash(&msg)
}
