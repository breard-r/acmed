use crate::acme_proto::account::register_account;
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
pub enum AccountContactType {
    Mailfrom,
}

impl FromStr for AccountContactType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "mailfrom" => Ok(AccountContactType::Mailfrom),
            _ => Err(format!("{}: unknown contact type.", s).into()),
        }
    }
}

impl fmt::Display for AccountContactType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            AccountContactType::Mailfrom => "mailfrom",
        };
        write!(f, "{}", s)
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
    pub order_url: String,
    pub key_hash: Vec<u8>,
    pub contacts_hash: Vec<u8>,
}

impl AccountEndpoint {
    pub fn new() -> Self {
        AccountEndpoint {
            creation_date: SystemTime::UNIX_EPOCH,
            account_url: String::new(),
            order_url: String::new(),
            key_hash: Vec::new(),
            contacts_hash: Vec::new(),
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
}

impl HasLogger for Account {
    fn warn(&self, msg: &str) {
        log::warn!("account \"{}\": {}", &self.name, msg);
    }

    fn info(&self, msg: &str) {
        log::info!("account \"{}\": {}", &self.name, msg);
    }

    fn debug(&self, msg: &str) {
        log::debug!("account \"{}\": {}", &self.name, msg);
    }

    fn trace(&self, msg: &str) {
        log::trace!("account \"{}\": {}", &self.name, msg);
    }
}

impl Account {
    pub fn get_endpoint_mut(&mut self, endpoint_name: &str) -> Result<&mut AccountEndpoint, Error> {
        match self.endpoints.get_mut(endpoint_name) {
            Some(ep) => Ok(ep),
            None => {
                let msg = format!(
                    "{}: unknown endpoint for account {}",
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
                    "{}: unknown endpoint for account {}",
                    endpoint_name, self.name
                );
                Err(msg.into())
            }
        }
    }

    pub fn load(
        file_manager: &FileManager,
        name: &str,
        contacts: &[(String, String)],
        key_type: &Option<String>,
        signature_algorithm: &Option<String>,
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

    pub fn synchronize(
        &mut self,
        endpoint: &mut Endpoint,
        root_certs: &[String],
    ) -> Result<(), Error> {
        register_account(endpoint, root_certs, self)?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), Error> {
        storage::save(&self.file_manager, self)
    }

    pub fn set_account_url(&mut self, endpoint_name: &str, account_url: &str) -> Result<(), Error> {
        let mut ep = self.get_endpoint_mut(endpoint_name)?;
        ep.account_url = account_url.to_string();
        Ok(())
    }

    pub fn set_order_url(&mut self, endpoint_name: &str, order_url: &str) -> Result<(), Error> {
        let mut ep = self.get_endpoint_mut(endpoint_name)?;
        ep.order_url = order_url.to_string();
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
            let msg = format!(
                "new {} account key created, using {} as signing algorithm",
                key_type, signature_algorithm
            );
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
    let mut msg = key.signature_algorithm.to_string().into_bytes();
    let pem = key.key.public_key_to_pem()?;
    msg.extend_from_slice(&pem);
    Ok(HashFunction::Sha256.hash(&msg))
}
