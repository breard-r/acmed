use crate::acme_proto::http;
use crate::acme_proto::structs::Account;
use crate::certificate::Certificate;
use crate::endpoint::Endpoint;
use crate::jws::encode_jwk;
use crate::storage;
use acme_common::crypto::{gen_keypair, JwsSignatureAlgorithm, KeyPair};
use acme_common::error::Error;

pub struct AccountManager {
    pub key_pair: KeyPair,
    pub signature_algorithm: JwsSignatureAlgorithm,
    pub account_url: String,
    pub orders_url: String,
}

impl AccountManager {
    pub fn new(
        endpoint: &mut Endpoint,
        root_certs: &[String],
        cert: &Certificate,
    ) -> Result<Self, Error> {
        // TODO: store the key id (account url)
        let key_pair = storage::get_account_keypair(cert)?;
        let signature_algorithm = endpoint.signature_algorithm;
        let kp_ref = &key_pair;
        let account = Account::new(cert, endpoint);
        let account = serde_json::to_string(&account)?;
        let acc_ref = &account;
        let data_builder = |n: &str, url: &str| {
            encode_jwk(kp_ref, &signature_algorithm, acc_ref.as_bytes(), url, n)
        };
        let (acc_rep, account_url) = http::new_account(endpoint, root_certs, &data_builder)?;
        let ac = AccountManager {
            key_pair,
            signature_algorithm,
            account_url,
            orders_url: acc_rep.orders.unwrap_or_default(),
        };
        // TODO: check account data and, if different from config, update them
        Ok(ac)
    }
}

pub fn init_account(cert: &Certificate, endpoint: &Endpoint) -> Result<(), Error> {
    if !storage::account_files_exists(cert) {
        let key_pair = gen_keypair(endpoint.key_type)?;
        storage::set_account_keypair(cert, &key_pair)?;
        cert.info(&format!("Account {} created", &cert.account.name));
    } else {
        let key_pair = storage::get_account_keypair(cert)?;
        if key_pair.key_type != endpoint.key_type {
            cert.debug(&format!("Account {} has a key pair of type {} while {} was expected. Creating a new {} key pair.", &cert.account.name, key_pair.key_type, endpoint.key_type, endpoint.key_type));
            // TODO: Do a propper key rollover?
            let key_pair = gen_keypair(endpoint.key_type)?;
            storage::set_account_keypair(cert, &key_pair)?;
        } else {
            cert.debug(&format!("Account {} already exists", &cert.account.name));
        }
    }
    Ok(())
}
