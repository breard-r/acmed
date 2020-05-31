use crate::acme_proto::http;
use crate::acme_proto::structs::{Account, AccountResponse, Directory};
use crate::certificate::Certificate;
use crate::endpoint::Endpoint;
use crate::jws::algorithms::SignatureAlgorithm;
use crate::jws::encode_jwk;
use crate::storage;
use acme_common::crypto::KeyPair;
use acme_common::error::Error;
use std::str::FromStr;

pub struct AccountManager {
    pub key_pair: KeyPair,
    pub account_url: String,
    pub orders_url: String,
}

impl AccountManager {
    pub fn new(
        cert: &Certificate,
        directory: &Directory,
        endpoint: &Endpoint,
        nonce: &str,
        root_certs: &[String],
    ) -> Result<(Self, String), Error> {
        // TODO: store the key id (account url)
        let key_pair = storage::get_account_keypair(cert)?;
        let account = Account::new(cert, endpoint);
        let account = serde_json::to_string(&account)?;
        let data_builder =
            |n: &str| encode_jwk(&key_pair, account.as_bytes(), &directory.new_account, n);
        let (acc_rep, account_url, nonce): (AccountResponse, String, String) = http::get_obj_loc(
            cert,
            root_certs,
            &directory.new_account,
            &data_builder,
            &nonce,
        )?;
        let ac = AccountManager {
            key_pair,
            account_url,
            orders_url: acc_rep.orders.unwrap_or_default(),
        };
        // TODO: check account data and, if different from config, update them
        Ok((ac, nonce))
    }
}

pub fn init_account(cert: &Certificate) -> Result<(), Error> {
    if !storage::account_files_exists(cert) {
        // TODO: allow to change the signature algo
        let sign_alg = SignatureAlgorithm::from_str(crate::DEFAULT_JWS_SIGN_ALGO)?;
        let key_pair = sign_alg.gen_key_pair()?;
        storage::set_account_keypair(cert, &key_pair)?;
        let msg = format!("Account {} created.", &cert.account.name);
        cert.info(&msg)
    } else {
        // TODO: check if the keys are suitable for the specified signature algorithm
        // and, if not, initiate a key rollover.
        let msg = format!("Account {} already exists.", &cert.account.name);
        cert.debug(&msg)
    }
    Ok(())
}
