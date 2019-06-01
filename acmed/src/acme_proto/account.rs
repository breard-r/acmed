use crate::acme_proto::http;
use crate::acme_proto::jws::algorithms::SignatureAlgorithm;
use crate::acme_proto::jws::encode_jwk;
use crate::acme_proto::structs::{Account, AccountResponse, Directory};
use crate::certificate::Certificate;
use crate::storage;
use acme_common::error::Error;
use openssl::pkey::{PKey, Private, Public};
use std::str::FromStr;

pub struct AccountManager {
    pub priv_key: PKey<Private>,
    pub pub_key: PKey<Public>,
    pub account_url: String,
    pub orders_url: String,
}

impl AccountManager {
    pub fn new(
        cert: &Certificate,
        directory: &Directory,
        nonce: &str,
        root_certs: &[String],
    ) -> Result<(Self, String), Error> {
        // TODO: store the key id (account url)
        let (priv_key, pub_key) = if storage::account_files_exists(cert) {
            // TODO: check if the keys are suitable for the specified signature algorithm
            // and, if not, initiate a key rollover.
            (
                storage::get_account_priv_key(cert)?,
                storage::get_account_pub_key(cert)?,
            )
        } else {
            // TODO: allow to change the signature algo
            let sign_alg = SignatureAlgorithm::from_str(crate::DEFAULT_JWS_SIGN_ALGO)?;
            let (priv_key, pub_key) = sign_alg.gen_key_pair()?;
            storage::set_account_priv_key(cert, &priv_key)?;
            storage::set_account_pub_key(cert, &pub_key)?;
            (priv_key, pub_key)
        };
        let account = Account::new(cert);
        let account = serde_json::to_string(&account)?;
        let data_builder =
            |n: &str| encode_jwk(&priv_key, account.as_bytes(), &directory.new_account, n);
        let (acc_rep, account_url, nonce): (AccountResponse, String, String) = http::get_obj_loc(
            cert,
            root_certs,
            &directory.new_account,
            &data_builder,
            &nonce,
        )?;
        let ac = AccountManager {
            priv_key,
            pub_key,
            account_url,
            orders_url: acc_rep.orders.unwrap_or_default(),
        };
        // TODO: check account data and, if different from config, update them
        Ok((ac, nonce))
    }
}
