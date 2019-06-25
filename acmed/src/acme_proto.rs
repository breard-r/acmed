use crate::acme_proto::account::AccountManager;
use crate::acme_proto::structs::{
    ApiError, Authorization, AuthorizationStatus, NewOrder, Order, OrderStatus,
};
use crate::certificate::Certificate;
use crate::jws::encode_kid;
use crate::storage;
use acme_common::crypto::Csr;
use acme_common::error::Error;
use serde_json::json;
use std::fmt;

mod account;
mod certificate;
mod http;
pub mod structs;

#[derive(Clone, Debug, PartialEq)]
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
            _ => Err(format!("{}: unknown challenge.", s).into()),
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
        write!(f, "{}", s)
    }
}

impl PartialEq<structs::Challenge> for Challenge {
    fn eq(&self, other: &structs::Challenge) -> bool {
        match (self, other) {
            (Challenge::Http01, structs::Challenge::Http01(_)) => true,
            (Challenge::Dns01, structs::Challenge::Dns01(_)) => true,
            (Challenge::TlsAlpn01, structs::Challenge::TlsAlpn01(_)) => true,
            _ => false,
        }
    }
}

macro_rules! set_data_builder {
    ($account: ident, $data: expr, $url: expr) => {
        |n: &str| encode_kid(&$account.key_pair, &$account.account_url, $data, &$url, n)
    };
}
macro_rules! set_empty_data_builder {
    ($account: ident, $url: expr) => {
        set_data_builder!($account, b"", $url)
    };
}

pub fn request_certificate(cert: &Certificate, root_certs: &[String]) -> Result<(), Error> {
    let domains = cert
        .domains
        .iter()
        .map(|d| d.dns.to_owned())
        .collect::<Vec<String>>();
    let mut hook_datas = vec![];

    // 1. Get the directory
    let directory = http::get_directory(cert, root_certs, &cert.remote_url)?;

    // 2. Get a first nonce
    let nonce = http::get_nonce(cert, root_certs, &directory.new_nonce)?;

    // 3. Get or create the account
    let (account, nonce) = AccountManager::new(cert, &directory, &nonce, root_certs)?;

    // 4. Create a new order
    let new_order = NewOrder::new(&domains);
    let new_order = serde_json::to_string(&new_order)?;
    let data_builder = set_data_builder!(account, new_order.as_bytes(), directory.new_order);
    let (order, order_url, mut nonce): (Order, String, String) = http::get_obj_loc(
        cert,
        root_certs,
        &directory.new_order,
        &data_builder,
        &nonce,
    )?;
    if let Some(e) = order.get_error() {
        cert.warn(&e.prefix("Error").message);
    }

    // 5. Get all the required authorizations
    for auth_url in order.authorizations.iter() {
        let data_builder = set_empty_data_builder!(account, auth_url);
        let (auth, new_nonce): (Authorization, String) =
            http::get_obj(cert, root_certs, &auth_url, &data_builder, &nonce)?;
        nonce = new_nonce;

        if let Some(e) = auth.get_error() {
            cert.warn(&e.prefix("Error").message);
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

        // 6. For each authorization, fetch the associated challenges
        let current_challenge = cert.get_domain_challenge(&auth.identifier.value)?;
        for challenge in auth.challenges.iter() {
            if current_challenge == *challenge {
                let proof = challenge.get_proof(&account.key_pair)?;
                let file_name = challenge.get_file_name();
                let domain = auth.identifier.value.to_owned();

                // 7. Call the challenge hook in order to complete it
                let mut data = cert.call_challenge_hooks(&file_name, &proof, &domain)?;
                data.0.is_clean_hook = true;
                hook_datas.push(data);

                // 8. Tell the server the challenge has been completed
                let chall_url = challenge.get_url();
                let data_builder = set_data_builder!(account, b"{}", chall_url);
                let new_nonce = http::post_challenge_response(
                    cert,
                    root_certs,
                    &chall_url,
                    &data_builder,
                    &nonce,
                )?;
                nonce = new_nonce;
            }
        }

        // 9. Pool the authorization in order to see whether or not it is valid
        let data_builder = set_empty_data_builder!(account, auth_url);
        let break_fn = |a: &Authorization| a.status == AuthorizationStatus::Valid;
        let (_, new_nonce): (Authorization, String) = http::pool_obj(
            cert,
            root_certs,
            &auth_url,
            &data_builder,
            &break_fn,
            &nonce,
        )?;
        nonce = new_nonce;
        for (data, hook_type) in hook_datas.iter() {
            cert.call_challenge_hooks_clean(&data, (*hook_type).to_owned())?;
        }
        hook_datas.clear();
    }

    // 10. Pool the order in order to see whether or not it is ready
    let data_builder = set_empty_data_builder!(account, order_url);
    let break_fn = |o: &Order| o.status == OrderStatus::Ready;
    let (order, nonce): (Order, String) = http::pool_obj(
        cert,
        root_certs,
        &order_url,
        &data_builder,
        &break_fn,
        &nonce,
    )?;

    // 11. Finalize the order by sending the CSR
    let key_pair = certificate::get_key_pair(cert)?;
    let domains: Vec<String> = cert.domains.iter().map(|e| e.dns.to_owned()).collect();
    let csr = json!({
        "csr": Csr::new(&key_pair, domains.as_slice())?.to_der_base64()?,
    });
    let csr = csr.to_string();
    let data_builder = set_data_builder!(account, csr.as_bytes(), order.finalize);
    let (order, nonce): (Order, String) =
        http::get_obj(cert, root_certs, &order.finalize, &data_builder, &nonce)?;
    if let Some(e) = order.get_error() {
        cert.warn(&e.prefix("Error").message);
    }

    // 12. Pool the order in order to see whether or not it is valid
    let data_builder = set_empty_data_builder!(account, order_url);
    let break_fn = |o: &Order| o.status == OrderStatus::Valid;
    let (order, nonce): (Order, String) = http::pool_obj(
        cert,
        root_certs,
        &order_url,
        &data_builder,
        &break_fn,
        &nonce,
    )?;

    // 13. Download the certificate
    let crt_url = order
        .certificate
        .ok_or_else(|| Error::from("No certificate available for download."))?;
    let data_builder = set_empty_data_builder!(account, crt_url);
    let (crt, _) = http::get_certificate(cert, root_certs, &crt_url, &data_builder, &nonce)?;
    storage::write_certificate(cert, &crt.as_bytes())?;

    cert.info("Certificate renewed");
    Ok(())
}
