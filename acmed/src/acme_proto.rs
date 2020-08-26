use crate::acme_proto::account::AccountManager;
use crate::acme_proto::structs::{
    ApiError, Authorization, AuthorizationStatus, NewOrder, Order, OrderStatus,
};
use crate::certificate::Certificate;
use crate::endpoint::Endpoint;
use crate::identifier::IdentifierType;
use crate::jws::encode_kid;
use crate::storage;
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
    ($account: ident, $data: expr) => {
        |n: &str, url: &str| {
            encode_kid(
                &$account.key_pair,
                &$account.signature_algorithm,
                &$account.account_url,
                $data,
                url,
                n,
            )
        }
    };
}
macro_rules! set_empty_data_builder {
    ($account: ident) => {
        set_data_builder!($account, b"")
    };
}

pub fn request_certificate(
    cert: &Certificate,
    root_certs: &[String],
    endpoint: &mut Endpoint,
) -> Result<(), Error> {
    let mut hook_datas = vec![];

    // Refresh the directory
    http::refresh_directory(endpoint, root_certs)?;

    // Get or create the account
    let account = AccountManager::new(endpoint, root_certs, cert)?;

    // Create a new order
    let new_order = NewOrder::new(&cert.identifiers);
    let new_order = serde_json::to_string(&new_order)?;
    let data_builder = set_data_builder!(account, new_order.as_bytes());
    let (order, order_url) = http::new_order(endpoint, root_certs, &data_builder)?;
    if let Some(e) = order.get_error() {
        cert.warn(&e.prefix("Error").message);
    }

    // Begin iter over authorizations
    for auth_url in order.authorizations.iter() {
        // Fetch the authorization
        let data_builder = set_empty_data_builder!(account);
        let auth = http::get_authorization(endpoint, root_certs, &data_builder, &auth_url)?;
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

        // Fetch the associated challenges
        let current_identifier = cert.get_identifier_from_str(&auth.identifier.value)?;
        let current_challenge = current_identifier.challenge;
        for challenge in auth.challenges.iter() {
            if current_challenge == *challenge {
                let proof = challenge.get_proof(&account.key_pair)?;
                let file_name = challenge.get_file_name();
                let identifier = auth.identifier.value.to_owned();

                // Call the challenge hook in order to complete it
                let mut data = cert.call_challenge_hooks(&file_name, &proof, &identifier)?;
                data.0.is_clean_hook = true;
                hook_datas.push(data);

                // Tell the server the challenge has been completed
                let chall_url = challenge.get_url();
                let data_builder = set_data_builder!(account, b"{}");
                let _ =
                    http::post_challenge_response(endpoint, root_certs, &data_builder, &chall_url)?;
            }
        }

        // Pool the authorization in order to see whether or not it is valid
        let data_builder = set_empty_data_builder!(account);
        let break_fn = |a: &Authorization| a.status == AuthorizationStatus::Valid;
        let _ =
            http::pool_authorization(endpoint, root_certs, &data_builder, &break_fn, &auth_url)?;
        for (data, hook_type) in hook_datas.iter() {
            cert.call_challenge_hooks_clean(&data, (*hook_type).to_owned())?;
        }
        hook_datas.clear();
    }
    // End iter over authorizations

    // Pool the order in order to see whether or not it is ready
    let data_builder = set_empty_data_builder!(account);
    let break_fn = |o: &Order| o.status == OrderStatus::Ready;
    let order = http::pool_order(endpoint, root_certs, &data_builder, &break_fn, &order_url)?;

    // Finalize the order by sending the CSR
    let key_pair = certificate::get_key_pair(cert)?;
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
    )?;
    cert.trace(&format!("New CSR:\n{}", csr.to_pem()?));
    let csr = json!({
        "csr": csr.to_der_base64()?,
    });
    let csr = csr.to_string();
    let data_builder = set_data_builder!(account, csr.as_bytes());
    let order = http::finalize_order(endpoint, root_certs, &data_builder, &order.finalize)?;
    if let Some(e) = order.get_error() {
        cert.warn(&e.prefix("Error").message);
    }

    // Pool the order in order to see whether or not it is valid
    let data_builder = set_empty_data_builder!(account);
    let break_fn = |o: &Order| o.status == OrderStatus::Valid;
    let order = http::pool_order(endpoint, root_certs, &data_builder, &break_fn, &order_url)?;

    // Download the certificate
    let crt_url = order
        .certificate
        .ok_or_else(|| Error::from("No certificate available for download."))?;
    let data_builder = set_empty_data_builder!(account);
    let crt = http::get_certificate(endpoint, root_certs, &data_builder, &crt_url)?;
    storage::write_certificate(cert, &crt.as_bytes())?;

    cert.info(&format!(
        "Certificate renewed (identifiers: {})",
        cert.identifier_list()
    ));
    Ok(())
}
