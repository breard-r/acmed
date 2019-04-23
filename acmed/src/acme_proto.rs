use crate::acme_proto::account::AccountManager;
use crate::acme_proto::jws::encode_kid;
use crate::acme_proto::structs::{
    Authorization, AuthorizationStatus, NewOrder, Order, OrderStatus,
};
use crate::certificate::Certificate;
use crate::error::Error;
use crate::storage;
use log::info;
use std::{fmt, thread, time};

mod account;
mod certificate;
mod http;
pub mod jws;
mod structs;

#[derive(Clone, Debug, PartialEq)]
pub enum Challenge {
    Http01,
    Dns01,
}

impl Challenge {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "http-01" => Ok(Challenge::Http01),
            "dns-01" => Ok(Challenge::Dns01),
            _ => Err(format!("{}: unknown challenge.", s).into()),
        }
    }
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Challenge::Http01 => "http-01",
            Challenge::Dns01 => "dns-01",
        };
        write!(f, "{}", s)
    }
}

impl PartialEq<structs::Challenge> for Challenge {
    fn eq(&self, other: &structs::Challenge) -> bool {
        match (self, other) {
            (Challenge::Http01, structs::Challenge::Http01(_)) => true,
            (Challenge::Dns01, structs::Challenge::Dns01(_)) => true,
            _ => false,
        }
    }
}

fn pool<T, F, G>(
    account: &AccountManager,
    url: &str,
    nonce: &str,
    get_fn: F,
    break_fn: G,
) -> Result<(T, String), Error>
where
    F: Fn(&str, &[u8]) -> Result<(T, String), Error>,
    G: Fn(&T) -> bool,
{
    let mut nonce: String = nonce.to_string();
    for _ in 0..crate::DEFAULT_POOL_NB_TRIES {
        thread::sleep(time::Duration::from_secs(crate::DEFAULT_POOL_WAIT_SEC));
        let data = encode_kid(&account.priv_key, &account.account_url, b"", url, &nonce)?;
        let (obj, new_nonce) = get_fn(url, data.as_bytes())?;
        if break_fn(&obj) {
            return Ok((obj, new_nonce));
        }
        nonce = new_nonce;
    }
    let msg = format!("Pooling failed for {}", url);
    Err(msg.into())
}

pub fn request_certificate(cert: &Certificate) -> Result<(), Error> {
    // 1. Get the directory
    let directory = http::get_directory(&cert.remote_url)?;

    // 2. Get a first nonce
    let nonce = http::get_nonce(&directory.new_nonce)?;

    // 3. Get or create the account
    let (account, nonce) = AccountManager::new(cert, &directory, &nonce)?;

    // 4. Create a new order
    let new_order = NewOrder::new(&cert.domains);
    let new_order = serde_json::to_string(&new_order)?;
    let new_order = encode_kid(
        &account.priv_key,
        &account.account_url,
        new_order.as_bytes(),
        &directory.new_order,
        &nonce,
    )?;
    let (order, order_url, mut nonce) =
        http::get_obj_loc::<Order>(&directory.new_order, new_order.as_bytes())?;

    // 5. Get all the required authorizations
    for auth_url in order.authorizations.iter() {
        let auth_data = encode_kid(
            &account.priv_key,
            &account.account_url,
            b"",
            &auth_url,
            &nonce,
        )?;
        let (auth, new_nonce) = http::get_obj::<Authorization>(&auth_url, auth_data.as_bytes())?;
        nonce = new_nonce;

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
        for challenge in auth.challenges.iter() {
            if cert.challenge == *challenge {
                let proof = challenge.get_proof(&account.priv_key)?;
                let file_name = challenge.get_file_name();
                let domain = auth.identifier.value.to_owned();

                // 7. Call the challenge hook in order to complete it
                cert.call_challenge_hooks(&file_name, &proof, &domain)?;

                // 8. Tell the server the challenge has been completed
                let chall_url = challenge.get_url();
                let chall_resp_data = encode_kid(
                    &account.priv_key,
                    &account.account_url,
                    b"{}",
                    &chall_url,
                    &nonce,
                )?;
                let new_nonce =
                    http::post_challenge_response(&chall_url, chall_resp_data.as_bytes())?;
                nonce = new_nonce;
            }
        }

        // 9. Pool the authorization in order to see whether or not it is valid
        let (_, new_nonce) = pool(
            &account,
            &auth_url,
            &nonce,
            |u, d| http::get_obj::<Authorization>(u, d),
            |a| a.status == AuthorizationStatus::Valid,
        )?;
        nonce = new_nonce;
    }

    // 10. Pool the order in order to see whether or not it is ready
    let (order, nonce) = pool(
        &account,
        &order_url,
        &nonce,
        |u, d| http::get_obj::<Order>(u, d),
        |a| a.status == OrderStatus::Ready,
    )?;

    // 11. Finalize the order by sending the CSR
    let (priv_key, pub_key) = certificate::get_key_pair(cert)?;
    let csr = certificate::generate_csr(cert, &priv_key, &pub_key)?;
    let csr_data = encode_kid(
        &account.priv_key,
        &account.account_url,
        csr.as_bytes(),
        &order.finalize,
        &nonce,
    )?;
    let (_, nonce) = http::get_obj::<Order>(&order.finalize, &csr_data.as_bytes())?;

    // 12. Pool the order in order to see whether or not it is valid
    let (order, nonce) = pool(
        &account,
        &order_url,
        &nonce,
        |u, d| http::get_obj::<Order>(u, d),
        |a| a.status == OrderStatus::Valid,
    )?;

    // 13. Download the certificate
    // TODO: implement
    let crt_url = order
        .certificate
        .ok_or_else(|| Error::from("No certificate available for download."))?;
    let crt_data = encode_kid(
        &account.priv_key,
        &account.account_url,
        b"",
        &crt_url,
        &nonce,
    )?;
    let (crt, _) = http::get_certificate(&crt_url, &crt_data.as_bytes())?;
    storage::write_certificate(cert, &crt.as_bytes())?;

    info!("Certificate renewed for {}", cert.domains.join(", "));
    Ok(())
}

pub fn b64_encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}
