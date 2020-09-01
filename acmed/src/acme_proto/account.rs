use crate::account::Account as BaseAccount;
use crate::acme_proto::http;
use crate::acme_proto::structs::{Account, AccountKeyRollover, AccountUpdate};
use crate::endpoint::Endpoint;
use crate::jws::{encode_jwk, encode_jwk_no_nonce, encode_kid};
use crate::logs::HasLogger;
use crate::set_data_builder;
use acme_common::error::Error;

pub fn register_account(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    account: &mut BaseAccount,
) -> Result<(), Error> {
    account.debug(&format!(
        "creating account on endpoint {}...",
        &endpoint.name
    ));
    let account_struct = Account::new(account, endpoint);
    let account_struct = serde_json::to_string(&account_struct)?;
    let acc_ref = &account_struct;
    let kp_ref = &account.current_key.key;
    let signature_algorithm = &account.current_key.signature_algorithm;
    let data_builder =
        |n: &str, url: &str| encode_jwk(kp_ref, signature_algorithm, acc_ref.as_bytes(), url, n);
    let (acc_rep, account_url) = http::new_account(endpoint, root_certs, &data_builder)?;
    account.set_account_url(&endpoint.name, &account_url)?;
    let msg = format!(
        "endpoint {}: account {}: the server has not provided an order URL upon account creation",
        &endpoint.name, &account.name
    );
    let order_url = acc_rep.orders.ok_or_else(|| Error::from(&msg))?;
    account.set_order_url(&endpoint.name, &order_url)?;
    account.update_key_hash(&endpoint.name)?;
    account.update_contacts_hash(&endpoint.name)?;
    account.save()?;
    account.info(&format!("account created on endpoint {}", &endpoint.name));
    Ok(())
}

pub fn update_account_contacts(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    account: &mut BaseAccount,
) -> Result<(), Error> {
    let endpoint_name = endpoint.name.clone();
    account.debug(&format!(
        "updating account contacts on endpoint {}...",
        &endpoint_name
    ));
    let new_contacts: Vec<String> = account.contacts.iter().map(|c| c.to_string()).collect();
    let acc_up_struct = AccountUpdate::new(&new_contacts);
    let acc_up_struct = serde_json::to_string(&acc_up_struct)?;
    let data_builder = set_data_builder!(account, endpoint_name, acc_up_struct.as_bytes());
    let url = account.get_endpoint(&endpoint_name)?.account_url.clone();
    http::post_no_response(endpoint, root_certs, &data_builder, &url)?;
    account.update_contacts_hash(&endpoint_name)?;
    account.save()?;
    account.info(&format!(
        "account contacts updated on endpoint {}",
        &endpoint_name
    ));
    Ok(())
}

pub fn update_account_key(
    endpoint: &mut Endpoint,
    root_certs: &[String],
    account: &mut BaseAccount,
) -> Result<(), Error> {
    let endpoint_name = endpoint.name.clone();
    account.debug(&format!(
        "updating account key on endpoint {}...",
        &endpoint_name
    ));
    let url = endpoint.dir.key_change.clone();
    let ep = account.get_endpoint(&endpoint_name)?;
    let old_account_key = account.get_past_key(&ep.key_hash)?;
    let old_key = &old_account_key.key;
    let rollover_struct = AccountKeyRollover::new(account, &old_key)?;
    let rollover_struct = serde_json::to_string(&rollover_struct)?;
    let rollover_payload = encode_jwk_no_nonce(
        &old_key,
        &old_account_key.signature_algorithm,
        rollover_struct.as_bytes(),
        &url,
    )?;
    let data_builder = set_data_builder!(account, endpoint_name, rollover_payload.as_bytes());
    http::post_no_response(endpoint, root_certs, &data_builder, &url)?;
    account.update_key_hash(&endpoint_name)?;
    account.save()?;
    account.info(&format!(
        "account key updated on endpoint {}",
        &endpoint_name
    ));
    Ok(())
}
