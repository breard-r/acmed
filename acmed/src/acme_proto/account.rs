use crate::account::Account as BaseAccount;
use crate::acme_proto::http;
use crate::acme_proto::structs::Account;
use crate::endpoint::Endpoint;
use crate::jws::encode_jwk;
use crate::logs::HasLogger;
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
