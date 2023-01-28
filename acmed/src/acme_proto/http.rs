use crate::acme_proto::structs::{AccountResponse, Authorization, Directory, Order};
use crate::endpoint::Endpoint;
use crate::http;
use acme_common::error::Error;
use std::{thread, time};

macro_rules! pool_object {
	($obj_type: ty, $obj_name: expr, $endpoint: expr, $url: expr, $data_builder: expr, $break: expr) => {{
		for _ in 0..crate::DEFAULT_POOL_NB_TRIES {
			thread::sleep(time::Duration::from_secs(crate::DEFAULT_POOL_WAIT_SEC));
			let response = http::post_jose($endpoint, $url, $data_builder)?;
			let obj = response.json::<$obj_type>()?;
			if $break(&obj) {
				return Ok(obj);
			}
		}
		let msg = format!("{} pooling failed on {}", $obj_name, $url);
		Err(msg.into())
	}};
}

pub fn refresh_directory(endpoint: &mut Endpoint) -> Result<(), http::HttpError> {
	let url = endpoint.url.clone();
	let response = http::get(endpoint, &url)?;
	endpoint.dir = response.json::<Directory>()?;
	Ok(())
}

pub fn post_jose_no_response<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<(), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let _ = http::post_jose(endpoint, url, data_builder)?;
	Ok(())
}

pub fn new_account<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
) -> Result<(AccountResponse, String), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let url = endpoint.dir.new_account.clone();
	let response = http::post_jose(endpoint, &url, data_builder)?;
	let acc_uri = response
		.get_header(http::HEADER_LOCATION)
		.ok_or_else(|| Error::from("no account location found"))?;
	let acc_resp = response.json::<AccountResponse>()?;
	Ok((acc_resp, acc_uri))
}

pub fn new_order<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
) -> Result<(Order, String), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let url = endpoint.dir.new_order.clone();
	let response = http::post_jose(endpoint, &url, data_builder)?;
	let order_uri = response
		.get_header(http::HEADER_LOCATION)
		.ok_or_else(|| Error::from("no account location found"))?;
	let order_resp = response.json::<Order>()?;
	Ok((order_resp, order_uri))
}

pub fn get_authorization<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<Authorization, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let response = http::post_jose(endpoint, url, data_builder)?;
	let auth = response.json::<Authorization>()?;
	Ok(auth)
}

pub fn pool_authorization<F, S>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	break_fn: &S,
	url: &str,
) -> Result<Authorization, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
	S: Fn(&Authorization) -> bool,
{
	pool_object!(
		Authorization,
		"authorization",
		endpoint,
		url,
		data_builder,
		break_fn
	)
}

pub fn pool_order<F, S>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	break_fn: &S,
	url: &str,
) -> Result<Order, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
	S: Fn(&Order) -> bool,
{
	pool_object!(Order, "order", endpoint, url, data_builder, break_fn)
}

pub fn finalize_order<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<Order, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let response = http::post_jose(endpoint, url, data_builder)?;
	let order = response.json::<Order>()?;
	Ok(order)
}

pub fn get_certificate<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<String, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let response = http::post(
		endpoint,
		url,
		data_builder,
		http::CONTENT_TYPE_JOSE,
		http::CONTENT_TYPE_PEM,
	)?;
	Ok(response.body)
}
