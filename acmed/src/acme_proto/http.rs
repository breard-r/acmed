use crate::acme_proto::structs::{AccountResponse, Authorization, Directory, Order};
use crate::config::NamedAcmeResource;
use crate::endpoint::Endpoint;
use crate::http;
use acme_common::error::Error;
use std::{thread, time};

macro_rules! pool_object {
	($obj_type: ty, $obj_name: expr, $endpoint: expr, $url: expr, $resource: expr, $data_builder: expr, $break: expr) => {{
		for _ in 0..crate::DEFAULT_POOL_NB_TRIES {
			thread::sleep(time::Duration::from_secs(crate::DEFAULT_POOL_WAIT_SEC));
			let response = http::post_jose($endpoint, $url, $resource, $data_builder).await?;
			let obj = response.json::<$obj_type>()?;
			if $break(&obj) {
				return Ok(obj);
			}
		}
		let msg = format!("{} pooling failed on {}", $obj_name, $url);
		Err(msg.into())
	}};
}

pub async fn refresh_directory(endpoint: &mut Endpoint) -> Result<(), http::HttpError> {
	let url = endpoint.url.clone();
	let response = http::get(endpoint, &url, Some(NamedAcmeResource::Directory)).await?;
	endpoint.dir = response.json::<Directory>()?;
	Ok(())
}

pub async fn post_jose_no_response<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
	resource: Option<NamedAcmeResource>,
) -> Result<(), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let _ = http::post_jose(endpoint, url, resource, data_builder).await?;
	Ok(())
}

pub async fn new_account<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
) -> Result<(AccountResponse, String), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let url = endpoint.dir.new_account.clone();
	let response = http::post_jose(
		endpoint,
		&url,
		Some(NamedAcmeResource::NewAccount),
		data_builder,
	)
	.await?;
	let acc_uri = response
		.get_header(http::HEADER_LOCATION)
		.ok_or_else(|| Error::from("no account location found"))?;
	let acc_resp = response.json::<AccountResponse>()?;
	Ok((acc_resp, acc_uri))
}

pub async fn new_order<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
) -> Result<(Order, String), http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let url = endpoint.dir.new_order.clone();
	let response = http::post_jose(
		endpoint,
		&url,
		Some(NamedAcmeResource::NewOrder),
		data_builder,
	)
	.await?;
	let order_uri = response
		.get_header(http::HEADER_LOCATION)
		.ok_or_else(|| Error::from("no account location found"))?;
	let order_resp = response.json::<Order>()?;
	Ok((order_resp, order_uri))
}

pub async fn get_authorization<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<Authorization, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let response = http::post_jose(endpoint, url, None, data_builder).await?;
	let auth = response.json::<Authorization>()?;
	Ok(auth)
}

pub async fn pool_authorization<F, S>(
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
		None,
		data_builder,
		break_fn
	)
}

pub async fn pool_order<F, S>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	break_fn: &S,
	url: &str,
) -> Result<Order, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
	S: Fn(&Order) -> bool,
{
	pool_object!(Order, "order", endpoint, url, None, data_builder, break_fn)
}

pub async fn finalize_order<F>(
	endpoint: &mut Endpoint,
	data_builder: &F,
	url: &str,
) -> Result<Order, http::HttpError>
where
	F: Fn(&str, &str) -> Result<String, Error>,
{
	let response = http::post_jose(endpoint, url, None, data_builder).await?;
	let order = response.json::<Order>()?;
	Ok(order)
}

pub async fn get_certificate<F>(
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
		None,
		data_builder,
		http::CONTENT_TYPE_JOSE,
		http::CONTENT_TYPE_PEM,
	)
	.await?;
	Ok(response.body)
}
