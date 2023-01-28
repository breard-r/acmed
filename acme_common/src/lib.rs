use base64::Engine;
use daemonize::Daemonize;
use std::fs::File;
use std::io::prelude::*;
use std::{fs, process};

pub mod crypto;
pub mod error;
pub mod logs;
#[cfg(test)]
mod tests;

macro_rules! exit_match {
	($e: expr) => {
		match $e {
			Ok(_) => {}
			Err(e) => {
				log::error!("error: {e}");
				std::process::exit(3);
			}
		}
	};
}

pub fn to_idna(domain_name: &str) -> Result<String, error::Error> {
	let mut idna_parts = vec![];
	let parts: Vec<&str> = domain_name.split('.').collect();
	for name in parts.iter() {
		let raw_name = name.to_lowercase();
		let idna_name = if name.is_ascii() {
			raw_name
		} else {
			let idna_name = punycode::encode(&raw_name)
				.map_err(|_| error::Error::from("IDNA encoding failed."))?;
			format!("xn--{idna_name}")
		};
		idna_parts.push(idna_name);
	}
	Ok(idna_parts.join("."))
}

pub fn b64_encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn b64_decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, error::Error> {
	let res = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)?;
	Ok(res)
}

pub fn init_server(foreground: bool, pid_file: Option<&str>) {
	if !foreground {
		let mut daemonize = Daemonize::new();
		if let Some(f) = pid_file {
			daemonize = daemonize.pid_file(f);
		}
		exit_match!(daemonize.start());
	} else if let Some(f) = pid_file {
		exit_match!(write_pid_file(f).map_err(|e| e.prefix(f)));
	}
}

fn write_pid_file(pid_file: &str) -> Result<(), error::Error> {
	let data = format!("{}\n", process::id()).into_bytes();
	let mut file = File::create(pid_file)?;
	file.write_all(&data)?;
	file.sync_all()?;
	Ok(())
}

pub fn clean_pid_file(pid_file: Option<&str>) -> Result<(), error::Error> {
	if let Some(f) = pid_file {
		fs::remove_file(f)?;
	}
	Ok(())
}
