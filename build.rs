extern crate serde;
extern crate toml;

use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

macro_rules! set_rustc_env_var {
	($name: expr, $value: expr) => {{
		println!("cargo:rustc-env={}={}", $name, $value);
	}};
}

#[derive(Deserialize)]
pub struct LockFile {
	package: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
	name: String,
	version: String,
}

struct Error;

impl From<std::io::Error> for Error {
	fn from(_error: std::io::Error) -> Self {
		Error {}
	}
}

impl From<toml::de::Error> for Error {
	fn from(_error: toml::de::Error) -> Self {
		Error {}
	}
}

fn get_lock_file() -> Result<LockFile, Error> {
	let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	path.push("Cargo.lock");
	let mut file = File::open(path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	let ret: LockFile = toml::from_str(&contents)?;
	Ok(ret)
}

fn set_http_agent() {
	let lock = match get_lock_file() {
		Ok(l) => l,
		Err(_) => {
			return;
		}
	};
	for p in lock.package.iter() {
		if p.name == "reqwest" {
			let agent = format!("{}/{}", p.name, p.version);
			set_rustc_env_var!("ACMED_HTTP_LIB_AGENT", agent);
			return;
		}
	}
}

fn set_target() {
	if let Ok(target) = env::var("TARGET") {
		set_rustc_env_var!("ACMED_TARGET", target);
	};
}

fn main() {
	set_target();
	set_http_agent();
}
