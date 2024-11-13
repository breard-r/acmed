use std::env;

macro_rules! set_rustc_env_var {
	($name: expr, $value: expr) => {{
		println!("cargo:rustc-env={}={}", $name, $value);
	}};
}

#[allow(clippy::unusual_byte_groupings)]
fn main() {
	if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
		let version = u64::from_str_radix(&v, 16).unwrap();
		// OpenSSL 1.1.1
		if version >= 0x1_01_01_00_0 {
			println!("cargo:rustc-cfg=feature=\"ed25519\"");
			println!("cargo:rustc-cfg=feature=\"ed448\"");
		}
		set_rustc_env_var!("ACMED_TLS_LIB_NAME", "OpenSSL");
	}
	if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
		set_rustc_env_var!("ACMED_TLS_LIB_NAME", "LibreSSL");
	}
}
