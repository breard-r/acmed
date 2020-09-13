use std::env;

macro_rules! set_rustc_env_var {
    ($name: expr, $value: expr) => {{
        println!("cargo:rustc-env={}={}", $name, $value);
    }};
}

fn main() {
    if let Ok(_) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        set_rustc_env_var!("ACMED_TLS_LIB_NAME", "OpenSSL");
    }
    if let Ok(_) = env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        set_rustc_env_var!("ACMED_TLS_LIB_NAME", "LibreSSL");
    }
}
