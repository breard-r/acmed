use std::env;
use std::path::PathBuf;

macro_rules! set_rustc_env_var {
	($name: expr, $value: expr) => {{
		println!("cargo:rustc-env={}={}", $name, $value);
	}};
}

macro_rules! set_env_var_if_absent {
	($name: expr, $default_value: expr) => {{
		if let Err(_) = env::var($name) {
			set_rustc_env_var!($name, $default_value);
		}
	}};
}

macro_rules! set_specific_path_if_absent {
	($env_name: expr, $env_default: expr, $name: expr, $default_value: expr) => {{
		let prefix = env::var($env_name).unwrap_or(String::from($env_default));
		let mut value = PathBuf::new();
		value.push(prefix);
		value.push($default_value);
		set_env_var_if_absent!($name, value.to_str().unwrap());
	}};
}

macro_rules! set_runstate_path_if_absent {
	($name: expr, $default_value: expr) => {{
		set_specific_path_if_absent!("RUNSTATEDIR", "/run", $name, $default_value);
	}};
}

fn main() {
	if let Ok(target) = env::var("TARGET") {
		println!("cargo:rustc-env=TACD_TARGET={}", target);
	};

	set_runstate_path_if_absent!("TACD_DEFAULT_PID_FILE", "tacd.pid");
}
