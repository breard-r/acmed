use std::fmt;

#[derive(Clone, Debug)]
pub struct Error {
	pub message: String,
}

impl Error {
	pub fn prefix(&self, prefix: &str) -> Self {
		Error {
			message: format!("{}: {}", prefix, &self.message),
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl From<&str> for Error {
	fn from(error: &str) -> Self {
		Error {
			message: error.to_string(),
		}
	}
}

impl From<String> for Error {
	fn from(error: String) -> Self {
		error.as_str().into()
	}
}

impl From<&String> for Error {
	fn from(error: &String) -> Self {
		error.as_str().into()
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Self {
		format!("IO error: {}", error).into()
	}
}

impl From<std::net::AddrParseError> for Error {
	fn from(error: std::net::AddrParseError) -> Self {
		format!("{}", error).into()
	}
}

impl From<std::string::FromUtf8Error> for Error {
	fn from(error: std::string::FromUtf8Error) -> Self {
		format!("UTF-8 error: {}", error).into()
	}
}

impl From<std::sync::mpsc::RecvError> for Error {
	fn from(error: std::sync::mpsc::RecvError) -> Self {
		format!("MSPC receiver error: {}", error).into()
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(error: std::time::SystemTimeError) -> Self {
		format!("SystemTimeError difference: {:?}", error.duration()).into()
	}
}

impl From<base64::DecodeError> for Error {
	fn from(error: base64::DecodeError) -> Self {
		format!("base 64 decode error: {}", error).into()
	}
}

impl From<syslog::Error> for Error {
	fn from(error: syslog::Error) -> Self {
		format!("syslog error: {}", error).into()
	}
}

impl From<toml::de::Error> for Error {
	fn from(error: toml::de::Error) -> Self {
		format!("IO error: {}", error).into()
	}
}

impl From<serde_json::error::Error> for Error {
	fn from(error: serde_json::error::Error) -> Self {
		format!("IO error: {}", error).into()
	}
}

impl From<attohttpc::Error> for Error {
	fn from(error: attohttpc::Error) -> Self {
		format!("HTTP error: {}", error).into()
	}
}

impl From<glob::PatternError> for Error {
	fn from(error: glob::PatternError) -> Self {
		format!("pattern error: {}", error).into()
	}
}

impl From<tinytemplate::error::Error> for Error {
	fn from(error: tinytemplate::error::Error) -> Self {
		format!("template error: {}", error).into()
	}
}

#[cfg(feature = "crypto_openssl")]
impl From<native_tls::Error> for Error {
	fn from(error: native_tls::Error) -> Self {
		format!("{}", error).into()
	}
}

#[cfg(feature = "crypto_openssl")]
impl From<openssl::error::ErrorStack> for Error {
	fn from(error: openssl::error::ErrorStack) -> Self {
		format!("{}", error).into()
	}
}

#[cfg(unix)]
impl From<nix::Error> for Error {
	fn from(error: nix::Error) -> Self {
		format!("{}", error).into()
	}
}
