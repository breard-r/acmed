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

impl From<handlebars::TemplateRenderError> for Error {
    fn from(error: handlebars::TemplateRenderError) -> Self {
        format!("Template error: {}", error).into()
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        format!("{}", error).into()
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        format!("HTTP error: {}", error).into()
    }
}

impl From<reqwest::header::InvalidHeaderName> for Error {
    fn from(error: reqwest::header::InvalidHeaderName) -> Self {
        format!("Invalid HTTP header name: {}", error).into()
    }
}

impl From<reqwest::header::InvalidHeaderValue> for Error {
    fn from(error: reqwest::header::InvalidHeaderValue) -> Self {
        format!("Invalid HTTP header value: {}", error).into()
    }
}

#[cfg(unix)]
impl From<nix::Error> for Error {
    fn from(error: nix::Error) -> Self {
        format!("{}", error).into()
    }
}
