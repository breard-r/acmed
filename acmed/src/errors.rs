use std::fmt;

pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new(msg: &str) -> Self {
        Error {
            message: msg.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::new(&format!("IO error: {}", error))
    }
}

impl From<toml::de::Error> for Error {
    fn from(error: toml::de::Error) -> Self {
        Error::new(&format!("IO error: {}", error))
    }
}

impl From<acme_lib::Error> for Error {
    fn from(error: acme_lib::Error) -> Self {
        let msg = match error {
            acme_lib::Error::ApiProblem(e) => format!("An API call failed: {}", e),
            acme_lib::Error::Call(e) => format!("An API call failed: {}", e),
            acme_lib::Error::Base64Decode(e) => format!("base 64 decode error: {}", e),
            acme_lib::Error::Json(e) => format!("JSON error: {}", e),
            acme_lib::Error::Io(e) => format!("IO error: {}", e),
            acme_lib::Error::Other(s) => s,
        };
        Error::new(&msg)
    }
}

impl From<handlebars::TemplateRenderError> for Error {
    fn from(error: handlebars::TemplateRenderError) -> Self {
        Error::new(&format!("Template error: {}", error))
    }
}

#[cfg(unix)]
impl From<nix::Error> for Error {
    fn from(error: nix::Error) -> Self {
        Error::new(&format!("{}", error))
    }
}
