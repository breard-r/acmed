use crate::acme_proto::structs::Directory;

pub struct Endpoint {
    pub name: String,
    pub url: String,
    pub tos_agreed: bool,
    pub dir: Directory,
    pub nonce: Option<String>,
    // TODO: rate limits
}

impl Endpoint {
    pub fn new(name: &str, url: &str, tos_agreed: bool) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            tos_agreed,
            dir: Directory {
                meta: None,
                new_nonce: String::new(),
                new_account: String::new(),
                new_order: String::new(),
                new_authz: None,
                revoke_cert: String::new(),
                key_change: String::new(),
            },
            nonce: None,
        }
    }
}
