use ring::digest::{digest, SHA256};

pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}
