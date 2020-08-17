pub fn sha256(data: &[u8]) -> Vec<u8> {
    openssl::sha::sha256(data).to_vec()
}

pub fn sha384(data: &[u8]) -> Vec<u8> {
    openssl::sha::sha384(data).to_vec()
}
