pub fn sha256(data: &[u8]) -> Vec<u8> {
    openssl::sha::sha256(data).to_vec()
}
