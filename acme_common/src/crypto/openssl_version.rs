pub fn get_lib_name() -> String {
    env!("ACMED_TLS_LIB_NAME").to_string()
}

pub fn get_lib_version() -> String {
    let v = openssl::version::number() as u64;
    let mut version = vec![];
    for i in 0..3 {
        let n = get_openssl_version_unit(v, i);
        version.push(format!("{}", n));
    }
    let version = version.join(".");
    let p = get_openssl_version_unit(v, 3);
    if p != 0 {
        let p = p + 0x60;
        let p = std::char::from_u32(p as u32).unwrap();
        format!("{}{}", version, p)
    } else {
        version
    }
}

fn get_openssl_version_unit(n: u64, pos: u32) -> u64 {
    let p = 0x000f_f000_0000 >> (8 * pos);
    let n = n & p;
    n >> (8 * (3 - pos) + 4)
}
