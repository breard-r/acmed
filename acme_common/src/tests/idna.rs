use crate::to_idna;

#[test]
fn test_no_idna() {
    let idna_res = to_idna("HeLo.example.com");
    assert!(idna_res.is_ok());
    assert_eq!(idna_res.unwrap(), "helo.example.com");
}

#[test]
fn test_simple_idna() {
    let idna_res = to_idna("Hélo.Example.com");
    assert!(idna_res.is_ok());
    assert_eq!(idna_res.unwrap(), "xn--hlo-bma.example.com");
}

#[test]
fn test_multiple_idna() {
    let idna_res = to_idna("ns1.hÉlo.aç-éièè.example.com");
    assert!(idna_res.is_ok());
    assert_eq!(
        idna_res.unwrap(),
        "ns1.xn--hlo-bma.xn--a-i-2lahae.example.com"
    );
}

#[test]
fn test_already_idna() {
    let idna_res = to_idna("xn--hlo-bma.example.com");
    assert!(idna_res.is_ok());
    assert_eq!(idna_res.unwrap(), "xn--hlo-bma.example.com");
}

#[test]
fn test_mixed_idna_parts() {
    let idna_res = to_idna("ns1.xn--hlo-bma.aç-éièè.example.com");
    assert!(idna_res.is_ok());
    assert_eq!(
        idna_res.unwrap(),
        "ns1.xn--hlo-bma.xn--a-i-2lahae.example.com"
    );
}
