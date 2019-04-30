use acme_common::error::Error;
use log::debug;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{self, AlpnError, SslAcceptor, SslMethod};
use openssl::x509::X509;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

#[cfg(ossl110)]
const ALPN_ERROR: AlpnError = AlpnError::ALERT_FATAL;
#[cfg(not(ossl110))]
const ALPN_ERROR: AlpnError = AlpnError::NOACK;

pub fn start(
    listen_addr: &str,
    certificate: &X509,
    private_key: &PKey<Private>,
) -> Result<(), Error> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    acceptor.set_alpn_select_callback(|_, client| {
        debug!("ALPN negociation");
        ssl::select_next_proto(crate::ALPN_ACME_PROTO_NAME, client).ok_or(ALPN_ERROR)
    });
    acceptor.set_private_key(private_key)?;
    acceptor.set_certificate(certificate)?;
    acceptor.check_private_key()?;
    let acceptor = Arc::new(acceptor.build());
    let listener = TcpListener::bind(listen_addr)?;
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let acceptor = acceptor.clone();
            thread::spawn(move || {
                debug!("New client");
                let _ = acceptor.accept(stream).unwrap();
            });
        };
    }
    Err("Main thread loop unexpectedly exited".into())
}
