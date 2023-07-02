use acme_common::crypto::{KeyPair, X509Certificate};
use anyhow::{bail, Result};
use log::debug;
use openssl::ssl::{self, AlpnError, SslAcceptor, SslMethod};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

#[cfg(target_family = "unix")]
use std::os::unix::net::UnixListener;

#[cfg(ossl110)]
const ALPN_ERROR: AlpnError = AlpnError::ALERT_FATAL;
#[cfg(not(ossl110))]
const ALPN_ERROR: AlpnError = AlpnError::NOACK;

macro_rules! listen_and_accept {
	($lt: ident, $addr: ident, $acceptor: ident) => {
		let listener = $lt::bind($addr)?;
		for stream in listener.incoming() {
			if let Ok(stream) = stream {
				let acceptor = $acceptor.clone();
				thread::spawn(move || {
					debug!("new client");
					let _ = acceptor.accept(stream).unwrap();
				});
			};
		}
	};
}

pub fn start(listen_addr: &str, certificate: &X509Certificate, key_pair: &KeyPair) -> Result<()> {
	let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
	acceptor.set_alpn_select_callback(|_, client| {
		debug!("ALPN negociation");
		ssl::select_next_proto(crate::ALPN_ACME_PROTO_NAME, client).ok_or(ALPN_ERROR)
	});
	acceptor.set_private_key(&key_pair.inner_key)?;
	acceptor.set_certificate(&certificate.inner_cert)?;
	acceptor.check_private_key()?;
	let acceptor = Arc::new(acceptor.build());
	if cfg!(unix) && listen_addr.starts_with("unix:") {
		let listen_addr = &listen_addr[5..];
		debug!("listening on unix socket {listen_addr}");
		listen_and_accept!(UnixListener, listen_addr, acceptor);
	} else {
		debug!("listening on {listen_addr}");
		listen_and_accept!(TcpListener, listen_addr, acceptor);
	}
	bail!("main thread loop unexpectedly exited")
}
