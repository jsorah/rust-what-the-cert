use crate::render::RenderOpts;
use clap::Parser;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::ConfigVerifierExt;
use std::sync::Arc;
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

mod cert_util;
mod models;
mod render;
mod tls_view;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long, default_value = "443")]
    port: String,

    #[arg(long)]
    sni_value: Option<String>,

    #[arg(long)]
    show_sans: bool,

    #[arg(long)]
    show_md5: bool,

    #[arg(long)]
    peer_only: bool,

    #[arg(long, default_value_t = 5)]
    connection_timeout: u64,

    #[arg(long)]
    insecure: bool,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn build_tls_config(insecure: bool) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    if insecure {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        Ok(Arc::new(config))
    } else {
        Ok(Arc::new(ClientConfig::with_platform_verifier()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let host = args.host;
    let port = args.port;
    let sni_value = args.sni_value.unwrap_or_else(|| host.clone());
    let addr = format!("{}:{}", host, port);

    println!("Connecting to {} with SNI value of {}", addr, sni_value);

    let config = build_tls_config(args.insecure)?;

    if args.insecure {
        println!("Verification Disabled!");
    } else {
        println!("Peer Verification");
    }

    let addr = Iterator::next(&mut addr.to_socket_addrs()?).ok_or("Could not resolve address")?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::new(args.connection_timeout, 0))?;

    stream.set_read_timeout(Some(Duration::new(args.connection_timeout, 0)))?;
    stream.set_write_timeout(Some(Duration::new(args.connection_timeout, 0)))?;

    let server_name = ServerName::try_from(sni_value)?;
    let mut conn = ClientConnection::new(config, server_name)?;

    while conn.is_handshaking() {
        let _ = conn.complete_io(&mut stream)?;
    }

    render::CliRender::render(
        &conn,
        RenderOpts {
            show_sans: args.show_sans,
            show_md5: args.show_md5,
            peer_only: args.peer_only,
        },
    );

    Ok(())
}
