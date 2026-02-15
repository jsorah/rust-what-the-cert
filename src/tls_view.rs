use chrono::Utc;
use rustls::ClientConnection;

use crate::models::{CertificateInfo, ParsedCertificate};

pub trait CertView {
    fn certificate_info(&self) -> &CertificateInfo;
    fn dns_sans(&self) -> &[String];
}

pub trait TlsSessionView {
    type Cert: CertView + Clone;

    fn cipher_description(&self) -> Option<String>;
    fn chain_len(&self) -> usize;
    fn chain(&self) -> Vec<Self::Cert>;
    fn peer_certificate(&self) -> Option<Self::Cert>;
}

pub struct RustlsSessionView<'a> {
    conn: &'a ClientConnection,
    include_md5: bool,
}

impl<'a> RustlsSessionView<'a> {
    pub fn new(conn: &'a ClientConnection, include_md5: bool) -> Self {
        Self { conn, include_md5 }
    }
}

#[derive(Clone)]
pub struct RustlsCert {
    parsed: ParsedCertificate,
}

impl RustlsCert {
    fn from_der(der: &[u8], include_md5: bool) -> Self {
        let parsed =
            CertificateInfo::from_der(der, include_md5).unwrap_or_else(|err| ParsedCertificate {
                info: CertificateInfo {
                    serial_number: "unknown".to_string(),
                    issuer: format!("parse error: {err}"),
                    subject: "unknown".to_string(),
                    not_before: Utc::now(),
                    not_after: Utc::now(),
                    fingerprint_md5: None,
                    fingerprint_sha256: String::new(),
                },
                dns_sans: Vec::new(),
            });

        Self { parsed }
    }
}

impl CertView for RustlsCert {
    fn certificate_info(&self) -> &CertificateInfo {
        &self.parsed.info
    }

    fn dns_sans(&self) -> &[String] {
        &self.parsed.dns_sans
    }
}

impl TlsSessionView for RustlsSessionView<'_> {
    type Cert = RustlsCert;

    fn cipher_description(&self) -> Option<String> {
        self.conn
            .negotiated_cipher_suite()
            .map(|cipher| format!("{:?}", cipher.suite()))
    }

    fn chain_len(&self) -> usize {
        self.conn
            .peer_certificates()
            .map(|chain| chain.len())
            .unwrap_or_default()
    }

    fn chain(&self) -> Vec<Self::Cert> {
        self.conn
            .peer_certificates()
            .map(|chain| {
                chain
                    .iter()
                    .map(|cert| RustlsCert::from_der(cert.as_ref(), self.include_md5))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn peer_certificate(&self) -> Option<Self::Cert> {
        self.conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| RustlsCert::from_der(cert.as_ref(), self.include_md5))
    }
}
