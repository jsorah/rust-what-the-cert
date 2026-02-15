use openssl::ssl::SslRef;
use openssl::x509::X509;

use crate::models::CertificateInfo;

pub trait CertView {
    fn certificate_info(&self) -> CertificateInfo;
    fn dns_sans(&self) -> Vec<String>;
}

pub trait TlsSessionView {
    type Cert: CertView;

    fn cipher_description(&self) -> Option<String>;
    fn chain(&self) -> Vec<Self::Cert>;
    fn peer_certificate(&self) -> Option<Self::Cert>;
}

pub struct OpenSslSession<'a> {
    ssl: &'a SslRef,
}

impl<'a> OpenSslSession<'a> {
    pub fn new(ssl: &'a SslRef) -> Self {
        Self { ssl }
    }
}

pub struct OpenSslCert {
    cert: X509,
}

impl OpenSslCert {
    fn from_x509(cert: X509) -> Self {
        Self { cert }
    }
}

impl CertView for OpenSslCert {
    fn certificate_info(&self) -> CertificateInfo {
        CertificateInfo::new(self.cert.as_ref())
    }

    fn dns_sans(&self) -> Vec<String> {
        self.cert
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.dnsname().map(|dns| dns.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl TlsSessionView for OpenSslSession<'_> {
    type Cert = OpenSslCert;

    fn cipher_description(&self) -> Option<String> {
        self.ssl
            .current_cipher()
            .map(|cipher| cipher.description().to_string())
    }

    fn chain(&self) -> Vec<Self::Cert> {
        self.ssl
            .peer_cert_chain()
            .map(|chain| {
                chain
                    .iter()
                    .map(|cert| cert.to_owned())
                    .map(OpenSslCert::from_x509)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn peer_certificate(&self) -> Option<Self::Cert> {
        self.ssl
            .peer_certificate()
            .map(OpenSslCert::from_x509)
    }
}
