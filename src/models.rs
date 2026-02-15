use crate::cert_util::{hexify_fingerprint, parse_der_certificate};
use chrono::{DateTime, Utc};
use md5::Md5;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct CertificateInfo {
    pub serial_number: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_md5: Option<String>,
    pub fingerprint_sha256: String,
}

#[derive(Clone)]
pub struct ParsedCertificate {
    pub info: CertificateInfo,
    pub dns_sans: Vec<String>,
}

impl CertificateInfo {
    pub fn from_der(der: &[u8], include_md5: bool) -> Result<ParsedCertificate, String> {
        let mut parsed = parse_der_certificate(der)?;

        if include_md5 {
            let mut hasher_md5 = Md5::new();
            hasher_md5.update(der);
            parsed.info.fingerprint_md5 = Some(hexify_fingerprint(&hasher_md5.finalize()));
        }

        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(der);
        parsed.info.fingerprint_sha256 = hexify_fingerprint(&hasher_sha256.finalize());

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    fn generate_test_cert_der() -> Vec<u8> {
        let certified =
            generate_simple_self_signed(vec!["example.com".to_string()]).expect("generate cert");
        certified.cert.der().to_vec()
    }

    #[test]
    fn certificate_info_reads_expected_fields_from_der() {
        let der = generate_test_cert_der();
        let parsed = CertificateInfo::from_der(&der, true).expect("parse certificate");

        assert!(parsed.info.issuer.contains("/CN="));
        assert!(parsed.info.subject.contains("/CN="));
        assert!(!parsed.info.serial_number.is_empty());
        assert!(parsed.info.not_after > parsed.info.not_before);
        assert!(
            parsed
                .info
                .fingerprint_md5
                .as_deref()
                .unwrap_or("")
                .contains(':')
        );
        assert!(parsed.info.fingerprint_sha256.contains(':'));
    }
}
