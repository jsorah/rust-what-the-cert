use crate::openssl_util::{asn1time_to_datetime, hexify_fingerprint, stringify_entry};
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;

pub struct CertificateInfo {
    pub serial_number: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_md5: String,
    pub fingerprint_sha256: String,
}

impl CertificateInfo {
    pub fn new(cert: &openssl::x509::X509Ref) -> Self {
        CertificateInfo {
            serial_number: cert
                .serial_number()
                .to_bn()
                .and_then(|bn| bn.to_hex_str())
                .unwrap()
                .to_string(),
            issuer: stringify_entry(cert.issuer_name()),
            subject: stringify_entry(cert.subject_name()),
            not_before: asn1time_to_datetime(cert.not_before()),
            not_after: asn1time_to_datetime(cert.not_after()),
            fingerprint_md5: hexify_fingerprint(&cert.digest(MessageDigest::md5()).expect("Opes")),
            fingerprint_sha256: hexify_fingerprint(
                &cert.digest(MessageDigest::sha256()).expect("Opes"),
            ),
        }
    }
}
