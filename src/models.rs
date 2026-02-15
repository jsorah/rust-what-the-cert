use crate::openssl_util::{asn1time_to_datetime, hexify_fingerprint, stringify_entry};
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;

#[derive(Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509, X509NameBuilder};

    fn build_test_cert() -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();

        let serial = BigNum::from_u32(42).unwrap();
        let serial = Asn1Integer::from_bn(&serial).unwrap();
        builder.set_serial_number(&serial).unwrap();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::from_unix(
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        let not_after = Asn1Time::from_unix(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let san = SubjectAlternativeName::new()
            .dns("example.com")
            .dns("www.example.com")
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn certificate_info_reads_expected_fields_from_real_x509() {
        let cert = build_test_cert();

        let info = CertificateInfo::new(cert.as_ref());

        assert_eq!(info.serial_number, "2A");
        assert!(info.issuer.contains("/CN=example.com"));
        assert!(info.subject.contains("/CN=example.com"));
        assert_eq!(info.not_before.year(), 2025);
        assert_eq!(info.not_after.year(), 2026);
        assert!(info.fingerprint_md5.contains(':'));
        assert!(info.fingerprint_sha256.contains(':'));
    }
}
