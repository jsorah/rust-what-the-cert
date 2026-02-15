use chrono::{DateTime, Utc};
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::x509::X509Name;

use crate::models::{CertificateInfo, ParsedCertificate};

pub fn hexify_fingerprint(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn oid_short_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".to_string(),
        "2.5.4.6" => "C".to_string(),
        "2.5.4.7" => "L".to_string(),
        "2.5.4.8" => "ST".to_string(),
        "2.5.4.10" => "O".to_string(),
        "2.5.4.11" => "OU".to_string(),
        "1.2.840.113549.1.9.1" => "emailAddress".to_string(),
        _ => oid.to_string(),
    }
}

pub fn stringify_entry(entry: &X509Name<'_>) -> String {
    entry
        .iter_attributes()
        .map(|item| {
            let name = oid_short_name(&item.attr_type().to_id_string());
            let value = item.as_str().unwrap_or("");
            format!("/{name}={value}")
        })
        .collect::<String>()
}

pub fn asn1time_to_datetime(epoch: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(epoch, 0).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

pub fn parse_der_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| format!("X509 parse failed: {e}"))?;

    let serial_number = cert.raw_serial_as_string();
    let issuer = stringify_entry(cert.issuer());
    let subject = stringify_entry(cert.subject());
    let not_before = asn1time_to_datetime(cert.validity().not_before.timestamp());
    let not_after = asn1time_to_datetime(cert.validity().not_after.timestamp());

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(ParsedCertificate {
        info: CertificateInfo {
            serial_number,
            issuer,
            subject,
            not_before,
            not_after,
            fingerprint_md5: None,
            fingerprint_sha256: String::new(),
        },
        dns_sans: sans,
    })
}
