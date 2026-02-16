use chrono::{DateTime, Utc};
use oid_registry::{Oid, OidRegistry};
use std::str::FromStr;
use std::sync::LazyLock;
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

static OID_REGISTRY: LazyLock<OidRegistry<'static>> = LazyLock::new(|| {
    OidRegistry::default()
        .with_x500()
        .with_x509()
        .with_pkcs9()
        .with_ms_spc()
});

fn openssl_short_name(oid: &str) -> Option<&'static str> {
    match oid {
        "2.5.4.3" => Some("CN"),
        "2.5.4.4" => Some("SN"),
        "2.5.4.5" => Some("serialNumber"),
        "2.5.4.6" => Some("C"),
        "2.5.4.7" => Some("L"),
        "2.5.4.8" => Some("ST"),
        "2.5.4.9" => Some("street"),
        "2.5.4.10" => Some("O"),
        "2.5.4.11" => Some("OU"),
        "2.5.4.12" => Some("title"),
        "2.5.4.15" => Some("businessCategory"),
        "2.5.4.17" => Some("postalCode"),
        "2.5.4.42" => Some("GN"),
        "2.5.4.43" => Some("initials"),
        "2.5.4.46" => Some("dnQualifier"),
        "2.5.4.97" => Some("organizationIdentifier"),
        "0.9.2342.19200300.100.1.1" => Some("UID"),
        "0.9.2342.19200300.100.1.25" => Some("DC"),
        "1.2.840.113549.1.9.1" => Some("emailAddress"),
        "1.3.6.1.4.1.311.60.2.1.1" => Some("jurisdictionL"),
        "1.3.6.1.4.1.311.60.2.1.2" => Some("jurisdictionST"),
        "1.3.6.1.4.1.311.60.2.1.3" => Some("jurisdictionC"),
        _ => None,
    }
}

fn oid_readable_name(oid: &str) -> String {
    if let Some(name) = openssl_short_name(oid) {
        return name.to_string();
    }

    Oid::from_str(oid)
        .ok()
        .and_then(|parsed_oid| {
            OID_REGISTRY
                .get(&parsed_oid)
                .map(|entry| entry.sn().to_string())
        })
        .unwrap_or_else(|| oid.to_string())
}

pub fn stringify_entry(entry: &X509Name<'_>) -> String {
    entry
        .iter_attributes()
        .map(|item| {
            let name = oid_readable_name(&item.attr_type().to_id_string());
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

#[cfg(test)]
mod tests {
    use super::oid_readable_name;

    #[test]
    fn uses_openssl_short_names_for_common_subject_fields() {
        assert_eq!(oid_readable_name("2.5.4.3"), "yCN");
        assert_eq!(oid_readable_name("2.5.4.6"), "C");
        assert_eq!(oid_readable_name("2.5.4.10"), "O");
        assert_eq!(oid_readable_name("2.5.4.11"), "OU");
        assert_eq!(oid_readable_name("0.9.2342.19200300.100.1.25"), "DC");
        assert_eq!(oid_readable_name("1.2.840.113549.1.9.1"), "emailAddress");
        assert_eq!(
            oid_readable_name("1.3.6.1.4.1.311.60.2.1.1"),
            "jurisdictionL"
        );
        assert_eq!(
            oid_readable_name("1.3.6.1.4.1.311.60.2.1.2"),
            "jurisdictionST"
        );
        assert_eq!(
            oid_readable_name("1.3.6.1.4.1.311.60.2.1.3"),
            "jurisdictionC"
        );
    }
}
