use chrono::{DateTime, Utc};
use openssl::asn1::{Asn1Time, Asn1TimeRef};

pub fn hexify_fingerprint(digest: &openssl::hash::DigestBytes) -> String {
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn asn1time_to_datetime(source: &Asn1TimeRef) -> DateTime<Utc> {
    let not_before_asn1time = Asn1Time::from_unix(0).unwrap().diff(source).unwrap();

    let epoch = not_before_asn1time.secs + not_before_asn1time.days * 86_400;

    DateTime::<Utc>::from_timestamp(epoch as i64, 0).unwrap()
}

pub fn stringify_entry(entry: &openssl::x509::X509NameRef) -> String {
    entry
        .entries()
        .map(|item| {
            let name = item.object().nid().short_name().unwrap_or("");
            let value: String = item
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_default();

            format!("/{name}={}", value)
        })
        .collect::<String>()
}
