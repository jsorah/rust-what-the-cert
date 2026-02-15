use chrono::{DateTime, Local, Utc};

use crate::models::CertificateInfo;

const LABEL_WIDTH: usize = 15;
const DAY_IN_SECONDS: i64 = 86_400;
const HOUR_IN_SECONDS: i64 = 3_600;

pub struct RenderOpts {
    pub show_sans: bool,
    pub peer_only: bool,
}

fn dhms(d: chrono::Duration) -> String {
    let mut secs = d.num_seconds().max(0);

    let days = secs / DAY_IN_SECONDS;
    secs %= DAY_IN_SECONDS;
    let hours = secs / HOUR_IN_SECONDS;
    secs %= HOUR_IN_SECONDS;
    let minutes = secs / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }

    parts.join(" ")
}

pub struct CliRender {}

impl CliRender {
    fn divider(width: usize) {
        println!("{}", "-".repeat(width));
    }

    fn format_cert_fingerprints(cert: &CertificateInfo) -> String {
        let mut out = String::new();
        out.push_str(&format!("{:<LABEL_WIDTH$}\n", "Fingerprints"));
        out.push_str(&format!("{:>LABEL_WIDTH$}{}\n", "SHA256:  ", cert.fingerprint_sha256));
        out.push_str(&format!("{:>LABEL_WIDTH$}{}\n", "MD5SUM:  ", cert.fingerprint_md5));
        out
    }

    fn format_cert(certificate_info: &CertificateInfo, now: DateTime<Utc>) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{}\n",
            "Issuer:", certificate_info.issuer
        ));
        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{}\n",
            "Subject:", certificate_info.subject
        ));

        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{}\n",
            "Serial:", certificate_info.serial_number
        ));

        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{} / {}\n",
            "Not Before:",
            certificate_info.not_before,
            certificate_info.not_before.with_timezone(&Local)
        ));
        out.push_str(&format!(
            "{:<LABEL_WIDTH$}{} / {}\n",
            "Not After:",
            certificate_info.not_after,
            certificate_info.not_after.with_timezone(&Local)
        ));

        let age = now - certificate_info.not_before;
        out.push_str(&format!("{:<LABEL_WIDTH$}{}\n", "Age:", dhms(age)));

        let time_difference = certificate_info.not_after - now;
        out.push_str(&format!("{:<LABEL_WIDTH$}{}\n", "Expires in:", dhms(time_difference)));

        out.push_str(&Self::format_cert_fingerprints(certificate_info));

        out
    }

    fn render_cert(certificate_info: &CertificateInfo) {
        print!("{}", Self::format_cert(certificate_info, Utc::now()));
    }

    pub fn render(ssl_stream_ssl: &openssl::ssl::SslRef, opts: RenderOpts) {
        if let Some(cipher) = ssl_stream_ssl.current_cipher() {
            println!("Negotiated Cipher: {}", cipher.description());
        }

        println!();

        if let Some(cert_chain) = ssl_stream_ssl.peer_cert_chain() {
            println!("Chained Certificates [{}]", cert_chain.len());

            if !opts.peer_only {
                CliRender::divider(20);

                for cert in cert_chain.iter().rev() {
                    let certificate_info = CertificateInfo::new(cert);
                    CliRender::render_cert(&certificate_info);
                    println!();
                }
            }
            println!();
        }

        println!("Peer Certificate");
        CliRender::divider(20);

        match ssl_stream_ssl.peer_certificate() {
            Some(peer_cert) => {
                let certificate_info = CertificateInfo::new(&peer_cert);
                CliRender::render_cert(&certificate_info);
                println!();

                match peer_cert.subject_alt_names() {
                    Some(names) => {
                        println!("Subject Alternative Names [{}]", names.len());
                        if opts.show_sans {
                            CliRender::divider(20);
                            for x in names {
                                if let Some(dnsname) = x.dnsname() {
                                    println!("{}", dnsname)
                                }
                            }
                        }
                    }
                    None => println!("Subject Alternative Names [0]"),
                }
            }
            None => println!("No certificate received."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn sample_cert_info() -> CertificateInfo {
        CertificateInfo {
            serial_number: "ABC123".to_string(),
            issuer: "/CN=Example Issuer".to_string(),
            subject: "/CN=example.com".to_string(),
            not_before: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            fingerprint_md5: "AA:BB".to_string(),
            fingerprint_sha256: "11:22".to_string(),
        }
    }

    #[test]
    fn dhms_formats_expected_units() {
        assert_eq!(dhms(Duration::seconds(0)), "0s");
        assert_eq!(dhms(Duration::seconds(59)), "59s");
        assert_eq!(dhms(Duration::seconds(61)), "1m 1s");
        assert_eq!(dhms(Duration::seconds(86_400 + 3_600 + 65)), "1d 1h 1m 5s");
    }

    #[test]
    fn dhms_clamps_negative_to_zero() {
        assert_eq!(dhms(Duration::seconds(-5)), "0s");
    }

    #[test]
    fn format_cert_includes_expected_labels_and_values() {
        let cert = sample_cert_info();
        let now = Utc.with_ymd_and_hms(2025, 1, 2, 1, 1, 5).unwrap();

        let output = CliRender::format_cert(&cert, now);

        assert!(output.contains("Issuer:"));
        assert!(output.contains("/CN=Example Issuer"));
        assert!(output.contains("Subject:"));
        assert!(output.contains("/CN=example.com"));
        assert!(output.contains("Serial:"));
        assert!(output.contains("ABC123"));
        assert!(output.contains("Age:"));
        assert!(output.contains("1d 1h 1m 5s"));
        assert!(output.contains("Expires in:"));
        assert!(output.contains("363d 22h 58m 55s"));
        assert!(output.contains("Fingerprints"));
        assert!(output.contains("SHA256:"));
        assert!(output.contains("11:22"));
        assert!(output.contains("MD5SUM:"));
        assert!(output.contains("AA:BB"));
    }
}
