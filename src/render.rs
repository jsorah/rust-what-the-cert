use chrono::{DateTime, Local, Utc};

use crate::models::CertificateInfo;
use crate::tls_view::{CertView, OpenSslSession, TlsSessionView};

const LABEL_WIDTH: usize = 15;
const DAY_IN_SECONDS: i64 = 86_400;
const HOUR_IN_SECONDS: i64 = 3_600;

#[derive(Clone, Copy)]
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
    fn divider(width: usize) -> String {
        format!("{}\n", "-".repeat(width))
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

    fn render_to_string<S: TlsSessionView>(session: &S, opts: RenderOpts, now: DateTime<Utc>) -> String {
        let mut out = String::new();

        if let Some(cipher) = session.cipher_description() {
            out.push_str(&format!("Negotiated Cipher: {cipher}\n"));
        }

        out.push('\n');

        let cert_chain = session.chain();
        if !cert_chain.is_empty() {
            out.push_str(&format!("Chained Certificates [{}]\n", cert_chain.len()));

            if !opts.peer_only {
                out.push_str(&Self::divider(20));

                for cert in cert_chain.iter().rev() {
                    let certificate_info = cert.certificate_info();
                    out.push_str(&Self::format_cert(&certificate_info, now));
                    out.push('\n');
                }
            }
            out.push('\n');
        }

        out.push_str("Peer Certificate\n");
        out.push_str(&Self::divider(20));

        match session.peer_certificate() {
            Some(peer_cert) => {
                let certificate_info = peer_cert.certificate_info();
                out.push_str(&Self::format_cert(&certificate_info, now));
                out.push('\n');

                let sans = peer_cert.dns_sans();
                out.push_str(&format!("Subject Alternative Names [{}]\n", sans.len()));
                if opts.show_sans {
                    out.push_str(&Self::divider(20));
                    for dns in sans {
                        out.push_str(&format!("{dns}\n"));
                    }
                }
            }
            None => out.push_str("No certificate received.\n"),
        }

        out
    }

    pub fn render(ssl_stream_ssl: &openssl::ssl::SslRef, opts: RenderOpts) {
        let session = OpenSslSession::new(ssl_stream_ssl);
        print!("{}", Self::render_to_string(&session, opts, Utc::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_view::{CertView, TlsSessionView};
    use chrono::{Duration, TimeZone};

    #[derive(Clone)]
    struct FakeCert {
        info: CertificateInfo,
        sans: Vec<String>,
    }

    impl CertView for FakeCert {
        fn certificate_info(&self) -> CertificateInfo {
            CertificateInfo {
                serial_number: self.info.serial_number.clone(),
                issuer: self.info.issuer.clone(),
                subject: self.info.subject.clone(),
                not_before: self.info.not_before,
                not_after: self.info.not_after,
                fingerprint_md5: self.info.fingerprint_md5.clone(),
                fingerprint_sha256: self.info.fingerprint_sha256.clone(),
            }
        }

        fn dns_sans(&self) -> Vec<String> {
            self.sans.clone()
        }
    }

    struct FakeSession {
        cipher: Option<String>,
        chain: Vec<FakeCert>,
        peer: Option<FakeCert>,
    }

    impl TlsSessionView for FakeSession {
        type Cert = FakeCert;

        fn cipher_description(&self) -> Option<String> {
            self.cipher.clone()
        }

        fn chain(&self) -> Vec<Self::Cert> {
            self.chain.clone()
        }

        fn peer_certificate(&self) -> Option<Self::Cert> {
            self.peer.clone()
        }
    }

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

    #[test]
    fn render_to_string_respects_peer_only_and_show_sans() {
        let cert = FakeCert {
            info: sample_cert_info(),
            sans: vec!["example.com".to_string(), "www.example.com".to_string()],
        };

        let session = FakeSession {
            cipher: Some("TLS_FAKE".to_string()),
            chain: vec![cert.clone()],
            peer: Some(cert),
        };

        let now = Utc.with_ymd_and_hms(2025, 1, 2, 1, 1, 5).unwrap();

        let hidden = CliRender::render_to_string(
            &session,
            RenderOpts {
                peer_only: true,
                show_sans: false,
            },
            now,
        );
        assert!(hidden.contains("Chained Certificates [1]"));
        assert!(!hidden.contains("www.example.com"));

        let shown = CliRender::render_to_string(
            &session,
            RenderOpts {
                peer_only: false,
                show_sans: true,
            },
            now,
        );

        assert!(shown.contains("Negotiated Cipher: TLS_FAKE"));
        assert!(shown.contains("Subject Alternative Names [2]"));
        assert!(shown.contains("example.com"));
        assert!(shown.contains("www.example.com"));
    }

    #[test]
    fn render_to_string_handles_missing_peer_cert() {
        let session = FakeSession {
            cipher: None,
            chain: Vec::new(),
            peer: None,
        };

        let now = Utc.with_ymd_and_hms(2025, 1, 2, 1, 1, 5).unwrap();
        let output = CliRender::render_to_string(
            &session,
            RenderOpts {
                peer_only: false,
                show_sans: true,
            },
            now,
        );

        assert!(output.contains("Peer Certificate"));
        assert!(output.contains("No certificate received."));
    }
}
