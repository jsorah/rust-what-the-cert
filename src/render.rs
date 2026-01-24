use chrono::{Local, Utc};

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

    fn render_cert_fingerprints(cert: &CertificateInfo) {
        println!("{:<LABEL_WIDTH$}", "Fingerprints");
        println!("{:>LABEL_WIDTH$}{}", "SHA256:  ", cert.fingerprint_sha256);
        println!("{:>LABEL_WIDTH$}{}", "MD5SUM:  ", cert.fingerprint_md5);
    }

    fn render_cert(certificate_info: &CertificateInfo) {
        println!("{:<LABEL_WIDTH$}{}", "Issuer:", certificate_info.issuer);
        println!("{:<LABEL_WIDTH$}{}", "Subject:", certificate_info.subject);

        println!(
            "{:<LABEL_WIDTH$}{}",
            "Serial:", certificate_info.serial_number
        );

        println!(
            "{:<LABEL_WIDTH$}{} / {}",
            "Not Before:",
            certificate_info.not_before,
            certificate_info.not_before.with_timezone(&Local)
        );
        println!(
            "{:<LABEL_WIDTH$}{} / {}",
            "Not After:",
            certificate_info.not_after,
            certificate_info.not_after.with_timezone(&Local)
        );

        // calculate age of cert

        let age = Utc::now() - certificate_info.not_before;

        println!("{:<LABEL_WIDTH$}{}", "Age:", dhms(age));

        // calculate cert lifetime left.

        let time_difference = certificate_info.not_after - Utc::now();

        println!("{:<LABEL_WIDTH$}{}", "Expires in:", dhms(time_difference));

        CliRender::render_cert_fingerprints(certificate_info);
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
