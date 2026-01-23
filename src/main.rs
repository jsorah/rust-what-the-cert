use clap::Parser;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
};
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

const LABEL_WIDTH: usize = 15;

fn stringify_entry(entry: &openssl::x509::X509NameRef) -> String {
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

fn hexify_fingerprint(digest: &openssl::hash::DigestBytes) -> String {
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
fn dump_cert_fingerprints(cert: &openssl::x509::X509Ref) {
    let sha256fingerprint = cert
        .digest(MessageDigest::sha256())
        .expect("Couldn't calculate fingerprint");

    let md5sumfingerprint = cert
        .digest(MessageDigest::md5())
        .expect("Couldn't calculate fingerprint");

    let hex = hexify_fingerprint(&sha256fingerprint);

    println!("{:<LABEL_WIDTH$}", "Fingerprints");
    println!("{:>LABEL_WIDTH$}{}", "SHA256:  ", hex);
    println!(
        "{:>LABEL_WIDTH$}{}",
        "MD5SUM:  ",
        hexify_fingerprint(&md5sumfingerprint)
    );
}

fn dump_cert(cert: &openssl::x509::X509Ref) {
    let certificate_info = CertificateInfo::new(cert);

    // TODO - need to make these a bit better
    println!("{:<LABEL_WIDTH$}{}", "Issuer:", certificate_info.issuer);
    println!("{:<LABEL_WIDTH$}{}", "Subject:", certificate_info.subject);

    println!(
        "{:<LABEL_WIDTH$}{}",
        "Serial:", certificate_info.serial_number
    );

    println!("{:<LABEL_WIDTH$}{}", "Not Before:", cert.not_before());
    println!("{:<LABEL_WIDTH$}{}", "Not After:", cert.not_after());

    // calculate cert lifetime left.
    let now = Asn1Time::days_from_now(0).expect("Couldn't get now.");

    match now.diff(&cert.not_after()) {
        Ok(time_difference) => {
            let hours = time_difference.secs / 3600;
            let minutes = (time_difference.secs % 3600) / 60;
            let seconds = time_difference.secs % 60;

            println!(
                "{:<LABEL_WIDTH$}{}d {}h {}m {}s",
                "Expires in:", time_difference.days, hours, minutes, seconds
            );
        }
        Err(err) => println!("Expires in: Could not be calculated due to {:?}", err),
    }
}

struct CertificateInfo {
    serial_number: String,
    issuer: String,
    subject: String,
    // not_before: DateTime<Utc>,
    // not_after: DateTime<Utc>,
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
            // not_before: cert.not_before().to_datetime()
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long, default_value = "443")]
    port: String,

    #[arg(long)]
    sni_value: Option<String>,

    #[arg(long)]
    show_sans: bool,

    #[arg(long)]
    peer_only: bool,

    #[arg(long, default_value_t = 5)]
    connection_timeout: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let host = args.host;
    let port = args.port;
    let sni_value = args.sni_value.unwrap_or_else(|| host.clone());
    let addr = format!("{}:{}", host, port);

    println!("Connecting to {} with SNI value of {}", addr, sni_value);

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);

    let connector = connector.build();
    let addr = Iterator::next(&mut addr.to_socket_addrs()?).expect("Could not resolve address");
    let stream = TcpStream::connect_timeout(&addr, Duration::new(args.connection_timeout, 0))?;
    let ssl_stream = connector.connect(&sni_value, stream)?;

    if let Some(cipher) = ssl_stream.ssl().current_cipher() {
        println!("Negotiated Cipher: {}", cipher.description());
    }

    println!();

    if let Some(cert_chain) = ssl_stream.ssl().peer_cert_chain() {
        println!("Chained Certificates [{}]", cert_chain.len());

        if !args.peer_only {
            println!("-----------------------");

            for cert in cert_chain.iter().rev() {
                dump_cert(cert);
                dump_cert_fingerprints(cert);
                println!("\n");
            }
        }
        println!();
    }

    println!("Peer Certificate");
    println!("-----------------------");

    match ssl_stream.ssl().peer_certificate() {
        Some(peer_cert) => {
            dump_cert(&peer_cert);
            dump_cert_fingerprints(&peer_cert);

            println!();

            match peer_cert.subject_alt_names() {
                Some(names) => {
                    println!("Subject Alternative Names [{}]", names.len());
                    if args.show_sans {
                        println!("-------------------");
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

    Ok(())
}
