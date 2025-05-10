use clap::Parser;
use openssl::{
    asn1::Asn1Time,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
};
use std::net::TcpStream;

const LABEL_WIDTH: usize = 20;

fn dump_cert(cert: &openssl::x509::X509Ref) {
    // TODO - need to make these a bit better
    println!("{:<LABEL_WIDTH$}{:?}", "Issuer:", cert.issuer_name());
    println!("{:<LABEL_WIDTH$}{:?}", "Subject:", cert.subject_name());

    if let Ok(serial) = cert.serial_number().to_bn().and_then(|bn| bn.to_hex_str()) {
        println!("{:<LABEL_WIDTH$}{}", "Serial:", serial);
    }

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
                "{:20}{}d {}h {}m {}s",
                "Expires in:", time_difference.days, hours, minutes, seconds
            );
        }
        Err(err) => println!("Expires in: Could not be calculated due to {:?}", err),
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
    let stream = TcpStream::connect(&addr)?;
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

            println!();

            match peer_cert.subject_alt_names() {
                Some(names) => {
                    println!("Subject Alternative Names [{}]", names.len());
                    if args.show_sans {
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
