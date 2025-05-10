use clap::Parser;
use openssl::{
    asn1::Asn1Time,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
};
use std::net::TcpStream;

fn dump_cert(cert: &openssl::x509::X509Ref) {
    // TODO - need to make these a bit better
    println!("{:20}{:?}", "Issuer:", cert.issuer_name());
    println!("{:20}{:?}", "Subject:", cert.subject_name());

    if let Ok(serial) = cert.serial_number().to_bn().and_then(|bn| bn.to_hex_str()) {
        println!("{:20}{}", "Serial:", serial);
    }

    println!("{:20}{}", "Not Before:", cert.not_before().to_string());
    println!("{:20}{}", "Not After:", cert.not_after().to_string());

    // calculate cert lifetime left.
    let now = Asn1Time::days_from_now(0).expect("Couldn't get now.");

    let time_difference = now.diff(&cert.not_after()).expect("Time diff failed!");

    let hours = time_difference.secs / 3600;
    let minutes = (time_difference.secs % 3600) / 60;
    let seconds = time_difference.secs % 60;

    println!(
        "{:20}{}d {}h {}m {}s",
        "Expires in:", time_difference.days, hours, minutes, seconds
    );
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
    let sni_value = args.sni_value.unwrap_or(host.clone());
    let addr = format!("{}:{}", host, port);

    println!("Connecting to {} with SNI value of {}", addr, sni_value);

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);

    let connector = connector.build();
    let stream = TcpStream::connect(&addr)?;
    let ssl_stream = connector.connect(&sni_value, stream)?;

    println!(
        "Negotiated Cipher: {}",
        ssl_stream
            .ssl()
            .current_cipher()
            .expect("Oh no!")
            .description()
    );
    println!();
    let chain = ssl_stream.ssl().peer_cert_chain();

    if let Some(chain_stack) = chain {
        println!("Chained Certificates [{}]", chain_stack.len());
        
        if !args.peer_only {
            println!("-----------------------");

            for cert in chain_stack.iter().rev() {
                dump_cert(cert);
                println!("\n");
            }
        }
        println!();
    }

    let cert = ssl_stream.ssl().peer_certificate();

    println!("Peer Certificate");
    println!("-----------------------");

    if let Some(cert) = cert {
        dump_cert(&cert);

        println!();

        match cert.subject_alt_names() {
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
    } else {
        println!("No certificate received.");
    }

    Ok(())
}
