use crate::render::RenderOpts;
use clap::Parser;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

mod models;
mod openssl_util;
mod render;
mod tls_view;

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

    #[arg(long)]
    insecure: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let host = args.host;
    let port = args.port;
    let sni_value = args.sni_value.unwrap_or_else(|| host.clone());
    let addr = format!("{}:{}", host, port);

    println!("Connecting to {} with SNI value of {}", addr, sni_value);

    let mut connector = SslConnector::builder(SslMethod::tls())?;

    if args.insecure {
        connector.set_verify(SslVerifyMode::NONE);
        println!("Verification Disabled!");
    } else {
        connector.set_verify(SslVerifyMode::PEER);
        println!("Peer Verification");
    }

    let connector = connector.build();
    let addr = Iterator::next(&mut addr.to_socket_addrs()?).expect("Could not resolve address");
    let stream = TcpStream::connect_timeout(&addr, Duration::new(args.connection_timeout, 0))?;
    let ssl_stream = connector.connect(&sni_value, stream)?;

    let ssl_stream_ssl = ssl_stream.ssl();

    render::CliRender::render(
        ssl_stream_ssl,
        RenderOpts {
            show_sans: args.show_sans,
            peer_only: args.peer_only,
        },
    );

    Ok(())
}
