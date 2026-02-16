# what-the-cert

`what-the-cert` is a terse CLI for quickly inspecting the TLS certificates a host actually serves.

This project started as a C++ + OpenSSL utility and was rebuilt in Rust to keep the same "fast, directed lookup" workflow:
- connect to a host and print certificate details without noise
- see the peer certificate and full presented chain
- optionally "pretend" to be another hostname with custom SNI and compare behavior

## Why

Use this when you need fast answers to questions like:
- What cert chain is this endpoint really presenting right now?
- Does cert selection change when SNI changes?
- How long until expiry?
- What are the certificate fingerprints and SANs?

## Install / Run

### From source

```bash
cargo run -- --host example.com
```

### Build binary

```bash
cargo build --release
./target/release/what-the-cert --host example.com
```

## Usage

```text
Usage: what-the-cert [OPTIONS] --host <HOST>

Options:
      --host <HOST>
      --port <PORT>                              [default: 443]
      --sni-value <SNI_VALUE>
      --show-sans
      --show-md5
      --peer-only
      --connection-timeout <CONNECTION_TIMEOUT>  [default: 5]
      --insecure
  -h, --help
  -V, --version
```

## Common examples

Inspect a normal endpoint:

```bash
what-the-cert --host example.com
```

Connect to an IP but send specific SNI:

```bash
what-the-cert --host 203.0.113.10 --sni-value example.com
```

Compare SNI behavior quickly:

```bash
what-the-cert --host 203.0.113.10 --sni-value app.example.com
what-the-cert --host 203.0.113.10 --sni-value admin.example.com
```

Show SANs and MD5 in addition to SHA-256:

```bash
what-the-cert --host example.com --show-sans --show-md5
```

Show only peer certificate details:

```bash
what-the-cert --host example.com --peer-only
```

Skip certificate verification (debugging only):

```bash
what-the-cert --host example.com --insecure
```

## Notes

- Default verification uses platform trust stores.
- `--insecure` disables certificate verification and should only be used for diagnostics.
- Output includes negotiated protocol/cipher, validity windows, age, time-to-expiry, and fingerprints.
