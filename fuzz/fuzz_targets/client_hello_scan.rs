#![no_main]
//! Fuzz `client_hello::scan` — the SNI-egress security boundary.
//!
//! Invariants checked on every input:
//!  - `scan` never panics (libfuzzer catches that for free);
//!  - `scan` is deterministic;
//!  - an accepted SNI is always a syntactically valid, lowercased DNS name;
//!  - the parser-differential check — when the rusticata `tls-parser`
//!    oracle extracts a host_name from the SAME bytes, it must equal ours.
//!    A mismatch is the CVE-2026-32305 bug class this proxy must not have.

use libfuzzer_sys::fuzz_target;

#[path = "../../src/client_hello.rs"]
mod client_hello;
use client_hello::{Scan, is_dns_name, scan};

fuzz_target!(|data: &[u8]| {
    let ours = scan(data);

    // scan must be a pure function of its input.
    assert_eq!(scan(data), ours, "scan is not deterministic");

    if let Scan::Done(Some(host)) = &ours {
        assert!(is_dns_name(host), "accepted a non-DNS host: {host:?}");
        assert_eq!(host, &host.to_ascii_lowercase(), "host not lowercased");

        // Differential: when a conformant parser also pulls a host_name
        // from these bytes, the two MUST agree.
        if let Some(oracle) = oracle_sni(data) {
            assert_eq!(*host, oracle, "SNI differential vs tls-parser");
        }
    }
});

/// Extract the SNI host_name with the rusticata `tls-parser` crate — the
/// differential oracle. Best-effort: returns None whenever it cannot pull
/// a host_name (multi-record inputs, anything it rejects). Only a positive
/// extraction is used, to cross-check ours.
fn oracle_sni(data: &[u8]) -> Option<String> {
    use tls_parser::{
        TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extensions,
        parse_tls_plaintext,
    };
    let (_, record) = parse_tls_plaintext(data).ok()?;
    for msg in &record.msg {
        let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
            continue;
        };
        let ext = ch.ext?;
        let (_, exts) = parse_tls_extensions(ext).ok()?;
        for e in exts {
            if let TlsExtension::SNI(names) = e {
                for (sni_type, name) in names {
                    // host_name is SNI name_type 0 (SNIType is a u8 newtype).
                    if sni_type.0 == 0 {
                        let s = std::str::from_utf8(name).ok()?;
                        return Some(s.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    None
}
