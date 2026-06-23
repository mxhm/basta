//! Minimal, bounded, fail-closed TLS ClientHello parsing — just enough to
//! extract the SNI host_name for egress allowlisting. Handles two framing
//! layers: TCP segmentation (caller feeds bytes incrementally) and TLS
//! record fragmentation (one handshake message spanning several records).
//!
//! It is STRICT and fail-closed: it rejects trailing bytes after any
//! length-delimited structure, a trailing TLS record after the
//! ClientHello, a duplicate server_name extension, a ServerNameList that
//! is not exactly one host_name entry, and the semantically invalid
//! length shapes (empty/odd cipher_suites, empty compression_methods,
//! over-long legacy_session_id) that a conformant endpoint also rejects.
//! This closes the parser-differential class (CVE-2026-32305) where a
//! lenient peek accepts an SNI a strict endpoint would parse differently.
#![forbid(unsafe_code)] // the parser's memory safety is a compile-time invariant

/// Hard cap on bytes peeked before giving up — a ClientHello past this is
/// treated as hostile.
pub const MAX_PEEK: usize = 64 * 1024;
/// Max TLS records a ClientHello may be fragmented across. Conformant
/// stacks emit it in ONE record; this bound only limits record-
/// fragmentation evasion. 32 is generous headroom over reality.
const MAX_RECORDS: usize = 32;
const REC_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
/// RFC 9180/draft Encrypted Client Hello. When present, the real SNI is in
/// the encrypted inner ClientHello; the outer `server_name` basta filters on
/// is a decoy a capable frontend ignores. Refuse it until intentionally
/// supported, so an allowlisted outer SNI can't tunnel to any inner host.
const EXT_ECH: u16 = 0xfe0d;
const SNI_TYPE_HOST: u8 = 0x00;

#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    /// Not enough bytes yet — read more and call again.
    Incomplete,
    /// A complete ClientHello was parsed: `Some` is the SNI host_name
    /// (lowercased), `None` a valid ClientHello with no SNI extension.
    Done(Option<String>),
    /// Malformed, not TLS, or caps exceeded — fail closed.
    Invalid,
}

/// Scan a prefix of the client's byte stream for the ClientHello SNI.
pub fn scan(buf: &[u8]) -> Scan {
    if buf.len() > MAX_PEEK {
        return Scan::Invalid;
    }
    // Reassemble handshake-layer bytes from consecutive handshake records.
    let mut hs: Vec<u8> = Vec::new();
    let mut off = 0usize;
    let mut records = 0usize;
    loop {
        let rest = &buf[off..];
        if rest.len() < 5 {
            return Scan::Incomplete; // need a full record header
        }
        if rest[0] != REC_HANDSHAKE {
            return Scan::Invalid; // not a handshake record
        }
        // rest[1..3] = legacy record version — ignored per RFC 8446 §5.1.
        let rec_len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if rec_len == 0 || rec_len > 16384 {
            return Scan::Invalid;
        }
        if rest.len() - 5 < rec_len {
            return Scan::Incomplete; // record body still arriving
        }
        hs.extend_from_slice(&rest[5..5 + rec_len]);
        off += 5 + rec_len;
        records += 1;
        if records > MAX_RECORDS || hs.len() > MAX_PEEK {
            return Scan::Invalid;
        }
        match handshake_message(&hs) {
            HsMsg::Incomplete => continue, // need another record
            HsMsg::Invalid => return Scan::Invalid,
            HsMsg::ClientHello(body) => {
                // The ClientHello is the client's entire first flight; any
                // bytes after it (a second record, junk, pipelined data)
                // are anomalous -> fail closed. This is the outermost of
                // the parser's four trailing-bytes checks.
                if off != buf.len() {
                    return Scan::Invalid;
                }
                return match try_parse(body) {
                    Some(sni) => Scan::Done(sni),
                    None => Scan::Invalid,
                };
            }
        }
    }
}

enum HsMsg<'a> {
    Incomplete,
    Invalid,
    ClientHello(&'a [u8]),
}

/// The reassembled handshake bytes: 4-byte header (type + uint24 len),
/// then the body. In the client's first flight the ClientHello is the
/// ONLY handshake message — so reassembled bytes longer than the declared
/// message are illegitimate (reject, do not silently slice).
fn handshake_message(hs: &[u8]) -> HsMsg<'_> {
    if hs.len() < 4 {
        return HsMsg::Incomplete;
    }
    if hs[0] != HS_CLIENT_HELLO {
        return HsMsg::Invalid;
    }
    let len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    let total = 4 + len;
    if total > MAX_PEEK {
        return HsMsg::Invalid;
    }
    if hs.len() < total {
        return HsMsg::Incomplete;
    }
    if hs.len() > total {
        return HsMsg::Invalid; // trailing handshake bytes past the ClientHello
    }
    HsMsg::ClientHello(&hs[4..total])
}

/// A forward-only cursor; every read is bounds-checked, None on underrun.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn at_end(&self) -> bool {
        self.i == self.b.len()
    }
}

/// Walk the ClientHello body. Returns Some(Some(host)) with an SNI,
/// Some(None) for a valid ClientHello with no SNI extension, None for
/// malformed input (→ fail closed).
fn try_parse(body: &[u8]) -> Option<Option<String>> {
    let mut c = Cur::new(body);
    c.take(2)?; // legacy_version
    c.take(32)?; // random
    // RFC 8446 §4.1.2 length constraints — reject the shapes a conformant
    // TLS stack would also reject, so basta's peek does not diverge from it.
    if c.vec8()?.len() > 32 {
        return None; // legacy_session_id: opaque<0..32>
    }
    let cipher_suites = c.vec16()?;
    if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
        return None; // CipherSuite cipher_suites<2..2^16-2>, 2 bytes each
    }
    if c.vec8()?.is_empty() {
        return None; // legacy_compression_methods<1..2^8-1>
    }
    // The extensions block may be absent entirely (a bare TLS 1.2
    // ClientHello) — valid, and means no SNI.
    let exts = match c.vec16() {
        Some(e) => e,
        None if c.at_end() => return Some(None),
        None => return None,
    };
    if !c.at_end() {
        return None; // trailing bytes after the extensions block
    }
    // Walk ALL extensions (do not return on the first SNI) so a duplicate
    // server_name extension can be detected and rejected.
    let mut e = Cur::new(exts);
    let mut sni_seen = false;
    let mut sni_host: Option<String> = None;
    while !e.at_end() {
        let ext_type = e.u16()?;
        let ext_body = e.vec16()?;
        if ext_type == EXT_ECH {
            return None; // ECH present → outer SNI is a decoy; fail closed
        }
        if ext_type == EXT_SERVER_NAME {
            if sni_seen {
                return None; // duplicate server_name extension (RFC 8446 §4.2)
            }
            sni_seen = true;
            // Present but malformed → fail closed.
            sni_host = Some(parse_sni(ext_body)?);
        }
    }
    Some(sni_host) // Some(host) → Done(Some); None (no ext) → Done(None)
}

/// server_name extension body: a 2-byte ServerNameList length, then the
/// entries. basta requires the list to be EXACTLY ONE host_name entry.
/// This is stricter than RFC 6066 §3 (which permits multiple entries of
/// differing name_type) — but `host_name` is the only name_type ever
/// standardised, and a single-entry rule removes a parser-differential
/// seam. Rejects: trailing bytes, an empty list, an unknown name_type,
/// and any second entry.
fn parse_sni(ext: &[u8]) -> Option<String> {
    let mut c = Cur::new(ext);
    let list = c.vec16()?;
    if !c.at_end() {
        return None; // trailing bytes after ServerNameList
    }
    let mut l = Cur::new(list);
    let name_type = l.u8()?; // empty list -> None here
    let name = l.vec16()?;
    if name_type != SNI_TYPE_HOST || !l.at_end() {
        return None; // unknown type, or a 2nd entry
    }
    sni_string(name)
}

/// The host_name must be a syntactically valid DNS name. Uses the SAME
/// validator as `--allow-sni` (egress.rs), so the wire side and the flag
/// side can never disagree.
fn sni_string(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?.to_ascii_lowercase();
    if is_dns_name(&s) { Some(s) } else { None }
}

/// True if `s` is a syntactically valid (already-lowercased) DNS hostname.
/// Shared by the parser and by `egress::validate_sni_host`.
pub fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ClientHello builders ---------------------------------------

    /// One TLS record around `payload` (handshake content type).
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![0x16, 0x03, 0x01];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    /// A handshake message frame: type 0x01, uint24 length, body.
    fn handshake(body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut h = vec![
            HS_CLIENT_HELLO,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ];
        h.extend_from_slice(body);
        h
    }

    /// A single host_name entry: name_type 0x00, uint16 name, name bytes.
    fn host_entry(host: &[u8]) -> Vec<u8> {
        let mut e = vec![SNI_TYPE_HOST];
        e.extend_from_slice(&(host.len() as u16).to_be_bytes());
        e.extend_from_slice(host);
        e
    }

    /// A server_name extension wrapping the given ServerNameList entries.
    fn sni_extension(entries: &[u8]) -> Vec<u8> {
        let mut list = (entries.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(entries);
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    /// A standard server_name extension for one host.
    fn sni_ext_for(host: &str) -> Vec<u8> {
        sni_extension(&host_entry(host.as_bytes()))
    }

    /// ClientHello body. `exts` = None ⇒ no extensions block at all.
    fn ch_body(exts: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0x03, 0x03]; // legacy_version
        b.extend_from_slice(&[0u8; 32]); // random
        b.push(0x00); // legacy_session_id (empty)
        b.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        b.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        if let Some(e) = exts {
            b.extend_from_slice(&(e.len() as u16).to_be_bytes());
            b.extend_from_slice(e);
        }
        b
    }

    /// A complete single-record ClientHello with the given SNI.
    fn full_ch(sni: &str) -> Vec<u8> {
        record(&handshake(&ch_body(Some(&sni_ext_for(sni)))))
    }

    /// Split `hs` (handshake bytes) into exactly `count` TLS records.
    fn records_exact(hs: &[u8], count: usize) -> Vec<u8> {
        assert!(count >= 1 && hs.len() >= count);
        let base = hs.len() / count;
        let mut out = Vec::new();
        let mut idx = 0;
        for i in 0..count {
            let end = if i == count - 1 { hs.len() } else { idx + base };
            out.extend_from_slice(&record(&hs[idx..end]));
            idx = end;
        }
        out
    }

    // --- happy path -------------------------------------------------

    #[test]
    fn parses_sni_lowercased() {
        assert_eq!(
            scan(&full_ch("API.Example.COM")),
            Scan::Done(Some("api.example.com".into()))
        );
    }

    #[test]
    fn no_extensions_block_is_done_none() {
        let ch = record(&handshake(&ch_body(None)));
        assert_eq!(scan(&ch), Scan::Done(None));
    }

    #[test]
    fn extensions_but_no_sni_is_done_none() {
        // One non-SNI extension (supported_versions, type 0x002b, empty).
        let ext = vec![0x00, 0x2b, 0x00, 0x00];
        let ch = record(&handshake(&ch_body(Some(&ext))));
        assert_eq!(scan(&ch), Scan::Done(None));
    }

    #[test]
    fn encrypted_client_hello_is_invalid() {
        // An allowlisted outer SNI alongside an ECH extension (0xfe0d) must
        // be refused — the real host is the encrypted inner SNI.
        let mut ext = sni_ext_for("api.example.com");
        ext.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x00]); // ECH, empty body
        let ch = record(&handshake(&ch_body(Some(&ext))));
        assert_eq!(scan(&ch), Scan::Invalid);
    }

    #[test]
    fn punycode_and_numeric_sni_accepted_by_parser() {
        assert_eq!(
            scan(&full_ch("xn--nxasmq6b.example")),
            Scan::Done(Some("xn--nxasmq6b.example".into()))
        );
        // All-numeric labels parse here; the allowlist is the second gate.
        assert_eq!(
            scan(&full_ch("123.456")),
            Scan::Done(Some("123.456".into()))
        );
    }

    // --- record fragmentation ---------------------------------------

    #[test]
    fn split_across_records() {
        let hs = handshake(&ch_body(Some(&sni_ext_for("split.example.com"))));
        for n in [2usize, 8, 32] {
            assert_eq!(
                scan(&records_exact(&hs, n)),
                Scan::Done(Some("split.example.com".into())),
                "n={n}"
            );
        }
    }

    #[test]
    fn too_many_records_is_invalid() {
        let hs = handshake(&ch_body(Some(&sni_ext_for("many.example.com"))));
        assert_eq!(scan(&records_exact(&hs, 33)), Scan::Invalid);
    }

    #[test]
    fn boundary_inside_hostname_reassembles() {
        // A record boundary cutting through the 5-byte hostname.
        let hs = handshake(&ch_body(Some(&sni_ext_for("ab.cd"))));
        let cut = hs.len() - 3;
        let mut buf = record(&hs[..cut]);
        buf.extend_from_slice(&record(&hs[cut..]));
        assert_eq!(scan(&buf), Scan::Done(Some("ab.cd".into())));
    }

    // --- truncation -------------------------------------------------

    #[test]
    fn empty_buffer_is_incomplete() {
        assert_eq!(scan(&[]), Scan::Incomplete);
    }

    #[test]
    fn partial_record_header_is_incomplete() {
        assert_eq!(scan(&[0x16, 0x03, 0x01]), Scan::Incomplete);
    }

    #[test]
    fn partial_record_body_is_incomplete() {
        let full = full_ch("trunc.example.com");
        assert_eq!(scan(&full[..full.len() - 1]), Scan::Incomplete);
    }

    #[test]
    fn partial_handshake_message_is_incomplete() {
        // A complete record, but the handshake message it carries is not
        // yet whole (declared uint24 length exceeds the bytes present).
        let body = ch_body(Some(&sni_ext_for("more.example.com")));
        let mut hs = handshake(&body);
        hs.truncate(hs.len() - 4);
        assert_eq!(scan(&record(&hs)), Scan::Incomplete);
    }

    // --- not TLS / wrong type ---------------------------------------

    #[test]
    fn non_handshake_content_type_is_invalid() {
        let mut ch = full_ch("x.example.com");
        ch[0] = 0x17; // application_data
        assert_eq!(scan(&ch), Scan::Invalid);
    }

    #[test]
    fn wrong_handshake_type_is_invalid() {
        let mut body = handshake(&ch_body(Some(&sni_ext_for("x.example.com"))));
        body[0] = 0x02; // ServerHello
        assert_eq!(scan(&record(&body)), Scan::Invalid);
    }

    #[test]
    fn interleaved_alert_record_is_invalid() {
        let hs = handshake(&ch_body(Some(&sni_ext_for("x.example.com"))));
        let mut buf = record(&hs[..4]); // partial handshake record
        buf.extend_from_slice(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00]); // alert
        assert_eq!(scan(&buf), Scan::Invalid);
    }

    #[test]
    fn record_length_zero_or_oversize_is_invalid() {
        assert_eq!(scan(&[0x16, 0x03, 0x01, 0x00, 0x00]), Scan::Invalid);
        assert_eq!(scan(&[0x16, 0x03, 0x01, 0x40, 0x01]), Scan::Invalid); // 16385
    }

    // --- strict rejections (parser-differential class) --------------

    #[test]
    fn trailing_bytes_after_extensions_block_is_invalid() {
        let mut body = ch_body(Some(&sni_ext_for("x.example.com")));
        body.extend_from_slice(&[0xde, 0xad]); // junk after the exts block
        assert_eq!(scan(&record(&handshake(&body))), Scan::Invalid);
    }

    #[test]
    fn trailing_bytes_after_server_name_list_is_invalid() {
        // server_name extension body = ServerNameList + junk.
        let mut list = (host_entry(b"x.example.com").len() as u16)
            .to_be_bytes()
            .to_vec();
        list.extend_from_slice(&host_entry(b"x.example.com"));
        list.extend_from_slice(&[0xff, 0xff]); // junk after the list
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        assert_eq!(
            scan(&record(&handshake(&ch_body(Some(&ext))))),
            Scan::Invalid
        );
    }

    #[test]
    fn reassembled_handshake_longer_than_declared_is_invalid() {
        let mut hs = handshake(&ch_body(Some(&sni_ext_for("x.example.com"))));
        hs.extend_from_slice(&[0x16, 0x00, 0x00, 0x00]); // extra handshake bytes
        assert_eq!(scan(&record(&hs)), Scan::Invalid);
    }

    #[test]
    fn duplicate_server_name_extension_is_invalid() {
        let mut exts = sni_ext_for("a.example.com");
        exts.extend_from_slice(&sni_ext_for("b.example.com"));
        assert_eq!(
            scan(&record(&handshake(&ch_body(Some(&exts))))),
            Scan::Invalid
        );
    }

    #[test]
    fn multi_entry_server_name_list_is_invalid() {
        let mut entries = host_entry(b"a.example.com");
        entries.extend_from_slice(&host_entry(b"b.example.com"));
        let ext = sni_extension(&entries);
        assert_eq!(
            scan(&record(&handshake(&ch_body(Some(&ext))))),
            Scan::Invalid
        );
    }

    #[test]
    fn empty_server_name_list_is_invalid() {
        let ext = sni_extension(&[]); // zero-length ServerNameList
        assert_eq!(
            scan(&record(&handshake(&ch_body(Some(&ext))))),
            Scan::Invalid
        );
    }

    #[test]
    fn non_dns_sni_bytes_are_invalid() {
        for bad in [b"x .com".as_slice(), b"x\0.com", b"under_score.com"] {
            let ext = sni_extension(&host_entry(bad));
            assert_eq!(
                scan(&record(&handshake(&ch_body(Some(&ext))))),
                Scan::Invalid,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn unknown_name_type_plus_host_is_invalid() {
        // {name_type=0x01, "abc"} + {host_name} — basta requires exactly one
        // host_name entry (F6).
        let mut entries = vec![0x01u8, 0x00, 0x03]; // unknown type, len 3
        entries.extend_from_slice(b"abc");
        entries.extend_from_slice(&host_entry(b"x.example.com"));
        let ext = sni_extension(&entries);
        assert_eq!(
            scan(&record(&handshake(&ch_body(Some(&ext))))),
            Scan::Invalid
        );
    }

    #[test]
    fn trailing_record_after_client_hello_is_invalid() {
        // A complete ClientHello followed by a second TLS record (F7).
        let mut buf = full_ch("x.example.com");
        buf.extend_from_slice(&record(&[0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(scan(&buf), Scan::Invalid);
    }

    #[test]
    fn trailing_junk_after_client_hello_is_invalid() {
        // Non-record trailing bytes are also rejected (F7).
        let mut buf = full_ch("x.example.com");
        buf.extend_from_slice(&[0x99, 0x99]);
        assert_eq!(scan(&buf), Scan::Invalid);
    }

    /// A ClientHello body with caller-chosen session_id / cipher_suites /
    /// compression bytes, a valid SNI, no other extensions.
    fn ch_body_fields(sid: &[u8], cipher: &[u8], comp: &[u8]) -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[0u8; 32]);
        b.push(sid.len() as u8);
        b.extend_from_slice(sid);
        b.extend_from_slice(&(cipher.len() as u16).to_be_bytes());
        b.extend_from_slice(cipher);
        b.push(comp.len() as u8);
        b.extend_from_slice(comp);
        let ext = sni_ext_for("x.example.com");
        b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        b.extend_from_slice(&ext);
        b
    }

    #[test]
    fn oversize_session_id_is_invalid() {
        let body = ch_body_fields(&[0u8; 33], &[0x13, 0x01], &[0x00]);
        assert_eq!(scan(&record(&handshake(&body))), Scan::Invalid);
    }

    #[test]
    fn empty_cipher_suites_is_invalid() {
        let body = ch_body_fields(&[], &[], &[0x00]);
        assert_eq!(scan(&record(&handshake(&body))), Scan::Invalid);
    }

    #[test]
    fn odd_cipher_suites_is_invalid() {
        let body = ch_body_fields(&[], &[0x13, 0x01, 0x02], &[0x00]);
        assert_eq!(scan(&record(&handshake(&body))), Scan::Invalid);
    }

    #[test]
    fn empty_compression_methods_is_invalid() {
        let body = ch_body_fields(&[], &[0x13, 0x01], &[]);
        assert_eq!(scan(&record(&handshake(&body))), Scan::Invalid);
    }

    #[test]
    fn valid_fields_still_parse() {
        let body = ch_body_fields(&[7u8; 32], &[0x13, 0x01], &[0x00]);
        assert_eq!(
            scan(&record(&handshake(&body))),
            Scan::Done(Some("x.example.com".into()))
        );
    }

    // --- size caps --------------------------------------------------

    #[test]
    fn over_max_peek_buffer_is_invalid() {
        assert_eq!(scan(&vec![0x16u8; MAX_PEEK + 1]), Scan::Invalid);
    }

    #[test]
    fn handshake_length_over_max_peek_is_invalid_fast() {
        // uint24 length 0x010000 ⇒ total 65540 > MAX_PEEK ⇒ Invalid.
        assert_eq!(
            scan(&record(&[HS_CLIENT_HELLO, 0x01, 0x00, 0x00])),
            Scan::Invalid
        );
    }

    #[test]
    fn large_valid_client_hello_parses() {
        // ~24 KiB ClientHello (a padding extension) across several records
        // — exercises the multi-record + large-buffer path.
        let mut exts = sni_ext_for("big.example.com");
        let pad = vec![0u8; 24 * 1024];
        exts.extend_from_slice(&[0x00, 0x15]); // padding extension (RFC 7685)
        exts.extend_from_slice(&(pad.len() as u16).to_be_bytes());
        exts.extend_from_slice(&pad);
        let hs = handshake(&ch_body(Some(&exts)));
        assert_eq!(
            scan(&records_exact(&hs, 4)),
            Scan::Done(Some("big.example.com".into()))
        );
    }

    // --- is_dns_name ------------------------------------------------

    #[test]
    fn is_dns_name_accepts_valid() {
        assert!(is_dns_name("api.anthropic.com"));
        assert!(is_dns_name("a-b.example.co.uk"));
        assert!(is_dns_name("x"));
        assert!(is_dns_name("xn--nxasmq6b.example"));
    }

    #[test]
    fn is_dns_name_rejects_invalid() {
        assert!(!is_dns_name(""));
        assert!(!is_dns_name("-lead.com"));
        assert!(!is_dns_name("trail-.com"));
        assert!(!is_dns_name("foo..bar"));
        assert!(!is_dns_name("under_score.com"));
        assert!(!is_dns_name(&"a".repeat(64))); // label > 63
        assert!(!is_dns_name(&format!("{}.com", "a".repeat(250)))); // name > 253
    }
}
