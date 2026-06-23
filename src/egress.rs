use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

/// fwmark the SNI proxy sets on its own upstream sockets, so the netns
/// nft rules can tell the proxy's egress apart from the sandbox's. The
/// sandbox cannot forge it — setting SO_MARK needs CAP_NET_ADMIN over the
/// netns's userns, which the nested sandbox userns lacks. The value is not
/// a secret; its unforgeability is the kernel's, not its.
pub const PROXY_MARK: u32 = 0x6277_7801;
/// netns-local TCP port the SNI proxy listens on (127.0.0.1). The netns
/// is private per launch, so a fixed port never collides.
pub const PROXY_PORT: u16 = 47999;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ports {
    One(u16),
    Range(u16, u16),
}

impl Ports {
    pub fn contains(self, port: u16) -> bool {
        match self {
            Ports::One(p) => p == port,
            Ports::Range(lo, hi) => lo <= port && port <= hi,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dest {
    Addr(Ipv4Addr),
    Cidr(Ipv4Addr, u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllowRule {
    pub dest: Dest,
    pub ports: Ports,
    pub proto: Proto,
}

impl AllowRule {
    fn nft_line(&self) -> String {
        let dest = match self.dest {
            Dest::Addr(a) => a.to_string(),
            Dest::Cidr(a, p) => format!("{a}/{p}"),
        };
        let ports = match self.ports {
            Ports::One(p) => p.to_string(),
            Ports::Range(lo, hi) => format!("{lo}-{hi}"),
        };
        format!(
            "ip daddr {dest} {} dport {ports} accept",
            self.proto.as_str()
        )
    }
}

/// A resolved `--allow-sni` entry: an exact SNI hostname and the IPv4
/// address(es) it resolved to at launch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SniRule {
    pub host: String,
    pub addrs: Vec<Ipv4Addr>,
}

/// Resolved `--allow` / `--allow-sni` flags: a deduplicated rule list for
/// the nft ruleset, a `/etc/hosts` map for the DNS names resolved at
/// launch, and the SNI allowlist for the in-netns proxy.
#[derive(Debug)]
pub struct EgressSpec {
    pub rules: Vec<AllowRule>,
    pub hosts: Vec<(String, Ipv4Addr)>,
    pub sni: Vec<SniRule>,
}

impl EgressSpec {
    /// Parse and resolve every `--allow SPEC`. DNS names are resolved
    /// here, in the host netns, before any `unshare` — the sandbox gets
    /// no resolver of its own by default.
    pub fn resolve(allow: &[String], allow_sni: &[String]) -> Result<EgressSpec> {
        let mut rules: Vec<AllowRule> = vec![];
        let mut hosts: Vec<(String, Ipv4Addr)> = vec![];

        for spec in allow {
            let (host_ports, proto) = split_proto(spec);
            let (host, ports_str) = host_ports
                .rsplit_once(':')
                .with_context(|| format!("--allow needs HOST:PORT, got '{spec}'"))?;
            if host.is_empty() {
                bail!("--allow needs a non-empty HOST, got '{spec}'");
            }
            let ports = parse_ports(ports_str, spec)?;

            if let Some((ip_str, prefix_str)) = host.split_once('/') {
                let addr: Ipv4Addr = ip_str
                    .parse()
                    .with_context(|| format!("--allow: invalid IPv4 in CIDR '{host}'"))?;
                let prefix: u8 = prefix_str
                    .parse()
                    .with_context(|| format!("--allow: invalid CIDR prefix in '{host}'"))?;
                if prefix > 32 {
                    bail!("--allow: CIDR prefix must be 0-32, got '{host}'");
                }
                // Refuse on range *intersection*, not just the network address:
                // `--allow 169.0.0.0/8` (or `0.0.0.0/0`) has a benign network
                // address but its range covers 169.254.169.254, the cloud
                // metadata endpoint. Private CIDRs stay allowed (as literal
                // private IPs do) — an explicit internal range is intent.
                if cidr_overlaps(addr, prefix, Ipv4Addr::new(127, 0, 0, 0), 8) {
                    refuse_loopback(spec, ports)?;
                }
                if cidr_overlaps(addr, prefix, Ipv4Addr::new(169, 254, 0, 0), 16) {
                    refuse_link_local(spec)?;
                }
                push_rule(
                    &mut rules,
                    AllowRule {
                        dest: Dest::Cidr(addr, prefix),
                        ports,
                        proto,
                    },
                );
            } else if let Ok(addr) = host.parse::<Ipv4Addr>() {
                if addr.is_loopback() {
                    refuse_loopback(spec, ports)?;
                }
                if addr.is_link_local() {
                    refuse_link_local(spec)?;
                }
                push_rule(
                    &mut rules,
                    AllowRule {
                        dest: Dest::Addr(addr),
                        ports,
                        proto,
                    },
                );
            } else {
                // F2: HOST is a DNS name (not an IPv4 literal, not a CIDR).
                // A DNS name on TCP :443 can resolve to a shared CDN edge
                // IP; an IP-only --allow rule then authorises every host
                // that edge fronts — a confirmed over-broad egress. Refuse
                // it: --allow-sni is the SNI-filtered tool for any TLS host.
                if proto == Proto::Tcp && ports.contains(443) {
                    bail!(
                        "--allow '{spec}': a DNS name on TCP port 443 is \
                         refused — it may resolve to a shared CDN edge IP, \
                         and an IP-only rule then authorises every host on \
                         that edge. Use `--allow-sni {host}` (filters by TLS \
                         SNI — the right tool for any HTTPS host), or pin a \
                         raw address explicitly with `--allow <IPv4>:443`."
                    );
                }
                let lookup_port = match ports {
                    Ports::One(p) => p,
                    Ports::Range(lo, _) => lo,
                };
                let resolved = (host, lookup_port)
                    .to_socket_addrs()
                    .with_context(|| format!("--allow: cannot resolve host '{host}'"))?;
                let mut found = false;
                for sa in resolved {
                    if let IpAddr::V4(v4) = sa.ip() {
                        // A name resolving inward — loopback (`localhost` etc.),
                        // link-local, or private — is the SSRF / DNS-rebinding
                        // pattern. A literal inward IP is handled above (link-
                        // local refused, private allowed as intent).
                        match classify_inward(v4) {
                            Some(Inward::Loopback) => refuse_loopback(spec, ports)?,
                            Some(Inward::LinkLocal) => refuse_link_local(spec)?,
                            Some(Inward::Private) => refuse_private_via_dns(spec, host, v4)?,
                            None => {}
                        }
                        found = true;
                        push_rule(
                            &mut rules,
                            AllowRule {
                                dest: Dest::Addr(v4),
                                ports,
                                proto,
                            },
                        );
                        let entry = (host.to_string(), v4);
                        if !hosts.contains(&entry) {
                            hosts.push(entry);
                        }
                    }
                }
                if !found {
                    bail!("--allow: host '{host}' has no IPv4 (A) address");
                }
            }
        }

        // --allow-sni: exact-host TLS egress, resolved at launch. Each
        // name's A records are pinned into /etc/hosts so a getaddrinfo
        // client reaches them, and recorded in `sni` for the proxy.
        let mut sni: Vec<SniRule> = vec![];
        for raw in allow_sni {
            let host = raw.to_ascii_lowercase();
            validate_sni_host(&host)?;
            if sni.iter().any(|s| s.host == host) {
                continue; // dedupe
            }
            let resolved = (host.as_str(), 443u16)
                .to_socket_addrs()
                .with_context(|| format!("--allow-sni: cannot resolve host '{host}'"))?;
            let mut addrs: Vec<Ipv4Addr> = vec![];
            for sa in resolved {
                if let IpAddr::V4(v4) = sa.ip() {
                    // An SNI name resolving link-local/private is the SSRF /
                    // rebinding threat — refuse. Loopback resolves to the
                    // sandbox's own empty lo (harmless, and pointless), so it
                    // is left to fall through.
                    match classify_inward(v4) {
                        Some(Inward::LinkLocal) => refuse_link_local(&host)?,
                        Some(Inward::Private) => refuse_private_via_dns(&host, &host, v4)?,
                        _ => {}
                    }
                    if !addrs.contains(&v4) {
                        addrs.push(v4);
                    }
                    let entry = (host.clone(), v4);
                    if !hosts.contains(&entry) {
                        hosts.push(entry);
                    }
                }
            }
            if addrs.is_empty() {
                bail!("--allow-sni: host '{host}' has no IPv4 (A) address");
            }
            sni.push(SniRule { host, addrs });
        }

        Ok(EgressSpec { rules, hosts, sni })
    }

    /// Render the netns-local nftables ruleset: an `output`-hook filter
    /// that drops by default and accepts loopback, return traffic, and
    /// each allow rule. Fed to `nft -f -` over stdin.
    pub fn nft_ruleset(&self) -> String {
        let mut s = String::new();
        s.push_str("table inet basta {\n");
        s.push_str("  chain output {\n");
        s.push_str("    type filter hook output priority 0; policy drop;\n");
        s.push_str("    oifname \"lo\" accept\n");
        s.push_str("    ct state established,related accept\n");
        if self.sni_enabled() {
            // Accept the sandbox's :443 connections after the bastanat
            // `redirect` has rewritten their destination to the proxy.
            // `redirect` in the output hook rewrites ip daddr/dport
            // immediately, but the reroute onto `lo` is deferred until
            // the hook finishes — so at filter time the packet already
            // reads `ip daddr 127.0.0.1` yet still carries the stale
            // `oifname` of its original route. Match it by destination,
            // not interface, or it falls through to `policy drop`.
            s.push_str(&format!(
                "    ip daddr 127.0.0.1 tcp dport {PROXY_PORT} accept\n"
            ));
            // The proxy's own upstream dials carry PROXY_MARK. Permit them
            // — but ONLY to the launch-resolved IPs of the allowlisted SNI
            // hosts. The kernel, not the proxy's code, is the final egress
            // arbiter: a buggy or compromised proxy still cannot reach any
            // host outside the allowlist.
            let mut ips: Vec<Ipv4Addr> = self
                .sni
                .iter()
                .flat_map(|r| r.addrs.iter().copied())
                .collect();
            ips.sort();
            ips.dedup();
            let set = ips
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!(
                "    meta mark {PROXY_MARK:#x} ip daddr {{ {set} }} tcp dport 443 accept\n"
            ));
        }
        for r in &self.rules {
            s.push_str("    ");
            s.push_str(&r.nft_line());
            s.push('\n');
        }
        s.push_str("  }\n");
        s.push_str("}\n");
        if self.sni_enabled() {
            // Redirect every sandbox :443 to the in-netns SNI proxy. nat
            // priority (-100) runs before the filter chain (0). The proxy's
            // own marked dials hit `return` first — no self-redirect loop.
            s.push_str(&format!(
                "table ip bastanat {{
  chain output {{
    type nat hook output priority -100; policy accept;
    meta mark {PROXY_MARK:#x} return
    tcp dport 443 redirect to :{PROXY_PORT}
  }}
}}
"
            ));
        }
        s
    }

    pub fn sni_enabled(&self) -> bool {
        !self.sni.is_empty()
    }

    /// True if any --allow rule covers TCP :443 (shadowed under --allow-sni).
    pub fn has_tcp443_rule(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.proto == Proto::Tcp && r.ports.contains(443))
    }

    /// True if any --allow rule is UDP (a potential exfil channel — esp. :53).
    pub fn has_udp_rule(&self) -> bool {
        self.rules.iter().any(|r| r.proto == Proto::Udp)
    }

    /// The sandbox `/etc/hosts`: localhost plus one line per resolved
    /// `--allow` DNS name, so `getaddrinfo`-based clients reach the same
    /// IP the nft rule allows.
    pub fn hosts_file(&self) -> String {
        let mut s = String::from("127.0.0.1 localhost\n::1 localhost\n");
        for (name, ip) in &self.hosts {
            s.push_str(&format!("{ip} {name}\n"));
        }
        s
    }

    /// If the caller opened a UDP `:53` rule, the resolver IP to point
    /// `/etc/resolv.conf` at. Only a concrete address qualifies — a
    /// CIDR `:53` rule has no single nameserver.
    pub fn resolver(&self) -> Option<Ipv4Addr> {
        self.rules.iter().find_map(|r| match r.dest {
            Dest::Addr(a) if r.proto == Proto::Udp && r.ports.contains(53) => Some(a),
            _ => None,
        })
    }

    /// The sandbox `/etc/resolv.conf` body. With a `:53/udp` rule, point
    /// at that resolver; otherwise no resolver — names were pinned into
    /// `/etc/hosts` at launch.
    pub fn resolv_conf(&self) -> String {
        match self.resolver() {
            Some(ip) => format!("nameserver {ip}\noptions edns0 trust-ad\n"),
            None => "# basta: no in-sandbox resolver — --allow names were resolved at\n\
                     # launch into /etc/hosts. For live DNS, relaunch adding\n\
                     # --allow <resolver-ip>:53/udp.\n"
                .to_string(),
        }
    }
}

/// Strip a trailing `/tcp` or `/udp`. A CIDR's `/prefix` is never a bare
/// `tcp`/`udp` word, so this is unambiguous.
fn split_proto(spec: &str) -> (&str, Proto) {
    if let Some((head, tail)) = spec.rsplit_once('/') {
        match tail {
            "tcp" => return (head, Proto::Tcp),
            "udp" => return (head, Proto::Udp),
            _ => {}
        }
    }
    (spec, Proto::Tcp)
}

fn parse_ports(s: &str, spec: &str) -> Result<Ports> {
    if let Some((lo, hi)) = s.split_once('-') {
        let lo: u16 = lo
            .parse()
            .with_context(|| format!("--allow: invalid port range start in '{spec}'"))?;
        let hi: u16 = hi
            .parse()
            .with_context(|| format!("--allow: invalid port range end in '{spec}'"))?;
        if lo == 0 || hi == 0 {
            bail!("--allow: port must be 1-65535 in '{spec}'");
        }
        if lo > hi {
            bail!("--allow: port range start > end in '{spec}'");
        }
        Ok(Ports::Range(lo, hi))
    } else {
        let p: u16 = s
            .parse()
            .with_context(|| format!("--allow: invalid port in '{spec}'"))?;
        if p == 0 {
            bail!("--allow: port must be 1-65535 in '{spec}'");
        }
        Ok(Ports::One(p))
    }
}

fn push_rule(rules: &mut Vec<AllowRule>, rule: AllowRule) {
    if !rules.contains(&rule) {
        rules.push(rule);
    }
}

/// An egress target that points back into the host's own networks rather than
/// out. Refused outright (link-local) or refused only when reached via a DNS
/// name (private); a literal private IP is intent and stays allowed.
#[derive(Clone, Copy)]
enum Inward {
    Loopback,
    LinkLocal,
    Private,
}

fn classify_inward(a: Ipv4Addr) -> Option<Inward> {
    if a.is_loopback() {
        Some(Inward::Loopback)
    } else if a.is_link_local() {
        Some(Inward::LinkLocal)
    } else if a.is_private() || is_cgnat(a) {
        Some(Inward::Private)
    } else {
        None
    }
}

/// 100.64.0.0/10 — RFC 6598 carrier-grade NAT shared space. (`Ipv4Addr::
/// is_shared` is still unstable, so classify it by hand.)
fn is_cgnat(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// Inclusive `[low, high]` address range a CIDR block spans.
fn cidr_range(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (bits & mask, (bits & mask) | !mask)
}

/// Whether CIDR `addr/prefix` overlaps the reserved block `base/base_prefix`.
/// Two inclusive ranges intersect iff each starts at or before the other ends.
fn cidr_overlaps(addr: Ipv4Addr, prefix: u8, base: Ipv4Addr, base_prefix: u8) -> bool {
    let (a_lo, a_hi) = cidr_range(addr, prefix);
    let (b_lo, b_hi) = cidr_range(base, base_prefix);
    a_lo <= b_hi && b_lo <= a_hi
}

/// Refuse any 169.254.0.0/16 link-local target — literal or DNS-resolved.
/// 169.254.169.254 is the cloud instance-metadata endpoint (IAM creds); no
/// legitimate agent egress goes there.
fn refuse_link_local(spec: &str) -> Result<()> {
    bail!(
        "--allow '{spec}': 169.254.0.0/16 is link-local — 169.254.169.254 is \
         the cloud instance-metadata endpoint (it returns IAM credentials and \
         instance secrets). basta refuses it; there is no legitimate agent use."
    )
}

/// Refuse a DNS name that resolved into private space (RFC1918 / CGNAT). A
/// literal private IP is honored as intent; a *name* pointing inward is the
/// SSRF / DNS-rebinding pattern.
fn refuse_private_via_dns(spec: &str, host: &str, ip: Ipv4Addr) -> Result<()> {
    bail!(
        "--allow '{spec}': the name '{host}' resolved to the private address \
         {ip}. A hostname pointing into private address space is refused (SSRF \
         / DNS-rebinding risk). If you really mean an internal host, pass the \
         literal address: `--allow {ip}:<port>`."
    )
}

/// Refuse `--allow` for any 127.0.0.0/8 destination — literal IP, CIDR, or
/// a DNS name that resolves there. Inside the sandbox netns `127.0.0.1` is
/// the sandbox's own (empty) loopback, not the host's; an `--allow` rule
/// here looks like it would reach the host service but only opens the
/// sandbox's own lo (which the netns ruleset already accepts). Point the
/// caller at `--allow-loopback PORT`, which uses pasta's host-loopback
/// forwarding to actually reach `127.0.0.1:PORT` on the basta host.
fn refuse_loopback(spec: &str, ports: Ports) -> Result<()> {
    let port_hint = match ports {
        Ports::One(p) => p.to_string(),
        Ports::Range(lo, _) => lo.to_string(),
    };
    bail!(
        "--allow '{spec}': loopback address — inside the sandbox netns \
         127.0.0.0/8 is the sandbox's own loopback, not the host's. To \
         reach a service on the basta host at 127.0.0.1:{port_hint}, use \
         `--allow-loopback {port_hint}` instead."
    )
}

/// Validate an `--allow-sni HOST` argument. Reuses the SAME DNS-name
/// validator as the wire-side ClientHello parser, so the flag side and
/// the wire side are provably the same check.
fn validate_sni_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        bail!(
            "--allow-sni: HOST must be a DNS name, not an IP — \
             use `--allow {host}:443` for an IP rule"
        );
    }
    if !crate::client_hello::is_dns_name(host) {
        bail!("--allow-sni: not a valid DNS name: '{host}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_defaults_to_tcp() {
        assert_eq!(split_proto("host:443"), ("host:443", Proto::Tcp));
        assert_eq!(split_proto("host:443/tcp"), ("host:443", Proto::Tcp));
        assert_eq!(split_proto("host:443/udp"), ("host:443", Proto::Udp));
    }

    #[test]
    fn proto_split_ignores_cidr_slash() {
        // The final /-segment is `23:443`, not a bare proto word.
        assert_eq!(
            split_proto("160.79.104.0/23:443"),
            ("160.79.104.0/23:443", Proto::Tcp)
        );
    }

    #[test]
    fn ports_single_and_range() {
        assert_eq!(parse_ports("443", "x").unwrap(), Ports::One(443));
        assert_eq!(
            parse_ports("8000-8010", "x").unwrap(),
            Ports::Range(8000, 8010)
        );
    }

    #[test]
    fn ports_reject_bad() {
        assert!(parse_ports("0", "x").is_err());
        assert!(parse_ports("70000", "x").is_err());
        assert!(parse_ports("8010-8000", "x").is_err());
        assert!(parse_ports("8000-0", "x").is_err());
        assert!(parse_ports("abc", "x").is_err());
    }

    fn one(spec: &str) -> AllowRule {
        let s = EgressSpec::resolve(&[spec.to_string()], &[]).unwrap();
        assert_eq!(s.rules.len(), 1, "expected exactly one rule for {spec}");
        s.rules[0]
    }

    #[test]
    fn resolve_plain_ip() {
        let r = one("10.9.9.11:8000/tcp");
        assert_eq!(r.dest, Dest::Addr("10.9.9.11".parse().unwrap()));
        assert_eq!(r.ports, Ports::One(8000));
        assert_eq!(r.proto, Proto::Tcp);
    }

    #[test]
    fn resolve_udp() {
        let r = one("10.0.0.53:53/udp");
        assert_eq!(r.proto, Proto::Udp);
        assert_eq!(r.ports, Ports::One(53));
    }

    #[test]
    fn resolve_cidr() {
        let r = one("160.79.104.0/23:443");
        assert_eq!(r.dest, Dest::Cidr("160.79.104.0".parse().unwrap(), 23));
        assert_eq!(r.ports, Ports::One(443));
    }

    #[test]
    fn resolve_port_range() {
        let r = one("10.9.9.11:8000-8010/tcp");
        assert_eq!(r.ports, Ports::Range(8000, 8010));
    }

    #[test]
    fn resolve_dedups_rules() {
        let s = EgressSpec::resolve(
            &[
                "10.0.0.1:443".to_string(),
                "10.0.0.1:443".to_string(),
                "10.0.0.1:443/tcp".to_string(),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(s.rules.len(), 1);
    }

    #[test]
    fn resolve_rejects_bad_specs() {
        assert!(EgressSpec::resolve(&["10.0.0.1".to_string()], &[]).is_err());
        assert!(EgressSpec::resolve(&["10.0.0.0/33:443".to_string()], &[]).is_err());
        assert!(EgressSpec::resolve(&["10.0.0.1:0".to_string()], &[]).is_err());
        assert!(EgressSpec::resolve(&[":443".to_string()], &[]).is_err());
    }

    #[test]
    fn allow_refuses_loopback_ipv4_literal() {
        let err = EgressSpec::resolve(&["127.0.0.1:8000".into()], &[]).unwrap_err();
        assert!(err.to_string().contains("--allow-loopback 8000"));
        assert!(EgressSpec::resolve(&["127.0.0.5:443".into()], &[]).is_err());
    }

    #[test]
    fn allow_refuses_loopback_cidr() {
        assert!(EgressSpec::resolve(&["127.0.0.0/8:8000".into()], &[]).is_err());
        assert!(EgressSpec::resolve(&["127.0.0.1/32:8000".into()], &[]).is_err());
        // A non-loopback CIDR with the same port still works.
        assert!(EgressSpec::resolve(&["10.0.0.0/8:8000".into()], &[]).is_ok());
    }

    #[test]
    fn allow_refuses_dns_resolving_to_loopback() {
        // `localhost` resolves to 127.0.0.1 — caught after resolution.
        let err = EgressSpec::resolve(&["localhost:8000".into()], &[]).unwrap_err();
        assert!(err.to_string().contains("--allow-loopback 8000"));
    }

    #[test]
    fn classify_inward_buckets() {
        assert!(matches!(
            classify_inward("169.254.169.254".parse().unwrap()),
            Some(Inward::LinkLocal)
        ));
        for p in [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
        ] {
            assert!(
                matches!(classify_inward(p.parse().unwrap()), Some(Inward::Private)),
                "{p} should be Private"
            );
        }
        assert!(matches!(
            classify_inward("127.0.0.1".parse().unwrap()),
            Some(Inward::Loopback)
        ));
        for ok in ["8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1"] {
            assert!(
                classify_inward(ok.parse().unwrap()).is_none(),
                "{ok} should be outward"
            );
        }
    }

    #[test]
    fn allow_refuses_link_local_literal() {
        let err = EgressSpec::resolve(&["169.254.169.254:80".into()], &[]).unwrap_err();
        assert!(err.to_string().contains("metadata"));
        assert!(EgressSpec::resolve(&["169.254.0.0/16:80".into()], &[]).is_err());
    }

    #[test]
    fn allow_refuses_broad_cidr_covering_reserved() {
        // A CIDR whose network address is benign but whose range covers a
        // reserved block must be refused (range intersection, not just the
        // network address).
        assert!(EgressSpec::resolve(&["169.0.0.0/8:80".into()], &[]).is_err()); // covers 169.254/16
        assert!(EgressSpec::resolve(&["0.0.0.0/0:443".into()], &[]).is_err()); // covers everything
        assert!(EgressSpec::resolve(&["169.254.128.0/17:80".into()], &[]).is_err());
        assert!(EgressSpec::resolve(&["127.128.0.0/9:8000".into()], &[]).is_err()); // covers 127/8
        // A neighbouring CIDR that does NOT reach the reserved block is fine.
        assert!(EgressSpec::resolve(&["169.253.0.0/16:80".into()], &[]).is_ok());
        assert!(EgressSpec::resolve(&["8.0.0.0/8:443".into()], &[]).is_ok());
    }

    #[test]
    fn cidr_overlaps_boundaries() {
        let ll = Ipv4Addr::new(169, 254, 0, 0);
        assert!(cidr_overlaps(Ipv4Addr::new(169, 0, 0, 0), 8, ll, 16));
        assert!(cidr_overlaps(Ipv4Addr::new(0, 0, 0, 0), 0, ll, 16));
        assert!(!cidr_overlaps(Ipv4Addr::new(169, 253, 0, 0), 16, ll, 16));
        // /32 host exactly inside / exactly outside.
        assert!(cidr_overlaps(Ipv4Addr::new(169, 254, 169, 254), 32, ll, 16));
        assert!(!cidr_overlaps(Ipv4Addr::new(169, 255, 0, 0), 16, ll, 16));
    }

    #[test]
    fn allow_allows_literal_private() {
        // A literal private IP is intent — still allowed (local-model case).
        assert!(EgressSpec::resolve(&["10.9.9.11:8000".into()], &[]).is_ok());
        assert!(EgressSpec::resolve(&["192.168.1.10:8000".into()], &[]).is_ok());
        assert!(EgressSpec::resolve(&["10.0.0.0/8:8000".into()], &[]).is_ok());
    }

    #[test]
    fn allow_refuses_dns_name_on_tcp_443() {
        // F2: a DNS name on TCP :443 is refused before any resolution.
        assert!(EgressSpec::resolve(&["example.com:443".into()], &[]).is_err());
        assert!(EgressSpec::resolve(&["example.com:443/tcp".into()], &[]).is_err());
        // A range spanning 443 is also refused.
        assert!(EgressSpec::resolve(&["example.com:440-450".into()], &[]).is_err());
        // A literal IP / CIDR on :443 is still accepted.
        assert!(EgressSpec::resolve(&["1.2.3.4:443".into()], &[]).is_ok());
        assert!(EgressSpec::resolve(&["1.2.3.0/24:443".into()], &[]).is_ok());
    }

    #[test]
    fn nft_ruleset_renders() {
        let spec = EgressSpec {
            rules: vec![
                AllowRule {
                    dest: Dest::Addr("10.9.9.11".parse().unwrap()),
                    ports: Ports::One(8000),
                    proto: Proto::Tcp,
                },
                AllowRule {
                    dest: Dest::Cidr("160.79.104.0".parse().unwrap(), 23),
                    ports: Ports::Range(8000, 8010),
                    proto: Proto::Udp,
                },
            ],
            hosts: vec![],
            sni: vec![],
        };
        let r = spec.nft_ruleset();
        assert!(r.contains("type filter hook output priority 0; policy drop;"));
        assert!(r.contains("oifname \"lo\" accept"));
        assert!(r.contains("ct state established,related accept"));
        assert!(r.contains("ip daddr 10.9.9.11 tcp dport 8000 accept"));
        assert!(r.contains("ip daddr 160.79.104.0/23 udp dport 8000-8010 accept"));
    }

    #[test]
    fn hosts_file_renders() {
        let spec = EgressSpec {
            rules: vec![],
            hosts: vec![("api.example.com".to_string(), "1.2.3.4".parse().unwrap())],
            sni: vec![],
        };
        let h = spec.hosts_file();
        assert!(h.starts_with("127.0.0.1 localhost\n::1 localhost\n"));
        assert!(h.contains("1.2.3.4 api.example.com\n"));
    }

    #[test]
    fn resolver_detects_udp_53() {
        let with = EgressSpec::resolve(
            &["10.0.0.53:53/udp".to_string(), "10.9.9.11:8000".to_string()],
            &[],
        )
        .unwrap();
        assert_eq!(with.resolver(), Some("10.0.0.53".parse().unwrap()));
        assert!(with.resolv_conf().contains("nameserver 10.0.0.53"));

        let without = EgressSpec::resolve(&["10.9.9.11:8000".to_string()], &[]).unwrap();
        assert_eq!(without.resolver(), None);
        assert!(without.resolv_conf().contains("no in-sandbox resolver"));
    }

    #[test]
    fn validate_sni_host_accepts_and_rejects() {
        assert!(validate_sni_host("api.anthropic.com").is_ok());
        assert!(validate_sni_host("a-b.example.co.uk").is_ok());
        // IP literals are rejected with the --allow hint.
        assert!(validate_sni_host("1.2.3.4").is_err());
        // Invalid DNS names are rejected.
        assert!(validate_sni_host("-lead.com").is_err());
        assert!(validate_sni_host("foo..bar").is_err());
        assert!(validate_sni_host("").is_err());
    }

    #[test]
    fn validate_sni_host_matches_is_dns_name() {
        // The flag side and the wire side are provably the same check:
        // for any non-IP-literal string, validate_sni_host succeeds iff
        // client_hello::is_dns_name does.
        for s in [
            "api.anthropic.com",
            "x",
            "foo..bar",
            "-bad.com",
            "trail-.com",
            "UPPER.example.com",
        ] {
            if s.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            assert_eq!(
                validate_sni_host(s).is_ok(),
                crate::client_hello::is_dns_name(s),
                "mismatch for {s:?}"
            );
        }
    }

    #[test]
    fn resolve_sni_localhost() {
        // `localhost` resolves without a network — exercises the SNI pass.
        let s = EgressSpec::resolve(&[], &["localhost".to_string()]).unwrap();
        assert_eq!(s.sni.len(), 1);
        assert_eq!(s.sni[0].host, "localhost");
        assert!(s.sni[0].addrs.contains(&"127.0.0.1".parse().unwrap()));
        assert!(
            s.hosts
                .contains(&("localhost".to_string(), "127.0.0.1".parse().unwrap()))
        );
        assert!(s.sni_enabled());
    }

    #[test]
    fn resolve_sni_dedupes_repeated_host() {
        let s = EgressSpec::resolve(
            &[],
            &[
                "localhost".to_string(),
                "LocalHost".to_string(),
                "localhost".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(s.sni.len(), 1);
    }

    #[test]
    fn resolve_sni_rejects_ip_literal() {
        assert!(EgressSpec::resolve(&[], &["1.2.3.4".to_string()]).is_err());
    }

    #[test]
    fn nft_ruleset_with_sni() {
        let spec = EgressSpec {
            rules: vec![],
            hosts: vec![],
            sni: vec![SniRule {
                host: "api.example.com".to_string(),
                addrs: vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
            }],
        };
        let r = spec.nft_ruleset();
        assert!(r.contains("table ip bastanat"));
        assert!(r.contains("redirect to :47999"));
        assert!(r.contains("meta mark 0x62777801 return"));
        assert!(r.contains("ip daddr 127.0.0.1 tcp dport 47999 accept"));
        assert!(
            r.contains("meta mark 0x62777801 ip daddr { 1.1.1.1, 2.2.2.2 } tcp dport 443 accept")
        );
    }

    #[test]
    fn nft_ruleset_without_sni_has_no_nat() {
        let spec = EgressSpec {
            rules: vec![],
            hosts: vec![],
            sni: vec![],
        };
        let r = spec.nft_ruleset();
        assert!(!r.contains("bastanat"));
        assert!(!r.contains("redirect"));
        assert!(!r.contains("meta mark"));
    }

    #[test]
    fn has_tcp443_and_udp_rule() {
        let tcp443 = EgressSpec::resolve(&["1.2.3.4:443".to_string()], &[]).unwrap();
        assert!(tcp443.has_tcp443_rule());
        assert!(!tcp443.has_udp_rule());

        let udp = EgressSpec::resolve(&["1.2.3.4:53/udp".to_string()], &[]).unwrap();
        assert!(udp.has_udp_rule());
        assert!(!udp.has_tcp443_rule());

        let range = EgressSpec::resolve(&["1.2.3.4:440-450".to_string()], &[]).unwrap();
        assert!(range.has_tcp443_rule());

        let other = EgressSpec::resolve(&["1.2.3.4:8000".to_string()], &[]).unwrap();
        assert!(!other.has_tcp443_rule());
        assert!(!other.has_udp_rule());
    }
}
