//! Configuration model and a small, line-oriented configuration language.
//!
//! The syntax is deliberately boring so it can be typed at the CLI, pasted into
//! the GUI, or checked into a lab repository:
//!
//! ```text
//! system hostname fw1
//! system cli-port 2200
//! system gui-port 8080
//! interface port1 zone wan address 10.0.0.1/24
//! interface port2 zone lan address 192.168.10.1/24
//! route default port1 via 10.0.0.254
//! policy 10 lan wan any any any any permit nat
//! policy 20 wan lan any any any any permit
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub const ANY: Cidr = Cidr {
        addr: Ipv4Addr::new(0, 0, 0, 0),
        prefix: 0,
    };

    pub fn parse(s: &str) -> Result<Cidr, String> {
        if s == "any" || s == "0.0.0.0/0" {
            return Ok(Cidr::ANY);
        }
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (
                a.parse::<Ipv4Addr>()
                    .map_err(|_| format!("invalid address '{a}'"))?,
                p.parse::<u8>()
                    .map_err(|_| format!("invalid prefix '{p}'"))?,
            ),
            None => (
                s.parse::<Ipv4Addr>()
                    .map_err(|_| format!("invalid address '{s}' (use a.b.c.d/len)"))?,
                32,
            ),
        };
        if prefix > 32 {
            return Err(format!("prefix /{prefix} is out of range"));
        }
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix as u32);
        (u32::from(ip) & mask) == (u32::from(self.addr) & mask)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// An IPv6 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr6 {
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

impl Cidr6 {
    pub const ANY: Cidr6 = Cidr6 { addr: Ipv6Addr::UNSPECIFIED, prefix: 0 };

    pub fn parse(s: &str) -> Result<Cidr6, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (
                a.parse::<Ipv6Addr>().map_err(|_| format!("invalid IPv6 address '{a}'"))?,
                p.parse::<u8>().map_err(|_| format!("invalid prefix '{p}'"))?,
            ),
            None => (s.parse::<Ipv6Addr>().map_err(|_| format!("invalid IPv6 address '{s}'"))?, 128),
        };
        if prefix > 128 {
            return Err(format!("prefix /{prefix} is out of range"));
        }
        Ok(Cidr6 { addr, prefix })
    }

    fn mask(&self) -> u128 {
        if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix)) }
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask()) == (u128::from(self.addr) & self.mask())
    }

    /// The network address (host bits cleared).
    pub fn network(&self) -> Cidr6 {
        Cidr6 { addr: Ipv6Addr::from(u128::from(self.addr) & self.mask()), prefix: self.prefix }
    }
}

impl fmt::Display for Cidr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A policy address: either a literal CIDR or a named object/group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrRef {
    Cidr(Cidr),
    Cidr6(Cidr6),
    Named(String),
}

impl AddrRef {
    pub fn parse(s: &str) -> Result<AddrRef, String> {
        if let Some(name) = s.strip_prefix('@') {
            if name.is_empty() {
                return Err("empty address object name".to_string());
            }
            Ok(AddrRef::Named(name.to_string()))
        } else if s.contains(':') {
            Ok(AddrRef::Cidr6(Cidr6::parse(s)?))
        } else {
            Ok(AddrRef::Cidr(Cidr::parse(s)?))
        }
    }
}

impl fmt::Display for AddrRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrRef::Cidr(c) => write!(f, "{c}"),
            AddrRef::Cidr6(c) => write!(f, "{c}"),
            AddrRef::Named(n) => write!(f, "@{n}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddressObject {
    pub name: String,
    pub entries: Vec<Cidr>,
    pub entries6: Vec<Cidr6>,
}

#[derive(Clone, Debug)]
pub struct AddressGroup {
    pub name: String,
    pub members: Vec<String>,
}

/// A service: one protocol and a list of destination port ranges.
/// An empty list means every port.
#[derive(Clone, Debug)]
pub struct ServiceObject {
    pub name: String,
    pub proto: Proto,
    pub ports: Vec<(u16, u16)>,
}

impl ServiceObject {
    pub fn matches(&self, proto: u8, port: u16) -> bool {
        self.proto.matches(proto)
            && (self.ports.is_empty() || self.ports.iter().any(|(lo, hi)| (*lo..=*hi).contains(&port)))
    }

    pub fn ports_text(&self) -> String {
        if self.ports.is_empty() {
            return "any".to_string();
        }
        self.ports
            .iter()
            .map(|(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Parse `80`, `80,443`, `8000-8080` or `any`.
pub fn parse_port_ranges(s: &str) -> Result<Vec<(u16, u16)>, String> {
    if s == "any" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let lo: u16 = lo.parse().map_err(|_| format!("invalid port '{part}'"))?;
        let hi: u16 = hi.parse().map_err(|_| format!("invalid port '{part}'"))?;
        if lo > hi {
            return Err(format!("invalid port range '{part}'"));
        }
        out.push((lo, hi));
    }
    if out.is_empty() {
        return Err(format!("invalid port list '{s}'"));
    }
    Ok(out)
}

/// A named list of services and service groups.
#[derive(Clone, Debug)]
pub struct ServiceGroup {
    pub name: String,
    pub members: Vec<String>,
}

/// A named list of applications, application groups and `category:<name>`.
#[derive(Clone, Debug)]
pub struct AppGroup {
    pub name: String,
    pub members: Vec<String>,
}

/// Security profiles applied together (PAN-OS profile group).
#[derive(Clone, Debug, Default)]
pub struct ProfileGroup {
    pub name: String,
    pub url: Option<String>,
    pub ips: Option<String>,
    pub av: Option<String>,
}

/// A named list of users and groups (in a directory this would come from
/// LDAP; here it is configured).
#[derive(Clone, Debug)]
pub struct UserGroup {
    pub name: String,
    pub members: Vec<String>,
}

/// A static IP-to-user mapping. Dynamic mappings (logins pushed by an
/// identity source) live in the engine and take precedence.
#[derive(Clone, Debug)]
pub struct UserMap {
    pub cidr: Cidr,
    pub user: String,
}

/// Special user-list entries, as on PAN-OS.
pub const KNOWN_USER: &str = "known-user";
pub const UNKNOWN_USER: &str = "unknown";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultKind {
    Intrazone,
    Interzone,
}

/// What happens to traffic no security policy matches (PAN-OS
/// `intrazone-default` / `interzone-default`, FortiOS zone `intrazone`).
/// Unconfigured, both are deny. A rule with a zone overrides the VDOM-wide
/// intrazone rule for that zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRule {
    pub vdom: String,
    pub kind: DefaultKind,
    pub zone: Option<String>,
    pub action: Action,
    pub log: bool,
}

/// Policy ids reserved for the default rules (never valid in the config).
pub const INTERZONE_ID: u32 = u32::MAX;
pub const INTRAZONE_ID: u32 = u32::MAX - 1;
/// Per-zone intrazone overrides count down from here.
pub const ZONE_DEFAULT_BASE: u32 = u32::MAX - 16;

pub fn is_default_rule_id(id: u32) -> bool {
    id > u32::MAX - 4096
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnatTarget {
    /// Translate to the egress interface address, with PAT.
    Masquerade,
    /// Translate to a fixed address, with PAT.
    Address(Ipv4Addr),
}

/// A source-NAT rule, evaluated separately from security policy (PAN-OS NAT
/// rulebase, FortiOS central SNAT). A policy's own `nat` flag wins.
#[derive(Clone, Debug)]
pub struct SnatRule {
    pub id: u32,
    pub vdom: String,
    pub src_zones: Vec<String>,
    pub dst_zones: Vec<String>,
    pub src: Vec<AddrRef>,
    pub dst: Vec<AddrRef>,
    pub to: SnatTarget,
    pub enabled: bool,
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AppDef {
    pub name: String,
    pub proto: Proto,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct UrlFilter {
    pub name: String,
    pub block: Vec<String>,
    pub allow: Vec<String>,
}

const URL_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "gambling",
        &[
            "bet365.com",
            "pokerstars.com",
            "draftkings.com",
            "betway.com",
        ],
    ),
    (
        "social",
        &[
            "facebook.com",
            "instagram.com",
            "tiktok.com",
            "x.com",
            "twitter.com",
            "reddit.com",
        ],
    ),
    ("adult", &["pornhub.com", "xvideos.com", "onlyfans.com"]),
    ("malware", &["malware.test", "evil.test", "c2.test"]),
    ("phishing", &["login-secure.test", "account-verify.test"]),
    (
        "streaming",
        &["netflix.com", "youtube.com", "twitch.tv", "hulu.com"],
    ),
];

impl UrlFilter {
    pub fn blocked(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.allow.iter().any(|item| url_item_matches(item, &host)) {
            return false;
        }
        self.block.iter().any(|item| url_item_matches(item, &host))
    }
}

fn url_item_matches(item: &str, host: &str) -> bool {
    let item = item.to_ascii_lowercase();
    if let Some(category) = item.strip_prefix("category:") {
        return URL_CATEGORIES
            .iter()
            .find(|(name, _)| *name == category)
            .map(|(_, domains)| domains.iter().any(|d| host_suffix(host, d)))
            .unwrap_or(false);
    }
    host_suffix(host, &item)
}

fn host_suffix(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

#[derive(Clone, Debug)]
pub struct SignatureProfile {
    pub name: String,
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DnatRule {
    pub id: u32,
    pub vdom: String,
    pub proto: Proto,
    pub dst: Cidr,
    pub dst_port: Option<u16>,
    pub to_ip: Ipv4Addr,
    pub to_port: Option<u16>,
    /// Optional label (FortiOS VIP name, PAN-OS NAT rule name).
    pub name: Option<String>,
}

impl DnatRule {
    pub fn matches(&self, proto: u8, dst: Ipv4Addr, dport: u16) -> bool {
        self.proto.matches(proto)
            && self.dst.contains(dst)
            && self.dst_port.map(|p| p == dport).unwrap_or(true)
    }
}

#[derive(Clone, Debug)]
pub struct Shaper {
    pub name: String,
    pub kbps: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ZoneProtection {
    pub name: String,
    pub vdom: String,
    pub syn_flood: Option<u32>,
    pub icmp_flood: Option<u32>,
    pub udp_flood: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
    Number(u8),
}

impl Proto {
    pub fn parse(s: &str) -> Result<Proto, String> {
        Ok(match s {
            "any" => Proto::Any,
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "icmp" => Proto::Icmp,
            other => {
                let n = other
                    .parse::<u8>()
                    .map_err(|_| format!("invalid protocol '{other}'"))?;
                Proto::Number(n)
            }
        })
    }

    pub fn number(self) -> Option<u8> {
        match self {
            Proto::Any => None,
            Proto::Tcp => Some(6),
            Proto::Udp => Some(17),
            Proto::Icmp => Some(1),
            Proto::Number(n) => Some(n),
        }
    }

    pub fn matches(self, number: u8) -> bool {
        match self {
            Proto::Any => true,
            other => other.number() == Some(number),
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Any => f.write_str("any"),
            Proto::Tcp => f.write_str("tcp"),
            Proto::Udp => f.write_str("udp"),
            Proto::Icmp => f.write_str("icmp"),
            Proto::Number(n) => write!(f, "{n}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Permit,
    Deny,
    /// Drop and tell the sender (TCP RST or ICMP unreachable).
    Reject,
}

impl Action {
    pub fn parse(s: &str) -> Result<Action, String> {
        match s {
            "permit" | "accept" | "allow" => Ok(Action::Permit),
            "deny" | "drop" => Ok(Action::Deny),
            "reject" => Ok(Action::Reject),
            other => Err(format!("invalid action '{other}' (permit, deny or reject)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Permit => "permit",
            Action::Deny => "deny",
            Action::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub vdom: String,
    pub zone: String,
    pub address: Option<Cidr>,
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    /// A WireGuard tunnel interface (virtual; no AF_PACKET socket).
    pub tunnel: bool,
    /// Global IPv6 address. A link-local address is derived from the MAC.
    pub address6: Option<Cidr6>,
}

impl Interface {
    pub fn new(name: &str, zone: &str) -> Interface {
        Interface {
            tunnel: false,
            address6: None,
            name: name.to_string(),
            vdom: "root".to_string(),
            zone: zone.to_string(),
            address: None,
            mac: None,
            mtu: 1500,
        }
    }
}

/// A security policy. Every match field is a list, as on FortiOS and PAN-OS:
/// a packet matches a field if it matches any entry in it.
#[derive(Clone, Debug)]
pub struct Policy {
    pub id: u32,
    pub vdom: String,
    /// Source zones; `any` matches every zone.
    pub src_zones: Vec<String>,
    pub dst_zones: Vec<String>,
    pub src: Vec<AddrRef>,
    pub dst: Vec<AddrRef>,
    /// Match addresses *not* in the list.
    pub negate_src: bool,
    pub negate_dst: bool,
    /// Inline protocol and port, for simple rules without service objects.
    pub proto: Proto,
    pub dst_port: Option<u16>,
    /// Service and service-group names, `any` or `application-default`.
    /// Empty means the inline protocol/port decide.
    pub services: Vec<String>,
    /// Applications, application groups and `category:<name>`. Empty means any.
    pub apps: Vec<String>,
    /// Users, user groups, `known-user` or `unknown`. Empty means any.
    pub users: Vec<String>,
    pub action: Action,
    pub nat: bool,
    pub url: Option<String>,
    pub ips: Option<String>,
    pub av: Option<String>,
    pub shaper: Option<String>,
    /// Profile group supplying URL/IPS/AV profiles not set on the policy.
    pub group: Option<String>,
    pub log: bool,
    /// Disabled policies stay in the configuration but never match.
    pub enabled: bool,
    pub name: Option<String>,
}

impl Policy {
    /// A permit-nothing skeleton: every list is `any`, the action is deny.
    pub fn new(id: u32, vdom: &str) -> Policy {
        Policy {
            id,
            vdom: vdom.to_string(),
            src_zones: vec!["any".to_string()],
            dst_zones: vec!["any".to_string()],
            src: vec![AddrRef::Cidr(Cidr::ANY)],
            dst: vec![AddrRef::Cidr(Cidr::ANY)],
            negate_src: false,
            negate_dst: false,
            proto: Proto::Any,
            dst_port: None,
            services: Vec::new(),
            apps: Vec::new(),
            users: Vec::new(),
            action: Action::Deny,
            nat: false,
            url: None,
            ips: None,
            av: None,
            shaper: None,
            group: None,
            log: true,
            enabled: true,
            name: None,
        }
    }

    pub fn names_app(&self) -> bool {
        !self.apps.is_empty() && !self.apps.iter().any(|a| a == "any")
    }
}

/// Render an address list for the config language: `any`, `a,b`, `!a,b`.
pub fn addr_list_text(list: &[AddrRef], negate: bool) -> String {
    let body = list
        .iter()
        .map(|a| match a {
            AddrRef::Cidr(c) if *c == Cidr::ANY => "any".to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    if negate { format!("!{body}") } else { body }
}

fn parse_addr_list(s: &str) -> Result<(Vec<AddrRef>, bool), String> {
    let (negate, body) = match s.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let mut out = Vec::new();
    for part in body.split(',').filter(|p| !p.is_empty()) {
        out.push(AddrRef::parse(part)?);
    }
    if out.is_empty() {
        return Err(format!("empty address list '{s}'"));
    }
    Ok((out, negate))
}

/// User names may carry a domain (`corp\\alice`, `alice@corp.example`).
pub fn valid_user_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@\\".contains(c)) {
        return Err(format!("invalid user name '{name}'"));
    }
    Ok(())
}

fn parse_name_list(s: &str) -> Vec<String> {
    s.split(',').filter(|p| !p.is_empty()).map(|p| p.trim_start_matches('@').to_string()).collect()
}

/// A static IPv6 route; same selection rules as [`Route`].
#[derive(Clone, Debug)]
pub struct Route6 {
    pub dst: Cidr6,
    pub interface: String,
    pub via: Option<Ipv6Addr>,
    pub distance: u8,
    pub vdom: String,
}

/// A static route. The most specific matching prefix wins; among equal
/// prefixes the lowest distance wins.
#[derive(Clone, Debug)]
pub struct Route {
    pub dst: Cidr,
    pub interface: String,
    pub via: Option<Ipv4Addr>,
    pub distance: u8,
    pub vdom: String,
    /// Optional label (PAN-OS route name, FortiOS sequence number).
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub hostname: String,
    pub cli_port: u16,
    pub gui_port: u16,
    /// Management listeners bind here. Loopback is the secure default; a
    /// container or appliance can opt into a management network explicitly.
    pub cli_bind: IpAddr,
    pub gui_bind: IpAddr,
    /// Serve the web management API over HTTPS.
    pub tls: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub api_rate: u32,
    pub api_burst: u32,
    pub max_body: usize,
    pub tcp_timeout: u64,
    pub udp_timeout: u64,
    pub icmp_timeout: u64,
    pub logging: bool,
    pub log_json: bool,
    /// Global cap on tracked flows; 0 disables the cap.
    pub max_sessions: usize,
    /// Cap on tracked flows opened by one source address; 0 disables it.
    pub max_sessions_per_ip: usize,
    /// Largest accepted Ethernet frame. Oversized frames are dropped before
    /// parsing so a hostile sender cannot force unbounded parser work.
    pub max_packet_size: usize,
    /// Upper bound on bytes handed to URL/IPS/AV payload inspection.
    pub max_inspection_bytes: usize,
    /// Per-source ingress packet rate and burst; 0 disables the limiter.
    pub source_rate: u32,
    pub source_burst: u32,
    /// Default CLI style for new CLI sessions: native, fortios or panos.
    pub cli_style: String,
    /// `system kernel-forwarding refuse` (default): the daemon will not start
    /// its dataplane while the kernel would forward between its interfaces,
    /// because the kernel would route traffic around the engine. `warn`
    /// starts anyway and reports the firewall as degraded.
    pub kernel_forwarding_refuse: bool,
    /// The CLI transport is plaintext TCP. Binding it to a non-loopback
    /// address is refused unless `system cli-remote-plaintext on`.
    pub cli_remote_plaintext: bool,
    /// `system dataplane kernel`: enforce in the kernel (nftables) instead of
    /// the userspace AF_PACKET engine. Fixed at startup.
    pub dataplane_kernel: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            hostname: "firewall".to_string(),
            cli_port: 2200,
            gui_port: 8080,
            cli_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            gui_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            tls: true,
            tls_cert: None,
            tls_key: None,
            api_rate: 600,
            api_burst: 120,
            max_body: 1024 * 1024,
            tcp_timeout: 300,
            udp_timeout: 30,
            icmp_timeout: 10,
            logging: true,
            log_json: false,
            max_sessions: 100_000,
            max_sessions_per_ip: 0,
            max_packet_size: 65_535,
            max_inspection_bytes: 65_535,
            source_rate: 0,
            source_burst: 0,
            cli_style: "native".to_string(),
            kernel_forwarding_refuse: true,
            cli_remote_plaintext: false,
            dataplane_kernel: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub settings: Settings,
    pub interfaces: Vec<Interface>,
    pub policies: Vec<Policy>,
    pub routes: Vec<Route>,
    pub vdoms: Vec<String>,
    pub current_vdom: String,
    pub addresses: Vec<AddressObject>,
    pub address_groups: Vec<AddressGroup>,
    pub services: Vec<ServiceObject>,
    pub service_groups: Vec<ServiceGroup>,
    pub apps: Vec<AppDef>,
    pub app_groups: Vec<AppGroup>,
    pub profile_groups: Vec<ProfileGroup>,
    pub snat: Vec<SnatRule>,
    pub url_filters: Vec<UrlFilter>,
    pub ips_profiles: Vec<SignatureProfile>,
    pub av_profiles: Vec<SignatureProfile>,
    pub dnat: Vec<DnatRule>,
    pub shapers: Vec<Shaper>,
    pub zones: Vec<ZoneProtection>,
    pub default_rules: Vec<DefaultRule>,
    pub user_groups: Vec<UserGroup>,
    pub user_maps: Vec<UserMap>,
    pub ha: crate::ha::HaSettings,
    pub tunnels: Vec<crate::wg::TunnelConfig>,
    pub routes6: Vec<Route6>,
    /// The default rules as policies, one set per VDOM; rebuilt by
    /// [`Config::rebuild_defaults`] and never written to the config text.
    pub default_policies: Vec<Policy>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg = Config::default();
        cfg.vdoms.push("root".to_string());
        cfg.current_vdom = "root".to_string();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            let err = |msg: String| format!("line {}: {msg}", lineno + 1);
            match words[0] {
                "system" => cfg.parse_system(&words[1..]).map_err(|e| err(e))?,
                "ha" => cfg.ha.parse_line(&words[1..]).map_err(|e| err(e))?,
                "vpn" => cfg.parse_vpn(&words[1..]).map_err(|e| err(e))?,
                "interface" => cfg.parse_interface(&words[1..]).map_err(|e| err(e))?,
                "route" => cfg.parse_route(&words[1..]).map_err(|e| err(e))?,
                "route6" => cfg.parse_route6(&words[1..]).map_err(|e| err(e))?,
                "vdom" => cfg.parse_vdom(&words[1..]).map_err(|e| err(e))?,
                "policy" => cfg.parse_policy(&words[1..]).map_err(|e| err(e))?,
                "address" => cfg.parse_address(&words[1..]).map_err(|e| err(e))?,
                "address-group" => cfg.parse_address_group(&words[1..]).map_err(|e| err(e))?,
                "service" => cfg.parse_service(&words[1..]).map_err(|e| err(e))?,
                "service-group" => cfg.parse_service_group(&words[1..]).map_err(|e| err(e))?,
                "app-group" => cfg.parse_app_group(&words[1..]).map_err(|e| err(e))?,
                "profile-group" => cfg.parse_profile_group(&words[1..]).map_err(|e| err(e))?,
                "snat" => cfg.parse_snat(&words[1..]).map_err(|e| err(e))?,
                "app-def" => cfg.parse_app(&words[1..]).map_err(|e| err(e))?,
                "url-filter" => cfg.parse_url_filter(&words[1..]).map_err(|e| err(e))?,
                "ips-profile" => cfg
                    .parse_signature_profile(&words[1..], false)
                    .map_err(|e| err(e))?,
                "ips-signature" => cfg
                    .parse_signature(&words[1..], false)
                    .map_err(|e| err(e))?,
                "av-profile" => cfg
                    .parse_signature_profile(&words[1..], true)
                    .map_err(|e| err(e))?,
                "av-signature" => cfg.parse_signature(&words[1..], true).map_err(|e| err(e))?,
                "dnat" => cfg.parse_dnat(&words[1..]).map_err(|e| err(e))?,
                "shaper" => cfg.parse_shaper(&words[1..]).map_err(|e| err(e))?,
                "zone" => cfg.parse_zone(&words[1..]).map_err(|e| err(e))?,
                "default-rule" => cfg.parse_default_rule(&words[1..]).map_err(|e| err(e))?,
                "user-group" => cfg.parse_user_group(&words[1..]).map_err(|e| err(e))?,
                "user-map" => cfg.parse_user_map(&words[1..]).map_err(|e| err(e))?,
                other => return Err(err(format!("unknown directive '{other}'"))),
            }
        }
        cfg.validate()?;
        cfg.rebuild_defaults();
        Ok(cfg)
    }

    fn parse_system(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 2 {
            return Err("usage: system <key> <value>".to_string());
        }
        let (key, value) = (words[0], words[1]);
        let s = &mut self.settings;
        match key {
            "hostname" => s.hostname = value.to_string(),
            "cli-port" => s.cli_port = value.parse().map_err(|_| "invalid cli-port".to_string())?,
            "gui-port" => s.gui_port = value.parse().map_err(|_| "invalid gui-port".to_string())?,
            "cli-bind" => {
                s.cli_bind = value
                    .parse()
                    .map_err(|_| "invalid cli-bind address".to_string())?
            }
            "gui-bind" => {
                s.gui_bind = value
                    .parse()
                    .map_err(|_| "invalid gui-bind address".to_string())?
            }
            "tls" => match value {
                "on" | "yes" | "true" => s.tls = true,
                "off" | "no" | "false" => s.tls = false,
                _ => return Err("system tls expects on or off".to_string()),
            },
            "tls-cert" => s.tls_cert = Some(value.to_string()),
            "tls-key" => s.tls_key = Some(value.to_string()),
            "api-rate" => s.api_rate = value.parse().map_err(|_| "invalid api-rate".to_string())?,
            "api-burst" => {
                s.api_burst = value.parse().map_err(|_| "invalid api-burst".to_string())?
            }
            "max-body" => s.max_body = value.parse().map_err(|_| "invalid max-body".to_string())?,
            "conntrack-tcp" => {
                s.tcp_timeout = value
                    .parse()
                    .map_err(|_| "invalid conntrack-tcp".to_string())?
            }
            "conntrack-udp" => {
                s.udp_timeout = value
                    .parse()
                    .map_err(|_| "invalid conntrack-udp".to_string())?
            }
            "conntrack-icmp" => {
                s.icmp_timeout = value
                    .parse()
                    .map_err(|_| "invalid conntrack-icmp".to_string())?
            }
            "max-sessions" => {
                s.max_sessions = value
                    .parse()
                    .map_err(|_| "invalid max-sessions".to_string())?
            }
            "kernel-forwarding" => {
                s.kernel_forwarding_refuse = match value {
                    "refuse" => true,
                    "warn" => false,
                    _ => return Err("kernel-forwarding must be refuse or warn".to_string()),
                }
            }
            "dataplane" => {
                s.dataplane_kernel = match value {
                    "kernel" => true,
                    "userspace" => false,
                    _ => return Err("dataplane must be userspace or kernel".to_string()),
                }
            }
            "cli-remote-plaintext" => {
                s.cli_remote_plaintext = match value {
                    "on" => true,
                    "off" => false,
                    _ => return Err("cli-remote-plaintext must be on or off".to_string()),
                }
            }
            "max-sessions-per-ip" => {
                s.max_sessions_per_ip = value
                    .parse()
                    .map_err(|_| "invalid max-sessions-per-ip".to_string())?
            }
            "max-packet" => {
                s.max_packet_size = value
                    .parse()
                    .map_err(|_| "invalid max-packet".to_string())?
            }
            "max-inspection" => {
                s.max_inspection_bytes = value
                    .parse()
                    .map_err(|_| "invalid max-inspection".to_string())?
            }
            "source-rate" => {
                s.source_rate = value
                    .parse()
                    .map_err(|_| "invalid source-rate".to_string())?
            }
            "source-burst" => {
                s.source_burst = value
                    .parse()
                    .map_err(|_| "invalid source-burst".to_string())?
            }
            "logging" => match value {
                "on" | "yes" | "true" => s.logging = true,
                "off" | "no" | "false" => s.logging = false,
                _ => return Err("system logging expects on or off".to_string()),
            },
            "cli-style" => match value {
                "native" | "fortios" | "panos" => s.cli_style = value.to_string(),
                _ => return Err("system cli-style expects native, fortios or panos".to_string()),
            },
            "log-format" => match value {
                "text" => s.log_json = false,
                "json" => s.log_json = true,
                _ => return Err("system log-format expects text or json".to_string()),
            },
            other => return Err(format!("unknown system key '{other}'")),
        }
        Ok(())
    }

    fn parse_interface(&mut self, words: &[&str]) -> Result<(), String> {
        if words.is_empty() {
            return Err("usage: interface <name> zone <zone> [address a.b.c.d/len] [mac aa:bb:cc:dd:ee:ff] [mtu N]".to_string());
        }
        let mut iface = Interface::new(words[0], "");
        iface.vdom = self.current_vdom.clone();
        let mut i = 1;
        while i < words.len() {
            if i + 1 >= words.len() {
                return Err(format!("interface option '{}' needs a value", words[i]));
            }
            let (key, value) = (words[i], words[i + 1]);
            match key {
                "zone" => iface.zone = value.to_string(),
                "address" => {
                    iface.address = Some(Cidr::parse(value).map_err(|e| format!("address: {e}"))?)
                }
                "address6" => iface.address6 = Some(Cidr6::parse(value).map_err(|e| format!("address6: {e}"))?),
                "mac" => iface.mac = Some(parse_mac(value)?),
                "mtu" => {
                    iface.mtu = value
                        .parse()
                        .map_err(|_| format!("invalid mtu '{value}'"))?
                }
                other => return Err(format!("unknown interface option '{other}'")),
            }
            i += 2;
        }
        if iface.zone.is_empty() {
            return Err(format!("interface {} needs a zone", iface.name));
        }
        if self.interfaces.iter().any(|i| i.name == iface.name) {
            return Err(format!("duplicate interface '{}'", iface.name));
        }
        self.interfaces.push(iface);
        Ok(())
    }

    fn parse_route(&mut self, words: &[&str]) -> Result<(), String> {
        const USAGE: &str = "usage: route <default|cidr> <interface> [via a.b.c.d] [distance n] [name n]";
        if words.len() < 2 {
            return Err(USAGE.to_string());
        }
        let dst = if words[0] == "default" {
            Cidr::ANY
        } else {
            Cidr::parse(words[0]).map_err(|e| format!("route destination: {e}"))?
        };
        let mut route = Route {
            dst,
            interface: words[1].to_string(),
            via: None,
            distance: 10,
            vdom: self.current_vdom.clone(),
            name: None,
        };
        let mut i = 2;
        while i < words.len() {
            let value = words.get(i + 1).ok_or_else(|| USAGE.to_string())?;
            match words[i] {
                "via" => route.via = Some(value.parse().map_err(|_| format!("invalid gateway '{value}'"))?),
                "distance" => route.distance = value.parse().map_err(|_| format!("invalid distance '{value}'"))?,
                "name" => route.name = Some(value.to_string()),
                _ => return Err(USAGE.to_string()),
            }
            i += 2;
        }
        if self
            .routes
            .iter()
            .any(|r| r.vdom == route.vdom && r.dst == route.dst && r.distance == route.distance)
        {
            return Err(if route.dst == Cidr::ANY {
                format!("duplicate default route for vdom '{}' (give one a different distance)", route.vdom)
            } else {
                format!("duplicate route {} for vdom '{}'", route.dst, route.vdom)
            });
        }
        self.routes.push(route);
        Ok(())
    }

    fn parse_route6(&mut self, words: &[&str]) -> Result<(), String> {
        const USAGE: &str = "usage: route6 <default|prefix> <interface> [via <ipv6>] [distance n]";
        if words.len() < 2 {
            return Err(USAGE.to_string());
        }
        let dst = if words[0] == "default" { Cidr6::ANY } else { Cidr6::parse(words[0])?.network() };
        let mut route = Route6 { dst, interface: words[1].to_string(), via: None, distance: 10, vdom: self.current_vdom.clone() };
        let mut i = 2;
        while i < words.len() {
            let value = words.get(i + 1).ok_or(USAGE)?;
            match words[i] {
                "via" => route.via = Some(value.parse().map_err(|_| format!("invalid IPv6 gateway '{value}'"))?),
                "distance" => route.distance = value.parse().map_err(|_| format!("invalid distance '{value}'"))?,
                _ => return Err(USAGE.to_string()),
            }
            i += 2;
        }
        if self.routes6.iter().any(|r| r.vdom == route.vdom && r.dst == route.dst && r.distance == route.distance) {
            return Err(format!("duplicate route6 {} for vdom '{}'", route.dst, route.vdom));
        }
        self.routes6.push(route);
        Ok(())
    }

    fn parse_vdom(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 1 {
            return Err("usage: vdom <name>".to_string());
        }
        let name = words[0];
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("invalid vdom name '{name}'"));
        }
        if !self.vdoms.iter().any(|v| v == name) {
            self.vdoms.push(name.to_string());
        }
        self.current_vdom = name.to_string();
        Ok(())
    }

    fn parse_policy(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 8 {
            return Err("usage: policy <id> <src-zones> <dst-zones> <[!]src,...> <[!]dst,...> <proto|any> <port|@svc,...|application-default|any> <permit|deny|reject> [options...]".to_string());
        }
        let id: u32 = words[0]
            .parse()
            .map_err(|_| format!("invalid policy id '{}'", words[0]))?;
        if self.policies.iter().any(|p| p.id == id) {
            return Err(format!("duplicate policy id {id}"));
        }
        let mut policy = Policy::new(id, &self.current_vdom);
        policy.src_zones = parse_name_list(words[1]);
        policy.dst_zones = parse_name_list(words[2]);
        (policy.src, policy.negate_src) = parse_addr_list(words[3]).map_err(|e| format!("source: {e}"))?;
        (policy.dst, policy.negate_dst) = parse_addr_list(words[4]).map_err(|e| format!("destination: {e}"))?;
        policy.proto = Proto::parse(words[5]).map_err(|e| format!("protocol: {e}"))?;
        let port = words[6];
        if port == "application-default" {
            policy.services = vec![port.to_string()];
        } else if port.starts_with('@') {
            policy.services = parse_name_list(port);
        } else if port != "any" {
            policy.dst_port = Some(port.parse().map_err(|_| format!("invalid port '{port}'"))?);
        }
        policy.action = Action::parse(words[7])?;
        let mut i = 8;
        while i < words.len() {
            match words[i] {
                "nat" => policy.nat = true,
                "log" => policy.log = true,
                "nolog" => policy.log = false,
                "disable" => policy.enabled = false,
                "enable" => policy.enabled = true,
                key @ ("name" | "app" | "url" | "ips" | "av" | "shaper" | "group" | "user") => {
                    let value = words
                        .get(i + 1)
                        .ok_or_else(|| format!("policy option '{key}' needs a value"))?
                        .to_string();
                    match key {
                        "name" => policy.name = Some(value),
                        "app" => policy.apps = parse_name_list(&value),
                        "user" => policy.users = parse_name_list(&value),
                        "url" => policy.url = Some(value),
                        "ips" => policy.ips = Some(value),
                        "av" => policy.av = Some(value),
                        "group" => policy.group = Some(value),
                        _ => policy.shaper = Some(value),
                    }
                    i += 1;
                }
                other => return Err(format!("unknown policy option '{other}'")),
            }
            i += 1;
        }
        self.policies.push(policy);
        Ok(())
    }

    fn parse_address(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 2 {
            return Err("usage: address <name> <cidr> [<cidr>...]".to_string());
        }
        if self.addresses.iter().any(|a| a.name == words[0]) {
            return Err(format!("duplicate address object '{}'", words[0]));
        }
        let mut entries = Vec::new();
        let mut entries6 = Vec::new();
        for value in &words[1..] {
            if value.contains(':') {
                entries6.push(Cidr6::parse(value).map_err(|e| format!("address: {e}"))?);
            } else {
                entries.push(Cidr::parse(value).map_err(|e| format!("address: {e}"))?);
            }
        }
        self.addresses.push(AddressObject {
            name: words[0].to_string(),
            entries,
            entries6,
        });
        Ok(())
    }

    fn parse_address_group(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 2 {
            return Err("usage: address-group <name> <member>...".to_string());
        }
        if self.address_groups.iter().any(|g| g.name == words[0]) {
            return Err(format!("duplicate address group '{}'", words[0]));
        }
        self.address_groups.push(AddressGroup {
            name: words[0].to_string(),
            members: words[1..]
                .iter()
                .map(|m| m.trim_start_matches('@').to_string())
                .collect(),
        });
        Ok(())
    }

    fn parse_service(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 3 {
            return Err("usage: service <name> <proto|any> <ports|any>  (ports: 80,443,8000-8080)".to_string());
        }
        if self.services.iter().any(|s| s.name == words[0]) || self.service_groups.iter().any(|g| g.name == words[0]) {
            return Err(format!("duplicate service object '{}'", words[0]));
        }
        let proto = Proto::parse(words[1]).map_err(|e| format!("service protocol: {e}"))?;
        let ports = parse_port_ranges(words[2]).map_err(|e| format!("service: {e}"))?;
        self.services.push(ServiceObject { name: words[0].to_string(), proto, ports });
        Ok(())
    }

    fn parse_service_group(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 2 {
            return Err("usage: service-group <name> <member>...".to_string());
        }
        if self.services.iter().any(|s| s.name == words[0]) || self.service_groups.iter().any(|g| g.name == words[0]) {
            return Err(format!("duplicate service object '{}'", words[0]));
        }
        self.service_groups.push(ServiceGroup {
            name: words[0].to_string(),
            members: words[1..].iter().map(|m| m.trim_start_matches('@').to_string()).collect(),
        });
        Ok(())
    }

    fn parse_app_group(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 2 {
            return Err("usage: app-group <name> <app|group|category:name>...".to_string());
        }
        if self.app_groups.iter().any(|g| g.name == words[0]) || crate::appid::is_builtin(words[0]) {
            return Err(format!("duplicate application name '{}'", words[0]));
        }
        self.app_groups.push(AppGroup {
            name: words[0].to_string(),
            members: words[1..].iter().map(|m| m.to_string()).collect(),
        });
        Ok(())
    }

    fn parse_profile_group(&mut self, words: &[&str]) -> Result<(), String> {
        if words.is_empty() || words.len() % 2 == 0 {
            return Err("usage: profile-group <name> [url <f>] [ips <p>] [av <p>]".to_string());
        }
        if self.profile_groups.iter().any(|g| g.name == words[0]) {
            return Err(format!("duplicate profile group '{}'", words[0]));
        }
        let mut group = ProfileGroup { name: words[0].to_string(), ..ProfileGroup::default() };
        for pair in words[1..].chunks(2) {
            let value = Some(pair[1].to_string());
            match pair[0] {
                "url" => group.url = value,
                "ips" => group.ips = value,
                "av" => group.av = value,
                other => return Err(format!("unknown profile type '{other}'")),
            }
        }
        self.profile_groups.push(group);
        Ok(())
    }

    fn parse_vpn(&mut self, words: &[&str]) -> Result<(), String> {
        const TUNNEL: &str = "usage: vpn wireguard <name> private-key <base64> listen-port <port> address <cidr> zone <zone> [mtu n]";
        const PEER: &str = "usage: vpn wireguard-peer <tunnel> <peer> public-key <base64> allowed-ips <cidr,...> [endpoint ip:port] [preshared-key <base64>] [keepalive <seconds>]";
        match words.first() {
            Some(&"wireguard") => {
                let name = words.get(1).ok_or(TUNNEL)?.to_string();
                if self.interfaces.iter().any(|i| i.name == name) {
                    return Err(format!("interface '{name}' already exists"));
                }
                let (mut key, mut port, mut address, mut zone, mut mtu) = (None, None, None, None, 1420);
                for pair in words[2..].chunks(2) {
                    let [k, v] = pair else { return Err(TUNNEL.to_string()) };
                    match *k {
                        "private-key" => key = Some(crate::wg::key_from_b64(v)?),
                        "listen-port" => port = Some(v.parse::<u16>().map_err(|_| format!("invalid listen-port '{v}'"))?),
                        "address" => address = Some(Cidr::parse(v)?),
                        "zone" => zone = Some(v.to_string()),
                        "mtu" => mtu = v.parse().map_err(|_| format!("invalid mtu '{v}'"))?,
                        _ => return Err(TUNNEL.to_string()),
                    }
                }
                let (Some(private_key), Some(listen_port), Some(zone)) = (key, port, zone) else {
                    return Err(TUNNEL.to_string());
                };
                let mut iface = Interface::new(&name, &zone);
                iface.vdom = self.current_vdom.clone();
                iface.address = address;
                iface.mtu = mtu;
                iface.tunnel = true;
                self.interfaces.push(iface);
                self.tunnels.push(crate::wg::TunnelConfig { name, vdom: self.current_vdom.clone(), private_key, listen_port, peers: Vec::new() });
                Ok(())
            }
            Some(&"wireguard-peer") => {
                let tunnel = words.get(1).ok_or(PEER)?;
                let name = words.get(2).ok_or(PEER)?.to_string();
                let t = self.tunnels.iter_mut().find(|t| t.name == *tunnel).ok_or_else(|| format!("unknown tunnel '{tunnel}'"))?;
                if t.peers.iter().any(|p| p.name == name) {
                    return Err(format!("duplicate peer '{name}'"));
                }
                let mut peer = crate::wg::PeerConfig {
                    name,
                    public_key: [0; 32],
                    preshared_key: None,
                    endpoint: None,
                    allowed_ips: Vec::new(),
                    keepalive: None,
                };
                let mut have_key = false;
                for pair in words[3..].chunks(2) {
                    let [k, v] = pair else { return Err(PEER.to_string()) };
                    match *k {
                        "public-key" => {
                            peer.public_key = crate::wg::key_from_b64(v)?;
                            have_key = true;
                        }
                        "preshared-key" => peer.preshared_key = Some(crate::wg::key_from_b64(v)?),
                        "endpoint" => peer.endpoint = Some(v.parse().map_err(|_| format!("endpoint expects ip:port, got '{v}'"))?),
                        "allowed-ips" => {
                            for c in v.split(',').filter(|c| !c.is_empty()) {
                                peer.allowed_ips.push(Cidr::parse(c)?);
                            }
                        }
                        "keepalive" => peer.keepalive = Some(v.parse().map_err(|_| format!("invalid keepalive '{v}'"))?),
                        _ => return Err(PEER.to_string()),
                    }
                }
                if !have_key || peer.allowed_ips.is_empty() {
                    return Err(PEER.to_string());
                }
                if t.peers.iter().any(|p| p.public_key == peer.public_key) {
                    return Err("two peers with the same public key".to_string());
                }
                t.peers.push(peer);
                Ok(())
            }
            _ => Err(format!("{TUNNEL}\n{PEER}")),
        }
    }

    fn parse_user_group(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 2 {
            return Err("usage: user-group <name> <user|group>...".to_string());
        }
        if self.user_groups.iter().any(|g| g.name == words[0]) {
            return Err(format!("duplicate user group '{}'", words[0]));
        }
        self.user_groups.push(UserGroup { name: words[0].to_string(), members: words[1..].iter().map(|m| m.to_string()).collect() });
        Ok(())
    }

    fn parse_user_map(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 2 {
            return Err("usage: user-map <ip|cidr> <user>".to_string());
        }
        let cidr = Cidr::parse(words[0]).map_err(|e| format!("user-map: {e}"))?;
        valid_user_name(words[1])?;
        self.user_maps.push(UserMap { cidr, user: words[1].to_string() });
        Ok(())
    }

    fn parse_default_rule(&mut self, words: &[&str]) -> Result<(), String> {
        const USAGE: &str = "usage: default-rule intrazone|interzone allow|deny [zone <z>] [log]";
        let kind = match words.first() {
            Some(&"intrazone") => DefaultKind::Intrazone,
            Some(&"interzone") => DefaultKind::Interzone,
            _ => return Err(USAGE.to_string()),
        };
        let action = match words.get(1) {
            Some(&"allow") | Some(&"permit") => Action::Permit,
            Some(&"deny") => Action::Deny,
            _ => return Err(USAGE.to_string()),
        };
        let mut rule = DefaultRule { vdom: self.current_vdom.clone(), kind, zone: None, action, log: false };
        let mut i = 2;
        while i < words.len() {
            match words[i] {
                "log" => rule.log = true,
                "zone" if kind == DefaultKind::Intrazone => {
                    rule.zone = Some(words.get(i + 1).ok_or(USAGE)?.to_string());
                    i += 1;
                }
                _ => return Err(USAGE.to_string()),
            }
            i += 1;
        }
        self.set_default_rule(rule)
    }

    /// Add or replace a default rule (one per VDOM, kind and zone).
    pub fn set_default_rule(&mut self, rule: DefaultRule) -> Result<(), String> {
        self.default_rules.retain(|r| !(r.vdom == rule.vdom && r.kind == rule.kind && r.zone == rule.zone));
        if self.default_rules.iter().filter(|r| r.zone.is_some()).count() >= 4000 {
            return Err("too many per-zone default rules".to_string());
        }
        self.default_rules.push(rule);
        self.rebuild_defaults();
        Ok(())
    }

    /// Materialize the default rules of every VDOM as policies so the
    /// dataplane can treat them like any rule (hits, logs, sessions).
    pub fn rebuild_defaults(&mut self) {
        let mut out = Vec::new();
        for vdom in &self.vdoms {
            let find = |kind: DefaultKind, zone: Option<&str>| {
                self.default_rules.iter().find(|r| &r.vdom == vdom && r.kind == kind && r.zone.as_deref() == zone)
            };
            for (kind, id, name) in [
                (DefaultKind::Intrazone, INTRAZONE_ID, "intrazone-default"),
                (DefaultKind::Interzone, INTERZONE_ID, "interzone-default"),
            ] {
                let mut p = Policy::new(id, vdom);
                p.name = Some(name.to_string());
                if let Some(r) = find(kind, None) {
                    p.action = r.action;
                    p.log = r.log;
                } else {
                    p.log = false;
                }
                out.push(p);
            }
            for (n, r) in self.default_rules.iter().filter(|r| &r.vdom == vdom && r.zone.is_some()).enumerate() {
                let zone = r.zone.clone().unwrap_or_default();
                let mut p = Policy::new(ZONE_DEFAULT_BASE - n as u32, vdom);
                p.name = Some(format!("intrazone-default:{zone}"));
                p.src_zones = vec![zone.clone()];
                p.dst_zones = vec![zone];
                p.action = r.action;
                p.log = r.log;
                out.push(p);
            }
        }
        self.default_policies = out;
    }

    fn parse_snat(&mut self, words: &[&str]) -> Result<(), String> {
        const USAGE: &str = "usage: snat <id> <src-zones> <dst-zones> <[!]src,...> <dst,...> masquerade|<ip> [name n] [disable]";
        if words.len() < 6 {
            return Err(USAGE.to_string());
        }
        let id: u32 = words[0].parse().map_err(|_| format!("invalid snat id '{}'", words[0]))?;
        if self.snat.iter().any(|r| r.id == id) {
            return Err(format!("duplicate snat id {id}"));
        }
        let (src, src_neg) = parse_addr_list(words[3]).map_err(|e| format!("snat source: {e}"))?;
        let (dst, dst_neg) = parse_addr_list(words[4]).map_err(|e| format!("snat destination: {e}"))?;
        if src_neg || dst_neg {
            return Err("snat rules do not support negation".to_string());
        }
        let to = match words[5] {
            "masquerade" => SnatTarget::Masquerade,
            ip => SnatTarget::Address(ip.parse().map_err(|_| format!("invalid snat address '{ip}'"))?),
        };
        let mut rule = SnatRule {
            id,
            vdom: self.current_vdom.clone(),
            src_zones: parse_name_list(words[1]),
            dst_zones: parse_name_list(words[2]),
            src,
            dst,
            to,
            enabled: true,
            name: None,
        };
        let mut i = 6;
        while i < words.len() {
            match words[i] {
                "disable" => rule.enabled = false,
                "name" => {
                    rule.name = Some(words.get(i + 1).ok_or_else(|| USAGE.to_string())?.to_string());
                    i += 1;
                }
                _ => return Err(USAGE.to_string()),
            }
            i += 1;
        }
        self.snat.push(rule);
        Ok(())
    }

    fn parse_app(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 3 {
            return Err("usage: app-def <name> <proto> <port>".to_string());
        }
        if self.apps.iter().any(|a| a.name == words[0]) {
            return Err(format!("duplicate application '{}'", words[0]));
        }
        let proto = Proto::parse(words[1]).map_err(|e| format!("app protocol: {e}"))?;
        let port = words[2]
            .parse()
            .map_err(|_| format!("invalid app port '{}'", words[2]))?;
        self.apps.push(AppDef {
            name: words[0].to_string(),
            proto,
            port,
        });
        Ok(())
    }

    fn parse_url_filter(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() < 3 {
            return Err("usage: url-filter <name> block|allow <item>...".to_string());
        }
        let name = words[0].to_string();
        let list = match words[1] {
            "block" => true,
            "allow" => false,
            other => return Err(format!("expected block or allow, got '{other}'")),
        };
        if !self.url_filters.iter().any(|f| f.name == name) {
            self.url_filters.push(UrlFilter {
                name: name.clone(),
                block: Vec::new(),
                allow: Vec::new(),
            });
        }
        let filter = self
            .url_filters
            .iter_mut()
            .find(|f| f.name == name)
            .unwrap();
        for item in &words[2..] {
            let value = if URL_CATEGORIES.iter().any(|(name, _)| name == item) {
                format!("category:{item}")
            } else {
                item.to_string()
            };
            if list {
                filter.block.push(value);
            } else {
                filter.allow.push(value);
            }
        }
        Ok(())
    }

    fn signature_list_mut(&mut self, av: bool) -> &mut Vec<SignatureProfile> {
        if av {
            &mut self.av_profiles
        } else {
            &mut self.ips_profiles
        }
    }

    fn parse_signature_profile(&mut self, words: &[&str], av: bool) -> Result<(), String> {
        if words.len() != 1 {
            return Err("usage: <ips|av>-profile <name>".to_string());
        }
        let list = self.signature_list_mut(av);
        if list.iter().any(|p| p.name == words[0]) {
            return Err(format!("duplicate profile '{}'", words[0]));
        }
        list.push(SignatureProfile {
            name: words[0].to_string(),
            patterns: Vec::new(),
        });
        Ok(())
    }

    fn parse_signature(&mut self, words: &[&str], av: bool) -> Result<(), String> {
        if words.len() != 3 {
            return Err("usage: <ips|av>-signature <profile> <id> <pattern>".to_string());
        }
        let list = self.signature_list_mut(av);
        if !list.iter().any(|p| p.name == words[0]) {
            list.push(SignatureProfile {
                name: words[0].to_string(),
                patterns: Vec::new(),
            });
        }
        let profile = list.iter_mut().find(|p| p.name == words[0]).unwrap();
        if profile.patterns.iter().any(|p| p == words[2]) {
            return Err(format!("duplicate signature '{}'", words[2]));
        }
        let _ = words[1];
        profile.patterns.push(words[2].to_string());
        Ok(())
    }

    fn parse_dnat(&mut self, words: &[&str]) -> Result<(), String> {
        let name = match words.len() {
            6 => None,
            8 if words[6] == "name" => Some(words[7].to_string()),
            _ => return Err("usage: dnat <id> <proto|any> <public-cidr|any> <public-port|any> <private-ip> <private-port|any> [name n]".to_string()),
        };
        let words = &words[..6];
        let id: u32 = words[0]
            .parse()
            .map_err(|_| format!("invalid dnat id '{}'", words[0]))?;
        if self.dnat.iter().any(|r| r.id == id) {
            return Err(format!("duplicate dnat id {id}"));
        }
        let proto = Proto::parse(words[1]).map_err(|e| format!("dnat protocol: {e}"))?;
        let dst = Cidr::parse(words[2]).map_err(|e| format!("dnat destination: {e}"))?;
        let dst_port = if words[3] == "any" {
            None
        } else {
            Some(
                words[3]
                    .parse()
                    .map_err(|_| format!("invalid dnat port '{}'", words[3]))?,
            )
        };
        let to_ip = words[4]
            .parse()
            .map_err(|_| format!("invalid dnat address '{}'", words[4]))?;
        let to_port = if words[5] == "any" {
            dst_port
        } else {
            Some(
                words[5]
                    .parse()
                    .map_err(|_| format!("invalid dnat translated port '{}'", words[5]))?,
            )
        };
        if to_port.is_some() && dst_port.is_none() {
            return Err("dnat translated port requires a public port".to_string());
        }
        self.dnat.push(DnatRule {
            id,
            vdom: self.current_vdom.clone(),
            proto,
            dst,
            dst_port,
            to_ip,
            to_port,
            name,
        });
        Ok(())
    }

    fn parse_shaper(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 2 {
            return Err("usage: shaper <name> <kbps>".to_string());
        }
        if self.shapers.iter().any(|s| s.name == words[0]) {
            return Err(format!("duplicate shaper '{}'", words[0]));
        }
        let kbps = words[1]
            .parse()
            .map_err(|_| format!("invalid shaper rate '{}'", words[1]))?;
        self.shapers.push(Shaper {
            name: words[0].to_string(),
            kbps,
        });
        Ok(())
    }

    fn parse_zone(&mut self, words: &[&str]) -> Result<(), String> {
        if words.len() != 3 {
            return Err("usage: zone <name> syn-flood|icmp-flood|udp-flood <pps>".to_string());
        }
        let pps = words[2]
            .parse()
            .map_err(|_| format!("invalid pps '{}'", words[2]))?;
        if !self
            .zones
            .iter()
            .any(|z| z.name == words[0] && z.vdom == self.current_vdom)
        {
            self.zones.push(ZoneProtection {
                name: words[0].to_string(),
                vdom: self.current_vdom.clone(),
                syn_flood: None,
                icmp_flood: None,
                udp_flood: None,
            });
        }
        let zone = self
            .zones
            .iter_mut()
            .find(|z| z.name == words[0] && z.vdom == self.current_vdom)
            .unwrap();
        match words[1] {
            "syn-flood" => zone.syn_flood = Some(pps),
            "icmp-flood" => zone.icmp_flood = Some(pps),
            "udp-flood" => zone.udp_flood = Some(pps),
            other => return Err(format!("unknown zone protection '{other}'")),
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        self.ha.validate()?;
        let s = &self.settings;
        if s.tcp_timeout == 0 || s.udp_timeout == 0 || s.icmp_timeout == 0 {
            return Err("conntrack timeouts must be greater than zero".to_string());
        }
        if s.max_packet_size < 64 || s.max_packet_size > 65_535 {
            return Err("max-packet must be between 64 and 65535".to_string());
        }
        if s.max_inspection_bytes == 0 || s.max_inspection_bytes > 65_535 {
            return Err("max-inspection must be between 1 and 65535".to_string());
        }
        if s.max_body < 1024 || s.max_body > 16 * 1024 * 1024 {
            return Err("max-body must be between 1024 and 16777216".to_string());
        }
        if s.tls_cert.is_some() != s.tls_key.is_some() {
            return Err("tls-cert and tls-key must be configured together".to_string());
        }
        if s.source_rate != 0 && s.source_burst == 0 {
            return Err(
                "source-burst must be greater than zero when source-rate is set".to_string(),
            );
        }
        for iface in &self.interfaces {
            if !iface
                .zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.'))
            {
                return Err(format!("interface {} has an invalid zone name", iface.name));
            }
        }
        for route in &self.routes6 {
            if !self.interfaces.iter().any(|i| i.name == route.interface && i.vdom == route.vdom) {
                return Err(format!("route6 {} interface '{}' is not configured in vdom '{}'", route.dst, route.interface, route.vdom));
            }
        }
        for route in &self.routes {
            if !self
                .interfaces
                .iter()
                .any(|i| i.name == route.interface && i.vdom == route.vdom)
            {
                return Err(format!(
                    "route {} interface '{}' is not configured in vdom '{}'",
                    route.dst, route.interface, route.vdom
                ));
            }
        }
        for group in &self.address_groups {
            for member in &group.members {
                if !self.address_ref_exists(member) {
                    return Err(format!(
                        "address group '{}' references unknown member '{}'",
                        group.name, member
                    ));
                }
            }
        }
        for group in &self.service_groups {
            for member in &group.members {
                if !self.service_exists(member) || member == &group.name {
                    return Err(format!("service group '{}' references unknown member '{}'", group.name, member));
                }
            }
        }
        for group in &self.app_groups {
            for member in &group.members {
                if member == &group.name || !self.app_name_valid(member) {
                    return Err(format!("application group '{}' references unknown member '{}'", group.name, member));
                }
            }
        }
        for group in &self.user_groups {
            for member in &group.members {
                valid_user_name(member).map_err(|e| format!("user group '{}': {e}", group.name))?;
            }
        }
        for group in &self.profile_groups {
            self.check_profiles(&format!("profile group '{}'", group.name), &group.url, &group.ips, &group.av)?;
        }
        for rule in &self.snat {
            for reference in rule.src.iter().chain(rule.dst.iter()) {
                if let AddrRef::Named(name) = reference {
                    if !self.address_ref_exists(name) {
                        return Err(format!("snat {} references unknown address '{}'", rule.id, name));
                    }
                }
            }
        }
        for (i, t) in self.tunnels.iter().enumerate() {
            if self.tunnels[..i].iter().any(|o| o.vdom == t.vdom && o.listen_port == t.listen_port) {
                return Err(format!("tunnel {}: listen-port {} is used by another tunnel", t.name, t.listen_port));
            }
        }
        for rule in &self.default_rules {
            if !self.vdoms.contains(&rule.vdom) {
                return Err(format!("default rule for unknown vdom '{}'", rule.vdom));
            }
            if rule.zone.as_deref() == Some("any") {
                return Err("a per-zone default rule needs a zone name, not any".to_string());
            }
        }
        for policy in &self.policies {
            let what = format!("policy {}", policy.id);
            if is_default_rule_id(policy.id) {
                return Err(format!("{what}: ids above {} are reserved for default rules", u32::MAX - 4096));
            }
            if policy.src_zones.is_empty() || policy.dst_zones.is_empty() {
                return Err(format!("{what} needs at least one source and one destination zone"));
            }
            for reference in policy.src.iter().chain(policy.dst.iter()) {
                if let AddrRef::Named(name) = reference {
                    if !self.address_ref_exists(name) {
                        return Err(format!("{what} references unknown address '{name}'"));
                    }
                }
            }
            for service in &policy.services {
                if service != "any" && service != APPLICATION_DEFAULT && !self.service_exists(service) {
                    return Err(format!("{what} references unknown service '{service}'"));
                }
            }
            if !policy.services.is_empty() && policy.dst_port.is_some() {
                return Err(format!("{what}: use either an inline port or services, not both"));
            }
            for app in &policy.apps {
                if app != "any" && !self.app_name_valid(app) {
                    return Err(format!("{what} references unknown application '{app}'"));
                }
            }
            for user in &policy.users {
                valid_user_name(user).map_err(|e| format!("{what}: {e}"))?;
            }
            if let Some(group) = &policy.group {
                if !self.profile_groups.iter().any(|g| &g.name == group) {
                    return Err(format!("{what} references unknown profile group '{group}'"));
                }
            }
            self.check_profiles(&what, &policy.url, &policy.ips, &policy.av)?;
            if let Some(shaper) = &policy.shaper {
                if !self.shapers.iter().any(|s| &s.name == shaper) {
                    return Err(format!("{what} references unknown shaper '{shaper}'"));
                }
            }
        }
        Ok(())
    }

    fn check_profiles(
        &self,
        what: &str,
        url: &Option<String>,
        ips: &Option<String>,
        av: &Option<String>,
    ) -> Result<(), String> {
        if let Some(url) = url {
            if !self.url_filters.iter().any(|f| &f.name == url) {
                return Err(format!("{what} references unknown URL filter '{url}'"));
            }
        }
        if let Some(ips) = ips {
            if !self.ips_profiles.iter().any(|p| &p.name == ips) {
                return Err(format!("{what} references unknown IPS profile '{ips}'"));
            }
        }
        if let Some(av) = av {
            if !self.av_profiles.iter().any(|p| &p.name == av) {
                return Err(format!("{what} references unknown antivirus profile '{av}'"));
            }
        }
        Ok(())
    }

    fn service_exists(&self, name: &str) -> bool {
        self.services.iter().any(|s| s.name == name) || self.service_groups.iter().any(|g| g.name == name)
    }

    /// A built-in or custom application, an application group, or a valid
    /// `category:<name>`.
    pub fn app_name_valid(&self, name: &str) -> bool {
        if let Some(category) = name.strip_prefix("category:") {
            return crate::appid::is_category(category);
        }
        crate::appid::is_builtin(name)
            || self.apps.iter().any(|a| a.name == name)
            || self.app_groups.iter().any(|g| g.name == name)
    }

    fn address_ref_exists(&self, name: &str) -> bool {
        self.addresses.iter().any(|a| a.name == name)
            || self.address_groups.iter().any(|g| g.name == name)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn addr_matches(&self, reference: &AddrRef, ip: Ipv4Addr) -> bool {
        self.addr_matches_ip(reference, IpAddr::V4(ip))
    }

    /// Address match for either family. `any` (0.0.0.0/0) matches IPv6 too;
    /// an IPv4 prefix never matches an IPv6 address, nor the reverse.
    pub fn addr_matches_ip(&self, reference: &AddrRef, ip: IpAddr) -> bool {
        match (reference, ip) {
            (AddrRef::Cidr(c), _) if *c == Cidr::ANY => true,
            (AddrRef::Cidr(c), IpAddr::V4(v4)) => c.contains(v4),
            (AddrRef::Cidr6(c), IpAddr::V6(v6)) => c.contains(v6),
            (AddrRef::Named(name), _) => self.named_addr_matches_ip(name, ip, 0),
            _ => false,
        }
    }

    fn named_addr_matches_ip(&self, name: &str, ip: IpAddr, depth: usize) -> bool {
        match ip {
            IpAddr::V4(v4) => self.named_addr_matches(name, v4, depth),
            IpAddr::V6(v6) => {
                if depth > 16 {
                    return false;
                }
                if let Some(object) = self.addresses.iter().find(|a| a.name == name) {
                    return object.entries6.iter().any(|c| c.contains(v6)) || object.entries.iter().any(|c| *c == Cidr::ANY);
                }
                self.address_groups
                    .iter()
                    .find(|g| g.name == name)
                    .map(|g| g.members.iter().any(|m| self.named_addr_matches_ip(m, ip, depth + 1)))
                    .unwrap_or(false)
            }
        }
    }

    fn named_addr_matches(&self, name: &str, ip: Ipv4Addr, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        if let Some(object) = self.addresses.iter().find(|a| a.name == name) {
            return object.entries.iter().any(|c| c.contains(ip));
        }
        if let Some(group) = self.address_groups.iter().find(|g| g.name == name) {
            return group
                .members
                .iter()
                .any(|member| self.named_addr_matches(member, ip, depth + 1));
        }
        false
    }

    /// Whether a service or service group covers `proto`/`port`.
    pub fn service_matches(&self, name: &str, proto: u8, port: u16) -> bool {
        self.service_matches_depth(name, proto, port, 0)
    }

    fn service_matches_depth(&self, name: &str, proto: u8, port: u16, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        if let Some(service) = self.services.iter().find(|s| s.name == name) {
            return service.matches(proto, port);
        }
        self.service_groups
            .iter()
            .find(|g| g.name == name)
            .map(|g| g.members.iter().any(|m| self.service_matches_depth(m, proto, port, depth + 1)))
            .unwrap_or(false)
    }

    /// Custom applications are identified by port, so they are known from a
    /// flow's first packet.
    pub fn custom_app_for(&self, proto: u8, port: u16) -> Option<&str> {
        self.apps
            .iter()
            .find(|a| a.proto.matches(proto) && a.port == port)
            .map(|a| a.name.as_str())
    }

    /// Whether `proto`/`port` is a standard port of `app` (`application-default`).
    pub fn app_default_port(&self, app: &str, proto: u8, port: u16) -> bool {
        match self.apps.iter().find(|a| a.name == app) {
            Some(custom) => custom.proto.matches(proto) && custom.port == port,
            None => crate::appid::default_port(app, proto, port),
        }
    }

    /// Does a policy application list allow `app`? `None` means the flow's
    /// application is not identified yet: any list matches provisionally, and
    /// the rulebase is evaluated again once App-ID has a verdict.
    pub fn app_matches(&self, list: &[String], app: Option<&str>) -> bool {
        if list.is_empty() || list.iter().any(|a| a == "any") {
            return true;
        }
        match app {
            None => true,
            Some(app) => list.iter().any(|entry| self.app_entry_matches(entry, app, 0)),
        }
    }

    fn app_entry_matches(&self, entry: &str, app: &str, depth: usize) -> bool {
        if entry == app {
            return true;
        }
        if let Some(category) = entry.strip_prefix("category:") {
            return crate::appid::in_category(app, category);
        }
        depth < 16
            && self
                .app_groups
                .iter()
                .find(|g| g.name == entry)
                .map(|g| g.members.iter().any(|m| self.app_entry_matches(m, app, depth + 1)))
                .unwrap_or(false)
    }

    /// Effective URL/IPS/AV profiles: the policy's own, else its profile group's.
    pub fn profiles<'a>(&'a self, policy: &'a Policy) -> (Option<&'a str>, Option<&'a str>, Option<&'a str>) {
        let group = policy.group.as_ref().and_then(|g| self.profile_groups.iter().find(|x| &x.name == g));
        let pick = |own: &'a Option<String>, from: fn(&'a ProfileGroup) -> &'a Option<String>| {
            own.as_deref().or_else(|| group.and_then(|g| from(g).as_deref()))
        };
        (pick(&policy.url, |g| &g.url), pick(&policy.ips, |g| &g.ips), pick(&policy.av, |g| &g.av))
    }

    fn addr_list_matches(&self, list: &[AddrRef], negate: bool, ip: Ipv4Addr) -> bool {
        self.addr_list_matches_ip(list, negate, IpAddr::V4(ip))
    }

    fn addr_list_matches_ip(&self, list: &[AddrRef], negate: bool, ip: IpAddr) -> bool {
        list.iter().any(|a| self.addr_matches_ip(a, ip)) != negate
    }

    fn service_list_matches(&self, policy: &Policy, proto: u8, port: u16, app: Option<&str>) -> bool {
        if !policy.proto.matches(proto) {
            return false;
        }
        if policy.services.is_empty() {
            return policy.dst_port.map(|p| p == port).unwrap_or(true);
        }
        policy.services.iter().any(|service| match service.as_str() {
            "any" => true,
            APPLICATION_DEFAULT => match app {
                Some(app) => self.app_default_port(app, proto, port),
                // Not identified yet: allow if the port is standard for any
                // concrete application the rule names (or the rule names none).
                None => {
                    !policy.names_app()
                        || policy.apps.iter().any(|a| {
                            a.starts_with("category:")
                                || self.app_groups.iter().any(|g| &g.name == a)
                                || self.app_default_port(a, proto, port)
                        })
                }
            },
            name => self.service_matches(name, proto, port),
        })
    }

    pub fn url_filter(&self, name: &str) -> Option<&UrlFilter> {
        self.url_filters.iter().find(|f| f.name == name)
    }

    pub fn signature_hit(&self, profile: &str, av: bool, payload: &[u8]) -> Option<String> {
        let list = if av {
            &self.av_profiles
        } else {
            &self.ips_profiles
        };
        let profile = list.iter().find(|p| p.name == profile)?;
        profile
            .patterns
            .iter()
            .find(|pattern| crate::inspect::pattern_matches(payload, pattern))
            .cloned()
    }

    pub fn shaper(&self, name: &str) -> Option<&Shaper> {
        self.shapers.iter().find(|s| s.name == name)
    }

    pub fn zone(&self, name: &str, vdom: &str) -> Option<&ZoneProtection> {
        self.zones.iter().find(|z| z.name == name && z.vdom == vdom)
    }

    pub fn dnat_match(
        &self,
        vdom: &str,
        proto: u8,
        dst: Ipv4Addr,
        dport: u16,
    ) -> Option<&DnatRule> {
        self.dnat
            .iter()
            .filter(|r| r.vdom == vdom && r.matches(proto, dst, dport))
            .min_by_key(|r| r.id)
    }

    /// Egress interface and next hop: the most specific of the connected
    /// networks and static routes; connected wins a tie, then lower distance.
    pub fn egress(&self, vdom: &str, dst: Ipv4Addr) -> Option<(&Interface, Ipv4Addr)> {
        let connected = self
            .interfaces
            .iter()
            .filter(|i| i.vdom == vdom)
            .filter_map(|i| i.address.filter(|c| c.contains(dst)).map(|c| (i, c.prefix)))
            .max_by_key(|(_, prefix)| *prefix);
        let route = self
            .routes
            .iter()
            .filter(|r| r.vdom == vdom && r.dst.contains(dst))
            .filter(|r| self.interfaces.iter().any(|i| i.name == r.interface && i.vdom == vdom))
            .min_by_key(|r| (std::cmp::Reverse(r.dst.prefix), r.distance));
        // WireGuard cryptokey routing: a peer's allowed IPs route to its tunnel.
        let tunneled = self
            .tunnels
            .iter()
            .filter(|t| t.vdom == vdom)
            .flat_map(|t| t.peers.iter().flat_map(|p| p.allowed_ips.iter()).map(move |c| (t, c)))
            .filter(|(_, c)| c.contains(dst))
            .max_by_key(|(_, c)| c.prefix)
            .and_then(|(t, c)| self.interfaces.iter().find(|i| i.name == t.name).map(|i| (i, c.prefix)));
        let best = match (connected, route) {
            (Some((_, prefix)), Some(r)) if r.dst.prefix > prefix => self.route_hop(r, dst).map(|h| (h, r.dst.prefix)),
            (Some((iface, prefix)), _) => Some(((iface, dst), prefix)),
            (None, Some(r)) => self.route_hop(r, dst).map(|h| (h, r.dst.prefix)),
            (None, None) => None,
        };
        match (best, tunneled) {
            (Some((_, prefix)), Some((iface, tprefix))) if tprefix > prefix => Some((iface, dst)),
            (Some((hop, _)), _) => Some(hop),
            (None, Some((iface, _))) => Some((iface, dst)),
            (None, None) => None,
        }
    }

    fn route_hop(&self, r: &Route, dst: Ipv4Addr) -> Option<(&Interface, Ipv4Addr)> {
        let iface = self.interfaces.iter().find(|i| i.name == r.interface && i.vdom == r.vdom)?;
        Some((iface, r.via.unwrap_or(dst)))
    }

    /// First matching security policy, lowest id first. `app` is `None` while
    /// App-ID has not classified the flow (see [`Config::app_matches`]).
    #[allow(clippy::too_many_arguments)]
    pub fn match_policy(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
    ) -> Option<&Policy> {
        let user = self.static_user_for(src);
        self.match_policy_user(vdom, src_zone, dst_zone, src, dst, proto, dst_port, app, user)
    }

    /// As [`Config::match_policy`], with the source user given explicitly
    /// (the dataplane passes dynamic User-ID mappings; `None` is unknown).
    #[allow(clippy::too_many_arguments)]
    pub fn match_policy_user(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
        user: Option<&str>,
    ) -> Option<&Policy> {
        self.match_policy_ip(vdom, src_zone, dst_zone, IpAddr::V4(src), IpAddr::V4(dst), proto, dst_port, app, user)
    }

    /// The policy matcher for both address families.
    #[allow(clippy::too_many_arguments)]
    pub fn match_policy_ip(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
        user: Option<&str>,
    ) -> Option<&Policy> {
        let zone_in = |list: &[String], zone: &str| list.iter().any(|z| z == "any" || z == zone);
        self.policies
            .iter()
            .filter(|p| p.vdom == vdom && p.enabled)
            .filter(|p| zone_in(&p.src_zones, src_zone) && zone_in(&p.dst_zones, dst_zone))
            .filter(|p| self.addr_list_matches_ip(&p.src, p.negate_src, src))
            .filter(|p| self.addr_list_matches_ip(&p.dst, p.negate_dst, dst))
            .filter(|p| self.service_list_matches(p, proto, dst_port, app))
            .filter(|p| self.app_matches(&p.apps, app))
            .filter(|p| self.user_matches_ip(p, src, user))
            // While the application is unknown, a deny rule that names
            // applications cannot apply yet: it is skipped so the handshake can
            // complete, and re-checked once App-ID has a verdict.
            .filter(|p| app.is_some() || p.action == Action::Permit || !p.names_app())
            .min_by_key(|p| p.id)
    }

    /// The default rule for traffic no policy matched.
    pub fn default_rule_for(&self, vdom: &str, src_zone: &str, dst_zone: &str) -> Option<&Policy> {
        let in_vdom = |p: &&Policy| p.vdom == vdom;
        if src_zone == dst_zone {
            self.default_policies
                .iter()
                .filter(in_vdom)
                .find(|p| p.id != INTRAZONE_ID && p.id != INTERZONE_ID && p.src_zones[0] == src_zone)
                .or_else(|| self.default_policies.iter().filter(in_vdom).find(|p| p.id == INTRAZONE_ID))
        } else {
            self.default_policies.iter().filter(in_vdom).find(|p| p.id == INTERZONE_ID)
        }
    }

    /// The first matching policy, else the default rule. This is what the
    /// dataplane enforces; [`Config::match_policy`] alone answers "which
    /// configured rule matches".
    #[allow(clippy::too_many_arguments)]
    pub fn match_or_default(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
    ) -> Option<&Policy> {
        self.match_policy(vdom, src_zone, dst_zone, src, dst, proto, dst_port, app)
            .or_else(|| self.default_rule_for(vdom, src_zone, dst_zone))
    }

    /// As [`Config::match_or_default`], with an explicit source user.
    #[allow(clippy::too_many_arguments)]
    pub fn match_or_default_user(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
        user: Option<&str>,
    ) -> Option<&Policy> {
        self.match_policy_user(vdom, src_zone, dst_zone, src, dst, proto, dst_port, app, user)
            .or_else(|| self.default_rule_for(vdom, src_zone, dst_zone))
    }

    /// As [`Config::match_or_default_user`], for either address family.
    #[allow(clippy::too_many_arguments)]
    pub fn match_or_default_ip(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        app: Option<&str>,
        user: Option<&str>,
    ) -> Option<&Policy> {
        self.match_policy_ip(vdom, src_zone, dst_zone, src, dst, proto, dst_port, app, user)
            .or_else(|| self.default_rule_for(vdom, src_zone, dst_zone))
    }

    /// IPv6 egress: connected prefixes, then `route6` (longest prefix, then distance).
    pub fn egress6(&self, vdom: &str, dst: Ipv6Addr) -> Option<(&Interface, Ipv6Addr)> {
        let connected = self
            .interfaces
            .iter()
            .filter(|i| i.vdom == vdom)
            .filter_map(|i| i.address6.filter(|c| c.contains(dst)).map(|c| (i, c.prefix)))
            .max_by_key(|(_, p)| *p);
        let route = self
            .routes6
            .iter()
            .filter(|r| r.vdom == vdom && r.dst.contains(dst))
            .filter_map(|r| self.interfaces.iter().find(|i| i.name == r.interface && i.vdom == vdom).map(|i| (r, i)))
            .min_by_key(|(r, _)| (std::cmp::Reverse(r.dst.prefix), r.distance));
        match (connected, route) {
            (Some((_, cp)), Some((r, i))) if r.dst.prefix > cp => Some((i, r.via.unwrap_or(dst))),
            (Some((i, _)), _) => Some((i, dst)),
            (None, Some((r, i))) => Some((i, r.via.unwrap_or(dst))),
            (None, None) => None,
        }
    }

    /// The user statically mapped to an address (most specific mapping).
    pub fn static_user_for(&self, ip: Ipv4Addr) -> Option<&str> {
        self.user_maps
            .iter()
            .filter(|m| m.cidr.contains(ip))
            .max_by_key(|m| m.cidr.prefix)
            .map(|m| m.user.as_str())
    }

    /// Does a policy user list allow `user` (`None` = no mapping)?
    pub fn user_matches(&self, list: &[String], user: Option<&str>) -> bool {
        if list.is_empty() || list.iter().any(|u| u == "any") {
            return true;
        }
        match user {
            None => list.iter().any(|u| u == UNKNOWN_USER),
            Some(user) => list.iter().any(|e| e == KNOWN_USER || self.user_in(e, user, 0)),
        }
    }

    /// User matching for either address family. User-ID maps IPv4 sources
    /// only, so an IPv6 source never has a known user. Matching that the same
    /// way as an unknown IPv4 user would let IPv6 traffic slip past a rule
    /// such as `deny user contractors`, so IPv6 fails closed instead: a
    /// user-scoped deny or reject applies to every IPv6 source, and a
    /// user-scoped permit never matches one (unless it names `unknown`).
    fn user_matches_ip(&self, p: &Policy, src: IpAddr, user: Option<&str>) -> bool {
        let scoped = !(p.users.is_empty() || p.users.iter().any(|u| u == "any"));
        if src.is_ipv6() && user.is_none() && scoped {
            return p.action != Action::Permit || p.users.iter().any(|u| u == UNKNOWN_USER);
        }
        self.user_matches(&p.users, user)
    }

    /// `entry` is the user itself, or a group that contains it (nested).
    pub fn user_in(&self, entry: &str, user: &str, depth: usize) -> bool {
        if entry.eq_ignore_ascii_case(user) {
            return true;
        }
        depth < 16
            && self
                .user_groups
                .iter()
                .find(|g| g.name == entry)
                .map(|g| g.members.iter().any(|m| self.user_in(m, user, depth + 1)))
                .unwrap_or(false)
    }

    /// A configured policy or a default rule, by id.
    pub fn policy_by_id(&self, vdom: &str, id: u32) -> Option<&Policy> {
        self.policies
            .iter()
            .chain(self.default_policies.iter())
            .find(|p| p.vdom == vdom && p.id == id)
    }

    /// `policy 10` for configured rules, the name for default rules.
    pub fn policy_label(p: &Policy) -> String {
        if is_default_rule_id(p.id) {
            p.name.clone().unwrap_or_default()
        } else {
            format!("policy {}", p.id)
        }
    }

    /// First matching source-NAT rule, lowest id first.
    pub fn snat_match(&self, vdom: &str, src_zone: &str, dst_zone: &str, src: Ipv4Addr, dst: Ipv4Addr) -> Option<&SnatRule> {
        let zone_in = |list: &[String], zone: &str| list.iter().any(|z| z == "any" || z == zone);
        self.snat
            .iter()
            .filter(|r| r.vdom == vdom && r.enabled)
            .filter(|r| zone_in(&r.src_zones, src_zone) && zone_in(&r.dst_zones, dst_zone))
            .filter(|r| self.addr_list_matches(&r.src, false, src) && self.addr_list_matches(&r.dst, false, dst))
            .min_by_key(|r| r.id)
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let s = &self.settings;
        out.push_str(&format!("system hostname {}\n", s.hostname));
        out.push_str(&format!("system cli-port {}\n", s.cli_port));
        out.push_str(&format!("system gui-port {}\n", s.gui_port));
        out.push_str(&format!("system cli-bind {}\n", s.cli_bind));
        out.push_str(&format!("system gui-bind {}\n", s.gui_bind));
        out.push_str(&format!(
            "system tls {}\n",
            if s.tls { "on" } else { "off" }
        ));
        if let Some(cert) = &s.tls_cert {
            out.push_str(&format!("system tls-cert {cert}\n"));
        }
        if let Some(key) = &s.tls_key {
            out.push_str(&format!("system tls-key {key}\n"));
        }
        out.push_str(&format!("system api-rate {}\n", s.api_rate));
        out.push_str(&format!("system api-burst {}\n", s.api_burst));
        out.push_str(&format!("system max-body {}\n", s.max_body));
        out.push_str(&format!("system max-sessions {}\n", s.max_sessions));
        out.push_str(&format!(
            "system max-sessions-per-ip {}\n",
            s.max_sessions_per_ip
        ));
        out.push_str(&format!("system max-packet {}\n", s.max_packet_size));
        out.push_str(&format!(
            "system max-inspection {}\n",
            s.max_inspection_bytes
        ));
        out.push_str(&format!("system source-rate {}\n", s.source_rate));
        out.push_str(&format!("system source-burst {}\n", s.source_burst));
        if !s.kernel_forwarding_refuse {
            out.push_str("system kernel-forwarding warn\n");
        }
        if s.cli_remote_plaintext {
            out.push_str("system cli-remote-plaintext on\n");
        }
        if s.dataplane_kernel {
            out.push_str("system dataplane kernel\n");
        }
        if s.cli_style != "native" {
            out.push_str(&format!("system cli-style {}\n", s.cli_style));
        }
        out.push_str(&format!("system conntrack-tcp {}\n", s.tcp_timeout));
        out.push_str(&format!("system conntrack-udp {}\n", s.udp_timeout));
        out.push_str(&format!("system conntrack-icmp {}\n", s.icmp_timeout));
        out.push_str(&format!(
            "system logging {}\n",
            if s.logging { "on" } else { "off" }
        ));
        out.push_str(&format!(
            "system log-format {}\n",
            if s.log_json { "json" } else { "text" }
        ));
        out.push_str(&self.ha.to_text());
        for address in &self.addresses {
            out.push_str(&format!("\naddress {}", address.name));
            for entry in &address.entries {
                out.push_str(&format!(" {entry}"));
            }
            for entry in &address.entries6 {
                out.push_str(&format!(" {entry}"));
            }
            out.push('\n');
        }
        for group in &self.address_groups {
            out.push_str(&format!(
                "\naddress-group {} {}",
                group.name,
                group.members.join(" ")
            ));
            out.push('\n');
        }
        for service in &self.services {
            out.push_str(&format!("\nservice {} {} {}\n", service.name, service.proto, service.ports_text()));
        }
        for group in &self.service_groups {
            out.push_str(&format!("\nservice-group {} {}\n", group.name, group.members.join(" ")));
        }
        for app in &self.apps {
            out.push_str(&format!(
                "\napp-def {} {} {}\n",
                app.name, app.proto, app.port
            ));
        }
        for group in &self.app_groups {
            out.push_str(&format!("\napp-group {} {}\n", group.name, group.members.join(" ")));
        }
        for group in &self.user_groups {
            out.push_str(&format!("\nuser-group {} {}\n", group.name, group.members.join(" ")));
        }
        for map in &self.user_maps {
            out.push_str(&format!("\nuser-map {} {}\n", map.cidr, map.user));
        }
        for filter in &self.url_filters {
            if !filter.block.is_empty() {
                out.push_str(&format!(
                    "\nurl-filter {} block {}\n",
                    filter.name,
                    filter.block.join(" ")
                ));
            }
            if !filter.allow.is_empty() {
                out.push_str(&format!(
                    "\nurl-filter {} allow {}\n",
                    filter.name,
                    filter.allow.join(" ")
                ));
            }
        }
        for profile in &self.ips_profiles {
            out.push_str(&format!("\nips-profile {}\n", profile.name));
            for (index, pattern) in profile.patterns.iter().enumerate() {
                out.push_str(&format!(
                    "ips-signature {} {} {}\n",
                    profile.name,
                    index + 1,
                    pattern
                ));
            }
        }
        for profile in &self.av_profiles {
            out.push_str(&format!("\nav-profile {}\n", profile.name));
            for (index, pattern) in profile.patterns.iter().enumerate() {
                out.push_str(&format!(
                    "av-signature {} {} {}\n",
                    profile.name,
                    index + 1,
                    pattern
                ));
            }
        }
        for shaper in &self.shapers {
            out.push_str(&format!("\nshaper {} {}\n", shaper.name, shaper.kbps));
        }
        for group in &self.profile_groups {
            out.push_str(&format!("\nprofile-group {}", group.name));
            for (kind, value) in [("url", &group.url), ("ips", &group.ips), ("av", &group.av)] {
                if let Some(v) = value {
                    out.push_str(&format!(" {kind} {v}"));
                }
            }
            out.push('\n');
        }
        let vdoms: Vec<String> = if self.vdoms.is_empty() {
            vec!["root".to_string()]
        } else {
            self.vdoms.clone()
        };
        for vdom in &vdoms {
            out.push_str(&format!("\nvdom {vdom}\n"));
            for t in self.tunnels.iter().filter(|t| &t.vdom == vdom) {
                let iface = self.interfaces.iter().find(|i| i.name == t.name);
                out.push_str(&format!(
                    "vpn wireguard {} private-key {} listen-port {} zone {}",
                    t.name,
                    crate::wg::b64_encode(&t.private_key),
                    t.listen_port,
                    iface.map(|i| i.zone.as_str()).unwrap_or("vpn")
                ));
                if let Some(a) = iface.and_then(|i| i.address) {
                    out.push_str(&format!(" address {a}"));
                }
                if let Some(m) = iface.map(|i| i.mtu).filter(|m| *m != 1420) {
                    out.push_str(&format!(" mtu {m}"));
                }
                out.push('\n');
                for p in &t.peers {
                    out.push_str(&format!(
                        "vpn wireguard-peer {} {} public-key {} allowed-ips {}",
                        t.name,
                        p.name,
                        crate::wg::b64_encode(&p.public_key),
                        p.allowed_ips.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",")
                    ));
                    if let Some(e) = p.endpoint {
                        out.push_str(&format!(" endpoint {e}"));
                    }
                    if let Some(k) = p.preshared_key {
                        out.push_str(&format!(" preshared-key {}", crate::wg::b64_encode(&k)));
                    }
                    if let Some(k) = p.keepalive {
                        out.push_str(&format!(" keepalive {k}"));
                    }
                    out.push('\n');
                }
            }
            for i in self.interfaces.iter().filter(|i| &i.vdom == vdom && !i.tunnel) {
                out.push_str(&format!("interface {} zone {}", i.name, i.zone));
                if let Some(a) = i.address {
                    out.push_str(&format!(" address {a}"));
                }
                if let Some(a) = i.address6 {
                    out.push_str(&format!(" address6 {a}"));
                }
                if let Some(m) = i.mac {
                    out.push_str(&format!(" mac {}", format_mac(&m)));
                }
                if i.mtu != 1500 {
                    out.push_str(&format!(" mtu {}", i.mtu));
                }
                out.push('\n');
            }
            for r in self.routes.iter().filter(|r| &r.vdom == vdom) {
                let dst = if r.dst == Cidr::ANY { "default".to_string() } else { r.dst.to_string() };
                out.push_str(&format!("route {dst} {}", r.interface));
                if let Some(via) = r.via {
                    out.push_str(&format!(" via {via}"));
                }
                if r.distance != 10 {
                    out.push_str(&format!(" distance {}", r.distance));
                }
                if let Some(name) = &r.name {
                    out.push_str(&format!(" name {name}"));
                }
                out.push('\n');
            }
            for r in self.routes6.iter().filter(|r| &r.vdom == vdom) {
                let dst = if r.dst == Cidr6::ANY { "default".to_string() } else { r.dst.to_string() };
                out.push_str(&format!("route6 {dst} {}", r.interface));
                if let Some(via) = r.via {
                    out.push_str(&format!(" via {via}"));
                }
                if r.distance != 10 {
                    out.push_str(&format!(" distance {}", r.distance));
                }
                out.push('\n');
            }
            for p in self.policies.iter().filter(|p| &p.vdom == vdom) {
                let port = if !p.services.is_empty() {
                    if p.services.len() == 1 && p.services[0] == APPLICATION_DEFAULT {
                        APPLICATION_DEFAULT.to_string()
                    } else {
                        p.services.iter().map(|s| format!("@{s}")).collect::<Vec<_>>().join(",")
                    }
                } else {
                    p.dst_port.map(|v| v.to_string()).unwrap_or_else(|| "any".to_string())
                };
                out.push_str(&format!(
                    "policy {} {} {} {} {} {} {} {}",
                    p.id,
                    p.src_zones.join(","),
                    p.dst_zones.join(","),
                    addr_list_text(&p.src, p.negate_src),
                    addr_list_text(&p.dst, p.negate_dst),
                    p.proto,
                    port,
                    p.action.as_str()
                ));
                if p.nat {
                    out.push_str(" nat");
                }
                if !p.log {
                    out.push_str(" nolog");
                }
                if !p.enabled {
                    out.push_str(" disable");
                }
                if let Some(name) = &p.name {
                    out.push_str(&format!(" name {name}"));
                }
                if !p.apps.is_empty() {
                    out.push_str(&format!(" app {}", p.apps.join(",")));
                }
                if !p.users.is_empty() {
                    out.push_str(&format!(" user {}", p.users.join(",")));
                }
                for (key, value) in [("url", &p.url), ("ips", &p.ips), ("av", &p.av), ("shaper", &p.shaper), ("group", &p.group)] {
                    if let Some(v) = value {
                        out.push_str(&format!(" {key} {v}"));
                    }
                }
                out.push('\n');
            }
            for rule in self.snat.iter().filter(|r| &r.vdom == vdom) {
                let to = match rule.to {
                    SnatTarget::Masquerade => "masquerade".to_string(),
                    SnatTarget::Address(ip) => ip.to_string(),
                };
                out.push_str(&format!(
                    "snat {} {} {} {} {} {to}",
                    rule.id,
                    rule.src_zones.join(","),
                    rule.dst_zones.join(","),
                    addr_list_text(&rule.src, false),
                    addr_list_text(&rule.dst, false),
                ));
                if let Some(name) = &rule.name {
                    out.push_str(&format!(" name {name}"));
                }
                if !rule.enabled {
                    out.push_str(" disable");
                }
                out.push('\n');
            }
            for rule in self.dnat.iter().filter(|r| &r.vdom == vdom) {
                out.push_str(&format!(
                    "dnat {} {} {} {} {} {}{}\n",
                    rule.id,
                    rule.proto,
                    rule.dst,
                    rule.dst_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "any".to_string()),
                    rule.to_ip,
                    rule.to_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "any".to_string()),
                    rule.name.as_ref().map(|n| format!(" name {n}")).unwrap_or_default()
                ));
            }
            for r in self.default_rules.iter().filter(|r| &r.vdom == vdom) {
                out.push_str(&format!(
                    "default-rule {} {}{}{}\n",
                    if r.kind == DefaultKind::Intrazone { "intrazone" } else { "interzone" },
                    if r.action == Action::Permit { "allow" } else { "deny" },
                    r.zone.as_ref().map(|z| format!(" zone {z}")).unwrap_or_default(),
                    if r.log { " log" } else { "" }
                ));
            }
            for zone in self.zones.iter().filter(|z| &z.vdom == vdom) {
                if let Some(pps) = zone.syn_flood {
                    out.push_str(&format!("zone {} syn-flood {}\n", zone.name, pps));
                }
                if let Some(pps) = zone.icmp_flood {
                    out.push_str(&format!("zone {} icmp-flood {}\n", zone.name, pps));
                }
                if let Some(pps) = zone.udp_flood {
                    out.push_str(&format!("zone {} udp-flood {}\n", zone.name, pps));
                }
            }
            out.push('\n');
        }
        out
    }
}

/// Service value meaning "the identified application's standard ports".
pub const APPLICATION_DEFAULT: &str = "application-default";

pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid MAC '{s}'"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC '{s}'"))?;
    }
    Ok(mac)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
system hostname fw1
system cli-port 2201
interface port1 zone wan address 10.0.0.1/24 mac 02:00:00:00:00:01
interface port2 zone lan address 192.168.10.1/24
route default port1 via 10.0.0.254
policy 10 lan wan any any any any permit nat
policy 5 lan wan any any tcp 22 deny
";

    #[test]
    fn parses_sample() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.settings.hostname, "fw1");
        assert_eq!(cfg.interfaces.len(), 2);
        assert_eq!(
            cfg.routes.first().unwrap().via,
            Some("10.0.0.254".parse().unwrap())
        );
        assert_eq!(cfg.policies.len(), 2);
        assert!(cfg.policies[0].nat);
    }

    #[test]
    fn management_hardening_settings_parse_and_validate() {
        let cfg = Config::parse(
            "system hostname fw\n\
             system cli-bind 127.0.0.1\n\
             system gui-bind 127.0.0.1\n\
             system tls on\n\
             system max-body 2048\n\
             system max-packet 9000\n\
             system max-inspection 1500\n\
             system source-rate 1000\n\
             system source-burst 500\n",
        )
        .unwrap();
        assert_eq!(cfg.settings.max_body, 2048);
        assert_eq!(cfg.settings.max_packet_size, 9000);
        assert_eq!(cfg.settings.max_inspection_bytes, 1500);
        assert_eq!(cfg.settings.source_rate, 1000);
        assert_eq!(cfg.settings.source_burst, 500);
        assert!(Config::parse("system source-rate 10\n").is_err());
        assert!(Config::parse("system tls-cert /tmp/a.crt\n").is_err());
        assert!(Config::parse("system max-packet 1\n").is_err());
    }

    const NGFW: &str = "\
system hostname ngfw
system log-format json
address web-servers 10.0.0.10 10.0.0.11
address-group servers web-servers
service custom tcp 9000
app-def custom-app tcp 9000
url-filter strict block gambling malware
url-filter strict allow good.test
ips-profile edge
ips-signature edge 1 /etc/passwd
av-profile av1
av-signature av1 1 EICAR
dnat 7 tcp 203.0.113.5 8080 10.0.0.10 80
shaper slow 1000
zone lan syn-flood 10
policy 20 lan wan @servers any any @custom permit app custom-app url strict ips edge av av1 shaper slow log
";

    #[test]
    fn ngfw_features_parse_and_match() {
        let cfg = Config::parse(NGFW).unwrap();
        assert!(cfg.settings.log_json);
        assert!(cfg.addr_matches(
            &AddrRef::Named("servers".into()),
            "10.0.0.11".parse().unwrap()
        ));
        assert!(!cfg.addr_matches(
            &AddrRef::Named("servers".into()),
            "10.0.0.12".parse().unwrap()
        ));
        assert!(cfg.service_matches("custom", 6, 9000));
        assert!(cfg.app_matches(&["custom-app".to_string()], Some("custom-app")));
        assert_eq!(cfg.custom_app_for(6, 9000), Some("custom-app"));
        assert_eq!(cfg.custom_app_for(6, 443), None, "built-in apps are identified by content, not port");
        assert!(cfg.url_filter("strict").unwrap().blocked("bet365.com"));
        assert!(!cfg.url_filter("strict").unwrap().blocked("good.test"));
        assert!(cfg
            .signature_hit("edge", false, b"GET /etc/passwd")
            .is_some());
        assert!(cfg
            .signature_hit("av1", true, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
            .is_some());
        assert_eq!(
            cfg.dnat_match("root", 6, "203.0.113.5".parse().unwrap(), 8080)
                .unwrap()
                .id,
            7
        );
        assert_eq!(cfg.shaper("slow").unwrap().kbps, 1000);
        let p = cfg
            .match_policy(
                "root",
                "lan",
                "wan",
                "10.0.0.10".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                6,
                9000,
                None,
            )
            .unwrap();
        assert_eq!(p.id, 20);
        assert!(p.nat == false);
    }

    #[test]
    fn ngfw_round_trips() {
        let cfg = Config::parse(NGFW).unwrap();
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert_eq!(again.to_text(), cfg.to_text());
    }

    #[test]
    fn ngfw_example_parses() {
        let cfg = Config::parse(include_str!("../examples/ngfw.conf")).unwrap();
        assert_eq!(cfg.settings.hostname, "ngfw");
        assert!(cfg.url_filter("corp").unwrap().blocked("evil.test"));
        assert_eq!(cfg.custom_app_for(6, 8443), Some("admin-ui"));
        assert!(cfg
            .dnat_match("root", 6, std::net::Ipv4Addr::new(198, 51, 100, 9), 8080)
            .is_some());
        assert_eq!(cfg.shaper("branch").unwrap().kbps, 2000);
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert_eq!(again.to_text(), cfg.to_text());
    }

    #[test]
    fn round_trips() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert_eq!(again.to_text(), cfg.to_text());
    }

    #[test]
    fn cidr_contains() {
        let c = Cidr::parse("192.168.10.0/24").unwrap();
        assert!(c.contains("192.168.10.55".parse().unwrap()));
        assert!(!c.contains("192.168.11.1".parse().unwrap()));
        assert!(Cidr::ANY.contains("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn first_matching_policy_wins() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let p = cfg
            .match_policy(
                "root",
                "lan",
                "wan",
                "192.168.10.5".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                6,
                22,
                None,
            )
            .unwrap();
        assert_eq!(p.id, 5);
        let p = cfg
            .match_policy(
                "root",
                "lan",
                "wan",
                "192.168.10.5".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                6,
                443,
                None,
            )
            .unwrap();
        assert_eq!(p.id, 10);
    }

    const VDOMS: &str = "\
system hostname edge-vdoms
address shared-host 192.168.10.20
service web tcp 80
vdom alpha
interface pa1 zone untrust address 10.0.0.1/24 mac 02:00:00:00:00:11
interface pa2 zone trust address 192.168.10.1/24 mac 02:00:00:00:00:12
route default pa1 via 10.0.0.254
policy 10 trust untrust @shared-host any any @web permit
vdom beta
interface pb1 zone untrust address 10.1.0.1/24 mac 02:00:00:00:00:21
interface pb2 zone trust address 192.168.20.1/24 mac 02:00:00:00:00:22
route default pb1 via 10.1.0.254
policy 20 trust untrust @shared-host any any @web deny
";

    #[test]
    fn vdom_partitions_lookups_and_roundtrips() {
        let cfg = Config::parse(VDOMS).unwrap();
        assert_eq!(cfg.vdoms, vec!["root", "alpha", "beta"]);
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(
            cfg.egress("alpha", "1.1.1.1".parse().unwrap())
                .unwrap()
                .0
                .name,
            "pa1"
        );
        assert_eq!(
            cfg.egress("beta", "1.1.1.1".parse().unwrap())
                .unwrap()
                .0
                .name,
            "pb1"
        );
        let alpha = cfg
            .match_policy(
                "alpha",
                "trust",
                "untrust",
                "192.168.10.20".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
                6,
                80,
                None,
            )
            .unwrap();
        assert_eq!(alpha.id, 10);
        let beta = cfg
            .match_policy(
                "beta",
                "trust",
                "untrust",
                "192.168.10.20".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
                6,
                80,
                None,
            )
            .unwrap();
        assert_eq!(beta.id, 20);
        assert_eq!(beta.action, Action::Deny);
        assert!(cfg
            .match_policy(
                "root",
                "trust",
                "untrust",
                "192.168.10.20".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
                6,
                80,
                None,
            )
            .is_none());
        assert_eq!(
            Config::parse(&cfg.to_text()).unwrap().to_text(),
            cfg.to_text()
        );
    }

    #[test]
    fn vdom_rejects_second_default_route() {
        let text = "\
vdom alpha
interface a1 zone x address 10.0.0.1/24
interface a2 zone y address 10.0.1.1/24
route default a1
route default a2
";
        let err = Config::parse(text).unwrap_err();
        assert!(err.contains("duplicate default route"), "{err}");
    }

    #[test]
    fn egress_uses_longest_prefix_route() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let (iface, next) = cfg
            .egress("root", "192.168.10.20".parse().unwrap())
            .unwrap();
        assert_eq!(iface.name, "port2");
        assert_eq!(next, "192.168.10.20".parse::<Ipv4Addr>().unwrap());
        let (iface, next) = cfg.egress("root", "1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(iface.name, "port1");
        assert_eq!(next, "10.0.0.254".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn reject_disable_and_name_round_trip() {
        let text = "interface a zone lan address 10.0.0.1/24\ninterface b zone wan address 192.0.2.1/24\npolicy 5 lan wan any any tcp 23 reject name no-telnet\npolicy 10 lan wan any any any any permit disable\npolicy 20 lan wan any any any any permit\nsystem max-sessions 500\nsystem max-sessions-per-ip 20\nzone lan udp-flood 50\n";
        let cfg = Config::parse(text).unwrap();
        let p5 = cfg.policies.iter().find(|p| p.id == 5).unwrap();
        assert_eq!(p5.action, Action::Reject);
        assert_eq!(p5.name.as_deref(), Some("no-telnet"));
        let p10 = cfg.policies.iter().find(|p| p.id == 10).unwrap();
        assert!(!p10.enabled);
        assert_eq!(cfg.settings.max_sessions, 500);
        assert_eq!(cfg.settings.max_sessions_per_ip, 20);
        assert_eq!(cfg.zones[0].udp_flood, Some(50));
        assert_eq!(
            Config::parse(&cfg.to_text()).unwrap().to_text(),
            cfg.to_text()
        );
    }

    #[test]
    fn disabled_policy_never_matches() {
        let text = "interface a zone lan address 10.0.0.1/24\ninterface b zone wan address 192.0.2.1/24\npolicy 10 lan wan any any any any deny disable\npolicy 20 lan wan any any any any permit\n";
        let cfg = Config::parse(text).unwrap();
        let hit = cfg
            .match_policy(
                "root",
                "lan",
                "wan",
                "10.0.0.5".parse().unwrap(),
                "192.0.2.9".parse().unwrap(),
                6,
                80,
                None,
            )
            .unwrap();
        assert_eq!(hit.id, 20);
    }

    #[test]
    fn rejects_duplicate_policy_id() {
        let text =
            "policy 10 lan wan any any any any permit\npolicy 10 lan wan any any any any deny\n";
        assert!(Config::parse(text).is_err());
    }

    const LISTS: &str = "\
interface lan zone trust address 10.0.0.1/24
interface dmz zone dmz address 10.1.0.1/24
interface wan zone untrust address 203.0.113.1/24
interface wan2 zone untrust address 198.51.100.1/24
route default wan via 203.0.113.254
route default wan2 via 198.51.100.254 distance 20
route 192.168.50.0/24 wan2 via 198.51.100.254
address blocked 10.0.0.66
address web 10.1.0.10 10.1.0.11
service web tcp 80,443,8000-8080
service dns udp 53
service-group basics @web dns
app-group social facebook instagram category:social-networking
url-filter strict block category:gambling
ips-profile edge
ips-signature edge 1 /etc/passwd
profile-group default url strict ips edge
policy 10 trust,dmz untrust !@blocked any any @basics permit nat group default name outbound
policy 20 trust untrust any any tcp application-default deny app social
policy 30 any dmz any @web tcp 8080 permit
snat 5 trust untrust 10.0.0.0/24 any masquerade name lan-out
";

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn list_policies_match_any_entry_and_negate() {
        let cfg = Config::parse(LISTS).unwrap();
        let m = |zone: &str, src: &str, proto: u8, port: u16| {
            cfg.match_policy("root", zone, "untrust", ip(src), ip("8.8.8.8"), proto, port, None).map(|p| p.id)
        };
        assert_eq!(m("trust", "10.0.0.10", 6, 443), Some(10));
        assert_eq!(m("dmz", "10.1.0.10", 17, 53), Some(10), "second zone, service from the group");
        assert_eq!(m("trust", "10.0.0.66", 6, 443), None, "negated source excluded");
        assert_eq!(m("trust", "10.0.0.10", 6, 8050), Some(10), "port range");
        assert_eq!(m("trust", "10.0.0.10", 6, 22), None);
    }

    #[test]
    fn app_groups_categories_and_application_default() {
        let cfg = Config::parse(LISTS).unwrap();
        let p20 = cfg.policies.iter().find(|p| p.id == 20).unwrap();
        assert!(cfg.app_matches(&p20.apps, Some("facebook")));
        assert!(cfg.app_matches(&p20.apps, Some("tiktok")), "via category:social-networking");
        assert!(!cfg.app_matches(&p20.apps, Some("github")));
        // Policy 20 is a deny that names apps: skipped while the app is unknown.
        let pending = cfg.match_policy("root", "trust", "untrust", ip("10.0.0.66"), ip("8.8.8.8"), 6, 443, None);
        assert!(pending.is_none());
        let known = cfg.match_policy("root", "trust", "untrust", ip("10.0.0.66"), ip("8.8.8.8"), 6, 443, Some("facebook"));
        assert_eq!(known.map(|p| p.id), Some(20));
        let wrong_port = cfg.match_policy("root", "trust", "untrust", ip("10.0.0.66"), ip("8.8.8.8"), 6, 8443, Some("facebook"));
        assert!(wrong_port.is_none(), "application-default: 8443 is not facebook's port");
    }

    #[test]
    fn profile_groups_fill_missing_profiles() {
        let cfg = Config::parse(LISTS).unwrap();
        let p10 = cfg.policies.iter().find(|p| p.id == 10).unwrap();
        assert_eq!(cfg.profiles(p10), (Some("strict"), Some("edge"), None));
    }

    #[test]
    fn routes_use_longest_prefix_then_distance() {
        let cfg = Config::parse(LISTS).unwrap();
        let hop = |dst: &str| cfg.egress("root", ip(dst)).map(|(i, h)| (i.name.clone(), h.to_string()));
        assert_eq!(hop("1.1.1.1"), Some(("wan".into(), "203.0.113.254".into())), "lower distance default");
        assert_eq!(hop("192.168.50.7"), Some(("wan2".into(), "198.51.100.254".into())), "more specific route");
        assert_eq!(hop("10.1.0.20"), Some(("dmz".into(), "10.1.0.20".into())), "connected");
    }

    #[test]
    fn snat_rules_match_by_zone_and_address() {
        let cfg = Config::parse(LISTS).unwrap();
        assert_eq!(cfg.snat_match("root", "trust", "untrust", ip("10.0.0.9"), ip("1.1.1.1")).map(|r| r.id), Some(5));
        assert!(cfg.snat_match("root", "dmz", "untrust", ip("10.1.0.9"), ip("1.1.1.1")).is_none());
    }

    #[test]
    fn new_objects_round_trip() {
        let cfg = Config::parse(LISTS).unwrap();
        let text = cfg.to_text();
        for line in [
            "policy 10 trust,dmz untrust !@blocked any any @basics permit nat name outbound group default",
            "policy 20 trust untrust any any tcp application-default deny app social",
            "service web tcp 80,443,8000-8080",
            "service-group basics web dns",
            "app-group social facebook instagram category:social-networking",
            "profile-group default url strict ips edge",
            "route default wan2 via 198.51.100.254 distance 20",
            "route 192.168.50.0/24 wan2 via 198.51.100.254",
            "snat 5 trust untrust 10.0.0.0/24 any masquerade name lan-out",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
        assert_eq!(Config::parse(&text).unwrap().to_text(), text);
    }

    #[test]
    fn rejects_unknown_apps_services_and_categories() {
        let base = "interface a zone lan address 10.0.0.1/24\n";
        for bad in [
            "policy 1 lan lan any any any any permit app warp-drive",
            "policy 1 lan lan any any any any permit app category:nonsense",
            "policy 1 lan lan any any any @nope permit",
            "policy 1 lan lan any any any any permit group nope",
            "service-group g nope",
        ] {
            assert!(Config::parse(&format!("{base}{bad}\n")).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn ngfw_appid_example_parses_and_behaves() {
        let cfg = Config::parse(include_str!("../examples/ngfw-appid.conf")).unwrap();
        let m = |src: &str, dst: &str, proto: u8, port: u16, app: Option<&str>| {
            cfg.match_policy("root", "trust", "untrust", ip(src), ip(dst), proto, port, app).and_then(|p| p.name.clone())
        };
        assert_eq!(m("10.0.0.5", "8.8.8.8", 6, 443, Some("tiktok")).as_deref(), Some("block-social"));
        assert_eq!(m("10.0.0.5", "8.8.8.8", 6, 443, Some("github")).as_deref(), Some("web-out"));
        assert_eq!(m("10.0.0.5", "8.8.8.8", 17, 53, Some("dns")).as_deref(), Some("infra"));
        assert_eq!(m("10.0.0.66", "8.8.8.8", 17, 53, Some("dns")).as_deref(), Some("quarantine"));
        assert_eq!(m("10.0.0.5", "8.8.8.8", 6, 8443, Some("ssl")), None, "application-default");
        assert_eq!(Config::parse(&cfg.to_text()).unwrap().to_text(), cfg.to_text());
    }

    #[test]
    fn default_rules_apply_when_no_policy_matches() {
        let text = "\
interface a zone trust address 10.0.0.1/24
interface b zone trust address 10.0.1.1/24
interface c zone guest address 10.0.2.1/24
interface d zone untrust address 203.0.113.1/24
policy 10 trust untrust any any any any permit
default-rule intrazone allow log
default-rule intrazone deny zone guest
";
        let cfg = Config::parse(text).unwrap();
        let d = |from: &str, to: &str| {
            cfg.match_or_default("root", from, to, ip("10.0.0.5"), ip("10.0.1.5"), 6, 80, None)
                .map(|p| (p.name.clone().unwrap_or_default(), p.action))
        };
        assert_eq!(d("trust", "trust"), Some(("intrazone-default".into(), Action::Permit)));
        assert_eq!(d("guest", "guest"), Some(("intrazone-default:guest".into(), Action::Deny)));
        assert_eq!(d("untrust", "trust"), Some(("interzone-default".into(), Action::Deny)));
        assert!(cfg.match_policy("root", "trust", "trust", ip("10.0.0.5"), ip("10.0.1.5"), 6, 80, None).is_none());
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert_eq!(again.to_text(), cfg.to_text());
        assert!(cfg.to_text().contains("default-rule intrazone deny zone guest"));
        // Unconfigured: both deny, as before this feature.
        let plain = Config::parse("interface a zone trust address 10.0.0.1/24\n").unwrap();
        assert_eq!(plain.match_or_default("root", "trust", "trust", ip("10.0.0.5"), ip("10.0.0.6"), 6, 80, None).unwrap().action, Action::Deny);
    }

    #[test]
    fn user_policies_match_users_groups_and_unknown() {
        let text = "\
interface a zone trust address 10.0.0.1/24
interface b zone untrust address 203.0.113.1/24
user-group eng alice bob
user-group staff eng carol
user-map 10.0.0.20 dave
policy 10 trust untrust any any tcp 22 permit user staff
policy 20 trust untrust any any tcp 22 deny user known-user
policy 30 trust untrust any any tcp 80 permit user unknown
";
        let cfg = Config::parse(text).unwrap();
        let m = |user: Option<&str>, port| {
            cfg.match_policy_user("root", "trust", "untrust", ip("10.0.0.5"), ip("1.1.1.1"), 6, port, None, user).map(|p| p.id)
        };
        assert_eq!(m(Some("alice"), 22), Some(10), "nested group");
        assert_eq!(m(Some("carol"), 22), Some(10));
        assert_eq!(m(Some("mallory"), 22), Some(20), "known but not staff");
        assert_eq!(m(None, 22), None, "unknown users match neither");
        assert_eq!(m(None, 80), Some(30));
        // Static mapping: 10.0.0.20 is dave.
        let p = cfg.match_policy("root", "trust", "untrust", ip("10.0.0.20"), ip("1.1.1.1"), 6, 22, None);
        assert_eq!(p.map(|p| p.id), Some(20));
        assert_eq!(Config::parse(&cfg.to_text()).unwrap().to_text(), cfg.to_text());
        assert!(Config::parse("user-map 10.0.0.1 bad user\n").is_err());
    }

    #[test]
    fn wireguard_tunnels_parse_route_and_round_trip() {
        let k1 = crate::wg::genkey();
        let p1 = crate::wg::pubkey(&crate::wg::genkey()).unwrap();
        let text = format!(
            "interface wan zone untrust address 203.0.113.1/24\n\
             vpn wireguard wg0 private-key {k1} listen-port 51820 address 10.99.0.1/24 zone vpn\n\
             vpn wireguard-peer wg0 branch public-key {p1} allowed-ips 10.99.0.2/32,10.2.0.0/16 endpoint 198.51.100.9:51820 keepalive 25\n\
             route default wan via 203.0.113.254\n"
        );
        let cfg = Config::parse(&text).unwrap();
        let wg0 = cfg.interfaces.iter().find(|i| i.name == "wg0").unwrap();
        assert!(wg0.tunnel && wg0.zone == "vpn");
        let hop = |d: &str| cfg.egress("root", ip(d)).map(|(i, h)| (i.name.clone(), h.to_string()));
        assert_eq!(hop("10.2.3.4"), Some(("wg0".into(), "10.2.3.4".into())), "allowed-ips route");
        assert_eq!(hop("10.99.0.2"), Some(("wg0".into(), "10.99.0.2".into())));
        assert_eq!(hop("8.8.8.8"), Some(("wan".into(), "203.0.113.254".into())));
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert_eq!(again.to_text(), cfg.to_text());
        assert!(!cfg.to_text().contains("interface wg0"));
        assert!(Config::parse(&format!("vpn wireguard wg0 private-key {k1} listen-port 51820 zone vpn\nvpn wireguard-peer wg0 x public-key nope allowed-ips 10.0.0.0/8\n")).is_err());
    }

    #[test]
    fn ipv6_objects_policies_and_routes() {
        let text = "\
interface lan zone trust address 10.0.0.1/24 address6 2001:db8:1::1/64
interface wan zone untrust address 203.0.113.1/24 address6 2001:db8:ffff::2/64
route6 default wan via 2001:db8:ffff::1
route6 2001:db8:50::/48 lan via 2001:db8:1::fe distance 5
address web 10.1.0.10 2001:db8:2::10
address-group servers web
policy 10 trust untrust any @servers tcp 443 permit
policy 20 trust untrust 2001:db8:1::/64 2001:db8:abcd::/48 any any permit
policy 30 trust untrust 10.0.0.0/24 any any any deny
";
        let cfg = Config::parse(text).unwrap();
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        let m = |src: IpAddr, dst: IpAddr, port| cfg.match_policy_ip("root", "trust", "untrust", src, dst, 6, port, None, None).map(|p| p.id);
        assert_eq!(m(v6("2001:db8:1::5"), v6("2001:db8:2::10"), 443), Some(10), "v6 entry of a named object via a group");
        assert_eq!(m(v6("2001:db8:1::5"), v6("2001:db8:abcd::9"), 22), Some(20), "v6 literals");
        assert_eq!(m(v6("2001:db8:1::5"), v6("2001:db8:9::9"), 22), None, "v4-only rule never matches v6");
        assert_eq!(m(IpAddr::V4(ip("10.0.0.5")), IpAddr::V4(ip("10.1.0.10")), 443), Some(10), "v4 still works");
        let e = |d: &str| cfg.egress6("root", d.parse().unwrap()).map(|(i, h)| (i.name.clone(), h.to_string()));
        assert_eq!(e("2001:db8:1::77"), Some(("lan".into(), "2001:db8:1::77".into())), "connected");
        assert_eq!(e("2001:db8:50::1"), Some(("lan".into(), "2001:db8:1::fe".into())), "more specific route6");
        assert_eq!(e("2606:4700::1111"), Some(("wan".into(), "2001:db8:ffff::1".into())), "default route6");
        assert_eq!(Config::parse(&cfg.to_text()).unwrap().to_text(), cfg.to_text());
        assert!(Cidr6::parse("2001:db8::/129").is_err());
        assert!(Config::parse("route6 default nowhere\n").is_err());
    }

    #[test]
    fn c5_user_scoped_rules_fail_closed_for_ipv6_sources() {
        let cfg = Config::parse(
            "interface lan zone trust address 10.0.0.1/24 address6 2001:db8:1::1/64\n\
             interface wan zone untrust address 203.0.113.1/24 address6 2001:db8:2::1/64\n\
             policy 5 trust untrust any any tcp any deny user contractors\n\
             policy 7 trust untrust any any tcp 22 permit user alice\n\
             policy 8 trust untrust any any tcp 23 permit user unknown\n\
             policy 10 trust untrust any any tcp any permit\n",
        )
        .unwrap();
        let v6 = |port| {
            cfg.match_policy_ip(
                "root", "trust", "untrust",
                "2001:db8:1::10".parse().unwrap(), "2001:db8:2::10".parse().unwrap(),
                6, port, None, None,
            )
            .map(|p| p.id)
        };
        // IPv6 has no User-ID, so the user-scoped deny applies to every source.
        assert_eq!(v6(443), Some(5), "deny user contractors must not be bypassed over IPv6");
        // IPv4 keeps its semantics: an unknown user is not a contractor.
        let v4 = cfg
            .match_policy_ip(
                "root", "trust", "untrust",
                "10.0.0.10".parse().unwrap(), "203.0.113.10".parse().unwrap(),
                6, 443, None, None,
            )
            .map(|p| p.id);
        assert_eq!(v4, Some(10));
        // A user-scoped permit never matches IPv6 (it falls through to the
        // deny above it anyway); `unknown` keeps matching unidentified users.
        let only_permits = Config::parse(
            "interface lan zone trust address 10.0.0.1/24 address6 2001:db8:1::1/64\n\
             interface wan zone untrust address 203.0.113.1/24 address6 2001:db8:2::1/64\n\
             policy 7 trust untrust any any tcp 22 permit user alice\n\
             policy 8 trust untrust any any tcp 23 permit user unknown\n",
        )
        .unwrap();
        let m = |port| {
            only_permits
                .match_policy_ip(
                    "root", "trust", "untrust",
                    "2001:db8:1::10".parse().unwrap(), "2001:db8:2::10".parse().unwrap(),
                    6, port, None, None,
                )
                .map(|p| p.id)
        };
        assert_eq!(m(22), None, "permit user alice does not match an IPv6 source");
        assert_eq!(m(23), Some(8), "permit user unknown still matches");
    }

    #[test]
    fn kernel_forwarding_and_cli_plaintext_settings_round_trip() {
        let cfg = Config::parse("system kernel-forwarding warn\nsystem cli-remote-plaintext on\n").unwrap();
        assert!(!cfg.settings.kernel_forwarding_refuse);
        assert!(cfg.settings.cli_remote_plaintext);
        let again = Config::parse(&cfg.to_text()).unwrap();
        assert!(!again.settings.kernel_forwarding_refuse && again.settings.cli_remote_plaintext);
        let default = Config::parse("").unwrap();
        assert!(default.settings.kernel_forwarding_refuse && !default.settings.cli_remote_plaintext);
        assert!(!default.to_text().contains("kernel-forwarding"), "defaults are not written out");
        assert!(Config::parse("system kernel-forwarding maybe\n").is_err());
    }
}
