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
use std::net::Ipv4Addr;

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

/// A policy address: either a literal CIDR or a named object/group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrRef {
    Cidr(Cidr),
    Named(String),
}

impl AddrRef {
    pub fn parse(s: &str) -> Result<AddrRef, String> {
        if let Some(name) = s.strip_prefix('@') {
            if name.is_empty() {
                return Err("empty address object name".to_string());
            }
            Ok(AddrRef::Named(name.to_string()))
        } else {
            Ok(AddrRef::Cidr(Cidr::parse(s)?))
        }
    }
}

impl fmt::Display for AddrRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrRef::Cidr(c) => write!(f, "{c}"),
            AddrRef::Named(n) => write!(f, "@{n}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddressObject {
    pub name: String,
    pub entries: Vec<Cidr>,
}

#[derive(Clone, Debug)]
pub struct AddressGroup {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceObject {
    pub name: String,
    pub proto: Proto,
    pub port: Option<u16>,
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
            other => Err(format!(
                "invalid action '{other}' (permit, deny or reject)"
            )),
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
}

impl Interface {
    pub fn new(name: &str, zone: &str) -> Interface {
        Interface {
            name: name.to_string(),
            vdom: "root".to_string(),
            zone: zone.to_string(),
            address: None,
            mac: None,
            mtu: 1500,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub id: u32,
    pub vdom: String,
    pub src_zone: String,
    pub dst_zone: String,
    pub src: AddrRef,
    pub dst: AddrRef,
    pub proto: Proto,
    pub dst_port: Option<u16>,
    pub service: Option<String>,
    pub action: Action,
    pub nat: bool,
    pub app: Option<String>,
    pub url: Option<String>,
    pub ips: Option<String>,
    pub av: Option<String>,
    pub shaper: Option<String>,
    pub log: bool,
    /// Disabled policies stay in the configuration but never match.
    pub enabled: bool,
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub interface: String,
    pub via: Option<Ipv4Addr>,
    pub vdom: String,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub hostname: String,
    pub cli_port: u16,
    pub gui_port: u16,
    pub tcp_timeout: u64,
    pub udp_timeout: u64,
    pub icmp_timeout: u64,
    pub logging: bool,
    pub log_json: bool,
    /// Global cap on tracked flows; 0 disables the cap.
    pub max_sessions: usize,
    /// Cap on tracked flows opened by one source address; 0 disables it.
    pub max_sessions_per_ip: usize,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            hostname: "firewall".to_string(),
            cli_port: 2200,
            gui_port: 8080,
            tcp_timeout: 300,
            udp_timeout: 30,
            icmp_timeout: 10,
            logging: true,
            log_json: false,
            max_sessions: 100_000,
            max_sessions_per_ip: 0,
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
    pub apps: Vec<AppDef>,
    pub url_filters: Vec<UrlFilter>,
    pub ips_profiles: Vec<SignatureProfile>,
    pub av_profiles: Vec<SignatureProfile>,
    pub dnat: Vec<DnatRule>,
    pub shapers: Vec<Shaper>,
    pub zones: Vec<ZoneProtection>,
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
                "interface" => cfg.parse_interface(&words[1..]).map_err(|e| err(e))?,
                "route" => cfg.parse_route(&words[1..]).map_err(|e| err(e))?,
                "vdom" => cfg.parse_vdom(&words[1..]).map_err(|e| err(e))?,
                "policy" => cfg.parse_policy(&words[1..]).map_err(|e| err(e))?,
                "address" => cfg.parse_address(&words[1..]).map_err(|e| err(e))?,
                "address-group" => cfg.parse_address_group(&words[1..]).map_err(|e| err(e))?,
                "service" => cfg.parse_service(&words[1..]).map_err(|e| err(e))?,
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
                other => return Err(err(format!("unknown directive '{other}'"))),
            }
        }
        cfg.validate()?;
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
            "max-sessions-per-ip" => {
                s.max_sessions_per_ip = value
                    .parse()
                    .map_err(|_| "invalid max-sessions-per-ip".to_string())?
            }
            "logging" => match value {
                "on" | "yes" | "true" => s.logging = true,
                "off" | "no" | "false" => s.logging = false,
                _ => return Err("system logging expects on or off".to_string()),
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
        if words.len() < 2 || words[0] != "default" {
            return Err("usage: route default <interface> [via a.b.c.d]".to_string());
        }
        let mut route = Route {
            interface: words[1].to_string(),
            via: None,
            vdom: self.current_vdom.clone(),
        };
        if words.len() == 4 && words[2] == "via" {
            route.via = Some(
                words[3]
                    .parse()
                    .map_err(|_| format!("invalid gateway '{}'", words[3]))?,
            );
        } else if words.len() != 2 {
            return Err("usage: route default <interface> [via a.b.c.d]".to_string());
        }
        if self.routes.iter().any(|r| r.vdom == route.vdom) {
            return Err(format!("duplicate default route for vdom '{}'", route.vdom));
        }
        self.routes.push(route);
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
            return Err("usage: policy <id> <src-zone> <dst-zone> <src-cidr|@object|any> <dst-cidr|@object|any> <proto|any> <dst-port|@service|any> <permit|deny> [options...]".to_string());
        }
        let id: u32 = words[0]
            .parse()
            .map_err(|_| format!("invalid policy id '{}'", words[0]))?;
        if self.policies.iter().any(|p| p.id == id) {
            return Err(format!("duplicate policy id {id}"));
        }
        let mut service = None;
        let dst_port = if let Some(name) = words[6].strip_prefix('@') {
            service = Some(name.to_string());
            None
        } else if words[6] == "any" {
            None
        } else {
            Some(
                words[6]
                    .parse()
                    .map_err(|_| format!("invalid port '{}'", words[6]))?,
            )
        };
        let mut policy = Policy {
            id,
            vdom: self.current_vdom.clone(),
            src_zone: words[1].to_string(),
            dst_zone: words[2].to_string(),
            src: AddrRef::parse(words[3]).map_err(|e| format!("source: {e}"))?,
            dst: AddrRef::parse(words[4]).map_err(|e| format!("destination: {e}"))?,
            proto: Proto::parse(words[5]).map_err(|e| format!("protocol: {e}"))?,
            dst_port,
            service,
            action: Action::parse(words[7])?,
            nat: false,
            app: None,
            url: None,
            ips: None,
            av: None,
            shaper: None,
            log: true,
            enabled: true,
            name: None,
        };
        let mut i = 8;
        while i < words.len() {
            match words[i] {
                "nat" => {
                    policy.nat = true;
                    i += 1;
                }
                "log" => {
                    policy.log = true;
                    i += 1;
                }
                "nolog" => {
                    policy.log = false;
                    i += 1;
                }
                "disable" => {
                    policy.enabled = false;
                    i += 1;
                }
                "enable" => {
                    policy.enabled = true;
                    i += 1;
                }
                "name" => {
                    let value = words
                        .get(i + 1)
                        .ok_or_else(|| "policy option 'name' needs a value".to_string())?;
                    policy.name = Some(value.to_string());
                    i += 2;
                }
                key @ ("app" | "url" | "ips" | "av" | "shaper") => {
                    let value = words
                        .get(i + 1)
                        .ok_or_else(|| format!("policy option '{key}' needs a value"))?;
                    match key {
                        "app" => policy.app = Some(value.to_string()),
                        "url" => policy.url = Some(value.to_string()),
                        "ips" => policy.ips = Some(value.to_string()),
                        "av" => policy.av = Some(value.to_string()),
                        _ => policy.shaper = Some(value.to_string()),
                    }
                    i += 2;
                }
                other => return Err(format!("unknown policy option '{other}'")),
            }
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
        for value in &words[1..] {
            entries.push(Cidr::parse(value).map_err(|e| format!("address: {e}"))?);
        }
        self.addresses.push(AddressObject {
            name: words[0].to_string(),
            entries,
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
            return Err("usage: service <name> <proto|any> <port|any>".to_string());
        }
        if self.services.iter().any(|s| s.name == words[0]) {
            return Err(format!("duplicate service object '{}'", words[0]));
        }
        let proto = Proto::parse(words[1]).map_err(|e| format!("service protocol: {e}"))?;
        let port = if words[2] == "any" {
            None
        } else {
            Some(
                words[2]
                    .parse()
                    .map_err(|_| format!("invalid service port '{}'", words[2]))?,
            )
        };
        self.services.push(ServiceObject {
            name: words[0].to_string(),
            proto,
            port,
        });
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
        if words.len() != 6 {
            return Err("usage: dnat <id> <proto|any> <public-cidr|any> <public-port|any> <private-ip> <private-port|any>".to_string());
        }
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
        self.dnat.push(DnatRule {
            id,
            vdom: self.current_vdom.clone(),
            proto,
            dst,
            dst_port,
            to_ip,
            to_port,
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
        for iface in &self.interfaces {
            if !iface
                .zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(format!("interface {} has an invalid zone name", iface.name));
            }
        }
        for route in &self.routes {
            if !self
                .interfaces
                .iter()
                .any(|i| i.name == route.interface && i.vdom == route.vdom)
            {
                return Err(format!(
                    "default route interface '{}' is not configured in vdom '{}'",
                    route.interface, route.vdom
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
        for policy in &self.policies {
            for (label, reference) in [("source", &policy.src), ("destination", &policy.dst)] {
                if let AddrRef::Named(name) = reference {
                    if !self.address_ref_exists(name) {
                        return Err(format!(
                            "policy {} {label} references unknown address '{}'",
                            policy.id, name
                        ));
                    }
                }
            }
            if let Some(service) = &policy.service {
                if !self.services.iter().any(|s| &s.name == service) {
                    return Err(format!(
                        "policy {} references unknown service '{}'",
                        policy.id, service
                    ));
                }
            }
            if let Some(app) = &policy.app {
                if app != "any"
                    && !self.apps.iter().any(|a| &a.name == app)
                    && builtin_app(app).is_none()
                {
                    return Err(format!(
                        "policy {} references unknown application '{}'",
                        policy.id, app
                    ));
                }
            }
            if let Some(url) = &policy.url {
                if !self.url_filters.iter().any(|f| &f.name == url) {
                    return Err(format!(
                        "policy {} references unknown URL filter '{}'",
                        policy.id, url
                    ));
                }
            }
            if let Some(ips) = &policy.ips {
                if !self.ips_profiles.iter().any(|p| &p.name == ips) {
                    return Err(format!(
                        "policy {} references unknown IPS profile '{}'",
                        policy.id, ips
                    ));
                }
            }
            if let Some(av) = &policy.av {
                if !self.av_profiles.iter().any(|p| &p.name == av) {
                    return Err(format!(
                        "policy {} references unknown antivirus profile '{}'",
                        policy.id, av
                    ));
                }
            }
            if let Some(shaper) = &policy.shaper {
                if !self.shapers.iter().any(|s| &s.name == shaper) {
                    return Err(format!(
                        "policy {} references unknown shaper '{}'",
                        policy.id, shaper
                    ));
                }
            }
        }
        Ok(())
    }

    fn address_ref_exists(&self, name: &str) -> bool {
        self.addresses.iter().any(|a| a.name == name)
            || self.address_groups.iter().any(|g| g.name == name)
    }

    pub fn addr_matches(&self, reference: &AddrRef, ip: Ipv4Addr) -> bool {
        match reference {
            AddrRef::Cidr(cidr) => cidr.contains(ip),
            AddrRef::Named(name) => self.named_addr_matches(name, ip, 0),
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

    pub fn service_matches(&self, name: &str, proto: u8, port: u16) -> bool {
        self.services
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.proto.matches(proto) && s.port.map(|p| p == port).unwrap_or(true))
            .unwrap_or(false)
    }

    pub fn detected_app(&self, proto: u8, port: u16) -> Option<&str> {
        if let Some(app) = self
            .apps
            .iter()
            .find(|a| a.proto.matches(proto) && a.port == port)
        {
            return Some(&app.name);
        }
        builtin_app_by_port(proto, port)
    }

    pub fn app_matches(&self, policy_app: &str, proto: u8, port: u16) -> bool {
        if policy_app == "any" {
            return true;
        }
        if let Some(app) = self.apps.iter().find(|a| a.name == policy_app) {
            return app.proto.matches(proto) && app.port == port;
        }
        builtin_app(policy_app)
            .map(|(p, builtin_port)| p.matches(proto) && builtin_port == port)
            .unwrap_or(false)
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

    pub fn egress(&self, vdom: &str, dst: Ipv4Addr) -> Option<(&Interface, Ipv4Addr)> {
        for iface in self.interfaces.iter().filter(|i| i.vdom == vdom) {
            if let Some(cidr) = iface.address {
                if cidr.contains(dst) {
                    return Some((iface, dst));
                }
            }
        }
        let route = self.routes.iter().find(|r| r.vdom == vdom)?;
        let iface = self
            .interfaces
            .iter()
            .find(|i| i.name == route.interface && i.vdom == vdom)?;
        Some((iface, route.via.unwrap_or(dst)))
    }

    pub fn match_policy(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
    ) -> Option<&Policy> {
        self.match_policy_ex(vdom, src_zone, dst_zone, src, dst, proto, dst_port)
    }

    pub fn match_policy_ex(
        &self,
        vdom: &str,
        src_zone: &str,
        dst_zone: &str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        dst_port: u16,
    ) -> Option<&Policy> {
        self.policies
            .iter()
            .filter(|p| p.vdom == vdom && p.enabled)
            .filter(|p| p.src_zone == src_zone && p.dst_zone == dst_zone)
            .filter(|p| self.addr_matches(&p.src, src) && self.addr_matches(&p.dst, dst))
            .filter(|p| p.proto.matches(proto))
            .filter(|p| match &p.service {
                Some(name) => self.service_matches(name, proto, dst_port),
                None => true,
            })
            .filter(|p| match p.dst_port {
                None => true,
                Some(port) => dst_port == port,
            })
            .filter(|p| match &p.app {
                Some(app) => self.app_matches(app, proto, dst_port),
                None => true,
            })
            .min_by_key(|p| p.id)
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let s = &self.settings;
        out.push_str(&format!("system hostname {}\n", s.hostname));
        out.push_str(&format!("system cli-port {}\n", s.cli_port));
        out.push_str(&format!("system gui-port {}\n", s.gui_port));
        out.push_str(&format!("system max-sessions {}\n", s.max_sessions));
        out.push_str(&format!(
            "system max-sessions-per-ip {}\n",
            s.max_sessions_per_ip
        ));
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
        for address in &self.addresses {
            out.push_str(&format!("\naddress {}", address.name));
            for entry in &address.entries {
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
            out.push_str(&format!(
                "\nservice {} {} {}\n",
                service.name,
                service.proto,
                service
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "any".to_string())
            ));
        }
        for app in &self.apps {
            out.push_str(&format!(
                "\napp-def {} {} {}\n",
                app.name, app.proto, app.port
            ));
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
        let vdoms: Vec<String> = if self.vdoms.is_empty() {
            vec!["root".to_string()]
        } else {
            self.vdoms.clone()
        };
        for vdom in &vdoms {
            out.push_str(&format!("\nvdom {vdom}\n"));
            for i in self.interfaces.iter().filter(|i| &i.vdom == vdom) {
                out.push_str(&format!("interface {} zone {}", i.name, i.zone));
                if let Some(a) = i.address {
                    out.push_str(&format!(" address {a}"));
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
                out.push_str(&format!("route default {}", r.interface));
                if let Some(via) = r.via {
                    out.push_str(&format!(" via {via}"));
                }
                out.push('\n');
            }
            for p in self.policies.iter().filter(|p| &p.vdom == vdom) {
                out.push_str(&format!(
                    "policy {} {} {} {} {} {} {} {}",
                    p.id,
                    p.src_zone,
                    p.dst_zone,
                    p.src,
                    p.dst,
                    p.proto,
                    p.service
                        .as_ref()
                        .map(|s| format!("@{s}"))
                        .or_else(|| p.dst_port.map(|v| v.to_string()))
                        .unwrap_or_else(|| "any".to_string()),
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
                if let Some(app) = &p.app {
                    out.push_str(&format!(" app {app}"));
                }
                if let Some(url) = &p.url {
                    out.push_str(&format!(" url {url}"));
                }
                if let Some(ips) = &p.ips {
                    out.push_str(&format!(" ips {ips}"));
                }
                if let Some(av) = &p.av {
                    out.push_str(&format!(" av {av}"));
                }
                if let Some(shaper) = &p.shaper {
                    out.push_str(&format!(" shaper {shaper}"));
                }
                out.push('\n');
            }
            for rule in self.dnat.iter().filter(|r| &r.vdom == vdom) {
                out.push_str(&format!(
                    "dnat {} {} {} {} {} {}\n",
                    rule.id,
                    rule.proto,
                    rule.dst,
                    rule.dst_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "any".to_string()),
                    rule.to_ip,
                    rule.to_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "any".to_string())
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

const BUILTIN_APPS: &[(&str, Proto, u16)] = &[
    ("http", Proto::Tcp, 80),
    ("https", Proto::Tcp, 443),
    ("dns", Proto::Udp, 53),
    ("ssh", Proto::Tcp, 22),
    ("smtp", Proto::Tcp, 25),
    ("ftp", Proto::Tcp, 21),
    ("rdp", Proto::Tcp, 3389),
    ("telnet", Proto::Tcp, 23),
    ("imap", Proto::Tcp, 143),
    ("pop3", Proto::Tcp, 110),
    ("ntp", Proto::Udp, 123),
    ("snmp", Proto::Udp, 161),
];

fn builtin_app(name: &str) -> Option<(Proto, u16)> {
    BUILTIN_APPS
        .iter()
        .find(|(app, _, _)| *app == name)
        .map(|(_, proto, port)| (*proto, *port))
}

fn builtin_app_by_port(proto: u8, port: u16) -> Option<&'static str> {
    BUILTIN_APPS
        .iter()
        .find(|(_, p, candidate)| p.matches(proto) && *candidate == port)
        .map(|(name, _, _)| *name)
}

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
        assert!(cfg.app_matches("custom-app", 6, 9000));
        assert_eq!(cfg.detected_app(6, 9000), Some("custom-app"));
        assert_eq!(cfg.detected_app(6, 443), Some("https"));
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
        assert_eq!(cfg.detected_app(6, 8443), Some("admin-ui"));
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
}
