//! App-ID: identify the application in a flow from its payload, not its port.
//!
//! This follows the model next-generation firewalls use:
//!
//! 1. A new TCP flow is matched against the rulebase before any payload is
//!    seen. Rules that name applications match *provisionally*, so the
//!    handshake can complete.
//! 2. The first payload packets are classified here, client-to-server and
//!    server-to-client (for protocols where the server speaks first, such as
//!    SMTP, FTP, POP3, IMAP and MySQL).
//! 3. Once the application is known the rulebase is evaluated again with it.
//!    If the result is a deny, or no rule, the flow is cut off.
//!
//! Applications form a small hierarchy: `facebook` is carried over `ssl` or
//! `web-browsing`. Identification always returns the most specific one, and a
//! rule allowing `ssl` does not allow `facebook`, as on PAN-OS.
//!
//! Signatures here are short and readable on purpose. They are good enough to
//! label lab traffic and to teach how classification works; they are not a
//! commercial signature set.

use crate::model::Proto;

#[derive(Debug)]
pub struct AppInfo {
    pub name: &'static str,
    /// One of: business-systems, collaboration, general-internet, media, networking.
    pub category: &'static str,
    pub subcategory: &'static str,
    /// 1 (low) to 5 (high).
    pub risk: u8,
    /// Application this one is carried over, if any.
    pub parent: Option<&'static str>,
    /// Standard ports, used by the `application-default` service.
    /// Empty means the application uses dynamic ports.
    pub ports: &'static [(Proto, u16, u16)],
    pub description: &'static str,
}

pub const UNKNOWN_TCP: &str = "unknown-tcp";
pub const UNKNOWN_UDP: &str = "unknown-udp";
pub const UNKNOWN_IP: &str = "unknown-ip";

/// Payload packets inspected before a flow is labelled unknown.
pub const MAX_TRIES: u8 = 8;

/// Bytes per direction buffered for classification. A ClientHello or an
/// HTTP request split across TCP segments is reassembled up to this size.
pub const MAX_BUFFER: usize = 4096;

/// Result of classifying the bytes seen so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    App(&'static str),
    /// A message has started but is incomplete (a TLS record or HTTP header
    /// that continues in the next segment).
    NeedMore,
    NoMatch,
}

const TCP: Proto = Proto::Tcp;
const UDP: Proto = Proto::Udp;
const ICMP: Proto = Proto::Icmp;
const WEB: &[(Proto, u16, u16)] = &[(TCP, 80, 80), (TCP, 443, 443), (TCP, 8080, 8080)];

macro_rules! app {
    ($name:literal, $cat:literal, $sub:literal, $risk:literal, $parent:expr, $ports:expr, $desc:literal) => {
        AppInfo { name: $name, category: $cat, subcategory: $sub, risk: $risk, parent: $parent, ports: $ports, description: $desc }
    };
}

pub static APPS: &[AppInfo] = &[
    // Base protocols
    app!("web-browsing", "general-internet", "internet-utility", 4, None, &[(TCP, 80, 80), (TCP, 8080, 8080)], "Plain HTTP"),
    app!("ssl", "networking", "encrypted-tunnel", 4, None, &[(TCP, 443, 443)], "TLS"),
    app!("http-proxy", "networking", "proxy", 5, Some("web-browsing"), &[(TCP, 3128, 3128), (TCP, 8080, 8080)], "HTTP CONNECT proxy"),
    app!("quic", "networking", "encrypted-tunnel", 3, None, &[(UDP, 443, 443)], "QUIC transport"),
    app!("dns", "networking", "infrastructure", 3, None, &[(UDP, 53, 53), (TCP, 53, 53)], "Domain Name System"),
    app!("ntp", "networking", "infrastructure", 1, None, &[(UDP, 123, 123)], "Network Time Protocol"),
    app!("dhcp", "networking", "infrastructure", 2, None, &[(UDP, 67, 68)], "DHCP"),
    app!("snmp", "networking", "infrastructure", 3, None, &[(UDP, 161, 162)], "SNMP"),
    app!("stun", "networking", "infrastructure", 2, None, &[(UDP, 3478, 3478), (UDP, 19302, 19302)], "STUN NAT discovery"),
    app!("ping", "networking", "infrastructure", 2, None, &[(ICMP, 0, 65535)], "ICMP echo"),
    app!("icmp", "networking", "ip-protocol", 2, None, &[(ICMP, 0, 65535)], "Other ICMP"),
    app!("ssh", "networking", "encrypted-tunnel", 4, None, &[(TCP, 22, 22)], "Secure Shell"),
    app!("telnet", "networking", "remote-access", 5, None, &[(TCP, 23, 23)], "Telnet"),
    app!("ms-rdp", "networking", "remote-access", 4, None, &[(TCP, 3389, 3389)], "Microsoft Remote Desktop"),
    app!("ms-ds-smb", "business-systems", "storage-backup", 4, None, &[(TCP, 139, 139), (TCP, 445, 445)], "SMB file sharing"),
    app!("wireguard", "networking", "encrypted-tunnel", 3, None, &[], "WireGuard VPN"),
    app!("sip", "collaboration", "voip-video", 3, None, &[(UDP, 5060, 5061), (TCP, 5060, 5061)], "Session Initiation Protocol"),
    app!("ftp", "general-internet", "file-sharing", 5, None, &[(TCP, 21, 21)], "File Transfer Protocol"),
    app!("smtp", "collaboration", "email", 4, None, &[(TCP, 25, 25), (TCP, 465, 465), (TCP, 587, 587)], "Mail transfer"),
    app!("pop3", "collaboration", "email", 4, None, &[(TCP, 110, 110), (TCP, 995, 995)], "POP3 mail retrieval"),
    app!("imap", "collaboration", "email", 4, None, &[(TCP, 143, 143), (TCP, 993, 993)], "IMAP mail retrieval"),
    app!("mysql", "business-systems", "database", 4, None, &[(TCP, 3306, 3306)], "MySQL"),
    app!("postgres", "business-systems", "database", 4, None, &[(TCP, 5432, 5432)], "PostgreSQL"),
    app!("redis", "business-systems", "database", 4, None, &[(TCP, 6379, 6379)], "Redis"),
    app!("mqtt", "business-systems", "iot", 3, None, &[(TCP, 1883, 1883), (TCP, 8883, 8883)], "MQTT messaging"),
    app!("bittorrent", "general-internet", "file-sharing", 5, None, &[], "BitTorrent peer-to-peer"),
    // SaaS applications, identified by HTTP Host or TLS SNI
    app!("youtube", "media", "photo-video", 3, Some("ssl"), WEB, "YouTube"),
    app!("netflix", "media", "photo-video", 2, Some("ssl"), WEB, "Netflix"),
    app!("spotify", "media", "audio-streaming", 2, Some("ssl"), WEB, "Spotify"),
    app!("twitch", "media", "photo-video", 3, Some("ssl"), WEB, "Twitch"),
    app!("tiktok", "general-internet", "social-networking", 4, Some("ssl"), WEB, "TikTok"),
    app!("facebook", "general-internet", "social-networking", 4, Some("ssl"), WEB, "Facebook"),
    app!("instagram", "general-internet", "social-networking", 4, Some("ssl"), WEB, "Instagram"),
    app!("twitter", "general-internet", "social-networking", 4, Some("ssl"), WEB, "X / Twitter"),
    app!("linkedin", "general-internet", "social-networking", 3, Some("ssl"), WEB, "LinkedIn"),
    app!("reddit", "general-internet", "social-networking", 3, Some("ssl"), WEB, "Reddit"),
    app!("whatsapp", "collaboration", "instant-messaging", 3, Some("ssl"), WEB, "WhatsApp"),
    app!("slack", "collaboration", "instant-messaging", 2, Some("ssl"), WEB, "Slack"),
    app!("ms-teams", "collaboration", "voip-video", 2, Some("ssl"), WEB, "Microsoft Teams"),
    app!("zoom", "collaboration", "voip-video", 3, Some("ssl"), WEB, "Zoom"),
    app!("ms-office365", "business-systems", "office-programs", 2, Some("ssl"), WEB, "Microsoft 365"),
    app!("gmail", "collaboration", "email", 3, Some("ssl"), WEB, "Gmail"),
    app!("google-drive", "general-internet", "file-sharing", 3, Some("ssl"), WEB, "Google Drive"),
    app!("dropbox", "general-internet", "file-sharing", 4, Some("ssl"), WEB, "Dropbox"),
    app!("github", "business-systems", "software-development", 3, Some("ssl"), WEB, "GitHub"),
    app!("openai-chatgpt", "business-systems", "generative-ai", 3, Some("ssl"), WEB, "ChatGPT"),
    app!("anthropic-claude", "business-systems", "generative-ai", 3, Some("ssl"), WEB, "Claude"),
    app!("google-base", "general-internet", "internet-utility", 2, Some("ssl"), WEB, "Google search and core services"),
    // Fallbacks
    app!("unknown-tcp", "unknown", "unknown", 4, None, &[], "TCP traffic no signature matched"),
    app!("unknown-udp", "unknown", "unknown", 4, None, &[], "UDP traffic no signature matched"),
    app!("unknown-ip", "unknown", "unknown", 4, None, &[], "Other IP protocols"),
];

/// Host suffix → SaaS application. More specific suffixes first.
const SAAS: &[(&str, &str)] = &[
    ("drive.google.com", "google-drive"),
    ("mail.google.com", "gmail"),
    ("teams.microsoft.com", "ms-teams"),
    ("youtube.com", "youtube"),
    ("youtu.be", "youtube"),
    ("googlevideo.com", "youtube"),
    ("ytimg.com", "youtube"),
    ("netflix.com", "netflix"),
    ("nflxvideo.net", "netflix"),
    ("spotify.com", "spotify"),
    ("twitch.tv", "twitch"),
    ("tiktok.com", "tiktok"),
    ("tiktokcdn.com", "tiktok"),
    ("facebook.com", "facebook"),
    ("fbcdn.net", "facebook"),
    ("instagram.com", "instagram"),
    ("cdninstagram.com", "instagram"),
    ("twitter.com", "twitter"),
    ("x.com", "twitter"),
    ("twimg.com", "twitter"),
    ("linkedin.com", "linkedin"),
    ("licdn.com", "linkedin"),
    ("reddit.com", "reddit"),
    ("whatsapp.com", "whatsapp"),
    ("whatsapp.net", "whatsapp"),
    ("slack.com", "slack"),
    ("slack-edge.com", "slack"),
    ("zoom.us", "zoom"),
    ("office.com", "ms-office365"),
    ("office365.com", "ms-office365"),
    ("sharepoint.com", "ms-office365"),
    ("outlook.com", "ms-office365"),
    ("github.com", "github"),
    ("githubusercontent.com", "github"),
    ("dropbox.com", "dropbox"),
    ("dropboxusercontent.com", "dropbox"),
    ("chatgpt.com", "openai-chatgpt"),
    ("openai.com", "openai-chatgpt"),
    ("claude.ai", "anthropic-claude"),
    ("anthropic.com", "anthropic-claude"),
    ("google.com", "google-base"),
];

/// The built-in catalog as a text table, optionally narrowed by a name,
/// category or subcategory substring.
pub fn catalog_text(filter: Option<&str>) -> String {
    let mut out = format!("{:<18} {:<17} {:<20} {:<4} {:<13} {}\n", "name", "category", "subcategory", "risk", "depends-on", "description");
    for a in APPS {
        if let Some(f) = filter {
            if !(a.name.contains(f) || a.category.contains(f) || a.subcategory.contains(f)) {
                continue;
            }
        }
        out.push_str(&format!(
            "{:<18} {:<17} {:<20} {:<4} {:<13} {}\n",
            a.name,
            a.category,
            a.subcategory,
            a.risk,
            a.parent.unwrap_or("-"),
            a.description
        ));
    }
    out
}

pub fn info(name: &str) -> Option<&'static AppInfo> {
    APPS.iter().find(|a| a.name == name)
}

pub fn is_builtin(name: &str) -> bool {
    info(name).is_some()
}

/// Every category and subcategory name, for validating `category:<name>`.
pub fn is_category(name: &str) -> bool {
    APPS.iter().any(|a| a.category == name || a.subcategory == name)
}

pub fn in_category(app: &str, category: &str) -> bool {
    info(app).map_or(false, |a| a.category == category || a.subcategory == category)
}

/// Whether `(proto, port)` is a standard port for `app`. Applications with
/// dynamic ports accept any port.
pub fn default_port(app: &str, proto: u8, port: u16) -> bool {
    match info(app) {
        Some(a) if a.ports.is_empty() => !a.name.starts_with("unknown"),
        Some(a) => a.ports.iter().any(|(p, lo, hi)| p.matches(proto) && (*lo..=*hi).contains(&port)),
        None => false,
    }
}

pub fn saas_for_host(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    SAAS.iter()
        .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .map(|(_, app)| *app)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

/// Classify one complete payload (no more bytes are coming).
pub fn identify(proto: u8, payload: &[u8], dir: Dir) -> Option<&'static str> {
    match classify(proto, payload, dir, true) {
        Class::App(a) => Some(a),
        _ => None,
    }
}

/// Classify the bytes of one direction seen so far. With `last` the caller
/// has no more bytes to offer, so an incomplete message is classified as far
/// as it goes (a TLS hello without its SNI is plain `ssl`).
pub fn classify(proto: u8, buf: &[u8], dir: Dir, last: bool) -> Class {
    if buf.is_empty() {
        return if last { Class::NoMatch } else { Class::NeedMore };
    }
    if proto == 6 && dir == Dir::ClientToServer && !last && incomplete_client_message(buf) {
        return Class::NeedMore;
    }
    let found = match (proto, dir) {
        (6, Dir::ClientToServer) => tcp_client(buf),
        (6, Dir::ServerToClient) => tcp_server(buf),
        (17, _) => udp(buf),
        _ => None,
    };
    match found {
        Some(a) => Class::App(a),
        // A few bytes are not enough to rule anything out.
        None if proto == 6 && buf.len() < 8 && !last => Class::NeedMore,
        None => Class::NoMatch,
    }
}

/// A TLS ClientHello record or an HTTP request header that has started but
/// not finished.
fn incomplete_client_message(p: &[u8]) -> bool {
    if p.len() >= 5 && p[0] == 0x16 && p[1] == 0x03 {
        let record = 5 + usize::from(u16::from_be_bytes([p[3], p[4]]));
        return p.len() < record;
    }
    if p.len() < 5 && p[0] == 0x16 {
        return true; // a TLS record header still arriving
    }
    let http = HTTP_METHODS.iter().chain([&b"CONNECT "[..]].iter()).any(|m| {
        let n = m.len().min(p.len());
        p[..n] == m[..n]
    });
    http && !contains(p, b"\r\n\r\n")
}

/// ICMP is labelled from the header alone.
pub fn identify_icmp(icmp_type: Option<u8>) -> &'static str {
    match icmp_type {
        Some(0) | Some(8) => "ping",
        _ => "icmp",
    }
}

fn starts(p: &[u8], s: &[u8]) -> bool {
    p.len() >= s.len() && &p[..s.len()] == s
}

fn contains(p: &[u8], s: &[u8]) -> bool {
    p.windows(s.len()).any(|w| w == s)
}

fn contains_ci(p: &[u8], s: &[u8]) -> bool {
    p.windows(s.len()).any(|w| w.eq_ignore_ascii_case(s))
}

const HTTP_METHODS: &[&[u8]] = &[b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE "];

fn tcp_client(p: &[u8]) -> Option<&'static str> {
    if is_tls_client_hello(p) {
        let sni = crate::inspect::tls_sni(p);
        return Some(sni.as_deref().and_then(saas_for_host).unwrap_or("ssl"));
    }
    if starts(p, b"CONNECT ") && contains(p, b" HTTP/1.") {
        return Some("http-proxy");
    }
    if HTTP_METHODS.iter().any(|m| starts(p, m)) && contains(p, b" HTTP/1.") {
        let host = crate::inspect::http_host(p);
        return Some(host.as_deref().and_then(saas_for_host).unwrap_or("web-browsing"));
    }
    if starts(p, b"SSH-") {
        return Some("ssh");
    }
    if starts(p, b"\x13BitTorrent protocol") {
        return Some("bittorrent");
    }
    // NetBIOS session header + SMB1/SMB2 magic.
    if p.len() >= 8 && p[0] == 0 && (&p[4..8] == b"\xffSMB" || &p[4..8] == b"\xfeSMB") {
        return Some("ms-ds-smb");
    }
    // TPKT + X.224 connection request carrying an RDP cookie or negotiation.
    if p.len() >= 11 && p[0] == 3 && p[1] == 0 && p[5] == 0xe0 && (contains(p, b"mstshash=") || p.len() >= 19 && p[11] == 0x01) {
        return Some("ms-rdp");
    }
    if (starts(p, b"INVITE sip:") || starts(p, b"REGISTER sip:") || starts(p, b"OPTIONS sip:")) && contains(p, b"SIP/2.0") {
        return Some("sip");
    }
    // DNS over TCP: 2-byte length, then a DNS query.
    if p.len() >= 14 && usize::from(u16::from_be_bytes([p[0], p[1]])) == p.len() - 2 && is_dns_query(&p[2..]) {
        return Some("dns");
    }
    // PostgreSQL StartupMessage (protocol 3.0) or SSLRequest.
    if p.len() >= 8 {
        let code = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let len = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        if len == p.len() && (code == 0x0003_0000 || code == 80_877_103) {
            return Some("postgres");
        }
    }
    // MQTT CONNECT with the protocol name.
    if p.len() >= 10 && p[0] == 0x10 && contains(&p[..p.len().min(16)], b"MQTT") {
        return Some("mqtt");
    }
    // Redis RESP array of bulk strings.
    if p[0] == b'*' && contains(&p[..p.len().min(32)], b"\r\n$") {
        return Some("redis");
    }
    if starts(p, b"EHLO ") || starts(p, b"HELO ") {
        return Some("smtp");
    }
    if starts(p, b"USER ") || starts(p, b"AUTH TLS") {
        return Some("ftp");
    }
    if p.len() >= 3 && p[0] == 0xff && (0xfb..=0xfe).contains(&p[1]) {
        return Some("telnet");
    }
    None
}

fn tcp_server(p: &[u8]) -> Option<&'static str> {
    if starts(p, b"SSH-") {
        return Some("ssh");
    }
    if starts(p, b"220") {
        let head = &p[..p.len().min(128)];
        if contains_ci(head, b"FTP") {
            return Some("ftp");
        }
        if contains_ci(head, b"SMTP") || contains_ci(head, b"mail") {
            return Some("smtp");
        }
    }
    if starts(p, b"+OK") {
        return Some("pop3");
    }
    if starts(p, b"* OK") {
        return Some("imap");
    }
    // MySQL initial handshake: 3-byte length, sequence 0, protocol version 10.
    if p.len() > 6 && p[3] == 0 && p[4] == 0x0a && usize::from(p[0]) + usize::from(p[1]) * 256 + 4 == p.len() {
        return Some("mysql");
    }
    if p.len() >= 3 && p[0] == 0xff && (0xfb..=0xfe).contains(&p[1]) {
        return Some("telnet");
    }
    None
}

fn udp(p: &[u8]) -> Option<&'static str> {
    // QUIC long header: header form and fixed bits set, version 1 or 2.
    if p.len() >= 5 && p[0] & 0xc0 == 0xc0 {
        let v = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        if v == 1 || v == 0x6b33_43cf {
            return Some("quic");
        }
    }
    // STUN magic cookie.
    if p.len() >= 20 && p[4..8] == [0x21, 0x12, 0xa4, 0x42] {
        return Some("stun");
    }
    // WireGuard handshake initiation: type 1, three reserved zero bytes, 148 bytes.
    if p.len() == 148 && p[0] == 1 && p[1..4] == [0, 0, 0] {
        return Some("wireguard");
    }
    // DHCP: BOOTP request or reply with the magic cookie.
    if p.len() >= 240 && (p[0] == 1 || p[0] == 2) && p[236..240] == [0x63, 0x82, 0x53, 0x63] {
        return Some("dhcp");
    }
    // NTP: 48-byte header, version 3 or 4, client or server mode.
    if p.len() == 48 && matches!((p[0] >> 3) & 7, 3 | 4) && matches!(p[0] & 7, 3 | 4) {
        return Some("ntp");
    }
    // SNMP: SEQUENCE, INTEGER version 0-3.
    if p.len() >= 5 && p[0] == 0x30 && p[2] == 0x02 && p[3] == 0x01 && p[4] <= 3 {
        return Some("snmp");
    }
    if starts(p, b"d1:ad2:id20:") || starts(p, b"d1:rd2:id20:") {
        return Some("bittorrent");
    }
    if (starts(p, b"INVITE sip:") || starts(p, b"REGISTER sip:") || starts(p, b"OPTIONS sip:")) && contains(p, b"SIP/2.0") {
        return Some("sip");
    }
    if is_dns_query(p) || is_dns_response(p) {
        return Some("dns");
    }
    None
}

fn is_tls_client_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == 0x01
}

/// A plausible DNS query: standard opcode, one question, a well-formed name.
fn is_dns_query(p: &[u8]) -> bool {
    if p.len() < 17 {
        return false;
    }
    let flags = u16::from_be_bytes([p[2], p[3]]);
    let qd = u16::from_be_bytes([p[4], p[5]]);
    let an = u16::from_be_bytes([p[6], p[7]]);
    flags & 0x8000 == 0 && (flags >> 11) & 0xf == 0 && qd == 1 && an == 0 && dns_name_ok(p, 12)
}

fn is_dns_response(p: &[u8]) -> bool {
    if p.len() < 17 {
        return false;
    }
    let flags = u16::from_be_bytes([p[2], p[3]]);
    let qd = u16::from_be_bytes([p[4], p[5]]);
    flags & 0x8000 != 0 && (flags >> 11) & 0xf == 0 && qd == 1 && dns_name_ok(p, 12)
}

fn dns_name_ok(p: &[u8], mut i: usize) -> bool {
    let mut labels = 0;
    while i < p.len() {
        let len = usize::from(p[i]);
        if len == 0 {
            return labels > 0 && i + 5 <= p.len();
        }
        if len > 63 || i + 1 + len > p.len() {
            return false;
        }
        if !p[i + 1..i + 1 + len].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_') {
            return false;
        }
        labels += 1;
        i += 1 + len;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = vec![0x00, 0x00];
        let list_len = (name.len() + 3) as u16;
        sni_ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);
        let mut hs = vec![0x01, 0x00];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.extend_from_slice(&[0, 0, 1, 0, 1]);
        p
    }

    #[test]
    fn tls_is_ssl_or_the_saas_app_from_sni() {
        let c2s = Dir::ClientToServer;
        assert_eq!(identify(6, &client_hello("www.youtube.com"), c2s), Some("youtube"));
        assert_eq!(identify(6, &client_hello("teams.microsoft.com"), c2s), Some("ms-teams"));
        assert_eq!(identify(6, &client_hello("intranet.example"), c2s), Some("ssl"));
    }

    #[test]
    fn http_is_web_browsing_or_saas() {
        let c2s = Dir::ClientToServer;
        assert_eq!(identify(6, b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n", c2s), Some("web-browsing"));
        assert_eq!(identify(6, b"GET /feed HTTP/1.1\r\nHost: m.facebook.com\r\n\r\n", c2s), Some("facebook"));
        assert_eq!(identify(6, b"CONNECT a.example:443 HTTP/1.1\r\n\r\n", c2s), Some("http-proxy"));
    }

    #[test]
    fn port_does_not_decide() {
        // SSH on port 443 is still SSH; HTTP on 2222 is still web-browsing.
        assert_eq!(identify(6, b"SSH-2.0-OpenSSH_9.6\r\n", Dir::ClientToServer), Some("ssh"));
        assert_eq!(identify(6, b"GET / HTTP/1.0\r\n\r\n", Dir::ClientToServer), Some("web-browsing"));
    }

    #[test]
    fn server_first_protocols() {
        let s2c = Dir::ServerToClient;
        assert_eq!(identify(6, b"220 mail.example ESMTP Postfix\r\n", s2c), Some("smtp"));
        assert_eq!(identify(6, b"220 (vsFTPd 3.0.5)\r\n", s2c), Some("ftp"));
        assert_eq!(identify(6, b"+OK POP3 ready\r\n", s2c), Some("pop3"));
        assert_eq!(identify(6, b"* OK IMAP4rev1 ready\r\n", s2c), Some("imap"));
        let mut mysql = vec![0u8, 0, 0, 0, 0x0a];
        mysql.extend_from_slice(b"8.0.36\0rest");
        mysql[0] = (mysql.len() - 4) as u8;
        assert_eq!(identify(6, &mysql, s2c), Some("mysql"));
    }

    #[test]
    fn udp_protocols() {
        let c2s = Dir::ClientToServer;
        assert_eq!(identify(17, &dns_query("example.com"), c2s), Some("dns"));
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x23; // version 4, client mode
        assert_eq!(identify(17, &ntp, c2s), Some("ntp"));
        let quic = [0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4];
        assert_eq!(identify(17, &quic, c2s), Some("quic"));
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        assert_eq!(identify(17, &wg, c2s), Some("wireguard"));
        assert_eq!(identify(17, b"random bytes here", c2s), None);
    }

    #[test]
    fn other_tcp_signatures() {
        let c2s = Dir::ClientToServer;
        assert_eq!(identify(6, b"\x13BitTorrent protocol\0\0\0\0\0\0\0\0", c2s), Some("bittorrent"));
        assert_eq!(identify(6, b"\0\0\0\x54\xfeSMB@\0\0\0", c2s), Some("ms-ds-smb"));
        assert_eq!(identify(6, b"\x03\0\0\x2b\x26\xe0\0\0\0\0\0Cookie: mstshash=a\r\n", c2s), Some("ms-rdp"));
        assert_eq!(identify(6, b"*1\r\n$4\r\nPING\r\n", c2s), Some("redis"));
        assert_eq!(identify(6, b"\0\0\0\x08\x04\xd2\x16\x2f", c2s), Some("postgres"));
        assert_eq!(identify(6, b"random text", c2s), None);
    }

    #[test]
    fn categories_and_default_ports() {
        assert!(in_category("facebook", "social-networking"));
        assert!(in_category("youtube", "media"));
        assert!(is_category("generative-ai"));
        assert!(default_port("ssl", 6, 443));
        assert!(!default_port("ssl", 6, 8443));
        assert!(default_port("bittorrent", 6, 51413), "dynamic ports");
        assert!(!default_port("unknown-tcp", 6, 1));
    }

    #[test]
    fn split_client_hello_waits_for_the_rest() {
        let hello = client_hello("www.github.com");
        let c2s = Dir::ClientToServer;
        assert_eq!(classify(6, &hello[..40], c2s, false), Class::NeedMore, "SNI not seen yet");
        assert_eq!(classify(6, &hello[..40], c2s, true), Class::App("ssl"), "best effort at the end");
        assert_eq!(classify(6, &hello, c2s, false), Class::App("github"));
        let get = b"GET / HTTP/1.1\r\nHost: www.reddit.com\r\n\r\n";
        assert_eq!(classify(6, &get[..20], c2s, false), Class::NeedMore);
        assert_eq!(classify(6, get, c2s, false), Class::App("reddit"));
        assert_eq!(classify(6, b"GE", c2s, false), Class::NeedMore);
        assert_eq!(classify(6, b"definitely not a protocol", c2s, false), Class::NoMatch);
    }

    #[test]
    fn catalog_is_consistent() {
        for a in APPS {
            if let Some(parent) = a.parent {
                assert!(info(parent).is_some(), "{} has unknown parent {parent}", a.name);
            }
            assert!((1..=5).contains(&a.risk));
        }
        for (_, app) in SAAS {
            assert!(info(app).is_some(), "SaaS host maps to unknown app {app}");
        }
    }
}
