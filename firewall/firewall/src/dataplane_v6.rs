//! IPv6 forwarding path.
//!
//! Uses the same policy engine, zones, default rules, App-ID, security
//! profiles and TCP state machine as IPv4. IPv6-specific parts:
//!
//! - extension headers (hop-by-hop, routing, destination options) are walked
//!   to find the upper layer; fragments are dropped, as for IPv4;
//! - Neighbor Discovery replaces ARP: Neighbor Solicitations for our
//!   addresses are answered, neighbors are learned from NS/NA options, and a
//!   cache miss sends an NS to the solicited-node multicast group. NDP
//!   messages must arrive with hop limit 255 (RFC 4861);
//! - each interface has a link-local address derived from its MAC (EUI-64)
//!   besides its configured `address6`;
//! - ICMPv6 echo to our addresses is answered; Time Exceeded, Destination
//!   Unreachable and TCP RST are sent like their IPv4 counterparts.
//!
//! - zone flood limits (SYN, UDP, ICMP echo) share the IPv4 counters;
//! - User-ID maps IPv4 sources only, so user-scoped rules fail closed for
//!   IPv6: a user-scoped deny applies to every IPv6 source and a user-scoped
//!   permit never matches one (see `Config::user_matches_ip`).
//!
//! Not implemented for IPv6: NAT66/NPTv6, DNAT, User-ID mappings, HA session
//! sync and IPv6 inside WireGuard.

use super::*;
use crate::packet::{add_bytes, fold_checksum};
use std::net::{IpAddr, Ipv6Addr};

pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const PROTO_ICMPV6: u8 = 58;
const ND_NS: u8 = 135;
const ND_NA: u8 = 136;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key6 {
    pub vdom: String,
    pub proto: u8,
    pub src: Ipv6Addr,
    pub sport: u16,
    pub dst: Ipv6Addr,
    pub dport: u16,
}

impl Key6 {
    fn reversed(&self) -> Key6 {
        Key6 { vdom: self.vdom.clone(), proto: self.proto, src: self.dst, sport: self.dport, dst: self.src, dport: self.sport }
    }
}

#[derive(Clone, Debug)]
pub struct Session6 {
    pub key: Key6,
    pub tcp: TcpState,
    pub fin_orig: bool,
    pub fin_reply: bool,
    pub in_slot: usize,
    pub out_slot: usize,
    pub policy_id: u32,
    pub app: Option<String>,
    pub app_tries: u8,
    buf: [Vec<u8>; 2],
    seq: [Option<u32>; 2],
    pub expires: Instant,
    pub src_zone: String,
    pub dst_zone: String,
    /// Configuration revision the policy decision was last checked against
    /// (see `Engine::session_still_permitted`).
    pub rev: u64,
}

#[derive(Default)]
pub struct Sessions6 {
    forward: HashMap<Key6, Session6>,
    reverse: HashMap<Key6, Key6>,
}

impl Sessions6 {
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// The flow a packet belongs to and whether it travels in the reply direction.
    fn lookup(&self, key: &Key6, now: Instant) -> Option<(Key6, bool)> {
        if let Some(s) = self.forward.get(key) {
            return (s.expires > now).then(|| (key.clone(), false));
        }
        let fwd = self.reverse.get(key)?;
        let s = self.forward.get(fwd)?;
        (s.expires > now).then(|| (fwd.clone(), true))
    }

    fn insert(&mut self, s: Session6) {
        self.reverse.insert(s.key.reversed(), s.key.clone());
        self.forward.insert(s.key.clone(), s);
    }

    pub fn purge(&mut self, now: Instant) {
        let dead: Vec<Key6> = self.forward.iter().filter(|(_, s)| s.expires <= now).map(|(k, _)| k.clone()).collect();
        for k in dead {
            self.reverse.remove(&k.reversed());
            self.forward.remove(&k);
        }
    }

    pub fn snapshot(&self) -> Vec<Session6> {
        self.forward.values().cloned().collect()
    }

    fn get_mut(&mut self, k: &Key6) -> Option<&mut Session6> {
        self.forward.get_mut(k)
    }

    /// Append in-order TCP bytes (or a whole datagram) to the App-ID buffer.
    fn feed(&mut self, k: &Key6, from_client: bool, seq: Option<u32>, payload: &[u8]) -> (Vec<u8>, bool) {
        let cap = crate::appid::MAX_BUFFER;
        let Some(s) = self.forward.get_mut(k) else { return (payload.to_vec(), true) };
        let d = usize::from(!from_client);
        let buf = &mut s.buf[d];
        match (seq, s.seq[d]) {
            (None, _) => {
                buf.clear();
                buf.extend_from_slice(&payload[..payload.len().min(cap)]);
            }
            (Some(seq), None) => {
                buf.extend_from_slice(payload);
                s.seq[d] = Some(seq.wrapping_add(payload.len() as u32));
            }
            (Some(seq), Some(next)) => {
                let ahead = seq.wrapping_sub(next) as i32;
                if ahead == 0 {
                    buf.extend_from_slice(payload);
                    s.seq[d] = Some(next.wrapping_add(payload.len() as u32));
                } else if ahead < 0 {
                    let overlap = (-(ahead as i64)) as usize;
                    if overlap < payload.len() {
                        buf.extend_from_slice(&payload[overlap..]);
                        s.seq[d] = Some(seq.wrapping_add(payload.len() as u32));
                    }
                }
            }
        }
        buf.truncate(cap);
        (buf.clone(), buf.len() >= cap)
    }
}

/// Parsed IPv6 header with the upper-layer protocol located.
struct View {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    hop_limit: u8,
    /// Offset of the upper-layer header from the start of the IPv6 header.
    l4: usize,
    total: usize,
}

fn parse(p: &[u8]) -> Result<View, &'static str> {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return Err("malformed");
    }
    let total = 40 + usize::from(u16::from_be_bytes([p[4], p[5]]));
    if total > p.len() {
        return Err("truncated");
    }
    let mut next = p[6];
    let mut off = 40;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if off + 8 > total {
                    return Err("malformed extension header");
                }
                next = p[off];
                off += (usize::from(p[off + 1]) + 1) * 8;
                if off > total {
                    return Err("malformed extension header");
                }
            }
            44 => return Err("fragment (reassembly not supported)"),
            _ => break,
        }
    }
    let addr = |o: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&p[o..o + 16]).expect("16 bytes"));
    Ok(View { src: addr(8), dst: addr(24), proto: next, hop_limit: p[7], l4: off, total })
}

/// Internet checksum over the IPv6 pseudo-header and `data`. Zero means a
/// received packet (checksum field included) is valid.
pub fn checksum6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, data: &[u8]) -> u16 {
    let mut sum = add_bytes(0, &src.octets());
    sum = add_bytes(sum, &dst.octets());
    sum = add_bytes(sum, &(data.len() as u32).to_be_bytes());
    sum = add_bytes(sum, &[0, 0, 0, proto]);
    sum = add_bytes(sum, data);
    fold_checksum(sum)
}

/// Link-local address from a MAC (modified EUI-64).
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]])
}

fn solicited_node(target: Ipv6Addr) -> (Ipv6Addr, [u8; 6]) {
    let t = target.octets();
    let ip = Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, t[13], t[14], t[15]]);
    (ip, [0x33, 0x33, 0xff, t[13], t[14], t[15]])
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// An IPv6 packet with a correct upper-layer checksum (checksum at `ck_off`
/// within `l4`, or none).
pub(crate) fn build(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, hop: u8, mut l4: Vec<u8>, ck_off: Option<usize>) -> Vec<u8> {
    if let Some(o) = ck_off {
        l4[o] = 0;
        l4[o + 1] = 0;
        let ck = checksum6(src, dst, proto, &l4);
        l4[o..o + 2].copy_from_slice(&ck.to_be_bytes());
    }
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    p.push(proto);
    p.push(hop);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&l4);
    p
}

enum AppV6<'c> {
    Pending,
    Allowed(&'c crate::model::Policy),
    Denied(&'c crate::model::Policy, String),
}

impl Engine {
    /// Our addresses on one interface: configured global and derived link-local.
    fn addrs6(&self, cfg: &Config, slot: usize) -> Vec<Ipv6Addr> {
        let iface = &self.ifaces[slot];
        let mut v = vec![link_local(iface.mac)];
        if let Some(a) = cfg.interfaces.iter().find(|i| i.name == iface.name).and_then(|i| i.address6) {
            v.push(a.addr);
        }
        v
    }

    fn is_local6(&self, cfg: &Config, vdom: &str, ip: Ipv6Addr) -> bool {
        self.ifaces.iter().enumerate().any(|(slot, i)| i.vdom == vdom && self.addrs6(cfg, slot).contains(&ip))
    }

    /// Source address for messages we originate on `slot`, matching scope.
    fn source6(&self, cfg: &Config, slot: usize, towards: Ipv6Addr) -> Ipv6Addr {
        let addrs = self.addrs6(cfg, slot);
        if is_link_local(towards) || addrs.len() == 1 { addrs[0] } else { addrs[1] }
    }

    pub fn nd_lookup(&self, vdom: &str, ip: Ipv6Addr) -> Option<[u8; 6]> {
        self.nd.lock().unwrap().get(&(vdom.to_string(), ip)).filter(|(_, seen)| seen.elapsed() < ARP_TTL).map(|(m, _)| *m)
    }

    fn nd_learn(&self, vdom: &str, ip: Ipv6Addr, mac: [u8; 6]) {
        if ip.is_unspecified() || ip.is_multicast() {
            return;
        }
        let mut nd = self.nd.lock().unwrap();
        if nd.len() < 16_384 || nd.contains_key(&(vdom.to_string(), ip)) {
            nd.insert((vdom.to_string(), ip), (mac, Instant::now()));
        }
    }

    fn send6(&self, slot: usize, dst_mac: [u8; 6], packet: &[u8]) {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + packet.len());
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&self.ifaces[slot].mac);
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend_from_slice(packet);
        self.send(slot, &frame);
    }

    fn send_ns(&self, cfg: &Config, slot: usize, target: Ipv6Addr) {
        let (group, mac) = solicited_node(target);
        let mut l4 = vec![ND_NS, 0, 0, 0, 0, 0, 0, 0];
        l4.extend_from_slice(&target.octets());
        l4.extend_from_slice(&[1, 1]);
        l4.extend_from_slice(&self.ifaces[slot].mac);
        let src = self.source6(cfg, slot, target);
        self.send6(slot, mac, &build(src, group, PROTO_ICMPV6, 255, l4, Some(2)));
    }

    fn on_ndp(&self, cfg: &Config, slot: usize, src_mac: [u8; 6], v: &View, pkt: &[u8]) {
        let icmp = &pkt[v.l4..v.total];
        if v.hop_limit != 255 || icmp.len() < 24 || icmp[1] != 0 {
            return; // RFC 4861: NDP must not have crossed a router
        }
        let vdom = self.ifaces[slot].vdom.clone();
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).expect("16 bytes"));
        // Link-layer address options (1 = source, 2 = target).
        let mut lladdr = None;
        let mut o = 24;
        while o + 8 <= icmp.len() {
            let (kind, len) = (icmp[o], usize::from(icmp[o + 1]) * 8);
            if len == 0 || o + len > icmp.len() {
                break;
            }
            if (kind == 1 || kind == 2) && len >= 8 {
                lladdr = Some(read_mac(icmp, o + 2));
            }
            o += len;
        }
        match icmp[0] {
            ND_NS => {
                if !v.src.is_unspecified() {
                    self.nd_learn(&vdom, v.src, lladdr.unwrap_or(src_mac));
                }
                if !self.addrs6(cfg, slot).contains(&target) {
                    return;
                }
                let solicited = !v.src.is_unspecified();
                let flags = 0x80 | if solicited { 0x40 } else { 0 } | 0x20; // router, solicited, override
                let mut l4 = vec![ND_NA, 0, 0, 0, flags, 0, 0, 0];
                l4.extend_from_slice(&target.octets());
                l4.extend_from_slice(&[2, 1]);
                l4.extend_from_slice(&self.ifaces[slot].mac);
                let (dst, dst_mac) = if solicited {
                    (v.src, lladdr.unwrap_or(src_mac))
                } else {
                    ("ff02::1".parse().expect("all-nodes"), [0x33, 0x33, 0, 0, 0, 1])
                };
                self.send6(slot, dst_mac, &build(target, dst, PROTO_ICMPV6, 255, l4, Some(2)));
            }
            ND_NA => self.nd_learn(&vdom, target, lladdr.unwrap_or(src_mac)),
            _ => {}
        }
    }

    /// ICMPv6 error about `orig` back to its sender on the ingress interface.
    fn icmp6_error(&self, cfg: &Config, slot: usize, src_mac: [u8; 6], orig: &[u8], kind: u8, code: u8) {
        if self.flood_exceeded(&self.ifaces[slot].zone, "icmp6-error", 100) || orig.len() < 40 {
            return;
        }
        let to = Ipv6Addr::from(<[u8; 16]>::try_from(&orig[8..24]).expect("16 bytes"));
        let mut l4 = vec![kind, code, 0, 0, 0, 0, 0, 0];
        l4.extend_from_slice(&orig[..orig.len().min(1232)]);
        let src = self.source6(cfg, slot, to);
        self.send6(slot, src_mac, &build(src, to, PROTO_ICMPV6, 64, l4, Some(2)));
    }

    /// TCP RST answering `pkt`, as the destination would.
    fn tcp_rst6(&self, slot: usize, src_mac: [u8; 6], v: &View, pkt: &[u8]) {
        let t = &pkt[v.l4..v.total];
        if t.len() < 20 {
            return;
        }
        let flags = t[13];
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
        let data = t.len() - usize::from(t[12] >> 4) * 4;
        let mut l4 = vec![0u8; 20];
        l4[0..2].copy_from_slice(&t[2..4]);
        l4[2..4].copy_from_slice(&t[0..2]);
        if flags & TCP_ACK != 0 {
            l4[4..8].copy_from_slice(&ack.to_be_bytes());
            l4[13] = TCP_RST;
        } else {
            let a = seq.wrapping_add(data as u32).wrapping_add(u32::from(flags & TCP_SYN != 0));
            l4[8..12].copy_from_slice(&a.to_be_bytes());
            l4[13] = TCP_RST | TCP_ACK;
        }
        l4[12] = 0x50;
        self.send6(slot, src_mac, &build(v.dst, v.src, PROTO_TCP, 64, l4, Some(16)));
    }

    /// IPv6 counterpart of `Engine::session_still_permitted`.
    fn session6_still_permitted(&self, cfg: &Config, s: &Session6) -> bool {
        let rev = self.config_revision();
        if s.rev == rev {
            return true;
        }
        let ok = cfg
            .match_or_default_ip(
                &s.key.vdom,
                &s.src_zone,
                &s.dst_zone,
                IpAddr::V6(s.key.src),
                IpAddr::V6(s.key.dst),
                s.key.proto,
                s.key.dport,
                s.app.as_deref(),
                None,
            )
            .is_some_and(|p| p.id == s.policy_id && p.action == Action::Permit);
        if ok {
            if let Some(x) = self.sessions6.lock().unwrap().get_mut(&s.key) {
                x.rev = rev;
            }
        }
        ok
    }

    fn app_verdict6<'c>(&self, cfg: &'c Config, s: &Session6, from_client: bool, seq: Option<u32>, payload: &[u8]) -> AppV6<'c> {
        let mut table = self.sessions6.lock().unwrap();
        let (buf, full) = table.feed(&s.key, from_client, seq, payload);
        let tries = table.get_mut(&s.key).map(|x| {
            x.app_tries = x.app_tries.saturating_add(1);
            x.app_tries
        });
        let last = full || tries.unwrap_or(u8::MAX) >= crate::appid::MAX_TRIES;
        let dir = if from_client { crate::appid::Dir::ClientToServer } else { crate::appid::Dir::ServerToClient };
        let app = match crate::appid::classify(s.key.proto, &buf, dir, last) {
            crate::appid::Class::App(a) => a,
            _ if !last => return AppV6::Pending,
            _ if s.key.proto == PROTO_TCP => crate::appid::UNKNOWN_TCP,
            _ => crate::appid::UNKNOWN_UDP,
        };
        let next = cfg.match_or_default_ip(
            &s.key.vdom,
            &s.src_zone,
            &s.dst_zone,
            IpAddr::V6(s.key.src),
            IpAddr::V6(s.key.dst),
            s.key.proto,
            s.key.dport,
            Some(app),
            None,
        );
        let Some(x) = table.get_mut(&s.key) else { return AppV6::Pending };
        x.app = Some(app.to_string());
        x.buf = [Vec::new(), Vec::new()];
        match next {
            Some(p) if p.action == Action::Permit => {
                x.policy_id = p.id;
                AppV6::Allowed(p)
            }
            Some(p) => {
                x.policy_id = p.id;
                x.expires = Instant::now();
                AppV6::Denied(p, app.to_string())
            }
            None => AppV6::Pending,
        }
    }

    fn drop6(&self, slot: usize) {
        self.stats.lock().unwrap().denied += 1;
        self.stats_bump(slot, |s| s.dropped += 1);
    }

    pub(super) fn handle_ipv6(&self, slot: usize, frame: &mut [u8]) {
        let l3 = ETH_HEADER_LEN;
        let src_mac = read_mac(frame, 6);
        let v = match parse(&frame[l3..]) {
            Ok(v) => v,
            Err(reason) => {
                self.stats_bump(slot, |s| s.dropped += 1);
                if reason.starts_with("fragment") {
                    let cfg = self.cfg.read().unwrap();
                    self.log_event(&cfg, "deny", Ipv6Addr::UNSPECIFIED, 0, Ipv6Addr::UNSPECIFIED, 0, 44, &self.ifaces[slot].zone, "", None, reason);
                }
                return;
            }
        };
        let cfg_guard = self.cfg.read().unwrap();
        let cfg: &Config = &cfg_guard;
        let pkt = frame[l3..l3 + v.total].to_vec();
        let in_iface = &self.ifaces[slot];
        let vdom = in_iface.vdom.clone();
        let in_zone = cfg.interfaces.iter().find(|i| i.name == in_iface.name).map(|i| i.zone.clone()).unwrap_or_else(|| in_iface.zone.clone());
        let proto = v.proto;
        let l4 = &pkt[v.l4..v.total];

        if matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_ICMPV6) && checksum6(v.src, v.dst, proto, l4) != 0 {
            self.stats.lock().unwrap().errors += 1;
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        if proto == PROTO_ICMPV6 && l4.len() >= 4 {
            match l4[0] {
                ND_NS | ND_NA => return self.on_ndp(cfg, slot, src_mac, &v, &pkt),
                133 | 134 | 137 => return, // router solicitation/advertisement, redirect
                _ => {}
            }
        }
        let martian = v.src.is_multicast() || v.src.is_unspecified() || v.src.is_loopback() || v.dst.is_loopback() || v.dst.is_unspecified();
        if martian {
            self.log_event(cfg, "deny", v.src, 0, v.dst, 0, proto, &in_zone, "", None, "martian-address");
            return self.drop6(slot);
        }
        if self.is_local6(cfg, &vdom, v.dst) {
            if proto == PROTO_ICMPV6 && l4.len() >= 8 && l4[0] == 128 {
                let mut reply = l4.to_vec();
                reply[0] = 129;
                self.send6(slot, src_mac, &build(v.dst, v.src, PROTO_ICMPV6, 64, reply, Some(2)));
            }
            return;
        }
        if v.dst.is_multicast() || is_link_local(v.dst) || is_link_local(v.src) {
            return self.stats_bump(slot, |s| s.dropped += 1); // not routed
        }

        let (sport, dport) = match proto {
            PROTO_TCP | PROTO_UDP if l4.len() >= 8 => (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]])),
            PROTO_ICMPV6 if l4.len() >= 8 && matches!(l4[0], 128 | 129) => {
                let id = u16::from_be_bytes([l4[4], l4[5]]);
                (id, id)
            }
            _ => (0, 0),
        };
        let tcp_flags = (proto == PROTO_TCP && l4.len() >= 20).then(|| l4[13]);
        let payload: &[u8] = match proto {
            PROTO_TCP if l4.len() >= 20 => &l4[(usize::from(l4[12] >> 4) * 4).min(l4.len())..],
            PROTO_UDP if l4.len() >= 8 => &l4[8..],
            _ => &[],
        };
        let seq = (proto == PROTO_TCP && l4.len() >= 8).then(|| u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]));
        if let Some(f) = tcp_flags {
            if !tcp_flags_sane(f) {
                self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", None, "invalid-tcp-flags");
                return self.drop6(slot);
            }
        }
        let key = Key6 { vdom: vdom.clone(), proto, src: v.src, sport, dst: v.dst, dport };
        let now = Instant::now();
        let found = self.sessions6.lock().unwrap().lookup(&key, now);

        let out_slot = match found {
            Some((fkey, reply)) => {
                let s = match self.sessions6.lock().unwrap().forward.get(&fkey) {
                    Some(s) => s.clone(),
                    None => return,
                };
                let Some(mut policy) = cfg
                    .policy_by_id(&vdom, s.policy_id)
                    .filter(|p| p.enabled && p.action == Action::Permit && self.session6_still_permitted(cfg, &s))
                else {
                    if let Some(x) = self.sessions6.lock().unwrap().get_mut(&fkey) {
                        x.expires = now;
                    }
                    self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", Some(s.policy_id), "policy-withdrawn");
                    return self.drop6(slot);
                };
                if let Some(flags) = tcp_flags {
                    let mut table = self.sessions6.lock().unwrap();
                    let Some(x) = table.get_mut(&fkey) else { return };
                    if !tcp_step(&mut x.tcp, &mut x.fin_orig, &mut x.fin_reply, !reply, flags) {
                        drop(table);
                        self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", Some(s.policy_id), "invalid tcp state");
                        return self.drop6(slot);
                    }
                    let secs = match x.tcp {
                        TcpState::Established => cfg.settings.tcp_timeout,
                        TcpState::Closed | TcpState::TimeWait => 10,
                        _ => cfg.settings.tcp_timeout.min(60),
                    };
                    x.expires = now + Duration::from_secs(secs);
                } else if let Some(x) = self.sessions6.lock().unwrap().get_mut(&fkey) {
                    x.expires = now + Duration::from_secs(timeout_for(proto, cfg));
                }
                if s.app.is_none() && !payload.is_empty() {
                    match self.app_verdict6(cfg, &s, !reply, seq, payload) {
                        AppV6::Pending => {}
                        AppV6::Allowed(p) => policy = p,
                        AppV6::Denied(p, app) => {
                            self.bump_hit(&vdom, p.id, v.total as u64);
                            let reason = format!("app {app}: {} {}", Config::policy_label(p), p.action.as_str());
                            self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", Some(p.id), &reason);
                            if p.action == Action::Reject && proto == PROTO_TCP && !reply {
                                self.tcp_rst6(slot, src_mac, &v, &pkt);
                            }
                            return self.drop6(slot);
                        }
                    }
                }
                if let Some(reason) = security_drop_payload(cfg, policy, payload) {
                    self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", Some(policy.id), &reason);
                    return self.drop6(slot);
                }
                self.bump_hit(&vdom, policy.id, v.total as u64);
                if reply { s.in_slot } else { s.out_slot }
            }
            None => {
                if let Some(f) = tcp_flags {
                    if f & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) != TCP_SYN {
                        self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, "", None, "invalid: no session and not a SYN");
                        return self.drop6(slot);
                    }
                }
                let Some((egress, _)) = cfg.egress6(&vdom, v.dst) else {
                    self.log_event(cfg, "drop", v.src, sport, v.dst, dport, proto, &in_zone, "", None, "no route");
                    self.icmp6_error(cfg, slot, src_mac, &pkt, 1, 0);
                    return self.drop6(slot);
                };
                let Some(egress_slot) = self.iface_slot(&egress.name) else { return self.drop6(slot) };
                // Zone protection, sharing the IPv4 counters so a zone's limit
                // covers both families instead of doubling over IPv6.
                if let Some(zone) = cfg.zone(&in_zone, &vdom) {
                    let flood = if proto == PROTO_TCP {
                        zone.syn_flood.map(|limit| ("syn", self.flood_exceeded(&zone.name, "syn", limit)))
                    } else if proto == PROTO_ICMPV6 && l4.first() == Some(&128) {
                        zone.icmp_flood.map(|limit| ("icmp", self.flood_exceeded(&zone.name, "icmp", limit)))
                    } else if proto == PROTO_UDP {
                        zone.udp_flood.map(|limit| ("udp", self.flood_exceeded(&zone.name, "udp", limit)))
                    } else {
                        None
                    };
                    if let Some((kind, true)) = flood {
                        let reason = format!("zone-protection {kind}-flood");
                        self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, &egress.zone, None, &reason);
                        self.stats.lock().unwrap().denied += 1;
                        return self.drop6(slot);
                    }
                }
                let app0: Option<String> = match proto {
                    PROTO_ICMPV6 => Some(if matches!(l4.first(), Some(128 | 129)) { "ping" } else { "icmp" }.to_string()),
                    PROTO_TCP | PROTO_UDP => cfg
                        .custom_app_for(proto, dport)
                        .map(str::to_string)
                        .or_else(|| crate::appid::identify(proto, payload, crate::appid::Dir::ClientToServer).map(str::to_string))
                        .or_else(|| (proto == PROTO_UDP).then(|| crate::appid::UNKNOWN_UDP.to_string())),
                    _ => Some(crate::appid::UNKNOWN_IP.to_string()),
                };
                let Some(policy) = cfg.match_or_default_ip(
                    &vdom,
                    &in_zone,
                    &egress.zone,
                    IpAddr::V6(v.src),
                    IpAddr::V6(v.dst),
                    proto,
                    dport,
                    app0.as_deref(),
                    None,
                ) else {
                    return self.drop6(slot);
                };
                let named = |p: &crate::model::Policy| {
                    if crate::model::is_default_rule_id(p.id) { p.name.clone().unwrap_or_default() } else { String::new() }
                };
                if policy.action != Action::Permit {
                    self.bump_hit(&vdom, policy.id, v.total as u64);
                    if policy.action == Action::Reject {
                        if proto == PROTO_TCP {
                            self.tcp_rst6(slot, src_mac, &v, &pkt);
                        } else {
                            self.icmp6_error(cfg, slot, src_mac, &pkt, 1, 1);
                        }
                    }
                    let id = (!crate::model::is_default_rule_id(policy.id)).then_some(policy.id);
                    self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, &egress.zone, id, &named(policy));
                    return self.drop6(slot);
                }
                if let Some(reason) = security_drop_payload(cfg, policy, payload) {
                    self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, &egress.zone, Some(policy.id), &reason);
                    return self.drop6(slot);
                }
                let max = cfg.settings.max_sessions;
                if max > 0 && self.sessions6.lock().unwrap().len() + self.sessions.lock().unwrap().len() >= max {
                    self.log_event(cfg, "deny", v.src, sport, v.dst, dport, proto, &in_zone, &egress.zone, Some(policy.id), "session-table-full");
                    return self.drop6(slot);
                }
                let timeout = if proto == PROTO_TCP { cfg.settings.tcp_timeout.min(60) } else { timeout_for(proto, cfg) };
                self.sessions6.lock().unwrap().insert(Session6 {
                    key,
                    tcp: if proto == PROTO_TCP { TcpState::SynSent } else { TcpState::Established },
                    fin_orig: false,
                    fin_reply: false,
                    in_slot: slot,
                    out_slot: egress_slot,
                    policy_id: policy.id,
                    app: app0,
                    app_tries: 0,
                    buf: [Vec::new(), Vec::new()],
                    seq: [None, None],
                    expires: now + Duration::from_secs(timeout),
                    src_zone: in_zone.clone(),
                    dst_zone: egress.zone.clone(),
                    rev: self.config_revision(),
                });
                self.stats.lock().unwrap().accepted += 1;
                self.bump_hit(&vdom, policy.id, v.total as u64);
                self.log_event(cfg, "permit", v.src, sport, v.dst, dport, proto, &in_zone, &egress.zone, Some(policy.id), &named(policy));
                egress_slot
            }
        };

        // Forward.
        if v.hop_limit <= 1 {
            self.icmp6_error(cfg, slot, src_mac, &pkt, 3, 0);
            return self.stats_bump(slot, |s| s.dropped += 1);
        }
        let Some(out) = self.ifaces.get(out_slot) else { return };
        if out.tunnel {
            self.log_event(cfg, "drop", v.src, sport, v.dst, dport, proto, &in_zone, &out.zone, None, "IPv6 over WireGuard is not supported");
            return self.stats_bump(slot, |s| s.dropped += 1);
        }
        if out.fd < 0 && !cfg!(test) {
            return self.stats_bump(slot, |s| s.dropped += 1);
        }
        let next_hop = cfg.egress6(&vdom, v.dst).map(|(_, h)| h).unwrap_or(v.dst);
        let Some(next_mac) = self.nd_lookup(&vdom, next_hop) else {
            self.stats.lock().unwrap().arp_misses += 1;
            self.send_ns(cfg, out_slot, next_hop);
            return self.stats_bump(slot, |s| s.dropped += 1);
        };
        frame[l3 + 7] -= 1;
        write_mac(frame, 0, next_mac);
        write_mac(frame, 6, out.mac);
        self.send(out_slot, &frame[..l3 + v.total]);
    }
}
