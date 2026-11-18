//! The forwarding engine: AF_PACKET sockets, ARP resolution, policy
//! evaluation, a small stateful connection table and source NAT.

use crate::model::{Action, Cidr, Config, Interface};
use crate::packet::{
    build_arp, build_icmp_error, build_tcp_rst, ethertype, icmp_identity, parse_arp, read_mac,
    read_u32, write_mac, Ipv4, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETH_HEADER_LEN, PROTO_ICMP,
    PROTO_TCP, PROTO_UDP,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const ARP_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SessionKey {
    pub vdom: String,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
}

impl fmt::Display for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {}:{} -> {}:{}",
            self.vdom, self.proto, self.src, self.sport, self.dst, self.dport
        )
    }
}

/// Connection state of a tracked TCP flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    SynRecv,
    Established,
    Closing,
    TimeWait,
    Closed,
}

impl TcpState {
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::Established => "ESTABLISHED",
            TcpState::Closing => "CLOSING",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Closed => "CLOSED",
        }
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Reject TCP flag combinations that no sane stack sends (null scan,
/// SYN+FIN, SYN+RST, FIN+RST).
pub fn tcp_flags_sane(flags: u8) -> bool {
    let syn = flags & TCP_SYN != 0;
    let fin = flags & TCP_FIN != 0;
    let rst = flags & TCP_RST != 0;
    flags & (TCP_FIN | TCP_SYN | TCP_RST | TCP_ACK) != 0
        && !(syn && fin)
        && !(syn && rst)
        && !(fin && rst)
}

/// Advance the TCP state machine for one packet. `from_orig` is true for the
/// direction that opened the flow. Returns false when the packet is not valid
/// in the current state; the caller must drop it. Sequence numbers are not
/// tracked, so in-window checks are not performed.
pub fn tcp_track(s: &mut Session, from_orig: bool, flags: u8) -> bool {
    tcp_step(&mut s.tcp, &mut s.fin_orig, &mut s.fin_reply, from_orig, flags)
}

/// The TCP state machine on bare fields, shared by IPv4 and IPv6 sessions.
pub fn tcp_step(tcp: &mut TcpState, fin_orig: &mut bool, fin_reply: &mut bool, from_orig: bool, flags: u8) -> bool {
    if flags & TCP_RST != 0 {
        *tcp = TcpState::Closed;
        return true;
    }
    let syn = flags & TCP_SYN != 0;
    let ack = flags & TCP_ACK != 0;
    match *tcp {
        TcpState::SynSent => {
            if from_orig {
                syn && !ack
            } else if syn && ack {
                *tcp = TcpState::SynRecv;
                true
            } else {
                false
            }
        }
        TcpState::SynRecv => {
            if from_orig {
                if syn && !ack {
                    true
                } else if !syn && ack {
                    *tcp = TcpState::Established;
                    true
                } else {
                    false
                }
            } else {
                syn && ack
            }
        }
        TcpState::Established | TcpState::Closing => {
            if syn {
                return false;
            }
            if flags & TCP_FIN != 0 {
                if from_orig {
                    *fin_orig = true;
                } else {
                    *fin_reply = true;
                }
                *tcp = if *fin_orig && *fin_reply {
                    TcpState::TimeWait
                } else {
                    TcpState::Closing
                };
            }
            true
        }
        TcpState::TimeWait | TcpState::Closed => {
            if from_orig && syn && !ack {
                // Port reuse: a fresh SYN from the original side re-opens the flow.
                *tcp = TcpState::SynSent;
                *fin_orig = false;
                *fin_reply = false;
                true
            } else {
                *tcp != TcpState::Closed && !syn
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub key: SessionKey,
    pub tcp: TcpState,
    pub fin_orig: bool,
    pub fin_reply: bool,
    pub in_index: i32,
    pub out_index: i32,
    pub nat_src: Option<(Ipv4Addr, u16)>,
    pub nat_dst: Option<(Ipv4Addr, u16)>,
    pub policy_id: u32,
    pub shaper: Option<String>,
    pub expires: Instant,
    /// Application identified by App-ID; `None` while classification is pending.
    pub app: Option<String>,
    /// Payload packets inspected without a verdict.
    pub app_tries: u8,
    /// Zones the flow was matched with, for re-evaluating policy after App-ID.
    pub src_zone: String,
    pub dst_zone: String,
    /// Reassembly buffers for App-ID while the application is pending:
    /// client-to-server and server-to-client bytes, in TCP sequence order.
    pub app_buf: [Vec<u8>; 2],
    /// Next expected TCP sequence number per direction.
    pub app_seq: [Option<u32>; 2],
    /// Source user from User-ID when the flow started.
    pub user: Option<String>,
}

/// Result of classifying a pending flow.
enum AppVerdict<'c> {
    /// Not enough payload yet; keep going under the provisional policy.
    Pending,
    /// The application is allowed by this policy.
    Allowed(&'c crate::model::Policy),
    /// The application hit a deny/reject policy, or no policy at all.
    Denied(Option<&'c crate::model::Policy>, String),
}

#[derive(Default)]
pub struct Sessions {
    forward: HashMap<SessionKey, Session>,
    reverse: HashMap<SessionKey, SessionKey>,
    /// (proto, nat ip, nat port, peer ip, peer port) in use, for O(1) PAT
    /// port allocation.
    nat_ports: HashSet<(u8, Ipv4Addr, u16, Ipv4Addr, u16)>,
    /// Number of tracked flows per original source address.
    per_src: HashMap<Ipv4Addr, usize>,
}

impl Sessions {
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn lookup(&self, key: SessionKey) -> Option<Session> {
        let now = Instant::now();
        if let Some(session) = self.forward.get(&key) {
            return if session.expires > now {
                Some(session.clone())
            } else {
                None
            };
        }
        let forward_key = self.reverse.get(&key)?;
        self.forward
            .get(forward_key)
            .filter(|s| s.expires > now)
            .cloned()
    }

    pub fn insert(&mut self, session: Session) {
        if let Some(old) = self.forward.remove(&session.key) {
            self.forget(&old);
        }
        if let Some((ip, port)) = session.nat_src {
            self.nat_ports.insert((
                session.key.proto,
                ip,
                port,
                session.key.dst,
                session.key.dport,
            ));
        }
        *self.per_src.entry(session.key.src).or_insert(0) += 1;
        self.reverse
            .insert(reverse_key(&session), session.key.clone());
        self.forward.insert(session.key.clone(), session);
    }

    /// Number of tracked flows opened by `src`.
    pub fn count_for_src(&self, src: Ipv4Addr) -> usize {
        self.per_src.get(&src).copied().unwrap_or(0)
    }

    /// Run the TCP state machine for the flow whose forward key is `key` and
    /// refresh its timeout according to the new state. Returns false when the
    /// packet is invalid for the state (or the flow no longer exists).
    pub fn track_tcp(
        &mut self,
        key: &SessionKey,
        from_orig: bool,
        flags: u8,
        established_timeout: u64,
    ) -> bool {
        let Some(s) = self.forward.get_mut(key) else {
            return false;
        };
        if !tcp_track(s, from_orig, flags) {
            return false;
        }
        let secs = match s.tcp {
            TcpState::SynSent | TcpState::SynRecv => established_timeout.min(60),
            TcpState::Established => established_timeout,
            TcpState::Closing => established_timeout.min(120),
            TcpState::TimeWait => established_timeout.min(30),
            TcpState::Closed => established_timeout.min(10),
        };
        s.expires = Instant::now() + Duration::from_secs(secs);
        true
    }

    /// Record App-ID's verdict and the policy now governing the flow.
    pub fn set_app(&mut self, key: &SessionKey, app: &str, policy_id: u32, shaper: Option<String>) {
        if let Some(s) = self.forward.get_mut(key) {
            s.app = Some(app.to_string());
            s.policy_id = policy_id;
            s.shaper = shaper;
            s.app_buf = [Vec::new(), Vec::new()];
        }
    }

    /// Add a payload to a pending flow's reassembly buffer and return the
    /// bytes so far and whether the buffer is full. TCP payloads are placed
    /// by sequence number: retransmitted bytes are trimmed, and a segment
    /// after a gap is not buffered (the flow continues and App-ID counts it
    /// as one more try). UDP and other protocols pass `None` and are
    /// classified one datagram at a time.
    pub fn app_feed(&mut self, key: &SessionKey, from_client: bool, seq: Option<u32>, payload: &[u8]) -> (Vec<u8>, bool) {
        let cap = crate::appid::MAX_BUFFER;
        let Some(s) = self.forward.get_mut(key) else {
            return (payload.to_vec(), true);
        };
        let d = usize::from(!from_client);
        let buf = &mut s.app_buf[d];
        match seq {
            None => {
                buf.clear();
                buf.extend_from_slice(&payload[..payload.len().min(cap)]);
            }
            Some(seq) => {
                let len = payload.len() as u32;
                match s.app_seq[d] {
                    None => {
                        buf.extend_from_slice(payload);
                        s.app_seq[d] = Some(seq.wrapping_add(len));
                    }
                    Some(next) => {
                        let ahead = seq.wrapping_sub(next) as i32;
                        if ahead == 0 {
                            buf.extend_from_slice(payload);
                            s.app_seq[d] = Some(next.wrapping_add(len));
                        } else if ahead < 0 {
                            // Retransmission, possibly carrying new bytes at its end.
                            let overlap = (-(ahead as i64)) as u32;
                            if overlap < len {
                                buf.extend_from_slice(&payload[overlap as usize..]);
                                s.app_seq[d] = Some(seq.wrapping_add(len));
                            }
                        }
                    }
                }
                buf.truncate(cap);
            }
        }
        (buf.clone(), buf.len() >= cap)
    }

    /// Count one more payload packet without an App-ID verdict.
    pub fn bump_app_try(&mut self, key: &SessionKey) -> u8 {
        match self.forward.get_mut(key) {
            Some(s) => {
                s.app_tries = s.app_tries.saturating_add(1);
                s.app_tries
            }
            None => u8::MAX,
        }
    }

    /// Refresh the idle timeout of a non-TCP flow.
    pub fn touch(&mut self, key: &SessionKey, secs: u64) {
        if let Some(s) = self.forward.get_mut(key) {
            s.expires = Instant::now() + Duration::from_secs(secs);
        }
    }

    fn forget(&mut self, session: &Session) {
        self.reverse.remove(&reverse_key(session));
        if let Some((ip, port)) = session.nat_src {
            self.nat_ports.remove(&(
                session.key.proto,
                ip,
                port,
                session.key.dst,
                session.key.dport,
            ));
        }
        if let Some(n) = self.per_src.get_mut(&session.key.src) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_src.remove(&session.key.src);
            }
        }
    }

    pub fn entries(&self) -> Vec<Session> {
        let mut sessions: Vec<Session> = self.forward.values().cloned().collect();
        sessions.sort_by_key(|s| s.expires);
        sessions
    }

    pub fn purge(&mut self, now: Instant) {
        let expired: Vec<SessionKey> = self
            .forward
            .iter()
            .filter(|(_, s)| s.expires <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(session) = self.forward.remove(&key) {
                self.forget(&session);
            }
        }
    }

    /// Replace the whole table (HA session sync on the passive unit).
    pub fn replace_all(&mut self, sessions: Vec<Session>) {
        *self = Sessions::default();
        for s in sessions {
            self.insert(s);
        }
    }

    pub fn snapshot(&self) -> Vec<Session> {
        let mut v: Vec<Session> = self.forward.values().cloned().collect();
        v.sort_by_key(|s| s.key.proto);
        v
    }

    fn port_in_use(
        &self,
        proto: u8,
        nat_ip: Ipv4Addr,
        port: u16,
        dst: Ipv4Addr,
        dport: u16,
    ) -> bool {
        self.nat_ports.contains(&(proto, nat_ip, port, dst, dport))
    }
}

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub vdom: String,
    pub zone: String,
    pub index: i32,
    pub mac: [u8; 6],
    pub address: Option<Cidr>,
    pub fd: RawFd,
    /// Virtual WireGuard interface: frames go to the tunnel, not a socket.
    pub tunnel: bool,
}

#[derive(Default, Clone, Debug)]
pub struct IfaceStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub dropped: u64,
}

#[derive(Default)]
pub struct Stats {
    pub ifaces: HashMap<String, IfaceStats>,
    pub accepted: u64,
    pub denied: u64,
    pub arp_misses: u64,
    pub errors: u64,
    pub started: Option<Instant>,
}

#[derive(Default)]
struct FloodCounter {
    window: Option<Instant>,
    count: u32,
}

#[derive(Default)]
struct ShaperBucket {
    tokens: f64,
    last: Option<Instant>,
}

pub struct Engine {
    pub cfg: Arc<RwLock<Config>>,
    pub stats: Arc<Mutex<Stats>>,
    pub sessions: Arc<Mutex<Sessions>>,
    pub arp: Arc<Mutex<HashMap<(String, Ipv4Addr), ([u8; 6], Instant)>>>,
    pub ifaces: Vec<Iface>,
    by_index: HashMap<i32, usize>,
    started: Instant,
    pub config_path: Option<PathBuf>,
    flood: Mutex<HashMap<String, FloodCounter>>,
    shapers: Mutex<HashMap<String, ShaperBucket>>,
    source_packets: Mutex<HashMap<Ipv4Addr, ShaperBucket>>,
    pub logs: Mutex<VecDeque<String>>,
    /// Per-policy counters keyed by (vdom, policy id): packets, bytes, last
    /// hit as unix seconds.
    pub hits: Mutex<HashMap<(String, u32), (u64, u64, u64)>>,
    /// Staged configuration text; it is not enforced until commit.
    pub candidate: Mutex<Option<String>>,
    /// Previous running configuration texts, oldest first.
    pub history: Mutex<Vec<String>>,
    pub revisions: Mutex<u64>,
    /// Dynamic User-ID mappings: address → (user, expiry).
    pub users: Mutex<HashMap<Ipv4Addr, (String, Option<Instant>)>>,
    /// HA: whether this unit forwards (always true when standalone).
    pub ha_active: AtomicBool,
    /// HA: manually suspended (`ha suspend`).
    pub ha_suspended: AtomicBool,
    pub ha: Mutex<crate::ha::Status>,
    /// IPv6 connection table and neighbor cache.
    pub sessions6: Mutex<v6::Sessions6>,
    pub nd: Mutex<HashMap<(String, std::net::Ipv6Addr), ([u8; 6], Instant)>>,
    /// One WireGuard device per tunnel, by tunnel name.
    pub vpn: Mutex<HashMap<String, crate::wg::Device>>,
    /// Decrypted packets waiting to be processed as tunnel ingress.
    inject: Mutex<Vec<(usize, Vec<u8>)>>,
    /// Frames sent, recorded by socket-less test engines.
    #[cfg(test)]
    pub sent: Mutex<Vec<(usize, Vec<u8>)>>,
}

impl Engine {
    pub fn open(
        cfg: Arc<RwLock<Config>>,
        stats: Arc<Mutex<Stats>>,
        sessions: Arc<Mutex<Sessions>>,
        arp: Arc<Mutex<HashMap<(String, Ipv4Addr), ([u8; 6], Instant)>>>,
        dry_run: bool,
        config_path: Option<PathBuf>,
    ) -> Engine {
        let snapshot = cfg.read().unwrap().clone();
        let mut ifaces: Vec<Iface> = Vec::new();
        let mut by_index = HashMap::new();
        // Container runtimes create the node's link interfaces shortly after
        // the process starts, so give them a few seconds to appear.
        let mut missing: Vec<&Interface> = snapshot.interfaces.iter().filter(|i| !i.tunnel).collect();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut still_missing = Vec::new();
            for iface in missing {
                let index = unsafe {
                    let name = CString::new(iface.name.as_str()).unwrap();
                    libc::if_nametoindex(name.as_ptr()) as i32
                };
                if index == 0 {
                    still_missing.push(iface);
                    continue;
                }
                let mac = iface
                    .mac
                    .unwrap_or_else(|| read_sysfs_mac(&iface.name).unwrap_or([2, 0, 0, 0, 0, 1]));
                let fd = if dry_run {
                    -1
                } else {
                    match open_socket(index) {
                        Ok(fd) => fd,
                        Err(e) => {
                            eprintln!("dataplane: cannot open {}: {e}", iface.name);
                            continue;
                        }
                    }
                };
                let entry = Iface {
                    name: iface.name.clone(),
                    vdom: iface.vdom.clone(),
                    zone: iface.zone.clone(),
                    index,
                    mac,
                    address: iface.address,
                    fd,
                    tunnel: false,
                };
                by_index.insert(index, ifaces.len());
                ifaces.push(entry);
            }
            missing = still_missing;
            if missing.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        for iface in missing {
            eprintln!(
                "dataplane: interface '{}' not found (configured for zone {}), skipping",
                iface.name, iface.zone
            );
        }
        // WireGuard interfaces are virtual slots.
        for (n, iface) in snapshot.interfaces.iter().filter(|i| i.tunnel).enumerate() {
            let index = 100_000 + n as i32;
            by_index.insert(index, ifaces.len());
            ifaces.push(Iface {
                name: iface.name.clone(),
                vdom: iface.vdom.clone(),
                zone: iface.zone.clone(),
                index,
                mac: [2, 0x77, 0x67, 0, 0, n as u8],
                address: iface.address,
                fd: -1,
                tunnel: true,
            });
        }
        let started = Instant::now();
        {
            let mut s = stats.lock().unwrap();
            s.started = Some(started);
            for iface in &ifaces {
                s.ifaces.entry(iface.name.clone()).or_default();
            }
        }
        Engine {
            cfg,
            stats,
            sessions,
            arp,
            ifaces,
            by_index,
            started,
            config_path,
            flood: Mutex::new(HashMap::new()),
            shapers: Mutex::new(HashMap::new()),
            source_packets: Mutex::new(HashMap::new()),
            logs: Mutex::new(VecDeque::new()),
            hits: Mutex::new(HashMap::new()),
            candidate: Mutex::new(None),
            history: Mutex::new(Vec::new()),
            revisions: Mutex::new(1),
            users: Mutex::new(HashMap::new()),
            ha_active: AtomicBool::new(true),
            ha_suspended: AtomicBool::new(false),
            ha: Mutex::new(crate::ha::Status::default()),
            vpn: Mutex::new(devices(&snapshot)),
            inject: Mutex::new(Vec::new()),
            sessions6: Mutex::new(v6::Sessions6::default()),
            nd: Mutex::new(HashMap::new()),
            #[cfg(test)]
            sent: Mutex::new(Vec::new()),
        }
    }

    /// Re-run the rulebase for a pending flow once App-ID has a verdict
    /// (or has given up). A deny cuts the flow off.
    fn app_verdict<'c>(&self, cfg: &'c Config, s: &Session, buf: &[u8], dir: crate::appid::Dir, full: bool) -> AppVerdict<'c> {
        let tries = self.sessions.lock().unwrap().bump_app_try(&s.key);
        let last = full || tries >= crate::appid::MAX_TRIES;
        let app = match crate::appid::classify(s.key.proto, buf, dir, last) {
            crate::appid::Class::App(app) => app,
            _ if !last => return AppVerdict::Pending,
            _ if s.key.proto == PROTO_TCP => crate::appid::UNKNOWN_TCP,
            _ => crate::appid::UNKNOWN_UDP,
        };
        // Same inputs as the first lookup: translated address, original port.
        let dst = s.nat_dst.map(|(ip, _)| ip).unwrap_or(s.key.dst);
        let next = cfg.match_or_default_user(
            &s.key.vdom,
            &s.src_zone,
            &s.dst_zone,
            s.key.src,
            dst,
            s.key.proto,
            s.key.dport,
            Some(app),
            s.user.as_deref(),
        );
        let mut sessions = self.sessions.lock().unwrap();
        match next {
            Some(p) if p.action == Action::Permit => {
                sessions.set_app(&s.key, app, p.id, p.shaper.clone());
                AppVerdict::Allowed(p)
            }
            other => {
                sessions.set_app(&s.key, app, other.map(|p| p.id).unwrap_or(s.policy_id), None);
                sessions.touch(&s.key, 0);
                AppVerdict::Denied(other, app.to_string())
            }
        }
    }

    /// Count a packet against a policy.
    fn bump_hit(&self, vdom: &str, policy: u32, bytes: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut hits = self.hits.lock().unwrap();
        let entry = hits.entry((vdom.to_string(), policy)).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += bytes;
        entry.2 = now;
    }

    /// Snapshot of per-policy counters: (vdom, id) -> (packets, bytes, last hit).
    pub fn policy_hits(&self) -> HashMap<(String, u32), (u64, u64, u64)> {
        self.hits.lock().unwrap().clone()
    }

    /// Send an ICMP error about `orig` (an IP header plus at least eight
    /// bytes of payload) back to its sender, rate limited per ingress zone.
    /// ICMP errors are never sent about ICMP errors or to non-unicast sources.
    fn send_icmp_error(&self, slot: usize, src_mac: [u8; 6], orig: &[u8], icmp_type: u8, code: u8) {
        if orig.len() < 28 {
            return;
        }
        let hlen = (orig[0] & 0x0f) as usize * 4;
        if hlen < 20 || orig.len() < hlen + 8 {
            return;
        }
        if orig[9] == PROTO_ICMP && matches!(orig[hlen], 3 | 4 | 5 | 11 | 12) {
            return;
        }
        let dst_ip = Ipv4Addr::new(orig[12], orig[13], orig[14], orig[15]);
        if dst_ip.is_multicast() || dst_ip.is_broadcast() || dst_ip.is_unspecified() {
            return;
        }
        let Some(out) = self.ifaces.get(slot) else {
            return;
        };
        let Some(cidr) = out.address else {
            return;
        };
        if self.flood_exceeded(&out.zone, "icmp-error", 100) {
            return;
        }
        let frame = build_icmp_error(src_mac, out.mac, cidr.addr, dst_ip, icmp_type, code, orig);
        self.send(slot, &frame);
    }

    /// Answer a refused TCP segment with a RST that appears to come from the
    /// intended destination (`peer_ip`:`peer_port`).
    fn send_tcp_rst(
        &self,
        slot: usize,
        src_mac: [u8; 6],
        ip: &Ipv4<'_>,
        peer_ip: Ipv4Addr,
        peer_port: u16,
    ) {
        let Some(out) = self.ifaces.get(slot) else {
            return;
        };
        let t = ip.transport();
        if t.len() < 20 {
            return;
        }
        let flags = t[13];
        if flags & TCP_RST != 0 {
            return;
        }
        if self.flood_exceeded(&out.zone, "reject", 200) {
            return;
        }
        let seq = read_u32(t, 4);
        let ack = read_u32(t, 8);
        let data_off = ((t[12] >> 4) as usize) * 4;
        let mut seg_len = t.len().saturating_sub(data_off) as u32;
        if flags & TCP_SYN != 0 {
            seg_len += 1;
        }
        if flags & TCP_FIN != 0 {
            seg_len += 1;
        }
        let (rseq, rack, with_ack) = if flags & TCP_ACK != 0 {
            (ack, 0, false)
        } else {
            (0, seq.wrapping_add(seg_len), true)
        };
        let (sport, _) = ip.ports().unwrap_or((0, 0));
        let frame = build_tcp_rst(
            src_mac,
            out.mac,
            peer_ip,
            ip.src(),
            peer_port,
            sport,
            rseq,
            rack,
            with_ack,
        );
        self.send(slot, &frame);
    }

    fn flood_exceeded(&self, zone: &str, kind: &str, limit: u32) -> bool {
        let key = format!("{zone}/{kind}");
        let now = Instant::now();
        let mut flood = self.flood.lock().unwrap();
        let counter = flood.entry(key).or_default();
        if counter
            .window
            .map(|w| now.duration_since(w).as_secs() >= 1)
            .unwrap_or(true)
        {
            counter.window = Some(now);
            counter.count = 0;
        }
        counter.count += 1;
        counter.count > limit
    }

    fn shaper_allow(&self, shaper: &crate::model::Shaper, bytes: usize) -> bool {
        let rate = (shaper.kbps as f64) * 1000.0 / 8.0;
        let burst = (rate * 0.5).max(1500.0);
        let now = Instant::now();
        let mut shapers = self.shapers.lock().unwrap();
        let bucket = shapers.entry(shaper.name.clone()).or_default();
        match bucket.last {
            None => bucket.tokens = burst,
            Some(last) => {
                let elapsed = now.duration_since(last).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
            }
        }
        bucket.last = Some(now);
        if bucket.tokens >= bytes as f64 {
            bucket.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_event(
        &self,
        cfg: &Config,
        action: &str,
        src: impl Into<std::net::IpAddr>,
        sport: u16,
        dst: impl Into<std::net::IpAddr>,
        dport: u16,
        proto: u8,
        zone_in: &str,
        zone_out: &str,
        policy: Option<u32>,
        note: &str,
    ) {
        let (src, dst): (std::net::IpAddr, std::net::IpAddr) = (src.into(), dst.into());
        if !cfg.settings.logging {
            return;
        }
        let line = if cfg.settings.log_json {
            format!(
                "{{\"action\":\"{}\",\"src\":\"{}\",\"sport\":{},\"dst\":\"{}\",\"dport\":{},\"proto\":{},\"from\":\"{}\",\"to\":\"{}\",\"policy\":{},\"note\":\"{}\"}}",
                json_escape(action),
                src,
                sport,
                dst,
                dport,
                proto,
                json_escape(zone_in),
                json_escape(zone_out),
                policy.map(|p| p.to_string()).unwrap_or_else(|| "null".to_string()),
                json_escape(note),
            )
        } else {
            format!(
                "{} {}:{} -> {}:{} proto {} ({} -> {}){}{}",
                action,
                src,
                sport,
                dst,
                dport,
                proto,
                zone_in,
                if zone_out.is_empty() { "-" } else { zone_out },
                policy.map(|p| format!(" policy {p}")).unwrap_or_default(),
                if note.is_empty() {
                    String::new()
                } else {
                    format!(" {note}")
                },
            )
        };
        println!("{line}");
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= 200 {
            logs.pop_front();
        }
        logs.push_back(line);
    }

    pub fn save(&self) -> Result<(), String> {
        let text = self.cfg.read().unwrap().to_text();
        self.save_text(&text)
    }

    fn save_text(&self, text: &str) -> Result<(), String> {
        let Some(path) = &self.config_path else {
            return Err("no configuration file is attached".to_string());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
    }

    /// Interface changes cannot be applied to a running AF_PACKET engine
    /// without reopening sockets, so they are rejected with a clear error.
    fn ensure_live_compatible(&self, next: &Config) -> Result<(), String> {
        let current = self.cfg.read().unwrap();
        if current.interfaces.len() != next.interfaces.len() {
            return Err("interface additions/removals require a daemon restart".to_string());
        }
        for (old, new) in current.interfaces.iter().zip(next.interfaces.iter()) {
            // Zone membership is read from the running config per packet, so
            // it may change live; the rest is bound to the open sockets.
            if old.name != new.name
                || old.vdom != new.vdom
                || old.address != new.address
                || old.mac != new.mac
                || old.mtu != new.mtu
            {
                return Err(format!(
                    "interface '{}' changes require a daemon restart; commit supports zone membership, policies, routes, objects, NAT, shapers and security profiles",
                    new.name
                ));
            }
        }
        Ok(())
    }

    pub fn stage_config(&self, text: &str) -> Result<(), String> {
        let parsed = Config::parse(text)?;
        self.ensure_live_compatible(&parsed)?;
        *self.candidate.lock().unwrap() = Some(text.to_string());
        Ok(())
    }

    pub fn candidate_text(&self) -> Option<String> {
        self.candidate.lock().unwrap().clone()
    }

    pub fn discard_candidate(&self) {
        *self.candidate.lock().unwrap() = None;
    }

    pub fn config_diff(&self) -> String {
        let running = self.cfg.read().unwrap().to_text();
        let candidate = self.candidate_text().unwrap_or_else(|| running.clone());
        crate::diff::unified(&running, &candidate, "running", "candidate")
    }

    pub fn commit_candidate(&self) -> Result<(), String> {
        let text = self
            .candidate_text()
            .ok_or_else(|| "no candidate configuration is staged".to_string())?;
        let parsed = Config::parse(&text)?;
        self.ensure_live_compatible(&parsed)?;
        let old = self.cfg.read().unwrap().to_text();
        self.save_text(&text)?;
        self.backup(&old);
        *self.cfg.write().unwrap() = parsed;
        *self.candidate.lock().unwrap() = None;
        self.push_history(old);
        *self.revisions.lock().unwrap() += 1;
        self.vpn_sync();
        Ok(())
    }

    /// Record a login pushed by an identity source. `timeout` of None keeps
    /// the mapping until logout.
    pub fn user_login(&self, ip: Ipv4Addr, user: &str, timeout: Option<Duration>) -> Result<(), String> {
        crate::model::valid_user_name(user)?;
        let mut users = self.users.lock().unwrap();
        if users.len() >= 100_000 && !users.contains_key(&ip) {
            return Err("user mapping table is full".into());
        }
        users.insert(ip, (user.to_string(), timeout.map(|t| Instant::now() + t)));
        Ok(())
    }

    pub fn user_logout(&self, ip: Ipv4Addr) -> bool {
        self.users.lock().unwrap().remove(&ip).is_some()
    }

    /// Dynamic mappings first, then the configuration's static ones.
    pub fn user_for(&self, cfg: &Config, ip: Ipv4Addr) -> Option<String> {
        let mut users = self.users.lock().unwrap();
        if let Some((user, expiry)) = users.get(&ip) {
            if expiry.map_or(true, |e| e > Instant::now()) {
                return Some(user.clone());
            }
            users.remove(&ip);
        }
        cfg.static_user_for(ip).map(str::to_string)
    }

    /// Every current mapping: (address or network, user, source, seconds left).
    pub fn user_mappings(&self, cfg: &Config) -> Vec<(String, String, &'static str, Option<u64>)> {
        let now = Instant::now();
        let mut out: Vec<_> = self
            .users
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (_, e))| e.map_or(true, |e| e > now))
            .map(|(ip, (u, e))| (ip.to_string(), u.clone(), "dynamic", e.map(|e| e.saturating_duration_since(now).as_secs())))
            .collect();
        out.extend(cfg.user_maps.iter().map(|m| (m.cidr.to_string(), m.user.clone(), "static", None)));
        out.sort();
        out
    }

    /// Validate, save and activate a whole configuration in one step. Used by
    /// the FortiOS- and PAN-OS-style CLIs, which keep their own drafts and do
    /// not touch the GUI's staged candidate.
    pub fn apply_config(&self, next: &Config) -> Result<(), String> {
        let text = next.to_text();
        let parsed = Config::parse(&text)?;
        self.ensure_live_compatible(&parsed)?;
        let old = self.cfg.read().unwrap().to_text();
        if old == text {
            return Ok(());
        }
        self.save_text(&text)?;
        self.backup(&old);
        *self.cfg.write().unwrap() = parsed;
        self.push_history(old);
        *self.revisions.lock().unwrap() += 1;
        self.vpn_sync();
        Ok(())
    }

    pub fn rollback_config(&self) -> Result<String, String> {
        let old = {
            let mut history = self.history.lock().unwrap();
            history
                .pop()
                .ok_or_else(|| "no previous configuration is available".to_string())?
        };
        let parsed = Config::parse(&old)?;
        self.ensure_live_compatible(&parsed)?;
        self.save_text(&old)?;
        *self.cfg.write().unwrap() = parsed;
        *self.candidate.lock().unwrap() = None;
        *self.revisions.lock().unwrap() += 1;
        Ok(old)
    }

    fn push_history(&self, text: String) {
        let mut history = self.history.lock().unwrap();
        history.push(text);
        if history.len() > 20 {
            history.remove(0);
        }
    }

    fn backup(&self, text: &str) {
        let Some(path) = &self.config_path else {
            return;
        };
        let dir = path.with_extension("backups");
        if fs::create_dir_all(&dir).is_err() {
            return;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = fs::write(dir.join(format!("{stamp}.conf")), text);
        if let Ok(entries) = fs::read_dir(&dir) {
            let mut files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
                .collect();
            files.sort();
            while files.len() > 10 {
                let path = files.remove(0);
                let _ = fs::remove_file(path);
            }
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn running_text(&self) -> String {
        self.cfg.read().unwrap().to_text()
    }

    pub fn config_revision(&self) -> u64 {
        *self.revisions.lock().unwrap()
    }

    pub fn local_ip(&self, vdom: &str, ip: Ipv4Addr) -> bool {
        self.ifaces
            .iter()
            .filter(|i| i.vdom == vdom)
            .any(|i| i.address.map(|c| c.addr == ip).unwrap_or(false))
    }

    pub fn run(self: Arc<Self>) -> ! {
        let mut buf = vec![0u8; 65536];
        let poll_timeout_ms = 250;
        let mut last_purge = Instant::now();
        loop {
            let mut fds: Vec<libc::pollfd> = self
                .ifaces
                .iter()
                .filter(|i| i.fd >= 0)
                .map(|i| libc::pollfd {
                    fd: i.fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            if fds.is_empty() {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            let rc =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, poll_timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    eprintln!("dataplane: poll: {err}");
                }
            } else if rc > 0 {
                for pfd in &fds {
                    if pfd.revents & libc::POLLIN == 0 {
                        continue;
                    }
                    let Some(slot) = self.ifaces.iter().position(|i| i.fd == pfd.fd) else {
                        continue;
                    };
                    loop {
                        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                        let mut addr_len =
                            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                        let n = unsafe {
                            libc::recvfrom(
                                pfd.fd,
                                buf.as_mut_ptr() as *mut libc::c_void,
                                buf.len(),
                                libc::MSG_DONTWAIT,
                                &mut addr as *mut _ as *mut libc::sockaddr,
                                &mut addr_len,
                            )
                        };
                        if n <= 0 {
                            break;
                        }
                        // AF_PACKET also delivers a copy of every frame we send.
                        // Ignore those or the firewall would feed on its own output.
                        if addr.sll_pkttype == libc::PACKET_OUTGOING {
                            continue;
                        }
                        let max_packet = self.cfg.read().unwrap().settings.max_packet_size;
                        if n as usize > max_packet {
                            self.stats.lock().unwrap().errors += 1;
                            self.stats_bump(slot, |s| s.dropped += 1);
                            continue;
                        }
                        let frame = &mut buf[..n as usize];
                        self.handle(slot, frame);
                    }
                }
            }
            if last_purge.elapsed() >= Duration::from_secs(5) {
                self.sessions.lock().unwrap().purge(Instant::now());
                self.sessions6.lock().unwrap().purge(Instant::now());
                let now = Instant::now();
                self.arp
                    .lock()
                    .unwrap()
                    .retain(|_, (_, seen)| now.duration_since(*seen) < ARP_TTL);
                let mut sources = self.source_packets.lock().unwrap();
                if sources.len() > 4096 {
                    sources.retain(|_, bucket| {
                        bucket
                            .last
                            .map(|t| now.duration_since(t).as_secs() < 10)
                            .unwrap_or(false)
                    });
                }
                last_purge = now;
            }
        }
    }

    fn source_allowed(&self, src: Ipv4Addr, rate: u32, burst: u32) -> bool {
        if rate == 0 {
            return true;
        }
        let now = Instant::now();
        let burst = burst.max(1) as f64;
        let mut buckets = self.source_packets.lock().unwrap();
        if buckets.len() >= 16384 && !buckets.contains_key(&src) {
            return false;
        }
        let bucket = buckets.entry(src).or_insert(ShaperBucket {
            tokens: burst,
            last: None,
        });
        if let Some(last) = bucket.last {
            let elapsed = now.duration_since(last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * rate as f64).min(burst);
        }
        bucket.last = Some(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn stats_bump<F: FnOnce(&mut IfaceStats)>(&self, slot: usize, f: F) {
        let name = self.ifaces[slot].name.clone();
        if let Some(s) = self.stats.lock().unwrap().ifaces.get_mut(&name) {
            f(s);
        }
    }

    fn handle(&self, slot: usize, frame: &mut [u8]) {
        if frame.len() < ETH_HEADER_LEN {
            return;
        }
        self.stats_bump(slot, |s| {
            s.rx_packets += 1;
            s.rx_bytes += frame.len() as u64;
        });
        // An HA passive or suspended unit neither forwards nor answers ARP.
        if !self.ha_active.load(Ordering::Relaxed) {
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        match ethertype(frame) {
            ETHERTYPE_ARP => self.handle_arp(slot, frame),
            v6::ETHERTYPE_IPV6 => self.handle_ipv6(slot, frame),
            ETHERTYPE_IPV4 => {
                self.handle_ipv4(slot, frame);
                // Packets decrypted by a tunnel, processed now that this
                // packet released the configuration lock.
                for _ in 0..64 {
                    let next = self.inject.lock().unwrap().pop();
                    let Some((tslot, mut inner)) = next else { break };
                    self.stats_bump(tslot, |s| {
                        s.rx_packets += 1;
                        s.rx_bytes += inner.len() as u64;
                    });
                    self.handle_ipv4(tslot, &mut inner);
                }
            }
            _ => self.stats_bump(slot, |s| s.dropped += 1),
        }
    }

    fn handle_arp(&self, slot: usize, frame: &mut [u8]) {
        let l3 = ETH_HEADER_LEN;
        if frame.len() < l3 + 28 {
            return;
        }
        let Some(info) = parse_arp(&frame[l3..]) else {
            return;
        };
        let vdom = self.ifaces[slot].vdom.clone();
        if info.sender_ip != Ipv4Addr::UNSPECIFIED {
            self.arp.lock().unwrap().insert(
                (vdom.clone(), info.sender_ip),
                (info.sender_mac, Instant::now()),
            );
        }
        if info.operation != 1 {
            return;
        }
        let Some(owner) = self
            .ifaces
            .iter()
            .filter(|i| i.vdom == vdom)
            .find(|i| i.address.map(|c| c.addr == info.target_ip).unwrap_or(false))
        else {
            return;
        };
        let mut reply = vec![0u8; 64];
        let n = build_arp(
            &mut reply,
            info.sender_mac,
            owner.mac,
            2,
            owner.mac,
            info.target_ip,
            info.sender_mac,
            info.sender_ip,
        );
        if n > 0 {
            self.send(slot, &reply[..n]);
        }
    }

    fn handle_ipv4(&self, slot: usize, frame: &mut [u8]) {
        let l3 = ETH_HEADER_LEN;
        let src_mac = read_mac(frame, 6);
        let Some(mut ip) = Ipv4::parse(&mut frame[l3..]) else {
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        };
        if !ip.checksum_valid() {
            self.stats.lock().unwrap().errors += 1;
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        let src = ip.src();
        let original_dst = ip.dst();
        if !ip.transport_sane() {
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        if !ip.transport_checksum_valid() {
            self.stats.lock().unwrap().errors += 1;
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        {
            let (rate, burst) = {
                let settings = &self.cfg.read().unwrap().settings;
                (settings.source_rate, settings.source_burst)
            };
            if !self.source_allowed(src, rate, burst) {
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            }
        }

        // Hold the read lock for this packet instead of cloning the whole
        // configuration. Nothing below takes the config lock again.
        let cfg_guard = self.cfg.read().unwrap();
        let cfg: &Config = &cfg_guard;
        let in_iface = &self.ifaces[slot];
        // Zone membership comes from the running config, so it can change on
        // commit without reopening sockets.
        let in_zone: String = cfg
            .interfaces
            .iter()
            .find(|i| i.name == in_iface.name)
            .map(|i| i.zone.clone())
            .unwrap_or_else(|| in_iface.zone.clone());
        let local = self.local_ip(&in_iface.vdom, original_dst);
        let proto = ip.protocol();
        // Quote of the packet as received, used for ICMP errors about a TTL
        // that is about to expire (before any NAT rewrites the header).
        let ttl_quote: Option<Vec<u8>> = if !local && ip.ttl() <= 1 {
            Some(ip.data[..(ip.header_len() + 8).min(ip.total_len())].to_vec())
        } else {
            None
        };
        let (sport, dport) = match proto {
            PROTO_TCP | PROTO_UDP => ip.ports().unwrap_or((0, 0)),
            PROTO_ICMP => {
                let id = icmp_identity(&ip);
                (id, id)
            }
            _ => (0, 0),
        };
        let vdom = in_iface.vdom.clone();

        // Ingress sanity: drop packets that no legitimate sender produces.
        let bad: Option<&str> = if ip.is_fragment() {
            Some("fragment (reassembly not supported)")
        } else if src.is_unspecified()
            || src.is_loopback()
            || src.is_multicast()
            || src.is_broadcast()
        {
            Some("martian-source")
        } else if original_dst.is_loopback()
            || original_dst.is_multicast()
            || original_dst.is_broadcast()
            || original_dst.is_unspecified()
        {
            Some("martian-destination")
        } else if src == original_dst {
            Some("land-attack")
        } else if proto == PROTO_TCP && !ip.tcp_flags().map(tcp_flags_sane).unwrap_or(false) {
            Some("invalid-tcp-flags")
        } else {
            None
        };
        if let Some(reason) = bad {
            // Multicast/broadcast chatter is dropped without a log line.
            if reason != "martian-destination" {
                self.log_event(
                    cfg,
                    "deny",
                    src,
                    sport,
                    original_dst,
                    dport,
                    proto,
                    &in_zone,
                    "",
                    None,
                    reason,
                );
            }
            self.stats.lock().unwrap().denied += 1;
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }

        // WireGuard datagrams to one of our addresses go to the tunnel.
        if local && proto == PROTO_UDP {
            if let Some(t) = cfg.tunnels.iter().find(|t| t.vdom == vdom && t.listen_port == dport) {
                let payload = crate::inspect::payload(&ip).to_vec();
                self.vpn_receive(cfg, &t.name, std::net::SocketAddrV4::new(src, sport), &payload);
                return;
            }
        }

        let key = SessionKey {
            vdom: vdom.clone(),
            proto,
            src,
            sport,
            dst: original_dst,
            dport,
        };

        let mut session = self.sessions.lock().unwrap().lookup(key.clone());
        let mut translated = false;
        let out_slot;

        if let Some(s) = session.clone() {
            if s.key == key {
                // Forward direction of an existing flow. Re-apply both NAT
                // translations because each packet arrives unmodified.
                out_slot = self.slot_for_index(s.out_index).unwrap_or(slot);
                let policy_now = cfg.policy_by_id(&s.key.vdom, s.policy_id);
                // A flow whose policy was deleted, disabled or turned into a
                // deny is cut off instead of living on until it times out.
                let Some(policy) = policy_now.filter(|p| p.enabled && p.action == Action::Permit)
                else {
                    self.sessions.lock().unwrap().touch(&s.key, 0);
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        ip.dst(),
                        dport,
                        proto,
                        &in_zone,
                        "",
                        Some(s.policy_id),
                        "policy-withdrawn",
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
                };
                let policy = if s.app.is_none() {
                    let payload = crate::inspect::payload(&ip);
                    if payload.is_empty() {
                        policy
                    } else {
                        let seq = (proto == PROTO_TCP).then(|| crate::packet::read_u32(ip.transport(), 4));
                        let (buf, full) = self.sessions.lock().unwrap().app_feed(&s.key, true, seq, payload);
                        match self.app_verdict(cfg, &s, &buf, crate::appid::Dir::ClientToServer, full) {
                            AppVerdict::Pending => policy,
                            AppVerdict::Allowed(next) => next,
                            AppVerdict::Denied(next, app) => {
                                if let Some(p) = next {
                                    self.bump_hit(&vdom, p.id, ip.total_len() as u64);
                                    if p.action == Action::Reject && proto == PROTO_TCP {
                                        self.send_tcp_rst(slot, src_mac, &ip, original_dst, dport);
                                    }
                                }
                                let reason = match next {
                                    Some(p) => format!("app {app}: {} {}", Config::policy_label(p), p.action.as_str()),
                                    None => format!("app {app}: no policy"),
                                };
                                self.log_event(cfg, "deny", src, sport, ip.dst(), dport, proto, &in_zone, "", next.map(|p| p.id), &reason);
                                self.stats.lock().unwrap().denied += 1;
                                self.stats_bump(slot, |st| st.dropped += 1);
                                return;
                            }
                        }
                    }
                } else {
                    policy
                };
                if let Some(reason) = security_drop(cfg, policy, &ip, dport) {
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        ip.dst(),
                        dport,
                        proto,
                        &in_zone,
                        "",
                        Some(policy.id),
                        &reason,
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
                }
                if proto == PROTO_TCP {
                    let flags = ip.tcp_flags().unwrap_or(0);
                    let ok = self.sessions.lock().unwrap().track_tcp(
                        &s.key,
                        true,
                        flags,
                        cfg.settings.tcp_timeout,
                    );
                    if !ok {
                        self.log_event(
                            cfg,
                            "deny",
                            src,
                            sport,
                            ip.dst(),
                            dport,
                            proto,
                            &in_zone,
                            "",
                            Some(policy.id),
                            "invalid tcp state",
                        );
                        self.stats.lock().unwrap().denied += 1;
                        self.stats_bump(slot, |st| st.dropped += 1);
                        return;
                    }
                }
                if let Some((nat_ip, nat_port)) = s.nat_src {
                    if ip.src() != nat_ip {
                        ip.set_src(nat_ip);
                        if proto == PROTO_TCP || proto == PROTO_UDP {
                            ip.set_source_port(nat_port);
                        }
                        translated = true;
                    }
                }
                if let Some((nat_ip, nat_port)) = s.nat_dst {
                    ip.set_dst(nat_ip);
                    if proto == PROTO_TCP || proto == PROTO_UDP {
                        ip.set_destination_port(nat_port);
                    }
                    translated = true;
                }
            } else {
                // Reply direction: inspect, track, then undo DNAT/SNAT back to
                // the original flow.
                out_slot = self.slot_for_index(s.in_index).unwrap_or(slot);
                let policy_now = cfg.policy_by_id(&s.key.vdom, s.policy_id);
                let Some(policy) = policy_now.filter(|p| p.enabled && p.action == Action::Permit)
                else {
                    self.sessions.lock().unwrap().touch(&s.key, 0);
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        original_dst,
                        dport,
                        proto,
                        &in_zone,
                        "",
                        Some(s.policy_id),
                        "policy-withdrawn",
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
                };
                // Server-first protocols (SMTP, FTP, POP3, IMAP, MySQL) are
                // classified from the reply.
                let policy = if s.app.is_none() {
                    let payload = crate::inspect::payload(&ip);
                    if payload.is_empty() {
                        policy
                    } else {
                        let seq = (proto == PROTO_TCP).then(|| crate::packet::read_u32(ip.transport(), 4));
                        let (buf, full) = self.sessions.lock().unwrap().app_feed(&s.key, false, seq, payload);
                        match self.app_verdict(cfg, &s, &buf, crate::appid::Dir::ServerToClient, full) {
                            AppVerdict::Pending => policy,
                            AppVerdict::Allowed(next) => next,
                            AppVerdict::Denied(next, app) => {
                                let reason = match next {
                                    Some(p) => format!("app {app}: {} {}", Config::policy_label(p), p.action.as_str()),
                                    None => format!("app {app}: no policy"),
                                };
                                self.log_event(cfg, "deny", src, sport, original_dst, dport, proto, &in_zone, "", next.map(|p| p.id), &reason);
                                self.stats.lock().unwrap().denied += 1;
                                self.stats_bump(slot, |st| st.dropped += 1);
                                return;
                            }
                        }
                    }
                } else {
                    policy
                };
                if let Some(reason) = security_drop(cfg, policy, &ip, dport) {
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        original_dst,
                        dport,
                        proto,
                        &in_zone,
                        "",
                        Some(policy.id),
                        &format!("reply {reason}"),
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
                }
                if proto == PROTO_TCP {
                    let flags = ip.tcp_flags().unwrap_or(0);
                    let ok = self.sessions.lock().unwrap().track_tcp(
                        &s.key,
                        false,
                        flags,
                        cfg.settings.tcp_timeout,
                    );
                    if !ok {
                        self.log_event(
                            cfg,
                            "deny",
                            src,
                            sport,
                            original_dst,
                            dport,
                            proto,
                            &in_zone,
                            "",
                            Some(policy.id),
                            "invalid tcp state",
                        );
                        self.stats.lock().unwrap().denied += 1;
                        self.stats_bump(slot, |st| st.dropped += 1);
                        return;
                    }
                }
                ip.set_dst(s.key.src);
                ip.set_src(s.key.dst);
                if proto == PROTO_TCP || proto == PROTO_UDP {
                    ip.set_destination_port(s.key.sport);
                    ip.set_source_port(s.key.dport);
                }
                translated = s.nat_src.is_some() || s.nat_dst.is_some();
            }
        } else {
            // Only a clean SYN may open a TCP flow. Anything else without a
            // session is INVALID (stray ACK, late RST, scan probe) and is dropped.
            if proto == PROTO_TCP {
                let flags = ip.tcp_flags().unwrap_or(0);
                if flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) != TCP_SYN {
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        original_dst,
                        dport,
                        proto,
                        &in_zone,
                        "",
                        None,
                        "invalid: no session and not a SYN",
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |s| s.dropped += 1);
                    return;
                }
            }
            // Header as received, for ICMP errors/rejects (DNAT rewrites it).
            let pre_nat: Vec<u8> = ip.data[..(ip.header_len() + 8).min(ip.total_len())].to_vec();

            // Destination NAT is evaluated before the local delivery check so
            // port forwards addressed to a firewall address are translated.
            let mut nat_dst = None;
            if let Some(rule) = cfg.dnat_match(&vdom, proto, original_dst, dport) {
                let to_port = rule.to_port.unwrap_or(dport);
                nat_dst = Some((rule.to_ip, to_port));
                ip.set_dst(rule.to_ip);
                if proto == PROTO_TCP || proto == PROTO_UDP {
                    ip.set_destination_port(to_port);
                }
                translated = true;
            }

            if local && nat_dst.is_none() {
                // A flow to one of our own addresses that is not a reply to an
                // existing session belongs to the firewall itself.
                self.handle_local(slot, src_mac, ip);
                return;
            }

            let dst = ip.dst();
            let Some((egress, _next_hop)) = cfg.egress(&vdom, dst) else {
                self.log_event(
                    &cfg,
                    "drop",
                    src,
                    sport,
                    dst,
                    dport,
                    proto,
                    &in_zone,
                    "",
                    None,
                    "no-route",
                );
                self.send_icmp_error(slot, src_mac, &pre_nat, 3, 0);
                self.stats.lock().unwrap().denied += 1;
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            };
            let Some(slot_out) = self.iface_slot(&egress.name) else {
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            };
            out_slot = slot_out;

            if let Some(zone) = cfg.zone(&in_zone, &vdom) {
                let flood = if proto == PROTO_TCP && ip.tcp_syn() {
                    zone.syn_flood
                        .map(|limit| ("syn", self.flood_exceeded(&zone.name, "syn", limit)))
                } else if proto == PROTO_ICMP && ip.icmp_type() == Some(8) {
                    zone.icmp_flood
                        .map(|limit| ("icmp", self.flood_exceeded(&zone.name, "icmp", limit)))
                } else if proto == PROTO_UDP {
                    zone.udp_flood
                        .map(|limit| ("udp", self.flood_exceeded(&zone.name, "udp", limit)))
                } else {
                    None
                };
                if let Some((kind, true)) = flood {
                    self.log_event(
                        &cfg,
                        "deny",
                        src,
                        sport,
                        dst,
                        dport,
                        proto,
                        &in_zone,
                        &egress.zone,
                        None,
                        &format!("zone-protection {kind}-flood"),
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |s| s.dropped += 1);
                    return;
                }
            }

            // App-ID on the first packet: custom (port-defined) applications,
            // ICMP and most UDP protocols are known immediately; TCP needs
            // payload, so its rules match provisionally until then.
            let app0: Option<String> = match proto {
                PROTO_ICMP => Some(crate::appid::identify_icmp(ip.icmp_type()).to_string()),
                PROTO_TCP | PROTO_UDP => cfg
                    .custom_app_for(proto, dport)
                    .map(str::to_string)
                    .or_else(|| {
                        let payload = crate::inspect::payload(&ip);
                        crate::appid::identify(proto, payload, crate::appid::Dir::ClientToServer).map(str::to_string)
                    })
                    .or_else(|| (proto == PROTO_UDP).then(|| crate::appid::UNKNOWN_UDP.to_string())),
                _ => Some(crate::appid::UNKNOWN_IP.to_string()),
            };
            let user = self.user_for(cfg, src);
            let policy = cfg.match_or_default_user(
                &vdom,
                &in_zone,
                &egress.zone,
                src,
                dst,
                proto,
                dport,
                app0.as_deref(),
                user.as_deref(),
            );
            let Some(policy) = policy else {
                self.log_event(
                    &cfg,
                    "deny",
                    src,
                    sport,
                    dst,
                    dport,
                    proto,
                    &in_zone,
                    &egress.zone,
                    None,
                    "no policy",
                );
                self.stats.lock().unwrap().denied += 1;
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            };
            if policy.action != Action::Permit {
                self.bump_hit(&vdom, policy.id, ip.total_len() as u64);
                if policy.action == Action::Reject {
                    match proto {
                        PROTO_TCP => self.send_tcp_rst(slot, src_mac, &ip, original_dst, dport),
                        PROTO_UDP => self.send_icmp_error(slot, src_mac, &pre_nat, 3, 3),
                        PROTO_ICMP => self.send_icmp_error(slot, src_mac, &pre_nat, 3, 13),
                        _ => {}
                    }
                }
                self.log_event(
                    &cfg,
                    "deny",
                    src,
                    sport,
                    dst,
                    dport,
                    proto,
                    &in_zone,
                    &egress.zone,
                    (!crate::model::is_default_rule_id(policy.id)).then_some(policy.id),
                    if crate::model::is_default_rule_id(policy.id) { policy.name.as_deref().unwrap_or("") } else { "" },
                );
                self.stats.lock().unwrap().denied += 1;
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            }
            if let Some(reason) = security_drop(&cfg, policy, &ip, dport) {
                self.log_event(
                    &cfg,
                    "deny",
                    src,
                    sport,
                    dst,
                    dport,
                    proto,
                    &in_zone,
                    &egress.zone,
                    Some(policy.id),
                    &reason,
                );
                self.stats.lock().unwrap().denied += 1;
                self.stats_bump(slot, |s| s.dropped += 1);
                return;
            }

            // Connection-table protection: global and per-source limits.
            {
                let sessions = self.sessions.lock().unwrap();
                let max = cfg.settings.max_sessions;
                let per_ip = cfg.settings.max_sessions_per_ip;
                let full = max > 0 && sessions.len() >= max;
                let source_full = per_ip > 0 && sessions.count_for_src(src) >= per_ip;
                drop(sessions);
                if full || source_full {
                    self.log_event(
                        cfg,
                        "deny",
                        src,
                        sport,
                        dst,
                        dport,
                        proto,
                        &in_zone,
                        &egress.zone,
                        Some(policy.id),
                        if full {
                            "session-table-full"
                        } else {
                            "per-source-session-limit"
                        },
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |s| s.dropped += 1);
                    return;
                }
            }

            let mut nat_src = None;
            // Source NAT: the policy's own `nat` flag, else the first matching
            // rule of the separate SNAT rulebase. DNAT-ed flows are left alone.
            let snat_ip = if nat_dst.is_some() {
                None
            } else if policy.nat {
                egress.address.map(|c| c.addr)
            } else {
                cfg.snat_match(&vdom, &in_zone, &egress.zone, src, dst).and_then(|rule| match rule.to {
                    crate::model::SnatTarget::Masquerade => egress.address.map(|c| c.addr),
                    crate::model::SnatTarget::Address(a) => Some(a),
                })
            };
            if let Some(nat_ip) = snat_ip {
                let mut nat_port = sport;
                if proto == PROTO_TCP || proto == PROTO_UDP {
                    let sessions = self.sessions.lock().unwrap();
                    nat_port = pick_port(&sessions, proto, nat_ip, dst, dport, sport);
                }
                nat_src = Some((nat_ip, nat_port));
            }
            let timeout = if proto == PROTO_TCP {
                cfg.settings.tcp_timeout.min(60)
            } else {
                timeout_for(proto, cfg)
            };
            let now = Instant::now();
            session = Some(Session {
                key: key.clone(),
                tcp: if proto == PROTO_TCP {
                    TcpState::SynSent
                } else {
                    TcpState::Established
                },
                fin_orig: false,
                fin_reply: false,
                in_index: in_iface.index,
                out_index: self.ifaces[slot_out].index,
                nat_src,
                nat_dst,
                policy_id: policy.id,
                shaper: policy.shaper.clone(),
                expires: now + Duration::from_secs(timeout),
                app: app0.clone(),
                app_tries: 0,
                src_zone: in_zone.clone(),
                dst_zone: egress.zone.clone(),
                app_buf: [Vec::new(), Vec::new()],
                app_seq: [None, None],
                user: user.clone(),
            });
            if let Some(s) = &session {
                self.sessions.lock().unwrap().insert(s.clone());
            }
            self.stats.lock().unwrap().accepted += 1;
            self.log_event(
                &cfg,
                "permit",
                src,
                sport,
                dst,
                dport,
                proto,
                &in_zone,
                &egress.zone,
                Some(policy.id),
                "",
            );
            if let Some((nat_ip, nat_port)) = session.as_ref().unwrap().nat_src {
                ip.set_src(nat_ip);
                if proto == PROTO_TCP || proto == PROTO_UDP {
                    ip.set_source_port(nat_port);
                }
                translated = true;
            }
        }

        if proto != PROTO_TCP {
            if let Some(s) = &session {
                // Refresh the idle timeout on activity. TCP flows are
                // refreshed by the state machine instead.
                let t = timeout_for(proto, cfg);
                self.sessions.lock().unwrap().touch(&s.key, t);
            }
        }
        let Some(out) = self.ifaces.get(out_slot) else {
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        };
        if out.fd < 0 && !out.tunnel && !cfg!(test) {
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        if ip.ttl() <= 1 {
            if let Some(quote) = &ttl_quote {
                self.send_icmp_error(slot, src_mac, quote, 11, 0);
            }
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        let total = ip.total_len();
        if let Some(s) = &session {
            self.bump_hit(&vdom, s.policy_id, total as u64);
        }
        if let Some(s) = &session {
            if s.key == key {
                if let Some(name) = &s.shaper {
                    if let Some(shaper) = cfg.shaper(name) {
                        if !self.shaper_allow(shaper, total + l3) {
                            self.log_event(
                                &cfg,
                                "deny",
                                src,
                                sport,
                                ip.dst(),
                                dport,
                                proto,
                                &in_zone,
                                &out.zone,
                                Some(s.policy_id),
                                "shaper",
                            );
                            self.stats.lock().unwrap().denied += 1;
                            self.stats_bump(slot, |st| st.dropped += 1);
                            return;
                        }
                    }
                }
            }
        }
        ip.set_ttl(ip.ttl() - 1);
        ip.recompute_header_checksum();
        if translated {
            ip.recompute_transport_checksum();
        }
        let dst_after = ip.dst();
        let next_hop = cfg
            .egress(&vdom, dst_after)
            .map(|(_, hop)| hop)
            .unwrap_or(dst_after);
        if out.tunnel {
            let packet = frame[l3..l3 + total].to_vec();
            let name = out.name.clone();
            self.stats_bump(out_slot, |s| {
                s.tx_packets += 1;
                s.tx_bytes += packet.len() as u64;
            });
            self.vpn_send(cfg, &name, &packet);
            return;
        }
        let Some(next_mac) = self.arp_lookup(&vdom, next_hop) else {
            self.stats.lock().unwrap().arp_misses += 1;
            self.arp_request(out_slot, next_hop);
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        };
        let out_mac = out.mac;
        let frame_len = l3 + total;
        write_mac(frame, 0, next_mac);
        write_mac(frame, 6, out_mac);
        self.send(out_slot, &frame[..frame_len]);
    }

    fn handle_local(&self, slot: usize, src_mac: [u8; 6], mut ip: Ipv4<'_>) {
        let src = ip.src();
        let dst = ip.dst();
        if ip.protocol() == PROTO_ICMP && ip.make_icmp_echo_reply() {
            let total = ip.total_len();
            ip.set_src(dst);
            ip.set_dst(src);
            ip.recompute_header_checksum();
            let Some(out) = self.ifaces.get(slot) else {
                return;
            };
            let out_mac = out.mac;
            let mut frame = Vec::with_capacity(ETH_HEADER_LEN + total);
            frame.extend_from_slice(&[0u8; ETH_HEADER_LEN]);
            frame.extend_from_slice(&ip.data[..total]);
            write_mac(&mut frame, 0, src_mac);
            write_mac(&mut frame, 6, out_mac);
            self.send(slot, &frame);
        } else {
            self.stats_bump(slot, |s| s.dropped += 1);
        }
    }

    fn send(&self, slot: usize, frame: &[u8]) {
        let Some(iface) = self.ifaces.get(slot) else {
            return;
        };
        if iface.fd < 0 {
            // Socket-less engines (tests) count and record what would have been sent.
            #[cfg(test)]
            {
                self.stats_bump(slot, |s| s.tx_packets += 1);
                self.sent.lock().unwrap().push((slot, frame.to_vec()));
            }
            return;
        }
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let etype = ethertype(frame);
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = etype.to_be();
        addr.sll_ifindex = iface.index;
        addr.sll_halen = 6;
        let dst = read_mac(frame, 0);
        addr.sll_addr[..6].copy_from_slice(&dst);
        let _ = unsafe {
            libc::sendto(
                iface.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        self.stats_bump(slot, |s| {
            s.tx_packets += 1;
            s.tx_bytes += frame.len() as u64;
        });
    }

    // ------------------------------------------------------------ WireGuard

    /// Rebuild tunnel devices whose configuration changed (keeping sessions
    /// of unchanged tunnels).
    pub fn vpn_sync(&self) {
        let cfg = self.cfg.read().unwrap();
        let mut vpn = self.vpn.lock().unwrap();
        vpn.retain(|name, dev| cfg.tunnels.iter().any(|t| &t.name == name && *t == dev.cfg));
        for t in &cfg.tunnels {
            vpn.entry(t.name.clone()).or_insert_with(|| crate::wg::Device::new(t.clone()));
        }
    }

    fn vpn_outputs(&self, cfg: &Config, tunnel: &str, outs: Vec<crate::wg::Output>) {
        let Some(t) = cfg.tunnels.iter().find(|t| t.name == tunnel) else { return };
        for out in outs {
            match out {
                crate::wg::Output::Network(endpoint, data) => self.send_udp(cfg, &t.vdom, t.listen_port, endpoint, &data),
                crate::wg::Output::Tunnel { packet, .. } => {
                    let Some(tslot) = self.iface_slot(tunnel) else { continue };
                    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + packet.len());
                    frame.extend_from_slice(&self.ifaces[tslot].mac);
                    frame.extend_from_slice(&[0u8; 6]);
                    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                    frame.extend_from_slice(&packet);
                    let mut queue = self.inject.lock().unwrap();
                    if queue.len() < 1024 {
                        queue.push((tslot, frame));
                    }
                }
            }
        }
    }

    fn vpn_receive(&self, cfg: &Config, tunnel: &str, from: std::net::SocketAddrV4, datagram: &[u8]) {
        let outs = match self.vpn.lock().unwrap().get_mut(tunnel) {
            Some(dev) => dev.receive(from, datagram, Instant::now()),
            None => return,
        };
        self.vpn_outputs(cfg, tunnel, outs);
    }

    fn vpn_send(&self, cfg: &Config, tunnel: &str, packet: &[u8]) {
        let outs = match self.vpn.lock().unwrap().get_mut(tunnel) {
            Some(dev) => dev.send(packet, Instant::now()),
            None => return,
        };
        self.vpn_outputs(cfg, tunnel, outs);
    }

    /// Run tunnel timers (handshake retries, keepalives, key expiry).
    pub fn vpn_tick(&self) {
        let cfg = self.cfg.read().unwrap();
        let now = Instant::now();
        let all: Vec<(String, Vec<crate::wg::Output>)> =
            self.vpn.lock().unwrap().iter_mut().map(|(name, dev)| (name.clone(), dev.tick(now))).collect();
        for (name, outs) in all {
            self.vpn_outputs(&cfg, &name, outs);
        }
    }

    pub fn vpn_status(&self) -> String {
        let vpn = self.vpn.lock().unwrap();
        if vpn.is_empty() {
            return "no WireGuard tunnels configured\n".into();
        }
        let mut names: Vec<&String> = vpn.keys().collect();
        names.sort();
        let mut out = String::new();
        for name in names {
            let dev = &vpn[name];
            out.push_str(&format!(
                "tunnel {name}: public-key {} listen-port {} vdom {}\n",
                crate::wg::b64_encode(&dev.public_key()),
                dev.cfg.listen_port,
                dev.cfg.vdom
            ));
            for line in dev.status() {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }

    /// Send a UDP datagram from one of our addresses, routed and ARP-resolved
    /// like forwarded traffic.
    fn send_udp(&self, cfg: &Config, vdom: &str, sport: u16, to: std::net::SocketAddrV4, data: &[u8]) {
        let Some((egress, hop)) = cfg.egress(vdom, *to.ip()) else { return };
        if egress.tunnel {
            return; // never send a tunnel's own traffic into a tunnel
        }
        let (Some(src), Some(slot)) = (egress.address.map(|c| c.addr), self.iface_slot(&egress.name)) else { return };
        let Some(mac) = self.arp_lookup(vdom, hop) else {
            self.stats.lock().unwrap().arp_misses += 1;
            self.arp_request(slot, hop);
            return;
        };
        let udp_len = 8 + data.len();
        let total = 20 + udp_len;
        if total > 65_535 {
            return;
        }
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + total);
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&self.ifaces[slot].mac);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&to.ip().octets());
        frame.extend_from_slice(&sport.to_be_bytes());
        frame.extend_from_slice(&to.port().to_be_bytes());
        frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(data);
        if let Some(mut ip) = Ipv4::parse(&mut frame[ETH_HEADER_LEN..]) {
            ip.recompute_header_checksum();
            ip.recompute_transport_checksum();
        }
        self.send(slot, &frame);
    }

    /// Announce every interface address (gratuitous ARP) after becoming the
    /// HA active unit, three times to survive a lost frame.
    pub fn gratuitous_arp(&self) {
        for _ in 0..3 {
            for (slot, iface) in self.ifaces.iter().enumerate() {
                if let Some(cidr) = iface.address {
                    self.arp_request(slot, cidr.addr);
                }
            }
        }
    }

    fn arp_request(&self, slot: usize, target: Ipv4Addr) {
        let Some(iface) = self.ifaces.get(slot) else {
            return;
        };
        let Some(cidr) = iface.address else {
            return;
        };
        let mut frame = vec![0u8; 64];
        let n = build_arp(
            &mut frame, [0xff; 6], iface.mac, 1, iface.mac, cidr.addr, [0; 6], target,
        );
        if n > 0 {
            self.send(slot, &frame[..n]);
        }
    }

    fn arp_lookup(&self, vdom: &str, ip: Ipv4Addr) -> Option<[u8; 6]> {
        self.arp
            .lock()
            .unwrap()
            .get(&(vdom.to_string(), ip))
            .filter(|(_, seen)| seen.elapsed() < ARP_TTL)
            .map(|(mac, _)| *mac)
    }

    fn iface_slot(&self, name: &str) -> Option<usize> {
        self.ifaces.iter().position(|i| i.name == name)
    }

    fn slot_for_index(&self, index: i32) -> Option<usize> {
        self.by_index.get(&index).copied()
    }
}

#[path = "dataplane_v6.rs"]
pub mod v6;

fn devices(cfg: &Config) -> HashMap<String, crate::wg::Device> {
    cfg.tunnels.iter().map(|t| (t.name.clone(), crate::wg::Device::new(t.clone()))).collect()
}

fn json_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

fn security_drop(
    cfg: &Config,
    policy: &crate::model::Policy,
    ip: &Ipv4<'_>,
    dport: u16,
) -> Option<String> {
    let _ = dport;
    security_drop_payload(cfg, policy, crate::inspect::payload(ip))
}

/// URL filter, IPS and AV verdict on one payload (either address family).
fn security_drop_payload(cfg: &Config, policy: &crate::model::Policy, payload: &[u8]) -> Option<String> {
    let payload = &payload[..payload.len().min(cfg.settings.max_inspection_bytes)];
    // Inspection is not tied to a well-known port: HTTP and TLS are
    // recognised from the payload so non-standard listeners still work.
    let host = crate::inspect::http_host(payload).or_else(|| crate::inspect::tls_sni(payload));
    let (url, ips, av) = cfg.profiles(policy);
    if let Some(name) = url {
        if let (Some(filter), Some(host)) = (cfg.url_filter(name), host.as_deref()) {
            if filter.blocked(host) {
                return Some(format!("url-filter {name}: {host}"));
            }
        }
    }
    if let Some(name) = ips {
        if cfg.signature_hit(name, false, payload).is_some() {
            return Some(format!("ips {name}"));
        }
    }
    if let Some(name) = av {
        if cfg.signature_hit(name, true, payload).is_some() {
            return Some(format!("av {name}"));
        }
    }
    None
}

fn reverse_key(session: &Session) -> SessionKey {
    let key = session.key.clone();
    let (reply_src, reply_sport) = session.nat_dst.unwrap_or((key.dst, key.dport));
    let (reply_dst, reply_dport) = session.nat_src.unwrap_or((key.src, key.sport));
    SessionKey {
        vdom: key.vdom.clone(),
        proto: key.proto,
        src: reply_src,
        sport: reply_sport,
        dst: reply_dst,
        dport: reply_dport,
    }
}

fn timeout_for(proto: u8, cfg: &Config) -> u64 {
    match proto {
        PROTO_TCP => cfg.settings.tcp_timeout,
        PROTO_UDP => cfg.settings.udp_timeout,
        PROTO_ICMP => cfg.settings.icmp_timeout,
        _ => 60,
    }
}

fn pick_port(
    sessions: &Sessions,
    proto: u8,
    nat_ip: Ipv4Addr,
    dst: Ipv4Addr,
    dport: u16,
    seed: u16,
) -> u16 {
    let mut port = 20000u16 + ((seed as u32 * 31) % 40000) as u16;
    for _ in 0..1000 {
        if port >= 1024 && !sessions.port_in_use(proto, nat_ip, port, dst, dport) {
            return port;
        }
        port = if port == 65535 { 20000 } else { port + 1 };
    }
    seed
}

fn read_sysfs_mac(name: &str) -> Option<[u8; 6]> {
    let text = fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    crate::model::parse_mac(text.trim()).ok()
}

fn open_socket(ifindex: i32) -> std::io::Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;

    fn key(sport: u16) -> SessionKey {
        SessionKey {
            vdom: "root".to_string(),
            proto: PROTO_TCP,
            src: "10.0.0.2".parse().unwrap(),
            sport,
            dst: "192.0.2.10".parse().unwrap(),
            dport: 80,
        }
    }

    fn session(sport: u16) -> Session {
        Session {
            key: key(sport),
            tcp: TcpState::SynSent,
            fin_orig: false,
            fin_reply: false,
            in_index: 1,
            out_index: 2,
            nat_src: None,
            nat_dst: None,
            policy_id: 10,
            shaper: None,
            expires: Instant::now() + Duration::from_secs(60),
            app: None,
            app_tries: 0,
            src_zone: "lan".into(),
            dst_zone: "wan".into(),
            app_buf: [Vec::new(), Vec::new()],
            app_seq: [None, None],
            user: None,
        }
    }

    #[test]
    fn handshake_reaches_established() {
        let mut s = session(1000);
        assert!(tcp_track(&mut s, true, SYN));
        assert!(tcp_track(&mut s, false, SYN | ACK));
        assert_eq!(s.tcp, TcpState::SynRecv);
        assert!(tcp_track(&mut s, true, ACK));
        assert_eq!(s.tcp, TcpState::Established);
        assert!(tcp_track(&mut s, true, ACK));
        assert!(tcp_track(&mut s, false, ACK));
    }

    #[test]
    fn ack_before_handshake_is_invalid() {
        let mut s = session(1001);
        assert!(!tcp_track(&mut s, true, ACK));
        assert!(!tcp_track(&mut s, false, ACK));
        assert_eq!(s.tcp, TcpState::SynSent);
    }

    #[test]
    fn syn_inside_established_flow_is_invalid() {
        let mut s = session(1002);
        s.tcp = TcpState::Established;
        assert!(!tcp_track(&mut s, true, SYN));
        assert!(!tcp_track(&mut s, false, SYN | ACK));
    }

    #[test]
    fn both_fins_reach_time_wait() {
        let mut s = session(1003);
        s.tcp = TcpState::Established;
        assert!(tcp_track(&mut s, true, FIN | ACK));
        assert_eq!(s.tcp, TcpState::Closing);
        assert!(tcp_track(&mut s, false, ACK));
        assert!(tcp_track(&mut s, false, FIN | ACK));
        assert_eq!(s.tcp, TcpState::TimeWait);
        assert!(tcp_track(&mut s, true, ACK));
    }

    #[test]
    fn rst_closes_and_blocks_further_traffic() {
        let mut s = session(1004);
        s.tcp = TcpState::Established;
        assert!(tcp_track(&mut s, false, RST | ACK));
        assert_eq!(s.tcp, TcpState::Closed);
        assert!(!tcp_track(&mut s, true, ACK));
    }

    #[test]
    fn new_syn_reopens_closed_or_time_wait_flow() {
        let mut s = session(1005);
        s.tcp = TcpState::TimeWait;
        s.fin_orig = true;
        s.fin_reply = true;
        assert!(tcp_track(&mut s, true, SYN));
        assert_eq!(s.tcp, TcpState::SynSent);
        assert!(!s.fin_orig && !s.fin_reply);
        s.tcp = TcpState::Closed;
        assert!(!tcp_track(&mut s, false, SYN | ACK));
        assert!(tcp_track(&mut s, true, SYN));
    }

    #[test]
    fn flag_sanity_rejects_scan_patterns() {
        assert!(tcp_flags_sane(SYN));
        assert!(tcp_flags_sane(SYN | ACK));
        assert!(tcp_flags_sane(FIN | ACK));
        assert!(tcp_flags_sane(RST));
        assert!(!tcp_flags_sane(0));
        assert!(!tcp_flags_sane(SYN | FIN));
        assert!(!tcp_flags_sane(SYN | RST));
        assert!(!tcp_flags_sane(FIN | RST));
    }

    #[test]
    fn session_indexes_follow_insert_and_purge() {
        let mut table = Sessions::default();
        let mut a = session(2000);
        a.nat_src = Some(("203.0.113.2".parse().unwrap(), 20001));
        let src = a.key.src;
        table.insert(a.clone());
        table.insert(session(2001));
        assert_eq!(table.len(), 2);
        assert_eq!(table.count_for_src(src), 2);
        assert!(table.port_in_use(
            PROTO_TCP,
            "203.0.113.2".parse().unwrap(),
            20001,
            a.key.dst,
            a.key.dport
        ));
        // Re-inserting the same key replaces it without double counting.
        table.insert(a.clone());
        assert_eq!(table.len(), 2);
        assert_eq!(table.count_for_src(src), 2);
        table.touch(&a.key, 0);
        table.purge(Instant::now() + Duration::from_millis(1));
        assert_eq!(table.len(), 1);
        assert_eq!(table.count_for_src(src), 1);
        assert!(!table.port_in_use(
            PROTO_TCP,
            "203.0.113.2".parse().unwrap(),
            20001,
            a.key.dst,
            a.key.dport
        ));
    }

    #[test]
    fn expired_sessions_are_not_found() {
        let mut table = Sessions::default();
        let s = session(3000);
        table.insert(s.clone());
        assert!(table.lookup(s.key.clone()).is_some());
        table.touch(&s.key, 0);
        std::thread::sleep(Duration::from_millis(2));
        assert!(table.lookup(s.key.clone()).is_none());
    }

    #[test]
    fn track_tcp_applies_state_timeouts() {
        let mut table = Sessions::default();
        let s = session(4000);
        let k = s.key.clone();
        table.insert(s);
        assert!(table.track_tcp(&k, true, SYN, 300));
        assert!(table.track_tcp(&k, false, SYN | ACK, 300));
        assert!(table.track_tcp(&k, true, ACK, 300));
        let est = table.lookup(k.clone()).unwrap();
        assert_eq!(est.tcp, TcpState::Established);
        assert!(est.expires > Instant::now() + Duration::from_secs(200));
        assert!(table.track_tcp(&k, false, RST, 300));
        let closed = table.lookup(k).unwrap();
        assert!(closed.expires <= Instant::now() + Duration::from_secs(11));
    }
}

/// End-to-end tests of the packet path with synthetic frames: no sockets,
/// interfaces get fake indexes and `send` only counts.
#[cfg(test)]
mod engine_tests {
    use super::*;
    use crate::packet::Ipv4;

    const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
    const SERVER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x20];

    impl Engine {
        pub(crate) fn for_test(cfg: Config) -> Engine {
            let snapshot = cfg.clone();
            let mut ifaces = Vec::new();
            let mut by_index = HashMap::new();
            for (n, i) in cfg.interfaces.iter().enumerate() {
                by_index.insert(n as i32 + 1, ifaces.len());
                ifaces.push(Iface {
                    name: i.name.clone(),
                    vdom: i.vdom.clone(),
                    zone: i.zone.clone(),
                    index: n as i32 + 1,
                    mac: [2, 0, 0, 0, 1, n as u8 + 1],
                    address: i.address,
                    fd: -1,
                    tunnel: i.tunnel,
                });
            }
            let mut stats = Stats::default();
            for i in &ifaces {
                stats.ifaces.entry(i.name.clone()).or_default();
            }
            Engine {
                cfg: Arc::new(RwLock::new(cfg)),
                stats: Arc::new(Mutex::new(stats)),
                sessions: Arc::new(Mutex::new(Sessions::default())),
                arp: Arc::new(Mutex::new(HashMap::new())),
                ifaces,
                by_index,
                started: Instant::now(),
                config_path: None,
                flood: Mutex::new(HashMap::new()),
                shapers: Mutex::new(HashMap::new()),
                source_packets: Mutex::new(HashMap::new()),
                logs: Mutex::new(VecDeque::new()),
                hits: Mutex::new(HashMap::new()),
                candidate: Mutex::new(None),
                history: Mutex::new(Vec::new()),
                revisions: Mutex::new(1),
                users: Mutex::new(HashMap::new()),
                ha_active: AtomicBool::new(true),
                ha_suspended: AtomicBool::new(false),
                ha: Mutex::new(crate::ha::Status::default()),
                vpn: Mutex::new(devices(&snapshot)),
                inject: Mutex::new(Vec::new()),
                sessions6: Mutex::new(v6::Sessions6::default()),
                nd: Mutex::new(HashMap::new()),
                sent: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn learn(&self, vdom: &str, ip: &str, mac: [u8; 6]) {
            self.arp.lock().unwrap().insert((vdom.into(), ip.parse().unwrap()), (mac, Instant::now() + Duration::from_secs(3600)));
        }

        pub(crate) fn tx(&self, iface: &str) -> u64 {
            self.stats.lock().unwrap().ifaces[iface].tx_packets
        }

        fn last_log(&self) -> String {
            self.logs.lock().unwrap().back().cloned().unwrap_or_default()
        }
    }

    /// Ethernet + IPv4 + TCP frame with valid checksums, sequence number 1.
    fn tcp(to_mac: [u8; 6], from_mac: [u8; 6], src: &str, sport: u16, dst: &str, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        tcp_seq(to_mac, from_mac, src, sport, dst, dport, flags, 1, payload)
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_seq(to_mac: [u8; 6], from_mac: [u8; 6], src: &str, sport: u16, dst: &str, dport: u16, flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&to_mac);
        f.extend_from_slice(&from_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let total = 20 + 20 + payload.len();
        f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        f.extend_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        let mut ip = Ipv4::parse(&mut f[14..]).unwrap();
        ip.recompute_header_checksum();
        ip.recompute_transport_checksum();
        f
    }

    const SYN: u8 = 0x02;
    const SYNACK: u8 = 0x12;
    const ACK: u8 = 0x10;
    const PSHACK: u8 = 0x18;

    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let list_len = (name.len() + 3) as u16;
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Engine with trust (lan, 10.0.0.0/24) and untrust (wan, 203.0.113.0/24).
    fn engine(policies: &str) -> Engine {
        let text = format!(
            "system logging on\n\
             interface lan zone trust address 10.0.0.1/24\n\
             interface wan zone untrust address 203.0.113.1/24\n\
             {policies}"
        );
        let e = Engine::for_test(Config::parse(&text).unwrap());
        e.learn("root", "203.0.113.10", SERVER_MAC);
        e.learn("root", "10.0.0.10", CLIENT_MAC);
        e
    }

    /// Run a TCP handshake from 10.0.0.10:sport to 203.0.113.10:dport, then
    /// send `payload`. Returns how many packets left on the wan side.
    fn flow(e: &Engine, sport: u16, dport: u16, payload: &[u8]) -> u64 {
        let lan = e.ifaces[0].mac;
        let wan = e.ifaces[1].mac;
        let before = e.tx("wan");
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", sport, "203.0.113.10", dport, SYN, &[]));
        // The server answers the address it saw: the NAT address if SNAT applied.
        let (reply_ip, reply_port) = e
            .sessions
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|s| s.key.sport == sport)
            .and_then(|s| s.nat_src)
            .map(|(ip, port)| (ip.to_string(), port))
            .unwrap_or(("10.0.0.10".to_string(), sport));
        e.handle(1, &mut tcp(wan, SERVER_MAC, "203.0.113.10", dport, &reply_ip, reply_port, SYNACK, &[]));
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", sport, "203.0.113.10", dport, ACK, &[]));
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", sport, "203.0.113.10", dport, PSHACK, payload));
        e.tx("wan") - before
    }

    fn session_app(e: &Engine, sport: u16) -> Option<String> {
        e.sessions.lock().unwrap().snapshot().into_iter().find(|s| s.key.sport == sport).and_then(|s| s.app)
    }

    #[test]
    fn app_id_blocks_social_media_after_handshake_and_allows_the_rest() {
        let e = engine(
            "policy 10 trust untrust any any tcp any deny app category:social-networking\n\
             policy 20 trust untrust any any tcp any permit nat\n",
        );
        // facebook: SYN and ACK pass under policy 20, the ClientHello is identified and dropped.
        assert_eq!(flow(&e, 40000, 443, &client_hello("www.facebook.com")), 2);
        assert!(e.last_log().contains("app facebook: policy 10 deny"), "{}", e.last_log());
        assert_eq!(session_app(&e, 40000).as_deref(), Some("facebook"));

        // github: all four packets pass and the session is labelled.
        assert_eq!(flow(&e, 40001, 443, &client_hello("github.com")), 3);
        assert_eq!(session_app(&e, 40001).as_deref(), Some("github"));
    }

    #[test]
    fn application_default_enforces_standard_ports() {
        let e = engine("policy 10 trust untrust any any tcp application-default permit app ssl,web-browsing\n");
        assert_eq!(flow(&e, 40010, 443, &client_hello("intranet.example")), 3);
        assert_eq!(session_app(&e, 40010).as_deref(), Some("ssl"));
        // TLS on 8443 is not ssl's default port: refused at the SYN.
        assert_eq!(flow(&e, 40011, 8443, &client_hello("intranet.example")), 0);
        // HTTP sent to 443 is web-browsing on a non-default port: cut off after App-ID.
        assert_eq!(flow(&e, 40012, 443, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), 2);
        assert!(e.last_log().contains("app web-browsing: interzone-default deny"), "{}", e.last_log());
    }

    #[test]
    fn unidentified_flows_become_unknown_tcp_after_max_tries() {
        let e = engine("policy 10 trust untrust any any tcp any permit app ssl\n");
        let lan = e.ifaces[0].mac;
        assert_eq!(flow(&e, 40020, 443, b"not a known protocol"), 3);
        for _ in 1..crate::appid::MAX_TRIES {
            e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40020, "203.0.113.10", 443, PSHACK, b"still nothing"));
        }
        assert_eq!(session_app(&e, 40020).as_deref(), Some("unknown-tcp"));
        assert!(e.last_log().contains("app unknown-tcp: interzone-default deny"), "{}", e.last_log());
    }

    #[test]
    fn split_client_hello_is_reassembled_before_app_id_decides() {
        let e = engine(
            "policy 10 trust untrust any any tcp any deny app github\n\
             policy 20 trust untrust any any tcp any permit app ssl\n",
        );
        let lan = e.ifaces[0].mac;
        // Handshake with an empty payload, then the hello in three pieces.
        assert_eq!(flow(&e, 40040, 443, &[]), 3, "handshake and an empty segment pass");
        let hello = client_hello("api.github.com");
        let (a, b) = (30, 60);
        let send = |seq: u32, bytes: &[u8]| {
            e.handle(0, &mut tcp_seq(lan, CLIENT_MAC, "10.0.0.10", 40040, "203.0.113.10", 443, PSHACK, seq, bytes));
        };
        send(1, &hello[..a]);
        assert_eq!(session_app(&e, 40040), None, "still pending after the first piece");
        send(1, &hello[..a]); // a retransmission adds nothing
        send(1 + a as u32, &hello[a..b]);
        assert_eq!(session_app(&e, 40040), None);
        send(1 + b as u32, &hello[b..]);
        // Without reassembly the first piece would have been labelled plain ssl
        // and allowed by policy 20.
        assert_eq!(session_app(&e, 40040).as_deref(), Some("github"));
        assert!(e.last_log().contains("app github: policy 10 deny"), "{}", e.last_log());
    }

    #[test]
    fn default_rules_govern_unmatched_traffic() {
        let text = "system logging on\n\
             interface lan zone trust address 10.0.0.1/24\n\
             interface lan2 zone trust address 10.0.1.1/24\n\
             interface wan zone untrust address 203.0.113.1/24\n\
             default-rule intrazone allow\n";
        let e = Engine::for_test(Config::parse(text).unwrap());
        e.learn("root", "10.0.1.10", SERVER_MAC);
        e.learn("root", "203.0.113.10", SERVER_MAC);
        let lan = e.ifaces[0].mac;
        // trust -> trust: allowed by intrazone-default, and the flow lives on.
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40050, "10.0.1.10", 22, SYN, &[]));
        assert_eq!(e.tx("lan2"), 1);
        let s = e.sessions.lock().unwrap().snapshot().into_iter().find(|s| s.key.sport == 40050).unwrap();
        assert_eq!(s.policy_id, crate::model::INTRAZONE_ID);
        // trust -> untrust: interzone-default deny, logged by name.
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40051, "203.0.113.10", 22, SYN, &[]));
        assert_eq!(e.tx("wan"), 0);
        assert!(e.last_log().contains("interzone-default"), "{}", e.last_log());
        assert!(e.policy_hits().contains_key(&("root".to_string(), crate::model::INTERZONE_ID)));
    }

    #[test]
    fn user_id_login_changes_which_policy_applies() {
        let e = engine(
            "user-group admins alice\n\
             policy 10 trust untrust any any tcp 22 permit user admins\n",
        );
        let lan = e.ifaces[0].mac;
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40060, "203.0.113.10", 22, SYN, &[]));
        assert_eq!(e.tx("wan"), 0, "no mapping: unknown user, denied");
        e.user_login("10.0.0.10".parse().unwrap(), "alice", Some(Duration::from_secs(600))).unwrap();
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40061, "203.0.113.10", 22, SYN, &[]));
        assert_eq!(e.tx("wan"), 1, "alice is in admins");
        let s = e.sessions.lock().unwrap().snapshot().into_iter().find(|s| s.key.sport == 40061).unwrap();
        assert_eq!(s.user.as_deref(), Some("alice"));
        assert!(e.user_logout("10.0.0.10".parse().unwrap()));
        e.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 40062, "203.0.113.10", 22, SYN, &[]));
        assert_eq!(e.tx("wan"), 1, "logged out");
        e.user_login("10.0.0.10".parse().unwrap(), "alice", Some(Duration::from_millis(1))).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(e.user_for(&e.cfg.read().unwrap(), "10.0.0.10".parse().unwrap()), None, "expired");
    }

    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn ha_engine(name: &str, priority: u8, me: u16, peer: u16, dir: &std::path::Path) -> Arc<Engine> {
        let text = format!(
            "system hostname {name}\nsystem logging on\n\
             ha mode active-passive\nha bind 127.0.0.1:{me}\nha peer 127.0.0.1:{peer}\n\
             ha secret test-secret-0123456789\nha priority {priority}\nha hello 20\nha dead 150\n\
             interface lan zone trust address 10.0.0.1/24\n\
             interface wan zone untrust address 203.0.113.1/24\n\
             policy 20 trust untrust any any tcp any permit\n"
        );
        let mut e = Engine::for_test(Config::parse(&text).unwrap());
        let path = dir.join(format!("{name}.conf"));
        std::fs::write(&path, &text).unwrap();
        e.config_path = Some(path);
        e.learn("root", "203.0.113.10", SERVER_MAC);
        e.learn("root", "10.0.0.10", CLIENT_MAC);
        Arc::new(e)
    }

    /// Tick both agents (or just the ones alive) for a while.
    fn run_for(agents: &mut [&mut crate::ha::Agent], ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end {
            for a in agents.iter_mut() {
                a.tick(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn ha_pair_elects_syncs_and_fails_over() {
        use crate::ha::{Agent, Role};
        let dir = std::env::temp_dir().join(format!("ha-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (pa, pb) = (free_port(), free_port());
        let a = ha_engine("fw-a", 200, pa, pb, &dir);
        let b = ha_engine("fw-b", 100, pb, pa, &dir);
        let mut agent_a = Agent::new(a.clone(), a.cfg.read().unwrap().ha.clone()).unwrap();
        let mut agent_b = Agent::new(b.clone(), b.cfg.read().unwrap().ha.clone()).unwrap();

        // 1. Election: the higher priority serves, the other is passive and drops.
        run_for(&mut [&mut agent_a, &mut agent_b], 400);
        assert_eq!((agent_a.role(), agent_b.role()), (Role::Active, Role::Passive));
        let lan = b.ifaces[0].mac;
        b.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 41000, "203.0.113.10", 22, SYN, &[]));
        assert_eq!(b.tx("wan"), 0, "passive unit forwards nothing");

        // 2. A flow through the active unit, then session and config sync.
        let lan_a = a.ifaces[0].mac;
        let wan_a = a.ifaces[1].mac;
        a.handle(0, &mut tcp(lan_a, CLIENT_MAC, "10.0.0.10", 41001, "203.0.113.10", 22, SYN, &[]));
        a.handle(1, &mut tcp(wan_a, SERVER_MAC, "203.0.113.10", 22, "10.0.0.10", 41001, SYNACK, &[]));
        a.handle(0, &mut tcp(lan_a, CLIENT_MAC, "10.0.0.10", 41001, "203.0.113.10", 22, ACK, &[]));
        let mut next = a.cfg.read().unwrap().clone();
        next.policies[0].name = Some("synced-name".into());
        a.apply_config(&next).unwrap();
        run_for(&mut [&mut agent_a, &mut agent_b], 2600);
        let synced = b.sessions.lock().unwrap().snapshot();
        assert!(synced.iter().any(|s| s.key.sport == 41001 && s.tcp == TcpState::Established), "{synced:?}");
        let cfg_b = b.cfg.read().unwrap().clone();
        assert_eq!(cfg_b.policies[0].name.as_deref(), Some("synced-name"), "config synchronized");
        assert_eq!(cfg_b.settings.hostname, "fw-b", "hostname is node-local");
        assert_eq!(cfg_b.ha.priority, 100, "HA settings are node-local");
        assert!(b.ha.lock().unwrap().in_sync);

        // 3. The active unit dies: the passive one takes over, announces
        //    itself and carries the established flow without a new handshake.
        let wan_tx_before = b.tx("wan");
        run_for(&mut [&mut agent_b], 400);
        assert_eq!(agent_b.role(), Role::Active);
        assert!(b.tx("wan") >= wan_tx_before + 3, "gratuitous ARP on failover");
        let before = b.tx("wan");
        b.handle(0, &mut tcp(lan, CLIENT_MAC, "10.0.0.10", 41001, "203.0.113.10", 22, PSHACK, b"SSH-2.0-test\r\n"));
        assert_eq!(b.tx("wan"), before + 1, "mid-flow packet forwarded thanks to session sync");

        // 4. The old unit restarts (new node id, Init): without preempt it
        //    stays passive even though its priority is higher...
        drop(agent_a);
        let mut agent_a = Agent::new(a.clone(), a.cfg.read().unwrap().ha.clone()).unwrap();
        run_for(&mut [&mut agent_a, &mut agent_b], 400);
        assert_eq!((agent_a.role(), agent_b.role()), (Role::Passive, Role::Active));
        // ...until the active unit is suspended (manual failover).
        b.ha_suspended.store(true, Ordering::SeqCst);
        run_for(&mut [&mut agent_a, &mut agent_b], 400);
        assert_eq!((agent_a.role(), agent_b.role()), (Role::Active, Role::Suspended));
        assert!(a.ha.lock().unwrap().text().contains("This unit: active"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ha_split_brain_resolves_by_rank() {
        use crate::ha::{Agent, Role};
        let dir = std::env::temp_dir().join(format!("ha-split-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (pa, pb) = (free_port(), free_port());
        let a = ha_engine("fw-a", 200, pa, pb, &dir);
        let b = ha_engine("fw-b", 100, pb, pa, &dir);
        let mut agent_a = Agent::new(a.clone(), a.cfg.read().unwrap().ha.clone()).unwrap();
        let mut agent_b = Agent::new(b.clone(), b.cfg.read().unwrap().ha.clone()).unwrap();
        // The HA link is down: each unit goes active alone.
        run_for(&mut [&mut agent_a], 300);
        run_for(&mut [&mut agent_b], 300);
        assert_eq!((agent_a.role(), agent_b.role()), (Role::Active, Role::Active));
        // Link restored: the lower-ranked unit steps down.
        run_for(&mut [&mut agent_a, &mut agent_b], 300);
        assert_eq!((agent_a.role(), agent_b.role()), (Role::Active, Role::Passive));
        assert!(!b.ha_active.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Move frames one engine sent on `from_slot` into another engine's `to_slot`.
    fn pump(from: &Engine, from_slot: usize, to: &Engine, to_slot: usize) -> usize {
        let frames: Vec<Vec<u8>> = {
            let mut sent = from.sent.lock().unwrap();
            let (out, keep): (Vec<_>, Vec<_>) = sent.drain(..).partition(|(s, _)| *s == from_slot);
            *sent = keep;
            out.into_iter().map(|(_, f)| f).collect()
        };
        let n = frames.len();
        for mut f in frames {
            to.handle(to_slot, &mut f);
        }
        n
    }

    fn sent_ipv4(e: &Engine, slot: usize) -> Vec<(Ipv4Addr, Ipv4Addr, u8)> {
        e.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, f)| *s == slot && f.len() > 34 && f[12..14] == [8, 0])
            .map(|(_, f)| (Ipv4Addr::new(f[26], f[27], f[28], f[29]), Ipv4Addr::new(f[30], f[31], f[32], f[33]), f[23]))
            .collect()
    }

    /// Two sites joined by WireGuard over a simulated internet.
    fn vpn_sites(b_allows_vpn: bool) -> (Engine, Engine) {
        let (ka, kb) = (crate::wg::genkey(), crate::wg::genkey());
        let (pa, pb) = (crate::wg::pubkey(&ka).unwrap(), crate::wg::pubkey(&kb).unwrap());
        let a = format!(
            "system logging on\n\
             interface lan zone trust address 10.1.0.1/24\n\
             interface wan zone untrust address 203.0.113.1/24\n\
             vpn wireguard wg0 private-key {ka} listen-port 51820 address 10.99.0.1/24 zone vpn\n\
             vpn wireguard-peer wg0 site-b public-key {pb} allowed-ips 10.99.0.2/32,10.2.0.0/24 endpoint 203.0.113.2:51820\n\
             policy 10 trust vpn any any any any permit\n\
             policy 20 vpn trust any any any any permit\n"
        );
        let b_policy = if b_allows_vpn { "policy 10 vpn trust any any any any permit\n" } else { "" };
        let b = format!(
            "system logging on\n\
             interface lan zone trust address 10.2.0.1/24\n\
             interface wan zone untrust address 203.0.113.2/24\n\
             vpn wireguard wg0 private-key {kb} listen-port 51820 address 10.99.0.2/24 zone vpn\n\
             vpn wireguard-peer wg0 site-a public-key {pa} allowed-ips 10.99.0.1/32,10.1.0.0/24 endpoint 203.0.113.1:51820\n\
             {b_policy}policy 20 trust vpn any any any any permit\n"
        );
        let ea = Engine::for_test(Config::parse(&a).unwrap());
        let eb = Engine::for_test(Config::parse(&b).unwrap());
        ea.learn("root", "203.0.113.2", eb.ifaces[1].mac);
        eb.learn("root", "203.0.113.1", ea.ifaces[1].mac);
        ea.learn("root", "10.1.0.10", CLIENT_MAC);
        eb.learn("root", "10.2.0.10", SERVER_MAC);
        (ea, eb)
    }

    #[test]
    fn wireguard_site_to_site_carries_a_tcp_flow_under_policy() {
        let (a, b) = vpn_sites(true);
        let (lan_a, lan_b) = (a.ifaces[0].mac, b.ifaces[0].mac);
        // Client at site A opens TCP to the server at site B.
        a.handle(0, &mut tcp(lan_a, CLIENT_MAC, "10.1.0.10", 45000, "10.2.0.10", 443, SYN, &[]));
        let wan = sent_ipv4(&a, 1);
        assert_eq!(wan.len(), 1, "SYN queued; one handshake initiation on the wire");
        assert_eq!(wan[0], ("203.0.113.1".parse().unwrap(), "203.0.113.2".parse().unwrap(), PROTO_UDP));
        // Initiation A->B, response B->A, encrypted SYN A->B.
        assert_eq!(pump(&a, 1, &b, 1), 1);
        assert_eq!(pump(&b, 1, &a, 1), 1);
        assert_eq!(pump(&a, 1, &b, 1), 1);
        let delivered = sent_ipv4(&b, 0);
        assert_eq!(delivered, vec![("10.1.0.10".parse().unwrap(), "10.2.0.10".parse().unwrap(), PROTO_TCP)], "decrypted SYN delivered to site B's LAN");
        // The server answers; the SYN-ACK goes back through both tunnels.
        b.handle(0, &mut tcp(lan_b, SERVER_MAC, "10.2.0.10", 443, "10.1.0.10", 45000, SYNACK, &[]));
        assert_eq!(pump(&b, 1, &a, 1), 1);
        let back = sent_ipv4(&a, 0);
        assert_eq!(back, vec![("10.2.0.10".parse().unwrap(), "10.1.0.10".parse().unwrap(), PROTO_TCP)], "SYN-ACK delivered to site A's LAN");
        // Both firewalls track the flow, with the tunnel as one side.
        let sa = a.sessions.lock().unwrap().snapshot();
        assert!(sa.iter().any(|s| s.key.sport == 45000 && s.dst_zone == "vpn"));
        let sb = b.sessions.lock().unwrap().snapshot();
        assert!(sb.iter().any(|s| s.key.sport == 45000 && s.src_zone == "vpn" && s.tcp == TcpState::SynRecv));
        assert!(a.vpn_status().contains("peer site-b") && !a.vpn_status().contains("(no session)"));
    }

    #[test]
    fn wireguard_traffic_obeys_the_receiving_firewalls_policy() {
        let (a, b) = vpn_sites(false);
        let lan_a = a.ifaces[0].mac;
        a.handle(0, &mut tcp(lan_a, CLIENT_MAC, "10.1.0.10", 45001, "10.2.0.10", 22, SYN, &[]));
        pump(&a, 1, &b, 1);
        pump(&b, 1, &a, 1);
        pump(&a, 1, &b, 1);
        assert!(sent_ipv4(&b, 0).is_empty(), "no vpn->trust policy on B: dropped after decryption");
        assert!(b.last_log().contains("interzone-default"), "{}", b.last_log());
    }

    // ---------------------------------------------------------------- IPv6

    fn ip6(s: &str) -> std::net::Ipv6Addr {
        s.parse().unwrap()
    }

    fn frame6(to: [u8; 6], from: [u8; 6], packet: Vec<u8>) -> Vec<u8> {
        let mut f = to.to_vec();
        f.extend_from_slice(&from);
        f.extend_from_slice(&[0x86, 0xdd]);
        f.extend_from_slice(&packet);
        f
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp6(to: [u8; 6], from: [u8; 6], src: &str, sport: u16, dst: &str, dport: u16, flags: u8, hop: u8, payload: &[u8]) -> Vec<u8> {
        let mut l4 = sport.to_be_bytes().to_vec();
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        l4.extend_from_slice(payload);
        frame6(to, from, v6::build(ip6(src), ip6(dst), PROTO_TCP, hop, l4, Some(16)))
    }

    fn icmp6(to: [u8; 6], from: [u8; 6], src: &str, dst: &str, hop: u8, body: Vec<u8>) -> Vec<u8> {
        frame6(to, from, v6::build(ip6(src), ip6(dst), v6::PROTO_ICMPV6, hop, body, Some(2)))
    }

    fn ns_body(target: &str, mac: [u8; 6]) -> Vec<u8> {
        let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&ip6(target).octets());
        b.extend_from_slice(&[1, 1]);
        b.extend_from_slice(&mac);
        b
    }

    /// (slot, ethertype, dst mac, IPv6 next header, first L4 byte, hop limit) of sent IPv6 frames.
    fn sent6(e: &Engine) -> Vec<(usize, [u8; 6], u8, u8, u8)> {
        e.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, f)| f.len() >= 58 && f[12..14] == [0x86, 0xdd])
            .map(|(slot, f)| (*slot, read_mac(f, 0), f[20], f[54], f[21]))
            .collect()
    }

    fn engine6() -> Engine {
        let text = "system logging on\n\
             interface lan zone trust address 10.0.0.1/24 address6 2001:db8:1::1/64\n\
             interface wan zone untrust address 203.0.113.1/24 address6 2001:db8:2::1/64\n\
             policy 5 trust untrust any any tcp any deny app category:social-networking\n\
             policy 10 trust untrust any 2001:db8:2::/64 tcp 443 permit\n\
             policy 15 trust untrust any any tcp 25 reject\n";
        let e = Engine::for_test(Config::parse(text).unwrap());
        let now = Instant::now();
        e.nd.lock().unwrap().insert(("root".into(), ip6("2001:db8:2::10")), (SERVER_MAC, now));
        e.nd.lock().unwrap().insert(("root".into(), ip6("2001:db8:1::10")), (CLIENT_MAC, now));
        e
    }

    #[test]
    fn ipv6_neighbor_discovery() {
        let e = engine6();
        let lan = e.ifaces[0].mac;
        // NS for our global address from a new host: answered with an NA, host learned.
        e.handle(0, &mut icmp6([0x33, 0x33, 0xff, 0, 0, 1], [2, 0, 0, 0, 0, 0x30], "2001:db8:1::30", "ff02::1:ff00:1", 255, ns_body("2001:db8:1::1", [2, 0, 0, 0, 0, 0x30])));
        let out = sent6(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], (0, [2, 0, 0, 0, 0, 0x30], 58, 136, 255), "NA to the soliciting host");
        let f = e.sent.lock().unwrap()[0].1.clone();
        assert_eq!(&f[62..78], &ip6("2001:db8:1::1").octets(), "NA target");
        assert_eq!(read_mac(&f, 80), lan, "target link-layer address is ours");
        assert_eq!(e.nd_lookup("root", ip6("2001:db8:1::30")), Some([2, 0, 0, 0, 0, 0x30]));
        // Our link-local address answers too.
        let ll = v6::link_local(lan).to_string();
        e.handle(0, &mut icmp6([0x33, 0x33, 0xff, 0, 0, 1], CLIENT_MAC, "fe80::10", "ff02::1:ff00:1", 255, ns_body(&ll, CLIENT_MAC)));
        assert_eq!(sent6(&e).len(), 2);
        // An NS that crossed a router (hop limit not 255) is ignored.
        e.handle(0, &mut icmp6(lan, CLIENT_MAC, "2001:db8:1::40", "2001:db8:1::1", 64, ns_body("2001:db8:1::1", CLIENT_MAC)));
        assert_eq!(sent6(&e).len(), 2);
    }

    #[test]
    fn ipv6_echo_to_the_firewall() {
        let e = engine6();
        let lan = e.ifaces[0].mac;
        e.handle(0, &mut icmp6(lan, CLIENT_MAC, "2001:db8:1::10", "2001:db8:1::1", 64, vec![128, 0, 0, 0, 0x12, 0x34, 0, 1, b'h', b'i']));
        assert_eq!(sent6(&e), vec![(0, CLIENT_MAC, 58, 129, 64)]);
    }

    #[test]
    fn ipv6_stateful_forwarding_under_policy() {
        let e = engine6();
        let (lan, wan) = (e.ifaces[0].mac, e.ifaces[1].mac);
        let c = "2001:db8:1::10";
        let srv = "2001:db8:2::10";
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50000, srv, 443, SYN, 64, &[]));
        assert_eq!(sent6(&e), vec![(1, SERVER_MAC, 6, 0xc3, 63)], "SYN forwarded, hop limit decremented");
        e.handle(1, &mut tcp6(wan, SERVER_MAC, srv, 443, c, 50000, SYNACK, 64, &[]));
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50000, srv, 443, ACK, 64, &[]));
        let out = sent6(&e);
        assert_eq!(out.len(), 3);
        assert_eq!((out[1].0, out[1].1), (0, CLIENT_MAC), "SYN-ACK back to the client");
        let s = e.sessions6.lock().unwrap().snapshot();
        assert_eq!(s[0].tcp, TcpState::Established);
        // A mid-flow packet of an unknown flow is invalid.
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50001, srv, 443, ACK, 64, &[]));
        assert_eq!(sent6(&e).len(), 3);
        // Port 22: no rule, interzone-default deny.
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50002, srv, 22, SYN, 64, &[]));
        assert_eq!(sent6(&e).len(), 3);
        assert!(e.last_log().contains("interzone-default"), "{}", e.last_log());
        // Port 25: reject sends a TCP RST back.
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50003, srv, 25, SYN, 64, &[]));
        let rst = e.sent.lock().unwrap().last().unwrap().1.clone();
        assert_eq!((rst[20], rst[54 + 13] & TCP_RST != 0), (6, true), "TCP RST over IPv6");
        assert_eq!(v6::checksum6(ip6(srv), ip6(c), 6, &rst[54..]), 0, "valid checksum");
    }

    #[test]
    fn ipv6_errors_neighbor_miss_and_bad_packets() {
        let e = engine6();
        let lan = e.ifaces[0].mac;
        // Hop limit 1: Time Exceeded to the sender.
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, "2001:db8:1::10", 50010, "2001:db8:2::10", 443, SYN, 1, &[]));
        assert_eq!(sent6(&e), vec![(0, CLIENT_MAC, 58, 3, 64)]);
        // Unknown neighbor: NS to its solicited-node group.
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, "2001:db8:1::10", 50011, "2001:db8:2::99", 443, SYN, 64, &[]));
        let last = sent6(&e).pop().unwrap();
        assert_eq!(last, (1, [0x33, 0x33, 0xff, 0, 0, 0x99], 58, 135, 255));
        // A corrupted checksum is dropped silently.
        let mut bad = tcp6(lan, CLIENT_MAC, "2001:db8:1::10", 50012, "2001:db8:2::10", 443, SYN, 64, &[]);
        bad[70] ^= 0xff;
        let errors = e.stats.lock().unwrap().errors;
        e.handle(0, &mut bad);
        assert_eq!(e.stats.lock().unwrap().errors, errors + 1);
        // Fragments are not reassembled.
        let frag = frame6(lan, CLIENT_MAC, v6::build(ip6("2001:db8:1::10"), ip6("2001:db8:2::10"), 44, 64, vec![6, 0, 0, 1, 0, 0, 0, 1], None));
        let mut frag = frag;
        e.handle(0, &mut frag);
        assert!(e.last_log().contains("fragment"), "{}", e.last_log());
    }

    #[test]
    fn ipv6_app_id_blocks_after_handshake() {
        let e = engine6();
        let (lan, wan) = (e.ifaces[0].mac, e.ifaces[1].mac);
        let (c, srv) = ("2001:db8:1::10", "2001:db8:2::10");
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50020, srv, 443, SYN, 64, &[]));
        e.handle(1, &mut tcp6(wan, SERVER_MAC, srv, 443, c, 50020, SYNACK, 64, &[]));
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50020, srv, 443, ACK, 64, &[]));
        let before = sent6(&e).len();
        e.handle(0, &mut tcp6(lan, CLIENT_MAC, c, 50020, srv, 443, PSHACK, 64, &client_hello("www.facebook.com")));
        assert_eq!(sent6(&e).len(), before, "ClientHello for facebook dropped");
        assert!(e.last_log().contains("app facebook: policy 5 deny"), "{}", e.last_log());
    }

    #[test]
    fn snat_rulebase_translates_when_policy_has_no_nat() {
        let e = engine(
            "policy 10 trust untrust any any tcp any permit\n\
             snat 1 trust untrust 10.0.0.0/24 any masquerade\n",
        );
        assert_eq!(flow(&e, 40030, 443, &client_hello("github.com")), 3);
        let s = e.sessions.lock().unwrap().snapshot().into_iter().find(|s| s.key.sport == 40030).unwrap();
        assert_eq!(s.nat_src.map(|n| n.0), Some("203.0.113.1".parse().unwrap()));
    }
}
