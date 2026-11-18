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
    if flags & TCP_RST != 0 {
        s.tcp = TcpState::Closed;
        return true;
    }
    let syn = flags & TCP_SYN != 0;
    let ack = flags & TCP_ACK != 0;
    match s.tcp {
        TcpState::SynSent => {
            if from_orig {
                syn && !ack
            } else if syn && ack {
                s.tcp = TcpState::SynRecv;
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
                    s.tcp = TcpState::Established;
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
                    s.fin_orig = true;
                } else {
                    s.fin_reply = true;
                }
                s.tcp = if s.fin_orig && s.fin_reply {
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
                s.tcp = TcpState::SynSent;
                s.fin_orig = false;
                s.fin_reply = false;
                true
            } else {
                s.tcp != TcpState::Closed && !syn
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
        let mut missing: Vec<&Interface> = snapshot.interfaces.iter().collect();
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
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        proto: u8,
        zone_in: &str,
        zone_out: &str,
        policy: Option<u32>,
        note: &str,
    ) {
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
            if old.name != new.name
                || old.vdom != new.vdom
                || old.zone != new.zone
                || old.address != new.address
                || old.mac != new.mac
                || old.mtu != new.mtu
            {
                return Err(format!(
                    "interface '{}' changes require a daemon restart; commit supports policies, routes, objects, NAT, zones, shapers and security profiles",
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
        match ethertype(frame) {
            ETHERTYPE_ARP => self.handle_arp(slot, frame),
            ETHERTYPE_IPV4 => self.handle_ipv4(slot, frame),
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
                    &in_iface.zone,
                    "",
                    None,
                    reason,
                );
            }
            self.stats.lock().unwrap().denied += 1;
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
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
                let policy_now = cfg
                    .policies
                    .iter()
                    .find(|p| p.id == s.policy_id && p.vdom == s.key.vdom);
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
                        &in_iface.zone,
                        "",
                        Some(s.policy_id),
                        "policy-withdrawn",
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
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
                        &in_iface.zone,
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
                            &in_iface.zone,
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
                let policy_now = cfg
                    .policies
                    .iter()
                    .find(|p| p.id == s.policy_id && p.vdom == s.key.vdom);
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
                        &in_iface.zone,
                        "",
                        Some(s.policy_id),
                        "policy-withdrawn",
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |st| st.dropped += 1);
                    return;
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
                        &in_iface.zone,
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
                            &in_iface.zone,
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
                        &in_iface.zone,
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
                    &in_iface.zone,
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

            if let Some(zone) = cfg.zone(&in_iface.zone, &vdom) {
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
                        &in_iface.zone,
                        &egress.zone,
                        None,
                        &format!("zone-protection {kind}-flood"),
                    );
                    self.stats.lock().unwrap().denied += 1;
                    self.stats_bump(slot, |s| s.dropped += 1);
                    return;
                }
            }

            let policy =
                cfg.match_policy(&vdom, &in_iface.zone, &egress.zone, src, dst, proto, dport);
            let Some(policy) = policy else {
                self.log_event(
                    &cfg,
                    "deny",
                    src,
                    sport,
                    dst,
                    dport,
                    proto,
                    &in_iface.zone,
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
                    &in_iface.zone,
                    &egress.zone,
                    Some(policy.id),
                    "",
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
                    &in_iface.zone,
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
                        &in_iface.zone,
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
            if policy.nat && nat_dst.is_none() {
                if let Some(cidr) = egress.address {
                    let mut nat_port = sport;
                    if proto == PROTO_TCP || proto == PROTO_UDP {
                        let sessions = self.sessions.lock().unwrap();
                        nat_port = pick_port(&sessions, proto, cidr.addr, dst, dport, sport);
                    }
                    nat_src = Some((cidr.addr, nat_port));
                }
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
                &in_iface.zone,
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
        if out.fd < 0 {
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
                                &in_iface.zone,
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
    let payload = crate::inspect::payload(ip);
    let payload = &payload[..payload.len().min(cfg.settings.max_inspection_bytes)];
    // Inspection is not tied to a well-known port: HTTP and TLS are
    // recognised from the payload so non-standard listeners still work.
    let host = crate::inspect::http_host(payload).or_else(|| crate::inspect::tls_sni(payload));
    if let Some(name) = &policy.url {
        if let (Some(filter), Some(host)) = (cfg.url_filter(name), host.as_deref()) {
            if filter.blocked(host) {
                return Some(format!("url-filter {name}: {host}"));
            }
        }
    }
    if let Some(name) = &policy.ips {
        if cfg.signature_hit(name, false, payload).is_some() {
            return Some(format!("ips {name}"));
        }
    }
    if let Some(name) = &policy.av {
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
