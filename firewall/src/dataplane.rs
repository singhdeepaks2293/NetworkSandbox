//! The forwarding engine: AF_PACKET sockets, ARP resolution, policy
//! evaluation, a small stateful connection table and source NAT.

use crate::model::{Action, Cidr, Config, Interface};
use crate::packet::{
    build_arp, ethertype, icmp_identity, parse_arp, read_mac, write_mac, Ipv4, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ETH_HEADER_LEN, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
};
use std::collections::{HashMap, VecDeque};
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

#[derive(Clone, Debug)]
pub struct Session {
    pub key: SessionKey,
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
}

impl Sessions {
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn lookup(&self, key: SessionKey) -> Option<Session> {
        if let Some(session) = self.forward.get(&key) {
            return Some(session.clone());
        }
        let forward_key = self.reverse.get(&key)?;
        self.forward.get(forward_key).cloned()
    }

    pub fn insert(&mut self, session: Session) {
        self.reverse
            .insert(reverse_key(&session), session.key.clone());
        self.forward.insert(session.key.clone(), session);
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
                self.reverse.remove(&reverse_key(&session));
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
        self.forward.values().any(|s| {
            matches!(s.nat_src, Some((ip, p)) if ip == nat_ip && p == port)
                && s.key.proto == proto
                && s.key.dst == dst
                && s.key.dport == dport
        })
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
    pub logs: Mutex<VecDeque<String>>,
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
            logs: Mutex::new(VecDeque::new()),
            candidate: Mutex::new(None),
            history: Mutex::new(Vec::new()),
            revisions: Mutex::new(1),
        }
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

    pub fn replace_config(&self, text: &str) -> Result<(), String> {
        let parsed = Config::parse(text)?;
        self.ensure_live_compatible(&parsed)?;
        let old = self.cfg.read().unwrap().to_text();
        self.save_text(text)?;
        *self.cfg.write().unwrap() = parsed;
        self.push_history(old);
        *self.revisions.lock().unwrap() += 1;
        Ok(())
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
                last_purge = now;
            }
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

        let cfg = self.cfg.read().unwrap().clone();
        let in_iface = &self.ifaces[slot];
        let local = self.local_ip(&in_iface.vdom, original_dst);
        let proto = ip.protocol();
        let (sport, dport) = match proto {
            PROTO_TCP | PROTO_UDP => ip.ports().unwrap_or((0, 0)),
            PROTO_ICMP => {
                let id = icmp_identity(&ip);
                (id, id)
            }
            _ => (0, 0),
        };
        let vdom = in_iface.vdom.clone();
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
                if let Some(policy) = cfg
                    .policies
                    .iter()
                    .find(|p| p.id == s.policy_id && p.vdom == s.key.vdom)
                {
                    if let Some(reason) = security_drop(&cfg, policy, &ip, dport) {
                        self.log_event(
                            &cfg,
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
                // Reply direction: undo DNAT/SNAT back to the original flow.
                out_slot = self.slot_for_index(s.in_index).unwrap_or(slot);
                ip.set_dst(s.key.src);
                ip.set_src(s.key.dst);
                if proto == PROTO_TCP || proto == PROTO_UDP {
                    ip.set_destination_port(s.key.sport);
                    ip.set_source_port(s.key.dport);
                }
                translated = s.nat_src.is_some() || s.nat_dst.is_some();
            }
        } else {
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
            if policy.action == Action::Deny {
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
            let timeout = timeout_for(proto, &cfg);
            let now = Instant::now();
            session = Some(Session {
                key: key.clone(),
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

        if let Some(s) = &session {
            if s.expires > Instant::now() {
                // Refresh the timeout on activity.
                let t = timeout_for(proto, &cfg);
                if let Some(fwd) = self.sessions.lock().unwrap().forward.get_mut(&s.key) {
                    fwd.expires = Instant::now() + Duration::from_secs(t);
                }
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
            self.stats_bump(slot, |s| s.dropped += 1);
            return;
        }
        let total = ip.total_len();
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
