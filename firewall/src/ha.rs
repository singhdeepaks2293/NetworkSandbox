//! Active/passive high availability, modelled on FortiGate FGCP and PAN-OS HA.
//!
//! Two firewalls with the same interfaces form a cluster over a dedicated HA
//! link (an address the OS owns, not a dataplane interface):
//!
//! - **Heartbeat.** Each unit sends a signed HELLO every `hello` ms. A peer
//!   silent for `dead` ms is considered down.
//! - **Election.** The unit with the higher (priority, node id) is active.
//!   Without `preempt`, a running active unit stays active when a
//!   higher-priority peer joins; with it, the higher-priority unit takes over.
//!   If both are active (split brain), the lower-ranked one steps down.
//! - **Passive units forward nothing** and answer no ARP. The unit that
//!   becomes active sends gratuitous ARP for each interface address so hosts
//!   and switches learn its MAC at once.
//! - **Config sync.** The active unit sends its configuration whenever the
//!   peer's differs. Node-local settings (hostname, `ha ...`, management
//!   binds and certificates) are not synchronized.
//! - **Session sync.** The active unit sends its session table every second,
//!   so established TCP flows survive a failover.
//! - **Manual failover.** Suspending a unit makes it passive and ineligible
//!   until resumed.
//!
//! Every datagram is `HMAC-SHA256(secret, json) || json`. Per-node sequence
//! numbers reject replays; a restarted unit has a new node id.

use crate::dataplane::{Engine, Session, SessionKey, TcpState};
use crate::model::Config;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ----------------------------------------------------------------- settings

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaSettings {
    pub enabled: bool,
    pub group: u8,
    pub priority: u8,
    pub bind: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub secret: Option<String>,
    pub preempt: bool,
    pub hello_ms: u64,
    pub dead_ms: u64,
    /// Largest session table synchronized; beyond it sync pauses (logged).
    pub max_sync_sessions: usize,
}

impl Default for HaSettings {
    fn default() -> Self {
        HaSettings {
            enabled: false,
            group: 1,
            priority: 128,
            bind: None,
            peer: None,
            secret: None,
            preempt: false,
            hello_ms: 200,
            dead_ms: 1000,
            max_sync_sessions: 20_000,
        }
    }
}

impl HaSettings {
    /// Parse one `ha <key> <value>` line.
    pub fn parse_line(&mut self, words: &[&str]) -> Result<(), String> {
        let [key, value] = words else {
            return Err("usage: ha <key> <value>".to_string());
        };
        let num = |v: &str| v.parse::<u64>().map_err(|_| format!("invalid ha {key} '{v}'"));
        match *key {
            "mode" => {
                self.enabled = match *value {
                    "active-passive" | "a-p" => true,
                    "standalone" => false,
                    _ => return Err("ha mode expects active-passive or standalone".to_string()),
                }
            }
            "group" => self.group = num(value)?.try_into().map_err(|_| "ha group must be 0-255".to_string())?,
            "priority" => self.priority = num(value)?.try_into().map_err(|_| "ha priority must be 0-255".to_string())?,
            "bind" => self.bind = Some(value.parse().map_err(|_| format!("ha bind expects ip:port, got '{value}'"))?),
            "peer" => self.peer = Some(value.parse().map_err(|_| format!("ha peer expects ip:port, got '{value}'"))?),
            "secret" => self.secret = Some(value.to_string()),
            "preempt" => {
                self.preempt = match *value {
                    "on" => true,
                    "off" => false,
                    _ => return Err("ha preempt expects on or off".to_string()),
                }
            }
            "hello" => self.hello_ms = num(value)?,
            "dead" => self.dead_ms = num(value)?,
            "max-sync-sessions" => self.max_sync_sessions = num(value)? as usize,
            other => return Err(format!("unknown ha key '{other}'")),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.bind.is_none() || self.peer.is_none() {
            return Err("ha active-passive needs ha bind and ha peer".to_string());
        }
        match &self.secret {
            Some(s) if s.len() >= 16 => {}
            _ => return Err("ha active-passive needs ha secret of at least 16 characters".to_string()),
        }
        if self.hello_ms < 10 || self.dead_ms < self.hello_ms * 3 {
            return Err("ha hello must be >= 10 ms and ha dead at least 3 x hello".to_string());
        }
        Ok(())
    }

    pub fn to_text(&self) -> String {
        if *self == HaSettings::default() {
            return String::new();
        }
        let mut out = format!("\nha mode {}\n", if self.enabled { "active-passive" } else { "standalone" });
        out.push_str(&format!("ha group {}\nha priority {}\n", self.group, self.priority));
        if let Some(b) = self.bind {
            out.push_str(&format!("ha bind {b}\n"));
        }
        if let Some(p) = self.peer {
            out.push_str(&format!("ha peer {p}\n"));
        }
        if let Some(s) = &self.secret {
            out.push_str(&format!("ha secret {s}\n"));
        }
        out.push_str(&format!("ha preempt {}\n", if self.preempt { "on" } else { "off" }));
        out.push_str(&format!("ha hello {}\nha dead {}\n", self.hello_ms, self.dead_ms));
        if self.max_sync_sessions != HaSettings::default().max_sync_sessions {
            out.push_str(&format!("ha max-sync-sessions {}\n", self.max_sync_sessions));
        }
        out
    }
}

// ----------------------------------------------------------------- election

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Waiting one dead interval for a peer before deciding.
    Init,
    Active,
    Passive,
    /// Manually taken out of service; never becomes active.
    Suspended,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Init => "init",
            Role::Active => "active",
            Role::Passive => "passive",
            Role::Suspended => "suspended",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerView {
    pub role: Role,
    pub priority: u8,
    pub node_id: u64,
    pub alive: bool,
}

/// The next role of this unit. Pure, so every case is unit-tested.
pub fn decide(me: Role, my_rank: (u8, u64), peer: Option<PeerView>, preempt: bool, waited: bool, suspended: bool) -> Role {
    if suspended {
        return Role::Suspended;
    }
    let peer = peer.filter(|p| p.alive);
    let Some(p) = peer else {
        // Alone: take over once the start-up wait is over (or immediately if
        // we were already serving).
        return if waited || me == Role::Active { Role::Active } else { Role::Init };
    };
    let i_win = my_rank > (p.priority, p.node_id);
    match (me, p.role) {
        (_, Role::Suspended) => Role::Active,
        (Role::Active, Role::Active) => if i_win { Role::Active } else { Role::Passive },
        (Role::Active, _) => if preempt && !i_win { Role::Passive } else { Role::Active },
        (_, Role::Active) => if preempt && i_win { Role::Active } else { Role::Passive },
        // Neither serves: the higher rank does.
        _ => if i_win { Role::Active } else { Role::Passive },
    }
}

// ----------------------------------------------------------------- wire

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub group: u8,
    pub node: u64,
    pub seq: u64,
    pub msg: Msg,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Msg {
    Hello { role: Role, priority: u8, config_hash: u64, sessions: usize },
    /// One piece of a larger payload (`stream` is "config" or "sessions").
    Chunk { stream: String, id: u64, part: u32, total: u32, data: String },
}

const MAX_CHUNK: usize = 48 * 1024;

pub fn seal(key: &hmac::Key, env: &Envelope) -> Vec<u8> {
    let json = serde_json::to_vec(env).expect("envelope serializes");
    let tag = hmac::sign(key, &json);
    let mut out = tag.as_ref().to_vec();
    out.extend_from_slice(&json);
    out
}

pub fn open(key: &hmac::Key, datagram: &[u8]) -> Result<Envelope, String> {
    if datagram.len() < 32 {
        return Err("short datagram".into());
    }
    let (tag, json) = datagram.split_at(32);
    hmac::verify(key, json, tag).map_err(|_| "bad signature".to_string())?;
    serde_json::from_slice(json).map_err(|e| format!("bad message: {e}"))
}

pub fn key_for(secret: &str) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes())
}

/// Split a payload into chunk messages.
pub fn chunks(stream: &str, id: u64, data: &str) -> Vec<Msg> {
    let bytes = data.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let mut end = (start + MAX_CHUNK).min(bytes.len());
        while !data.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(data[start..end].to_string());
        start = end;
    }
    if parts.is_empty() {
        parts.push(String::new());
    }
    let total = parts.len() as u32;
    parts
        .into_iter()
        .enumerate()
        .map(|(i, data)| Msg::Chunk { stream: stream.into(), id, part: i as u32, total, data })
        .collect()
}

/// Reassembles chunk streams; keeps only the newest id per stream.
#[derive(Default)]
pub struct Reassembly {
    streams: HashMap<String, (u64, Vec<Option<String>>)>,
}

impl Reassembly {
    pub fn add(&mut self, stream: &str, id: u64, part: u32, total: u32, data: String) -> Option<String> {
        if total == 0 || total > 4096 || part >= total {
            return None;
        }
        let entry = self.streams.entry(stream.to_string()).or_insert((id, Vec::new()));
        if entry.0 != id || entry.1.len() != total as usize {
            if id < entry.0 {
                return None; // an older stream than the one in progress
            }
            *entry = (id, vec![None; total as usize]);
        }
        entry.1[part as usize] = Some(data);
        if entry.1.iter().all(Option::is_some) {
            let (_, parts) = self.streams.remove(stream).expect("present");
            return Some(parts.into_iter().map(|p| p.expect("complete")).collect());
        }
        None
    }
}

// ----------------------------------------------------------- config sync

/// The configuration with node-local settings reset, as synchronized.
pub fn synced_view(cfg: &Config) -> Config {
    let mut c = cfg.clone();
    let d = crate::model::Settings::default();
    c.settings.hostname = d.hostname;
    c.settings.cli_bind = d.cli_bind;
    c.settings.gui_bind = d.gui_bind;
    c.settings.tls_cert = d.tls_cert;
    c.settings.tls_key = d.tls_key;
    c.ha = HaSettings::default();
    c
}

/// FNV-1a of the synchronized view's text; equal on both units when in sync.
pub fn config_hash(cfg: &Config) -> u64 {
    synced_view(cfg).to_text().bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// The peer's configuration with this unit's node-local settings kept.
pub fn merge_peer_config(local: &Config, peer_text: &str) -> Result<Config, String> {
    let mut next = Config::parse(peer_text)?;
    next.settings.hostname = local.settings.hostname.clone();
    next.settings.cli_bind = local.settings.cli_bind;
    next.settings.gui_bind = local.settings.gui_bind;
    next.settings.tls_cert = local.settings.tls_cert.clone();
    next.settings.tls_key = local.settings.tls_key.clone();
    next.ha = local.ha.clone();
    Ok(next)
}

// ---------------------------------------------------------- session sync

/// A session as synchronized: interfaces by name (indexes differ per unit),
/// expiry as seconds remaining.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncedSession {
    pub vdom: String,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
    pub tcp: String,
    pub fin: (bool, bool),
    pub in_if: String,
    pub out_if: String,
    pub nat_src: Option<(Ipv4Addr, u16)>,
    pub nat_dst: Option<(Ipv4Addr, u16)>,
    pub policy: u32,
    pub shaper: Option<String>,
    pub ttl: u64,
    pub app: Option<String>,
    pub user: Option<String>,
    pub zones: (String, String),
}

fn tcp_from(s: &str) -> TcpState {
    match s {
        "SYN_SENT" => TcpState::SynSent,
        "SYN_RECV" => TcpState::SynRecv,
        "ESTABLISHED" => TcpState::Established,
        "CLOSING" => TcpState::Closing,
        "TIME_WAIT" => TcpState::TimeWait,
        _ => TcpState::Closed,
    }
}

pub fn export_session(s: &Session, names: &HashMap<i32, String>, now: Instant) -> Option<SyncedSession> {
    Some(SyncedSession {
        vdom: s.key.vdom.clone(),
        proto: s.key.proto,
        src: s.key.src,
        sport: s.key.sport,
        dst: s.key.dst,
        dport: s.key.dport,
        tcp: s.tcp.as_str().to_string(),
        fin: (s.fin_orig, s.fin_reply),
        in_if: names.get(&s.in_index)?.clone(),
        out_if: names.get(&s.out_index)?.clone(),
        nat_src: s.nat_src,
        nat_dst: s.nat_dst,
        policy: s.policy_id,
        shaper: s.shaper.clone(),
        ttl: s.expires.saturating_duration_since(now).as_secs(),
        app: s.app.clone(),
        user: s.user.clone(),
        zones: (s.src_zone.clone(), s.dst_zone.clone()),
    })
}

pub fn import_session(s: &SyncedSession, indexes: &HashMap<String, i32>, now: Instant) -> Option<Session> {
    Some(Session {
        key: SessionKey { vdom: s.vdom.clone(), proto: s.proto, src: s.src, sport: s.sport, dst: s.dst, dport: s.dport },
        tcp: tcp_from(&s.tcp),
        fin_orig: s.fin.0,
        fin_reply: s.fin.1,
        in_index: *indexes.get(&s.in_if)?,
        out_index: *indexes.get(&s.out_if)?,
        nat_src: s.nat_src,
        nat_dst: s.nat_dst,
        policy_id: s.policy,
        shaper: s.shaper.clone(),
        expires: now + Duration::from_secs(s.ttl.min(86_400)),
        app: s.app.clone(),
        app_tries: 0,
        src_zone: s.zones.0.clone(),
        dst_zone: s.zones.1.clone(),
        app_buf: [Vec::new(), Vec::new()],
        app_seq: [None, None],
        user: s.user.clone(),
    })
}

// ---------------------------------------------------------------- status

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub enabled: bool,
    pub role: Option<Role>,
    pub node_id: u64,
    pub priority: u8,
    pub peer: Option<(Role, u8, u64, u64)>, // role, priority, node id, ms since last hello
    pub peer_addr: Option<SocketAddr>,
    pub transitions: u64,
    pub in_sync: bool,
    pub sessions_synced: usize,
    pub last_event: String,
}

impl Status {
    pub fn text(&self) -> String {
        if !self.enabled {
            return "HA: standalone\n".to_string();
        }
        let role = self.role.map(Role::as_str).unwrap_or("init");
        let mut out = format!(
            "HA mode: active-passive\nThis unit: {role} (priority {}, node {:016x})\n",
            self.priority, self.node_id
        );
        match self.peer {
            Some((r, p, n, age)) => out.push_str(&format!(
                "Peer {}: {} (priority {p}, node {n:016x}), last hello {age} ms ago\n",
                self.peer_addr.map(|a| a.to_string()).unwrap_or_default(),
                r.as_str()
            )),
            None => out.push_str("Peer: not seen\n"),
        }
        out.push_str(&format!(
            "Configuration: {}\nSessions synchronized: {}\nRole changes: {}\nLast event: {}\n",
            if self.in_sync { "in sync" } else { "out of sync" },
            self.sessions_synced,
            self.transitions,
            self.last_event
        ));
        out
    }
}

// ----------------------------------------------------------------- agent

struct Peer {
    role: Role,
    priority: u8,
    node_id: u64,
    config_hash: u64,
    last_seen: Instant,
    last_seq: u64,
}

pub struct Agent {
    engine: Arc<Engine>,
    socket: UdpSocket,
    key: hmac::Key,
    settings: HaSettings,
    node_id: u64,
    seq: u64,
    role: Role,
    started: Instant,
    peer: Option<Peer>,
    last_hello: Option<Instant>,
    last_sync: Option<Instant>,
    last_config_push: Option<Instant>,
    reassembly: Reassembly,
    sync_id: u64,
}

fn new_node_id() -> u64 {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let mut x = t ^ (u64::from(std::process::id()) << 32) ^ 0x9e37_79b9_7f4a_7c15;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^ (x >> 33)
}

impl Agent {
    pub fn new(engine: Arc<Engine>, settings: HaSettings) -> std::io::Result<Agent> {
        let bind = settings.bind.ok_or_else(|| std::io::Error::other("ha bind is not set"))?;
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        let key = key_for(settings.secret.as_deref().unwrap_or(""));
        let node_id = new_node_id();
        {
            let mut st = engine.ha.lock().unwrap();
            st.enabled = true;
            st.node_id = node_id;
            st.priority = settings.priority;
            st.peer_addr = settings.peer;
            st.role = Some(Role::Init);
        }
        engine.ha_active.store(false, Ordering::SeqCst);
        Ok(Agent {
            engine,
            socket,
            key,
            settings,
            node_id,
            seq: 0,
            role: Role::Init,
            started: Instant::now(),
            peer: None,
            last_hello: None,
            last_sync: None,
            last_config_push: None,
            reassembly: Reassembly::default(),
            sync_id: 0,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Run forever (daemon thread).
    pub fn run(mut self) -> ! {
        let nap = Duration::from_millis((self.settings.hello_ms / 4).max(5));
        loop {
            self.tick(Instant::now());
            std::thread::sleep(nap);
        }
    }

    fn send(&mut self, msg: Msg) {
        self.seq += 1;
        let env = Envelope { group: self.settings.group, node: self.node_id, seq: self.seq, msg };
        if let Some(peer) = self.settings.peer {
            let _ = self.socket.send_to(&seal(&self.key, &env), peer);
        }
    }

    fn event(&self, text: String) {
        eprintln!("ha: {text}");
        self.engine.ha.lock().unwrap().last_event = text;
    }

    /// One step: receive, decide, send. Safe to call at any rate.
    pub fn tick(&mut self, now: Instant) {
        self.receive(now);
        self.elect(now);
        if self.last_hello.map_or(true, |t| now.duration_since(t) >= Duration::from_millis(self.settings.hello_ms)) {
            let cfg_hash = config_hash(&self.engine.cfg.read().unwrap());
            let sessions = self.engine.sessions.lock().unwrap().len();
            self.send(Msg::Hello { role: self.role, priority: self.settings.priority, config_hash: cfg_hash, sessions });
            self.last_hello = Some(now);
        }
        if self.role == Role::Active {
            self.push_config(now);
            self.push_sessions(now);
        }
        self.publish(now);
    }

    fn receive(&mut self, now: Instant) {
        let mut buf = vec![0u8; 65_536];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => return,
            };
            if Some(from.ip()) != self.settings.peer.map(|p| p.ip()) {
                continue;
            }
            let env = match open(&self.key, &buf[..n]) {
                Ok(e) => e,
                Err(e) => {
                    self.event(format!("dropped datagram from {from}: {e}"));
                    continue;
                }
            };
            if env.group != self.settings.group || env.node == self.node_id {
                continue;
            }
            if let Some(p) = &self.peer {
                if p.node_id == env.node && env.seq <= p.last_seq {
                    continue; // replay or reordering
                }
            }
            match env.msg {
                Msg::Hello { role, priority, config_hash, .. } => {
                    if self.peer.as_ref().map_or(true, |p| p.node_id != env.node) {
                        self.event(format!("peer {:016x} joined (priority {priority})", env.node));
                    }
                    self.peer = Some(Peer { role, priority, node_id: env.node, config_hash, last_seen: now, last_seq: env.seq });
                }
                Msg::Chunk { stream, id, part, total, data } => {
                    if let Some(p) = &mut self.peer {
                        if p.node_id == env.node {
                            p.last_seq = env.seq;
                        }
                    }
                    if let Some(full) = self.reassembly.add(&stream, id, part, total, data) {
                        self.apply_stream(&stream, &full);
                    }
                }
            }
        }
    }

    fn apply_stream(&mut self, stream: &str, payload: &str) {
        // Only an active peer's state is authoritative.
        if self.role == Role::Active || self.peer.as_ref().map(|p| p.role) != Some(Role::Active) {
            return;
        }
        match stream {
            "config" => {
                let local = self.engine.cfg.read().unwrap().clone();
                let result = merge_peer_config(&local, payload).and_then(|next| self.engine.apply_config(&next));
                match result {
                    Ok(()) => self.event("configuration synchronized from the active unit".into()),
                    Err(e) => self.event(format!("configuration sync failed: {e}")),
                }
            }
            "sessions" => {
                let Ok(list) = serde_json::from_str::<Vec<SyncedSession>>(payload) else {
                    self.event("bad session sync payload".into());
                    return;
                };
                let indexes: HashMap<String, i32> = self.engine.ifaces.iter().map(|i| (i.name.clone(), i.index)).collect();
                let now = Instant::now();
                let imported: Vec<Session> = list.iter().filter_map(|s| import_session(s, &indexes, now)).collect();
                let count = imported.len();
                self.engine.sessions.lock().unwrap().replace_all(imported);
                self.engine.ha.lock().unwrap().sessions_synced = count;
            }
            _ => {}
        }
    }

    fn elect(&mut self, now: Instant) {
        let dead = Duration::from_millis(self.settings.dead_ms);
        let peer = self.peer.as_ref().map(|p| PeerView {
            role: p.role,
            priority: p.priority,
            node_id: p.node_id,
            alive: now.duration_since(p.last_seen) < dead,
        });
        let waited = now.duration_since(self.started) >= dead;
        let suspended = self.engine.ha_suspended.load(Ordering::SeqCst);
        let next = decide(self.role, (self.settings.priority, self.node_id), peer, self.settings.preempt, waited, suspended);
        if next != self.role {
            let why = match peer {
                Some(p) if p.alive => format!("peer is {}", p.role.as_str()),
                Some(_) => "peer heartbeat lost".to_string(),
                None => "no peer".to_string(),
            };
            self.event(format!("{} -> {} ({why})", self.role.as_str(), next.as_str()));
            self.role = next;
            self.engine.ha.lock().unwrap().transitions += 1;
            let active = next == Role::Active;
            self.engine.ha_active.store(active, Ordering::SeqCst);
            if active {
                self.engine.gratuitous_arp();
                self.last_config_push = None;
                self.last_sync = None;
            }
        }
    }

    fn push_config(&mut self, now: Instant) {
        let Some(peer) = &self.peer else { return };
        let mine = config_hash(&self.engine.cfg.read().unwrap());
        let due = self.last_config_push.map_or(true, |t| now.duration_since(t) >= Duration::from_secs(2));
        if peer.config_hash == mine || !due {
            return;
        }
        let text = synced_view(&self.engine.cfg.read().unwrap()).to_text();
        self.sync_id += 1;
        for msg in chunks("config", self.sync_id, &text) {
            self.send(msg);
        }
        self.last_config_push = Some(now);
    }

    fn push_sessions(&mut self, now: Instant) {
        if self.peer.is_none() || self.last_sync.map_or(false, |t| now.duration_since(t) < Duration::from_secs(1)) {
            return;
        }
        self.last_sync = Some(now);
        let sessions = self.engine.sessions.lock().unwrap().snapshot();
        if sessions.len() > self.settings.max_sync_sessions {
            self.event(format!("session sync paused: {} sessions exceeds ha max-sync-sessions", sessions.len()));
            return;
        }
        let names: HashMap<i32, String> = self.engine.ifaces.iter().map(|i| (i.index, i.name.clone())).collect();
        let list: Vec<SyncedSession> = sessions.iter().filter_map(|s| export_session(s, &names, now)).collect();
        let json = serde_json::to_string(&list).expect("sessions serialize");
        self.sync_id += 1;
        for msg in chunks("sessions", self.sync_id, &json) {
            self.send(msg);
        }
        self.engine.ha.lock().unwrap().sessions_synced = list.len();
    }

    fn publish(&self, now: Instant) {
        let mine = config_hash(&self.engine.cfg.read().unwrap());
        let mut st = self.engine.ha.lock().unwrap();
        st.role = Some(self.role);
        st.peer = self.peer.as_ref().map(|p| (p.role, p.priority, p.node_id, now.duration_since(p.last_seen).as_millis() as u64));
        st.in_sync = self.peer.as_ref().map_or(false, |p| p.config_hash == mine);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(role: Role, priority: u8, alive: bool) -> Option<PeerView> {
        Some(PeerView { role, priority, node_id: 5, alive })
    }

    #[test]
    fn election_rules() {
        let me = (100, 7);
        // Start-up: wait for a peer, then take over alone.
        assert_eq!(decide(Role::Init, me, None, false, false, false), Role::Init);
        assert_eq!(decide(Role::Init, me, None, false, true, false), Role::Active);
        // Peer dead: active.
        assert_eq!(decide(Role::Passive, me, peer(Role::Active, 200, false), false, true, false), Role::Active);
        // Both idle: higher rank serves.
        assert_eq!(decide(Role::Init, me, peer(Role::Init, 50, true), false, true, false), Role::Active);
        assert_eq!(decide(Role::Init, me, peer(Role::Init, 150, true), false, true, false), Role::Passive);
        // Equal priority: node id breaks the tie.
        assert_eq!(decide(Role::Init, (100, 1), Some(PeerView { role: Role::Init, priority: 100, node_id: 2, alive: true }), false, true, false), Role::Passive);
        // A higher-priority peer joins: stays active without preempt, yields with it.
        assert_eq!(decide(Role::Active, me, peer(Role::Init, 200, true), false, true, false), Role::Active);
        assert_eq!(decide(Role::Active, me, peer(Role::Passive, 200, true), true, true, false), Role::Passive);
        assert_eq!(decide(Role::Passive, (200, 7), peer(Role::Active, 100, true), true, true, false), Role::Active);
        assert_eq!(decide(Role::Passive, (200, 7), peer(Role::Active, 100, true), false, true, false), Role::Passive);
        // Split brain: the lower rank steps down.
        assert_eq!(decide(Role::Active, me, peer(Role::Active, 200, true), false, true, false), Role::Passive);
        assert_eq!(decide(Role::Active, (250, 7), peer(Role::Active, 200, true), false, true, false), Role::Active);
        // Suspension.
        assert_eq!(decide(Role::Active, me, peer(Role::Passive, 1, true), false, true, true), Role::Suspended);
        assert_eq!(decide(Role::Passive, me, peer(Role::Suspended, 255, true), false, true, false), Role::Active);
    }

    #[test]
    fn datagrams_are_authenticated() {
        let key = key_for("a-long-shared-secret");
        let env = Envelope { group: 1, node: 9, seq: 3, msg: Msg::Hello { role: Role::Active, priority: 10, config_hash: 1, sessions: 0 } };
        let wire = seal(&key, &env);
        assert_eq!(open(&key, &wire).unwrap(), env);
        assert!(open(&key_for("another-secret-entirely"), &wire).is_err());
        let mut tampered = wire.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        assert!(open(&key, &tampered).is_err());
    }

    #[test]
    fn chunks_reassemble_in_any_order() {
        let data: String = (0..200_000).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        let mut msgs = chunks("config", 4, &data);
        assert!(msgs.len() > 1);
        msgs.reverse();
        let mut r = Reassembly::default();
        let mut out = None;
        for m in msgs {
            if let Msg::Chunk { stream, id, part, total, data } = m {
                out = r.add(&stream, id, part, total, data).or(out);
            }
        }
        assert_eq!(out.as_deref(), Some(data.as_str()));
    }

    #[test]
    fn config_sync_keeps_node_local_settings() {
        let a = Config::parse("system hostname fw-a\nha mode active-passive\nha bind 10.9.9.1:7600\nha peer 10.9.9.2:7600\nha secret 0123456789abcdef\nha priority 200\ninterface p1 zone lan address 10.0.0.1/24\npolicy 10 lan lan any any any any permit\n").unwrap();
        let b = Config::parse("system hostname fw-b\nha mode active-passive\nha bind 10.9.9.2:7600\nha peer 10.9.9.1:7600\nha secret 0123456789abcdef\nha priority 100\ninterface p1 zone lan address 10.0.0.1/24\n").unwrap();
        assert_ne!(config_hash(&a), config_hash(&b));
        let merged = merge_peer_config(&b, &synced_view(&a).to_text()).unwrap();
        assert_eq!(merged.settings.hostname, "fw-b");
        assert_eq!(merged.ha.priority, 100);
        assert_eq!(merged.policies.len(), 1);
        assert_eq!(config_hash(&merged), config_hash(&a));
    }

    #[test]
    fn settings_validate_and_round_trip() {
        let mut s = HaSettings::default();
        s.parse_line(&["mode", "active-passive"]).unwrap();
        assert!(s.validate().is_err(), "needs bind, peer and secret");
        s.parse_line(&["bind", "10.0.0.1:7600"]).unwrap();
        s.parse_line(&["peer", "10.0.0.2:7600"]).unwrap();
        s.parse_line(&["secret", "short"]).unwrap();
        assert!(s.validate().is_err());
        s.parse_line(&["secret", "long-enough-secret"]).unwrap();
        s.validate().unwrap();
        assert!(s.parse_line(&["priority", "300"]).is_err());
        assert!(HaSettings::default().to_text().is_empty());
    }
}
