//! WireGuard, implemented from the protocol description (Noise_IKpsk2 with
//! X25519, ChaCha20-Poly1305 and BLAKE2s). Primitives come from audited
//! crates; the handshake, transport, replay protection, cryptokey routing
//! and timers are here. Interoperability is tested against boringtun, an
//! independent implementation.
//!
//! A [`Device`] is one tunnel: a private key, a UDP port and peers, each with
//! allowed IPs. It turns plaintext IPv4 packets into datagrams for the
//! network and datagrams into plaintext packets; the dataplane carries both.
//!
//! Not implemented: cookie replies under load (mac2 is sent as zeros and not
//! checked), IPv6 inner packets.

use crate::model::Cidr;
use blake2::digest::{consts::U16, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const MAX_QUEUED: usize = 64;

// ------------------------------------------------------------- primitives

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104, 64-byte block).
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hash(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner_parts: Vec<&[u8]> = vec![&ipad];
    inner_parts.extend_from_slice(parts);
    let inner = hash(&inner_parts);
    hash(&[&opad, &inner])
}

fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let t0 = hmac(key, &[input]);
    hmac(&t0, &[&[1]])
}

fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    (t1, t2)
}

fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    let t3 = hmac(&t0, &[&t2, &[3]]);
    (t1, t2, t3)
}

fn mac16(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("32-byte key");
    Mac::update(&mut m, data);
    m.finalize().into_bytes().into()
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn seal(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(&nonce(counter).into(), Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption cannot fail")
}

fn open(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(key.into()).decrypt(&nonce(counter).into(), Payload { msg: ciphertext, aad }).ok()
}

fn dh(secret: &StaticSecret, public: &[u8; 32]) -> [u8; 32] {
    secret.diffie_hellman(&PublicKey::from(*public)).to_bytes()
}

fn tai64n() -> [u8; 12] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut t = [0u8; 12];
    t[..8].copy_from_slice(&((1u64 << 62) + now.as_secs()).to_be_bytes());
    t[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    t
}

fn random_secret() -> StaticSecret {
    StaticSecret::random_from_rng(rand_core::OsRng)
}

fn random_u32() -> u32 {
    use rand_core::RngCore;
    rand_core::OsRng.next_u32()
}

// ------------------------------------------------------------------- keys

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A 32-byte key in WireGuard's base64 form (44 characters).
pub fn key_from_b64(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 44 || !s.ends_with('=') {
        return Err("a WireGuard key is 44 characters of base64".into());
    }
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = Vec::with_capacity(33);
    for c in s.trim_end_matches('=').bytes() {
        let v = B64.iter().position(|b| *b == c).ok_or("invalid base64 in key")? as u32;
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    out.try_into().map_err(|_| "a WireGuard key is 32 bytes".to_string())
}

/// `wg genkey`: a new private key, clamped as X25519 requires.
pub fn genkey() -> String {
    b64_encode(&random_secret().to_bytes())
}

/// `wg pubkey`.
pub fn pubkey(private_b64: &str) -> Result<String, String> {
    let secret = StaticSecret::from(key_from_b64(private_b64)?);
    Ok(b64_encode(PublicKey::from(&secret).as_bytes()))
}

// ----------------------------------------------------------------- config

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddrV4>,
    pub allowed_ips: Vec<Cidr>,
    pub keepalive: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelConfig {
    pub name: String,
    pub vdom: String,
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

// --------------------------------------------------------------- transport

/// Sliding window of 2048 counters (RFC 6479 style, circular bitmap).
#[derive(Clone, Debug, Default)]
pub struct Replay {
    top: u64,
    bits: [u64; 32],
}

impl Replay {
    const WINDOW: u64 = 2048;

    fn bit(&mut self, c: u64) -> (&mut u64, u64) {
        let i = (c % Self::WINDOW) as usize;
        (&mut self.bits[i / 64], 1 << (i % 64))
    }

    /// Accept a counter once; reject repeats and counters too far behind.
    pub fn accept(&mut self, c: u64) -> bool {
        if c >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if c >= self.top {
            let advance = c + 1 - self.top;
            if advance >= Self::WINDOW {
                self.bits = [0; 32];
            } else {
                for k in self.top..=c {
                    let (word, mask) = self.bit(k);
                    *word &= !mask;
                }
            }
            self.top = c + 1;
        } else if self.top - c > Self::WINDOW {
            return false;
        }
        let (word, mask) = self.bit(c);
        if *word & mask != 0 {
            return false;
        }
        *word |= mask;
        true
    }
}

struct Session {
    local_index: u32,
    remote_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    replay: Replay,
    created: Instant,
    initiator: bool,
}

struct Pending {
    local_index: u32,
    ephemeral: StaticSecret,
    chaining: [u8; 32],
    hash: [u8; 32],
    sent: Instant,
    first_sent: Instant,
}

pub struct Peer {
    pub cfg: PeerConfig,
    pub endpoint: Option<SocketAddrV4>,
    pending: Option<Pending>,
    current: Option<Session>,
    previous: Option<Session>,
    /// Responder side: usable once the initiator sends its first packet.
    next: Option<Session>,
    last_timestamp: [u8; 12],
    queue: Vec<Vec<u8>>,
    pub last_handshake: Option<SystemTime>,
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// What to do with the output of the device.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    /// Send this UDP payload to the peer's endpoint.
    Network(SocketAddrV4, Vec<u8>),
    /// A decrypted inner IPv4 packet from peer `peer`.
    Tunnel { peer: usize, packet: Vec<u8> },
}

pub struct Device {
    pub cfg: TunnelConfig,
    secret: StaticSecret,
    public: [u8; 32],
    pub peers: Vec<Peer>,
    /// Our session/handshake index → peer.
    indexes: HashMap<u32, usize>,
}

fn inner_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    (packet.len() >= 20 && packet[0] >> 4 == 4).then(|| Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

fn inner_src(packet: &[u8]) -> Option<Ipv4Addr> {
    (packet.len() >= 20 && packet[0] >> 4 == 4).then(|| Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))
}

impl Device {
    pub fn new(cfg: TunnelConfig) -> Device {
        let secret = StaticSecret::from(cfg.private_key);
        let public = PublicKey::from(&secret).to_bytes();
        let peers = cfg
            .peers
            .iter()
            .map(|p| Peer {
                cfg: p.clone(),
                endpoint: p.endpoint,
                pending: None,
                current: None,
                previous: None,
                next: None,
                last_timestamp: [0; 12],
                queue: Vec::new(),
                last_handshake: None,
                last_sent: None,
                last_received: None,
                rx_bytes: 0,
                tx_bytes: 0,
            })
            .collect();
        Device { cfg, secret, public, peers, indexes: HashMap::new() }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Cryptokey routing: the peer whose allowed IPs most specifically
    /// contain `ip`.
    pub fn peer_for(&self, ip: Ipv4Addr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.cfg.allowed_ips.iter().filter(|c| c.contains(ip)).map(move |c| (i, c.prefix)))
            .max_by_key(|(_, prefix)| *prefix)
            .map(|(i, _)| i)
    }

    fn new_index(&mut self, peer: usize) -> u32 {
        loop {
            let i = random_u32();
            if !self.indexes.contains_key(&i) {
                self.indexes.insert(i, peer);
                return i;
            }
        }
    }

    fn forget_session(&mut self, s: Option<Session>) {
        if let Some(s) = s {
            self.indexes.remove(&s.local_index);
        }
    }

    // ------------------------------------------------------- handshake

    fn initiation(&mut self, peer: usize, now: Instant) -> Option<Output> {
        let endpoint = self.peers[peer].endpoint?;
        let remote = self.peers[peer].cfg.public_key;
        // A retry keeps the time of the first attempt, so REKEY_ATTEMPT_TIME ends it.
        let mut first_sent = now;
        if let Some(old) = self.peers[peer].pending.take() {
            first_sent = old.first_sent;
            self.indexes.remove(&old.local_index);
        }
        let local_index = self.new_index(peer);
        let eph = random_secret();
        let eph_pub = PublicKey::from(&eph).to_bytes();

        let mut c = hash(&[CONSTRUCTION]);
        let mut h = hash(&[&c, IDENTIFIER]);
        h = hash(&[&h, &remote]);
        c = kdf1(&c, &eph_pub);
        h = hash(&[&h, &eph_pub]);
        let (c2, k) = kdf2(&c, &dh(&eph, &remote));
        c = c2;
        let enc_static = seal(&k, 0, &self.public, &h);
        h = hash(&[&h, &enc_static]);
        let (c3, k) = kdf2(&c, &dh(&self.secret, &remote));
        c = c3;
        let enc_time = seal(&k, 0, &tai64n(), &h);
        h = hash(&[&h, &enc_time]);

        let mut msg = vec![1u8, 0, 0, 0];
        msg.extend_from_slice(&local_index.to_le_bytes());
        msg.extend_from_slice(&eph_pub);
        msg.extend_from_slice(&enc_static);
        msg.extend_from_slice(&enc_time);
        let mac1 = mac16(&hash(&[LABEL_MAC1, &remote]), &msg);
        msg.extend_from_slice(&mac1);
        msg.extend_from_slice(&[0u8; 16]);
        debug_assert_eq!(msg.len(), 148);

        self.peers[peer].pending = Some(Pending { local_index, ephemeral: eph, chaining: c, hash: h, sent: now, first_sent });
        self.peers[peer].last_sent = Some(now);
        Some(Output::Network(endpoint, msg))
    }

    fn on_initiation(&mut self, from: SocketAddrV4, msg: &[u8], now: Instant) -> Vec<Output> {
        if msg.len() != 148 || mac16(&hash(&[LABEL_MAC1, &self.public]), &msg[..116]) != msg[116..132] {
            return Vec::new();
        }
        let sender = u32::from_le_bytes(msg[4..8].try_into().expect("4 bytes"));
        let eph_i: [u8; 32] = msg[8..40].try_into().expect("32 bytes");
        let mut c = hash(&[CONSTRUCTION]);
        let mut h = hash(&[&c, IDENTIFIER]);
        h = hash(&[&h, &self.public]);
        c = kdf1(&c, &eph_i);
        h = hash(&[&h, &eph_i]);
        let (c2, k) = kdf2(&c, &dh(&self.secret, &eph_i));
        c = c2;
        let Some(static_i) = open(&k, 0, &msg[40..88], &h) else { return Vec::new() };
        let Ok(static_i) = <[u8; 32]>::try_from(static_i.as_slice()) else { return Vec::new() };
        let Some(peer) = self.peers.iter().position(|p| p.cfg.public_key == static_i) else { return Vec::new() };
        h = hash(&[&h, &msg[40..88]]);
        let (c3, k) = kdf2(&c, &dh(&self.secret, &static_i));
        c = c3;
        let Some(ts) = open(&k, 0, &msg[88..116], &h) else { return Vec::new() };
        let Ok(ts) = <[u8; 12]>::try_from(ts.as_slice()) else { return Vec::new() };
        if ts <= self.peers[peer].last_timestamp {
            return Vec::new(); // replayed initiation
        }
        h = hash(&[&h, &msg[88..116]]);

        // Response.
        let local_index = self.new_index(peer);
        let eph = random_secret();
        let eph_pub = PublicKey::from(&eph).to_bytes();
        c = kdf1(&c, &eph_pub);
        h = hash(&[&h, &eph_pub]);
        c = kdf1(&c, &dh(&eph, &eph_i));
        c = kdf1(&c, &dh(&eph, &static_i));
        let psk = self.peers[peer].cfg.preshared_key.unwrap_or([0; 32]);
        let (c4, tau, k) = kdf3(&c, &psk);
        c = c4;
        h = hash(&[&h, &tau]);
        let enc_nothing = seal(&k, 0, &[], &h);

        let mut out = vec![2u8, 0, 0, 0];
        out.extend_from_slice(&local_index.to_le_bytes());
        out.extend_from_slice(&sender.to_le_bytes());
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&enc_nothing);
        let mac1 = mac16(&hash(&[LABEL_MAC1, &static_i]), &out);
        out.extend_from_slice(&mac1);
        out.extend_from_slice(&[0u8; 16]);

        let (recv, send) = kdf2(&c, &[]);
        let p = &mut self.peers[peer];
        p.last_timestamp = ts;
        p.endpoint = Some(from);
        p.last_handshake = Some(SystemTime::now());
        p.last_sent = Some(now);
        let old = p.next.replace(Session {
            local_index,
            remote_index: sender,
            send_key: send,
            recv_key: recv,
            send_counter: 0,
            replay: Replay::default(),
            created: now,
            initiator: false,
        });
        self.forget_session(old);
        vec![Output::Network(from, out)]
    }

    fn on_response(&mut self, from: SocketAddrV4, msg: &[u8], now: Instant) -> Vec<Output> {
        if msg.len() != 92 || mac16(&hash(&[LABEL_MAC1, &self.public]), &msg[..60]) != msg[60..76] {
            return Vec::new();
        }
        let sender = u32::from_le_bytes(msg[4..8].try_into().expect("4 bytes"));
        let receiver = u32::from_le_bytes(msg[8..12].try_into().expect("4 bytes"));
        let Some(&peer) = self.indexes.get(&receiver) else { return Vec::new() };
        let Some(pending) = self.peers[peer].pending.as_ref().filter(|p| p.local_index == receiver) else { return Vec::new() };
        let eph_r: [u8; 32] = msg[12..44].try_into().expect("32 bytes");
        let mut c = kdf1(&pending.chaining, &eph_r);
        let mut h = hash(&[&pending.hash, &eph_r]);
        c = kdf1(&c, &dh(&pending.ephemeral, &eph_r));
        c = kdf1(&c, &dh(&self.secret, &eph_r));
        let psk = self.peers[peer].cfg.preshared_key.unwrap_or([0; 32]);
        let (c2, tau, k) = kdf3(&c, &psk);
        c = c2;
        h = hash(&[&h, &tau]);
        if open(&k, 0, &msg[44..60], &h).is_none() {
            return Vec::new();
        }
        let (send, recv) = kdf2(&c, &[]);
        let p = &mut self.peers[peer];
        let pending = p.pending.take().expect("checked");
        p.endpoint = Some(from);
        p.last_handshake = Some(SystemTime::now());
        let session = Session {
            local_index: pending.local_index,
            remote_index: sender,
            send_key: send,
            recv_key: recv,
            send_counter: 0,
            replay: Replay::default(),
            created: now,
            initiator: true,
        };
        let prev = p.previous.take();
        p.previous = p.current.replace(session);
        self.forget_session(prev);
        // Flush what waited for the handshake; a keepalive confirms it otherwise.
        let queued = std::mem::take(&mut self.peers[peer].queue);
        let mut out: Vec<Output> = queued.iter().filter_map(|pkt| self.data(peer, pkt, now)).collect();
        if out.is_empty() {
            out.extend(self.data(peer, &[], now));
        }
        out
    }

    // ------------------------------------------------------- transport

    fn data(&mut self, peer: usize, packet: &[u8], now: Instant) -> Option<Output> {
        let p = &mut self.peers[peer];
        let endpoint = p.endpoint?;
        let s = p.current.as_mut()?;
        if s.send_counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let mut padded = packet.to_vec();
        padded.resize(packet.len().div_ceil(16) * 16, 0);
        let counter = s.send_counter;
        s.send_counter += 1;
        let mut msg = vec![4u8, 0, 0, 0];
        msg.extend_from_slice(&s.remote_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(&seal(&s.send_key, counter, &padded, &[]));
        p.last_sent = Some(now);
        p.tx_bytes += msg.len() as u64;
        Some(Output::Network(endpoint, msg))
    }

    fn on_data(&mut self, from: SocketAddrV4, msg: &[u8], now: Instant) -> Vec<Output> {
        if msg.len() < 32 {
            return Vec::new();
        }
        let receiver = u32::from_le_bytes(msg[4..8].try_into().expect("4 bytes"));
        let counter = u64::from_le_bytes(msg[8..16].try_into().expect("8 bytes"));
        let Some(&peer) = self.indexes.get(&receiver) else { return Vec::new() };
        let p = &mut self.peers[peer];
        let (slot, plain) = {
            let try_open = |s: &mut Option<Session>| -> Option<Vec<u8>> {
                let s = s.as_mut().filter(|s| s.local_index == receiver && now.duration_since(s.created) < REJECT_AFTER_TIME)?;
                let plain = open(&s.recv_key, counter, &msg[16..], &[])?;
                s.replay.accept(counter).then_some(plain)
            };
            if let Some(pl) = try_open(&mut p.current) {
                (0, pl)
            } else if let Some(pl) = try_open(&mut p.next) {
                (1, pl)
            } else if let Some(pl) = try_open(&mut p.previous) {
                (2, pl)
            } else {
                return Vec::new();
            }
        };
        if slot == 1 {
            // The initiator used our new session: it becomes current.
            let prev = p.previous.take();
            p.previous = p.current.take();
            p.current = p.next.take();
            self.forget_session(prev);
        }
        let p = &mut self.peers[peer];
        p.endpoint = Some(from);
        p.last_received = Some(now);
        p.rx_bytes += msg.len() as u64;
        if plain.is_empty() {
            return Vec::new(); // keepalive
        }
        let total = usize::from(u16::from_be_bytes([*plain.get(2).unwrap_or(&0), *plain.get(3).unwrap_or(&0)]));
        if total < 20 || total > plain.len() {
            return Vec::new();
        }
        let packet = plain[..total].to_vec();
        // The source must be one this peer may use (anti-spoofing).
        match inner_src(&packet) {
            Some(src) if self.peer_for(src) == Some(peer) => vec![Output::Tunnel { peer, packet }],
            _ => Vec::new(),
        }
    }

    // ------------------------------------------------------------- api

    /// Encrypt an inner IPv4 packet for the peer that owns its destination.
    /// Without a session the packet waits and a handshake starts.
    pub fn send(&mut self, packet: &[u8], now: Instant) -> Vec<Output> {
        let Some(dst) = inner_dst(packet) else { return Vec::new() };
        let Some(peer) = self.peer_for(dst) else { return Vec::new() };
        let usable = self.peers[peer].current.as_ref().map_or(false, |s| now.duration_since(s.created) < REJECT_AFTER_TIME);
        let mut out = Vec::new();
        if usable {
            out.extend(self.data(peer, packet, now));
            let old = self.peers[peer].current.as_ref().map_or(false, |s| s.initiator && now.duration_since(s.created) >= REKEY_AFTER_TIME);
            if old && self.peers[peer].pending.is_none() {
                out.extend(self.initiation(peer, now));
            }
        } else {
            let p = &mut self.peers[peer];
            if p.queue.len() < MAX_QUEUED {
                p.queue.push(packet.to_vec());
            }
            if p.pending.is_none() {
                out.extend(self.initiation(peer, now));
            }
        }
        out
    }

    /// Handle one UDP datagram received on the tunnel's port.
    pub fn receive(&mut self, from: SocketAddrV4, datagram: &[u8], now: Instant) -> Vec<Output> {
        if datagram.len() < 4 || datagram[1..4] != [0, 0, 0] {
            return Vec::new();
        }
        match datagram[0] {
            1 => self.on_initiation(from, datagram, now),
            2 => self.on_response(from, datagram, now),
            4 => self.on_data(from, datagram, now),
            _ => Vec::new(), // cookie replies are not implemented
        }
    }

    /// Timers: handshake retry, giving up, key expiry and keepalives.
    pub fn tick(&mut self, now: Instant) -> Vec<Output> {
        let mut out = Vec::new();
        for i in 0..self.peers.len() {
            // Expire old keys.
            for which in 0..3 {
                let p = &mut self.peers[i];
                let slot = match which {
                    0 => &mut p.current,
                    1 => &mut p.next,
                    _ => &mut p.previous,
                };
                if slot.as_ref().map_or(false, |s| now.duration_since(s.created) >= REJECT_AFTER_TIME * 3) {
                    let s = slot.take();
                    self.forget_session(s);
                }
            }
            let p = &self.peers[i];
            if let Some(pending) = &p.pending {
                if now.duration_since(pending.first_sent) >= REKEY_ATTEMPT_TIME {
                    let idx = pending.local_index;
                    let p = &mut self.peers[i];
                    p.pending = None;
                    p.queue.clear();
                    self.indexes.remove(&idx);
                } else if now.duration_since(pending.sent) >= REKEY_TIMEOUT {
                    out.extend(self.initiation(i, now));
                }
                continue;
            }
            let p = &self.peers[i];
            let session_ok = p.current.as_ref().map_or(false, |s| now.duration_since(s.created) < REJECT_AFTER_TIME);
            let since_sent = p.last_sent.map(|t| now.duration_since(t));
            if let Some(ka) = p.cfg.keepalive.filter(|k| *k > 0) {
                if since_sent.map_or(true, |d| d >= Duration::from_secs(u64::from(ka))) && p.endpoint.is_some() {
                    if session_ok {
                        out.extend(self.data(i, &[], now));
                    } else {
                        out.extend(self.initiation(i, now));
                    }
                    continue;
                }
            }
            // Passive keepalive: answer received data within KEEPALIVE_TIMEOUT.
            let p = &self.peers[i];
            if let (Some(rx), true) = (p.last_received, session_ok) {
                let replied = p.last_sent.map_or(false, |tx| tx >= rx);
                if !replied && now.duration_since(rx) >= KEEPALIVE_TIMEOUT {
                    out.extend(self.data(i, &[], now));
                }
            }
        }
        out
    }

    /// One line per peer for `show vpn`.
    pub fn status(&self) -> Vec<String> {
        self.peers
            .iter()
            .map(|p| {
                let hs = p
                    .last_handshake
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .map(|d| format!("{}s ago", d.as_secs()))
                    .unwrap_or_else(|| "never".into());
                format!(
                    "  peer {} ({}) endpoint {} allowed {} handshake {hs} rx {} B tx {} B{}",
                    p.cfg.name,
                    b64_encode(&p.cfg.public_key),
                    p.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "(none)".into()),
                    p.cfg.allowed_ips.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
                    p.rx_bytes,
                    p.tx_bytes,
                    if p.current.is_some() { "" } else { " (no session)" }
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::{Tunn, TunnResult};

    /// A minimal IPv4/UDP packet (valid header checksum is not needed by WireGuard).
    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 17, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, ((8 + payload.len()) >> 8) as u8, (8 + payload.len()) as u8, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn pair() -> (StaticSecret, StaticSecret) {
        (random_secret(), random_secret())
    }

    fn device(own: &StaticSecret, peer_pub: [u8; 32], allowed: &str, endpoint: Option<&str>, psk: Option<[u8; 32]>) -> Device {
        Device::new(TunnelConfig {
            name: "wg0".into(),
            vdom: "root".into(),
            private_key: own.to_bytes(),
            listen_port: 51820,
            peers: vec![PeerConfig {
                name: "peer".into(),
                public_key: peer_pub,
                preshared_key: psk,
                endpoint: endpoint.map(|e| e.parse().unwrap()),
                allowed_ips: vec![Cidr::parse(allowed).unwrap()],
                keepalive: None,
            }],
        })
    }

    fn network(out: &[Output]) -> Vec<Vec<u8>> {
        out.iter().filter_map(|o| if let Output::Network(_, d) = o { Some(d.clone()) } else { None }).collect()
    }

    #[test]
    fn keys_encode_like_wg() {
        let k = genkey();
        assert_eq!(k.len(), 44);
        assert_eq!(b64_encode(&key_from_b64(&k).unwrap()), k);
        // RFC 7748 test vector: Alice's key pair.
        let alice_priv = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb,
            0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_pub = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26,
            0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(key_from_b64(&pubkey(&b64_encode(&alice_priv)).unwrap()).unwrap(), alice_pub);
        assert!(key_from_b64("not a key").is_err());
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.accept(0) && r.accept(2) && r.accept(1));
        assert!(!r.accept(1), "duplicate");
        assert!(r.accept(5000));
        assert!(!r.accept(100), "too old");
        assert!(r.accept(4000) && !r.accept(4000));
    }

    #[test]
    fn interop_we_initiate_boringtun_responds() {
        let (ours, theirs) = pair();
        let ours_pub = PublicKey::from(&ours);
        let psk = [7u8; 32];
        let mut me = device(&ours, PublicKey::from(&theirs).to_bytes(), "10.99.0.2/32", Some("192.0.2.2:51820"), Some(psk));
        let mut bt = Tunn::new(theirs, ours_pub, Some(psk), None, 1, None);
        let now = Instant::now();
        let mut buf = vec![0u8; 2048];

        let pkt = ipv4([10, 99, 0, 1], [10, 99, 0, 2], b"hello from the firewall");
        let init = network(&me.send(&pkt, now));
        assert_eq!(init.len(), 1, "packet queued, initiation sent");
        let resp = match bt.decapsulate(None, &init[0], &mut buf) {
            TunnResult::WriteToNetwork(r) => r.to_vec(),
            other => panic!("boringtun rejected our initiation: {other:?}"),
        };
        let from: SocketAddrV4 = "192.0.2.2:51820".parse().unwrap();
        let data = network(&me.receive(from, &resp, now));
        assert_eq!(data.len(), 1, "queued packet sent after the handshake");
        match bt.decapsulate(None, &data[0], &mut buf) {
            TunnResult::WriteToTunnelV4(p, src) => {
                assert_eq!(p, pkt.as_slice());
                assert_eq!(src, Ipv4Addr::new(10, 99, 0, 1));
            }
            other => panic!("boringtun could not decrypt our data: {other:?}"),
        }
        // And back.
        let reply = ipv4([10, 99, 0, 2], [10, 99, 0, 1], b"hello from boringtun");
        let wire = match bt.encapsulate(&reply, &mut buf) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        assert_eq!(me.receive(from, &wire, now), vec![Output::Tunnel { peer: 0, packet: reply.clone() }]);
        assert!(me.receive(from, &wire, now).is_empty(), "replayed data is dropped");
    }

    #[test]
    fn interop_boringtun_initiates_we_respond() {
        let (ours, theirs) = pair();
        let ours_pub = PublicKey::from(&ours);
        let mut me = device(&ours, PublicKey::from(&theirs).to_bytes(), "10.99.0.2/32", None, None);
        let mut bt = Tunn::new(theirs, ours_pub, None, None, 2, None);
        let now = Instant::now();
        let mut buf = vec![0u8; 2048];
        let from: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();

        let init = match bt.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        let resp = network(&me.receive(from, &init, now));
        assert_eq!(resp.len(), 1);
        assert!(!me.receive(from, &init, now).iter().any(|o| matches!(o, Output::Network(..))), "replayed initiation ignored");
        // boringtun completes the handshake (and may send a keepalive).
        let mut first = Vec::new();
        if let TunnResult::WriteToNetwork(w) = bt.decapsulate(None, &resp[0], &mut buf) {
            first = w.to_vec();
        }
        if !first.is_empty() {
            assert!(me.receive(from, &first, now).is_empty(), "keepalive");
        }
        let pkt = ipv4([10, 99, 0, 2], [10, 99, 0, 1], b"over the tunnel");
        let wire = match bt.encapsulate(&pkt, &mut buf) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{other:?}"),
        };
        assert_eq!(me.receive(from, &wire, now), vec![Output::Tunnel { peer: 0, packet: pkt }]);
        assert_eq!(me.peers[0].endpoint, Some(from), "endpoint learned from the peer");
        // Our reply uses the session boringtun confirmed.
        let reply = ipv4([10, 99, 0, 1], [10, 99, 0, 2], b"reply");
        let out = network(&me.send(&reply, now));
        match bt.decapsulate(None, &out[0], &mut buf) {
            TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, reply.as_slice()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn spoofed_inner_source_is_dropped() {
        let (a, b) = pair();
        let mut x = device(&a, PublicKey::from(&b).to_bytes(), "10.99.0.2/32", Some("192.0.2.2:51820"), None);
        let mut y = device(&b, PublicKey::from(&a).to_bytes(), "10.99.0.1/32", Some("192.0.2.1:51820"), None);
        let now = Instant::now();
        let (ex, ey): (SocketAddrV4, SocketAddrV4) = ("192.0.2.1:51820".parse().unwrap(), "192.0.2.2:51820".parse().unwrap());
        let init = network(&x.send(&ipv4([10, 99, 0, 1], [10, 99, 0, 2], b"a"), now));
        let resp = network(&y.receive(ex, &init[0], now));
        let data = network(&x.receive(ey, &resp[0], now));
        assert!(matches!(y.receive(ex, &data[0], now).as_slice(), [Output::Tunnel { .. }]));
        // y now has a session with x. x sends a packet claiming another source.
        let spoof = network(&x.send(&ipv4([10, 0, 0, 66], [10, 99, 0, 2], b"spoof"), now));
        assert!(y.receive(ex, &spoof[0], now).is_empty(), "inner source outside x's allowed IPs");
    }

    #[test]
    fn retries_then_gives_up() {
        let (a, b) = pair();
        let mut x = device(&a, PublicKey::from(&b).to_bytes(), "10.99.0.2/32", Some("192.0.2.2:51820"), None);
        let t0 = Instant::now();
        assert_eq!(network(&x.send(&ipv4([10, 99, 0, 1], [10, 99, 0, 2], b"a"), t0)).len(), 1);
        assert!(network(&x.tick(t0 + Duration::from_secs(1))).is_empty());
        assert_eq!(network(&x.tick(t0 + Duration::from_secs(6))).len(), 1, "retry after REKEY_TIMEOUT");
        x.tick(t0 + Duration::from_secs(91));
        assert!(x.peers[0].queue.is_empty(), "queue dropped after REKEY_ATTEMPT_TIME");
    }
}
