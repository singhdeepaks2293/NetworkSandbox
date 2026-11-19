//! OpenFlow 1.3 (wire version 0x04) support for the educational switch.
//!
//! The switch implements the *switch side* of a small but useful OpenFlow
//! subset on top of its existing VLAN dataplane:
//!
//! * a controller session (active `openflow controller HOST [PORT]` or a
//!   passive listener on TCP 6653 by default), HELLO negotiation,
//!   echo keep-alives, features and configuration requests;
//! * one flow table with `in_port`, `eth_dst`, `eth_src`, `eth_type`,
//!   `vlan_vid`, `vlan_pcp`, `ip_proto`, `ipv4_src` and `ipv4_dst` exact
//!   matches, priorities and idle/hard timeouts;
//! * `OUTPUT` actions, including the `IN_PORT`, `FLOOD`, `ALL`, `NORMAL`,
//!   `CONTROLLER` and `TABLE` pseudo-ports;
//! * `PACKET_IN` (with buffering), `PACKET_OUT`, flow stats, aggregate stats,
//!   table stats, port descriptions and port stats.
//!
//! Forwarding stays deliberately transparent: a table miss produces a
//! `PACKET_IN` while a controller is connected (secure behaviour), and falls
//! back to the native VLAN bridge when no controller is attached and the fail
//! mode is `standalone`.  When the feature is disabled the packet path is
//! exactly the original 802.1Q bridge.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::dataplane::Io;
use crate::model::{PortMode, Switch};
use crate::packet::{self, L2Frame, VlanTag};

// ---------------------------------------------------------------------------
// Protocol constants (OpenFlow 1.3.5)
// ---------------------------------------------------------------------------

pub const OF_VERSION: u8 = 0x04;

const OFPT_HELLO: u8 = 0;
const OFPT_ERROR: u8 = 1;
const OFPT_ECHO_REQUEST: u8 = 2;
const OFPT_ECHO_REPLY: u8 = 3;
const OFPT_EXPERIMENTER: u8 = 4;
const OFPT_FEATURES_REQUEST: u8 = 5;
const OFPT_FEATURES_REPLY: u8 = 6;
const OFPT_GET_CONFIG_REQUEST: u8 = 7;
const OFPT_GET_CONFIG_REPLY: u8 = 8;
const OFPT_SET_CONFIG: u8 = 9;
const OFPT_PACKET_IN: u8 = 10;
const OFPT_FLOW_REMOVED: u8 = 11;
const OFPT_PORT_STATUS: u8 = 12;
const OFPT_PACKET_OUT: u8 = 13;
const OFPT_FLOW_MOD: u8 = 14;
const OFPT_GROUP_MOD: u8 = 15;
const OFPT_PORT_MOD: u8 = 16;
const OFPT_TABLE_MOD: u8 = 17;
const OFPT_MULTIPART_REQUEST: u8 = 18;
const OFPT_MULTIPART_REPLY: u8 = 19;
const OFPT_BARRIER_REQUEST: u8 = 20;
const OFPT_BARRIER_REPLY: u8 = 21;
const OFPT_ROLE_REQUEST: u8 = 24;
const OFPT_ROLE_REPLY: u8 = 25;

// Error types and codes we use.
const OFPET_HELLO_FAILED: u16 = 0;
const OFPHFC_INCOMPATIBLE: u16 = 0;
const OFPET_BAD_REQUEST: u16 = 1;
const OFPBRC_BAD_VERSION: u16 = 0;
const OFPBRC_BAD_TYPE: u16 = 1;
const OFPBRC_BAD_MULTIPART: u16 = 2;
const OFPBRC_BAD_LEN: u16 = 6;
const OFPBRC_BUFFER_UNKNOWN: u16 = 8;
const OFPET_BAD_ACTION: u16 = 2;
const OFPBAC_BAD_TYPE: u16 = 0;
const OFPBAC_BAD_LEN: u16 = 1;
const OFPET_BAD_INSTRUCTION: u16 = 3;
const OFPBIC_UNKNOWN_INST: u16 = 0;
const OFPBIC_UNSUP_INST: u16 = 1;
const OFPET_BAD_MATCH: u16 = 4;
const OFPBMC_BAD_TYPE: u16 = 0;
const OFPBMC_BAD_LEN: u16 = 1;
const OFPBMC_BAD_FIELD: u16 = 6;
const OFPBMC_BAD_MASK: u16 = 8;
const OFPBMC_BAD_PREREQ: u16 = 9;
const OFPBMC_DUP_FIELD: u16 = 10;
const OFPET_FLOW_MOD_FAILED: u16 = 5;
const OFPFMFC_BAD_COMMAND: u16 = 6;
const OFPFMFC_BAD_TABLE_ID: u16 = 2;
const OFPET_PORT_MOD_FAILED: u16 = 7;
const OFPPMFC_BAD_PORT: u16 = 0;

const OFPFC_ADD: u8 = 0;
const OFPFC_MODIFY: u8 = 1;
const OFPFC_MODIFY_STRICT: u8 = 2;
const OFPFC_DELETE: u8 = 3;
const OFPFC_DELETE_STRICT: u8 = 4;

const OFPIT_GOTO_TABLE: u16 = 1;
const OFPIT_WRITE_METADATA: u16 = 2;
const OFPIT_WRITE_ACTIONS: u16 = 3;
const OFPIT_APPLY_ACTIONS: u16 = 4;
const OFPIT_CLEAR_ACTIONS: u16 = 5;
const OFPIT_METER: u16 = 6;

const OFPAT_OUTPUT: u16 = 0;

const OFPP_MAX: u32 = 0x00ff_ff00;
const OFPP_IN_PORT: u32 = 0xffff_fff8;
const OFPP_TABLE: u32 = 0xffff_fff9;
const OFPP_NORMAL: u32 = 0xffff_fffa;
const OFPP_FLOOD: u32 = 0xffff_fffb;
const OFPP_ALL: u32 = 0xffff_fffc;
const OFPP_CONTROLLER: u32 = 0xffff_fffd;
const OFPP_LOCAL: u32 = 0xffff_fffe;
const OFPP_ANY: u32 = 0xffff_ffff;

const OFPMP_DESC: u16 = 0;
const OFPMP_FLOW: u16 = 1;
const OFPMP_AGGREGATE: u16 = 2;
const OFPMP_TABLE: u16 = 3;
const OFPMP_PORT_STATS: u16 = 4;
const OFPMP_GROUP: u16 = 6;
const OFPMP_GROUP_DESC: u16 = 7;
const OFPMP_GROUP_FEATURES: u16 = 8;
const OFPMP_METER: u16 = 9;
const OFPMP_METER_CONFIG: u16 = 10;
const OFPMP_METER_FEATURES: u16 = 11;
const OFPMP_TABLE_FEATURES: u16 = 12;
const OFPMP_PORT_DESC: u16 = 13;

const OFPR_NO_MATCH: u8 = 0;
const OFPR_ACTION: u8 = 1;

const OFPVID_PRESENT: u16 = 0x1000;
const OFPVID_NONE: u16 = 0x0000;
const OFP_NO_BUFFER: u32 = 0xffff_ffff;

const OFPPC_PORT_DOWN: u32 = 1 << 0;
const OFPPS_LINK_DOWN: u32 = 1 << 0;
const OFPPS_BLOCKED: u32 = 1 << 1;
const OFPPS_LIVE: u32 = 1 << 2;

const OFPPF_10MB_HD: u32 = 1 << 0;
const OFPPF_10MB_FD: u32 = 1 << 1;
const OFPPF_100MB_HD: u32 = 1 << 2;
const OFPPF_100MB_FD: u32 = 1 << 3;
const OFPPF_1GB_HD: u32 = 1 << 4;
const OFPPF_1GB_FD: u32 = 1 << 5;
const OFPPF_10GB_FD: u32 = 1 << 6;
const OFPPF_COPPER: u32 = 1 << 11;
const OFPPF_AUTONEG: u32 = 1 << 13;

const OFPC_FLOW_STATS: u32 = 1 << 0;
const OFPC_TABLE_STATS: u32 = 1 << 1;
const OFPC_PORT_STATS: u32 = 1 << 2;
const OFPC_QUEUE_STATS: u32 = 1 << 4;

const OFP_MAX_BUFFERS: usize = 64;
const OFP_MAX_QUEUE: usize = 256;

// OXM fields (OpenFlow basic class 0x8000).
const OXM_IN_PORT: u8 = 0;
const OXM_ETH_DST: u8 = 3;
const OXM_ETH_SRC: u8 = 4;
const OXM_ETH_TYPE: u8 = 5;
const OXM_VLAN_VID: u8 = 6;
const OXM_VLAN_PCP: u8 = 7;
const OXM_IP_PROTO: u8 = 10;
const OXM_IPV4_SRC: u8 = 11;
const OXM_IPV4_DST: u8 = 12;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ---------------------------------------------------------------------------
// Configuration and shared runtime state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailMode {
    /// Forward with the native VLAN bridge when no controller is attached.
    Standalone,
    /// Drop packets when no controller is attached.
    Secure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFlowConfig {
    pub enabled: bool,
    /// Active connection to a controller, `host:port`.
    pub controller: Option<(String, u16)>,
    /// Passive listener port.  `None` means the default 6653 while enabled.
    pub listen_port: Option<u16>,
    pub fail_mode: FailMode,
    pub datapath_id: u64,
}

impl OpenFlowConfig {
    pub fn listening_port(&self) -> u16 {
        self.listen_port.unwrap_or(6653)
    }
}

#[derive(Clone, Debug, Default)]
pub struct OfStats {
    pub msgs_in: u64,
    pub msgs_out: u64,
    pub packet_in: u64,
    pub packet_out: u64,
    pub flow_mods: u64,
    pub errors: u64,
    pub dropped: u64,
    pub lookups: u64,
    pub matched: u64,
}

pub struct OfShared {
    pub flows: Mutex<FlowTable>,
    pub queue: Mutex<VecDeque<Vec<u8>>>,
    pub buffers: Mutex<VecDeque<(u32, Buffered)>>,
    next_buffer: AtomicU32,
    pub connected: AtomicBool,
    pub remote: Mutex<Option<String>>,
    pub stats: Mutex<OfStats>,
}

impl OfShared {
    fn new() -> Self {
        OfShared {
            flows: Mutex::new(FlowTable::default()),
            queue: Mutex::new(VecDeque::new()),
            buffers: Mutex::new(VecDeque::new()),
            next_buffer: AtomicU32::new(1),
            connected: AtomicBool::new(false),
            remote: Mutex::new(None),
            stats: Mutex::new(OfStats::default()),
        }
    }

    fn push_out(&self, msg: Vec<u8>) {
        let mut q = lock(&self.queue);
        if q.len() >= OFP_MAX_QUEUE {
            q.pop_front();
            lock(&self.stats).dropped += 1;
        }
        q.push_back(msg);
    }

    fn alloc_buffer(&self, pkt: &Buffered) -> u32 {
        let mut id = self.next_buffer.fetch_add(1, Ordering::SeqCst);
        if id == 0 || id == OFP_NO_BUFFER {
            id = self.next_buffer.fetch_add(1, Ordering::SeqCst);
        }
        let mut q = lock(&self.buffers);
        if q.len() >= OFP_MAX_BUFFERS {
            q.pop_front();
        }
        q.push_back((id, pkt.clone()));
        id
    }

    fn take_buffer(&self, id: u32) -> Option<Buffered> {
        let mut q = lock(&self.buffers);
        if let Some(pos) = q.iter().position(|(b, _)| *b == id) {
            q.remove(pos).map(|(_, p)| p)
        } else {
            None
        }
    }

    pub fn clear_flows(&self) {
        lock(&self.flows).clear();
        lock(&self.buffers).clear();
    }

    pub fn flow_count(&self) -> usize {
        lock(&self.flows).entries.len()
    }
}

pub struct OpenFlow {
    pub config: OpenFlowConfig,
    pub shared: Arc<OfShared>,
}

impl OpenFlow {
    pub fn new(system_mac: [u8; 6]) -> Self {
        OpenFlow {
            config: OpenFlowConfig {
                enabled: false,
                controller: None,
                listen_port: None,
                fail_mode: FailMode::Standalone,
                datapath_id: packet::mac_to_u64(system_mac),
            },
            shared: Arc::new(OfShared::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }
}

// ---------------------------------------------------------------------------
// Flow table
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OfMatch {
    pub in_port: Option<u32>,
    pub eth_dst: Option<[u8; 6]>,
    pub eth_src: Option<[u8; 6]>,
    pub eth_type: Option<u16>,
    pub vlan_vid: Option<u16>,
    pub vlan_pcp: Option<u8>,
    pub ip_proto: Option<u8>,
    pub ipv4_src: Option<[u8; 4]>,
    pub ipv4_dst: Option<[u8; 4]>,
}

impl OfMatch {
    fn matches(&self, v: &PacketView) -> bool {
        if self.in_port.map_or(false, |p| p != v.in_port) {
            return false;
        }
        if self.eth_dst.map_or(false, |m| m != v.eth_dst) {
            return false;
        }
        if self.eth_src.map_or(false, |m| m != v.eth_src) {
            return false;
        }
        if self.eth_type.map_or(false, |t| t != v.eth_type) {
            return false;
        }
        if let Some(vv) = self.vlan_vid {
            // Accept both the raw VID and the OFPVID_PRESENT form.  The
            // switch always classifies a frame into a VLAN, so the present
            // bit is implied.
            if vv == OFPVID_NONE || (vv & 0x0fff) != v.vlan {
                return false;
            }
        }
        if self.vlan_pcp.map_or(false, |p| p != v.vlan_pcp) {
            return false;
        }
        if self.ip_proto.map_or(false, |p| Some(p) != v.ip_proto) {
            return false;
        }
        if self.ipv4_src.map_or(false, |a| Some(a) != v.ipv4_src) {
            return false;
        }
        if self.ipv4_dst.map_or(false, |a| Some(a) != v.ipv4_dst) {
            return false;
        }
        true
    }

    /// True when every field specified in `self` is also present with the
    /// same value in `other` (used for non-strict deletes/modifies).
    fn covers(&self, other: &OfMatch) -> bool {
        self.in_port.map_or(true, |x| other.in_port == Some(x))
            && self.eth_dst.map_or(true, |x| other.eth_dst == Some(x))
            && self.eth_src.map_or(true, |x| other.eth_src == Some(x))
            && self.eth_type.map_or(true, |x| other.eth_type == Some(x))
            && self.vlan_vid.map_or(true, |x| other.vlan_vid == Some(x))
            && self.vlan_pcp.map_or(true, |x| other.vlan_pcp == Some(x))
            && self.ip_proto.map_or(true, |x| other.ip_proto == Some(x))
            && self.ipv4_src.map_or(true, |x| other.ipv4_src == Some(x))
            && self.ipv4_dst.map_or(true, |x| other.ipv4_dst == Some(x))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfAction {
    Output(u32),
}

#[derive(Clone, Debug)]
pub struct FlowEntry {
    pub cookie: u64,
    pub priority: u16,
    pub mat: OfMatch,
    pub actions: Vec<OfAction>,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub flags: u16,
    pub created: Instant,
    pub last_used: Instant,
    pub packets: u64,
    pub bytes: u64,
}

impl FlowEntry {
    fn expired(&self, now: Instant) -> bool {
        if self.hard_timeout != 0
            && now.duration_since(self.created).as_secs() >= self.hard_timeout as u64
        {
            return true;
        }
        if self.idle_timeout != 0
            && now.duration_since(self.last_used).as_secs() >= self.idle_timeout as u64
        {
            return true;
        }
        false
    }

    fn outputs_to(&self, port: u32) -> bool {
        self.actions
            .iter()
            .any(|a| matches!(a, OfAction::Output(p) if *p == port))
    }
}

#[derive(Default)]
pub struct FlowTable {
    pub entries: Vec<FlowEntry>,
}

impl FlowTable {
    fn clear(&mut self) {
        self.entries.clear();
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|e| !e.expired(now));
    }

    fn add(&mut self, entry: FlowEntry) {
        // OFPFC_ADD replaces a flow with the same priority and match.
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.priority == entry.priority && e.mat == entry.mat)
        {
            self.entries.remove(pos);
        }
        self.entries.push(entry);
        self.entries.sort_by_key(|e| std::cmp::Reverse(e.priority));
    }

    /// Return the highest-priority matching entry and account the lookup.
    fn lookup(&mut self, view: &PacketView) -> Option<usize> {
        let pos = self.entries.iter().position(|e| e.mat.matches(view))?;
        let e = &mut self.entries[pos];
        e.packets += 1;
        e.bytes += view.len as u64;
        e.last_used = view.now;
        Some(pos)
    }

    fn delete(
        &mut self,
        mat: &OfMatch,
        priority: Option<u16>,
        strict: bool,
        out_port: u32,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            let m = if strict {
                e.mat == *mat && priority.map_or(true, |p| p == e.priority)
            } else {
                mat.covers(&e.mat)
            };
            let port_ok = out_port == OFPP_ANY || e.outputs_to(out_port);
            !(m && port_ok)
        });
        before - self.entries.len()
    }

    fn modify(
        &mut self,
        mat: &OfMatch,
        priority: Option<u16>,
        strict: bool,
        new: &FlowEntry,
    ) -> usize {
        let mut n = 0;
        for e in self.entries.iter_mut() {
            let m = if strict {
                e.mat == *mat && priority.map_or(true, |p| p == e.priority)
            } else {
                mat.covers(&e.mat)
            };
            if m {
                e.actions = new.actions.clone();
                e.idle_timeout = new.idle_timeout;
                e.hard_timeout = new.hard_timeout;
                if strict {
                    e.priority = new.priority;
                }
                e.cookie = new.cookie;
                n += 1;
            }
        }
        if n > 0 {
            self.entries.sort_by_key(|e| std::cmp::Reverse(e.priority));
        }
        n
    }

    fn aggregate(&self) -> (u64, u64, u32) {
        let packets = self.entries.iter().map(|e| e.packets).sum();
        let bytes = self.entries.iter().map(|e| e.bytes).sum();
        (packets, bytes, self.entries.len() as u32)
    }
}

// ---------------------------------------------------------------------------
// Packet representation used by the flow table and packet-in buffers
// ---------------------------------------------------------------------------

pub struct PacketView {
    pub in_port: u32,
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub eth_type: u16,
    pub vlan: u16,
    pub vlan_pcp: u8,
    pub ip_proto: Option<u8>,
    pub ipv4_src: Option<[u8; 4]>,
    pub ipv4_dst: Option<[u8; 4]>,
    pub len: usize,
    pub now: Instant,
}

impl PacketView {
    fn new(in_port: usize, vlan: u16, pcp: u8, frame: &L2Frame<'_>) -> Self {
        let (ip_proto, ipv4_src, ipv4_dst) = ip_fields(frame);
        PacketView {
            in_port: in_port as u32,
            eth_dst: frame.dst,
            eth_src: frame.src,
            eth_type: frame.ethertype,
            vlan,
            vlan_pcp: pcp,
            ip_proto,
            ipv4_src,
            ipv4_dst,
            len: frame.payload.len() + 18,
            now: Instant::now(),
        }
    }
}

/// A buffered packet, stored with the internal (untagged) view of the frame
/// and the original wire bytes for packet-in.
#[derive(Clone)]
pub struct Buffered {
    pub in_port: u32,
    pub vlan: u16,
    pub pcp: u8,
    pub dei: bool,
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: Vec<u8>,
    pub wire: Vec<u8>,
}

impl Buffered {
    fn from_frame(
        in_port: usize,
        vlan: u16,
        pcp: u8,
        dei: bool,
        frame: &L2Frame<'_>,
        wire: &[u8],
    ) -> Self {
        Buffered {
            in_port: in_port as u32,
            vlan,
            pcp,
            dei,
            dst: frame.dst,
            src: frame.src,
            ethertype: frame.ethertype,
            payload: frame.payload.to_vec(),
            wire: wire.to_vec(),
        }
    }

    #[cfg(test)]
    fn view(&self) -> PacketView {
        let (ip_proto, ipv4_src, ipv4_dst) =
            if self.ethertype == packet::ETHERTYPE_IPV4 && self.payload.len() >= 20 {
                (
                    Some(self.payload[9]),
                    Some([
                        self.payload[12],
                        self.payload[13],
                        self.payload[14],
                        self.payload[15],
                    ]),
                    Some([
                        self.payload[16],
                        self.payload[17],
                        self.payload[18],
                        self.payload[19],
                    ]),
                )
            } else {
                (None, None, None)
            };
        PacketView {
            in_port: self.in_port,
            eth_dst: self.dst,
            eth_src: self.src,
            eth_type: self.ethertype,
            vlan: self.vlan,
            vlan_pcp: self.pcp,
            ip_proto,
            ipv4_src,
            ipv4_dst,
            len: self.payload.len() + 18,
            now: Instant::now(),
        }
    }

    fn match_fields(&self) -> OfMatch {
        let (ip_proto, ipv4_src, ipv4_dst) = ip_fields_from_payload(self.ethertype, &self.payload);
        OfMatch {
            in_port: Some(self.in_port),
            eth_dst: Some(self.dst),
            eth_src: Some(self.src),
            eth_type: Some(self.ethertype),
            vlan_vid: Some(OFPVID_PRESENT | (self.vlan & 0x0fff)),
            vlan_pcp: Some(self.pcp),
            ip_proto,
            ipv4_src,
            ipv4_dst,
        }
    }
}

fn ip_fields(frame: &L2Frame<'_>) -> (Option<u8>, Option<[u8; 4]>, Option<[u8; 4]>) {
    ip_fields_from_payload(frame.ethertype, frame.payload)
}

fn ip_fields_from_payload(
    ethertype: u16,
    payload: &[u8],
) -> (Option<u8>, Option<[u8; 4]>, Option<[u8; 4]>) {
    if ethertype == packet::ETHERTYPE_IPV4 && payload.len() >= 20 {
        (
            Some(payload[9]),
            Some([payload[12], payload[13], payload[14], payload[15]]),
            Some([payload[16], payload[17], payload[18], payload[19]]),
        )
    } else {
        (None, None, None)
    }
}

// ---------------------------------------------------------------------------
// Ingress pipeline hook
// ---------------------------------------------------------------------------

pub enum Verdict {
    /// The frame was handled (output, dropped or sent to the controller).
    Consumed,
    /// Fall through to the native VLAN bridge.
    Native,
}

/// Consult the OpenFlow flow table for a frame that passed ingress
/// classification and STP gating.
pub fn process_ingress(
    sw: &mut Switch,
    io: &Io,
    in_port: usize,
    vlan: u16,
    pcp: u8,
    dei: bool,
    frame: &L2Frame<'_>,
    wire: &[u8],
) -> Verdict {
    if !sw.openflow.enabled() {
        return Verdict::Native;
    }
    let shared = Arc::clone(&sw.openflow.shared);
    let view = PacketView::new(in_port, vlan, pcp, frame);
    let actions = {
        let mut flows = lock(&shared.flows);
        let now = Instant::now();
        flows.expire(now);
        {
            let mut st = lock(&shared.stats);
            st.lookups += 1;
        }
        match flows.lookup(&view) {
            Some(pos) => {
                let actions = flows.entries[pos].actions.clone();
                lock(&shared.stats).matched += 1;
                Some(actions)
            }
            None => None,
        }
    };

    let Some(actions) = actions else {
        if shared.connected.load(Ordering::SeqCst) {
            let pkt = Buffered::from_frame(in_port, vlan, pcp, dei, frame, wire);
            queue_packet_in(&shared, &pkt, OFPR_NO_MATCH, 0, 0);
            return Verdict::Consumed;
        }
        return if sw.openflow.config.fail_mode == FailMode::Secure {
            Verdict::Consumed
        } else {
            Verdict::Native
        };
    };

    let pkt = Buffered::from_frame(in_port, vlan, pcp, dei, frame, wire);
    let native = apply_actions(sw, io, &shared, &pkt, &actions);
    if native {
        Verdict::Native
    } else {
        Verdict::Consumed
    }
}

/// Apply a list of actions.  Returns true when the action list asks for the
/// native learning/bridging pipeline (`NORMAL` or `TABLE`).
fn apply_actions(
    sw: &mut Switch,
    io: &Io,
    shared: &OfShared,
    pkt: &Buffered,
    actions: &[OfAction],
) -> bool {
    let mut native = false;
    for action in actions {
        let OfAction::Output(port) = *action;
        match port {
            OFPP_IN_PORT => send_out(sw, io, pkt, pkt.in_port as usize),
            OFPP_FLOOD => {
                let ports = sw.vlan_ports(pkt.vlan);
                for p in ports {
                    if p != pkt.in_port as usize {
                        send_out(sw, io, pkt, p);
                    }
                }
            }
            OFPP_ALL => {
                let ports: Vec<usize> = sw
                    .ports
                    .iter()
                    .filter(|p| p.oper_up())
                    .map(|p| p.index)
                    .collect();
                for p in ports {
                    if p != pkt.in_port as usize {
                        send_out(sw, io, pkt, p);
                    }
                }
            }
            OFPP_NORMAL | OFPP_TABLE => native = true,
            OFPP_CONTROLLER => queue_packet_in(shared, pkt, OFPR_ACTION, 0, 0),
            OFPP_LOCAL | OFPP_ANY => {}
            p if p <= OFPP_MAX => send_out(sw, io, pkt, p as usize),
            _ => {}
        }
    }
    native
}

fn send_out(sw: &mut Switch, io: &Io, pkt: &Buffered, port: usize) {
    if port == 0 || port > sw.ports.len() {
        return;
    }
    let Some(op) = sw.port(port).cloned() else {
        return;
    };
    if !op.oper_up() {
        return;
    }
    let tag = if op.mode == PortMode::Trunk && pkt.vlan != op.trunk.native_vlan {
        Some(VlanTag::with_pcp(pkt.vlan, pkt.pcp, pkt.dei))
    } else {
        None
    };
    let wire = packet::build_tagged(pkt.dst, pkt.src, tag, pkt.ethertype, &pkt.payload);
    io.send(port, &wire);
    if let Some(p) = sw.port_mut(port) {
        p.counters.tx_packets += 1;
        p.counters.tx_bytes += wire.len() as u64;
    }
}

fn queue_packet_in(shared: &OfShared, pkt: &Buffered, reason: u8, table_id: u8, cookie: u64) {
    let buffer_id = shared.alloc_buffer(pkt);
    let mat = pkt.match_fields();
    let mbytes = encode_match(&mat);
    let total_len = pkt.wire.len().min(u16::MAX as usize) as u16;
    let mut body = Vec::with_capacity(16 + mbytes.len() + pkt.wire.len());
    body.extend_from_slice(&buffer_id.to_be_bytes());
    body.extend_from_slice(&total_len.to_be_bytes());
    body.push(reason);
    body.push(table_id);
    body.extend_from_slice(&cookie.to_be_bytes());
    body.extend_from_slice(&mbytes);
    body.extend_from_slice(&[0u8, 0u8]);
    body.extend_from_slice(&pkt.wire[..total_len as usize]);
    shared.push_out(of_msg(OFPT_PACKET_IN, 0, &body));
    lock(&shared.stats).packet_in += 1;
}

// ---------------------------------------------------------------------------
// Message encoding helpers
// ---------------------------------------------------------------------------

fn of_msg(typ: u8, xid: u32, body: &[u8]) -> Vec<u8> {
    let len = (8 + body.len()).min(u16::MAX as usize) as u16;
    let mut v = Vec::with_capacity(len as usize);
    v.push(OF_VERSION);
    v.push(typ);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&xid.to_be_bytes());
    let keep = len as usize - 8;
    v.extend_from_slice(&body[..keep.min(body.len())]);
    v
}

fn push_oxm(out: &mut Vec<u8>, field: u8, value: &[u8]) {
    let hdr = 0x8000_0000u32 | ((field as u32) << 9) | value.len() as u32;
    out.extend_from_slice(&hdr.to_be_bytes());
    out.extend_from_slice(value);
}

fn encode_match(m: &OfMatch) -> Vec<u8> {
    let mut oxm = Vec::new();
    if let Some(v) = m.in_port {
        push_oxm(&mut oxm, OXM_IN_PORT, &v.to_be_bytes());
    }
    if let Some(v) = m.eth_dst {
        push_oxm(&mut oxm, OXM_ETH_DST, &v);
    }
    if let Some(v) = m.eth_src {
        push_oxm(&mut oxm, OXM_ETH_SRC, &v);
    }
    if let Some(v) = m.eth_type {
        push_oxm(&mut oxm, OXM_ETH_TYPE, &v.to_be_bytes());
    }
    if let Some(v) = m.vlan_vid {
        push_oxm(&mut oxm, OXM_VLAN_VID, &v.to_be_bytes());
    }
    if let Some(v) = m.vlan_pcp {
        push_oxm(&mut oxm, OXM_VLAN_PCP, &[v]);
    }
    if let Some(v) = m.ip_proto {
        push_oxm(&mut oxm, OXM_IP_PROTO, &[v]);
    }
    if let Some(v) = m.ipv4_src {
        push_oxm(&mut oxm, OXM_IPV4_SRC, &v);
    }
    if let Some(v) = m.ipv4_dst {
        push_oxm(&mut oxm, OXM_IPV4_DST, &v);
    }
    let len = 4 + oxm.len();
    let padded = (len + 7) & !7;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&oxm);
    out.resize(padded, 0);
    out
}

fn parse_match(data: &[u8]) -> Result<(OfMatch, usize), (u16, u16)> {
    if data.len() < 4 {
        return Err((OFPET_BAD_MATCH, OFPBMC_BAD_LEN));
    }
    let typ = u16::from_be_bytes([data[0], data[1]]);
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if typ != 1 {
        return Err((OFPET_BAD_MATCH, OFPBMC_BAD_TYPE));
    }
    if len < 4 || len > data.len() {
        return Err((OFPET_BAD_MATCH, OFPBMC_BAD_LEN));
    }
    let mut m = OfMatch::default();
    let mut off = 4;
    while off < len {
        if off + 4 > len {
            return Err((OFPET_BAD_MATCH, OFPBMC_BAD_LEN));
        }
        let hdr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let class = (hdr >> 16) as u16;
        let field = ((hdr >> 9) & 0x7f) as u8;
        let hasmask = (hdr >> 8) & 1 != 0;
        let flen = (hdr & 0xff) as usize;
        off += 4;
        if class != 0x8000 {
            return Err((OFPET_BAD_MATCH, OFPBMC_BAD_FIELD));
        }
        if hasmask {
            return Err((OFPET_BAD_MATCH, OFPBMC_BAD_MASK));
        }
        if off + flen > len {
            return Err((OFPET_BAD_MATCH, OFPBMC_BAD_LEN));
        }
        let v = &data[off..off + flen];
        match field {
            OXM_IN_PORT if flen == 4 => {
                if m.in_port.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.in_port = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            }
            OXM_ETH_DST if flen == 6 => {
                if m.eth_dst.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(v);
                m.eth_dst = Some(a);
            }
            OXM_ETH_SRC if flen == 6 => {
                if m.eth_src.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(v);
                m.eth_src = Some(a);
            }
            OXM_ETH_TYPE if flen == 2 => {
                if m.eth_type.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.eth_type = Some(u16::from_be_bytes([v[0], v[1]]));
            }
            OXM_VLAN_VID if flen == 2 => {
                if m.vlan_vid.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.vlan_vid = Some(u16::from_be_bytes([v[0], v[1]]));
            }
            OXM_VLAN_PCP if flen == 1 => {
                if m.vlan_pcp.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.vlan_pcp = Some(v[0]);
            }
            OXM_IP_PROTO if flen == 1 => {
                if m.ip_proto.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.ip_proto = Some(v[0]);
            }
            OXM_IPV4_SRC if flen == 4 => {
                if m.ipv4_src.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.ipv4_src = Some([v[0], v[1], v[2], v[3]]);
            }
            OXM_IPV4_DST if flen == 4 => {
                if m.ipv4_dst.is_some() {
                    return Err((OFPET_BAD_MATCH, OFPBMC_DUP_FIELD));
                }
                m.ipv4_dst = Some([v[0], v[1], v[2], v[3]]);
            }
            _ => return Err((OFPET_BAD_MATCH, OFPBMC_BAD_FIELD)),
        }
        off += flen;
    }
    // Basic prerequisites: IP fields require an IPv4 ethertype.
    if (m.ipv4_src.is_some() || m.ipv4_dst.is_some() || m.ip_proto.is_some())
        && m.eth_type != Some(packet::ETHERTYPE_IPV4)
    {
        return Err((OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ));
    }
    let padded = (len + 7) & !7;
    Ok((m, padded))
}

fn encode_actions(actions: &[OfAction]) -> Vec<u8> {
    let mut out = Vec::with_capacity(actions.len() * 16);
    for a in actions {
        let OfAction::Output(port) = *a;
        out.extend_from_slice(&OFPAT_OUTPUT.to_be_bytes());
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // max_len
        out.extend_from_slice(&[0u8; 6]);
    }
    out
}

fn parse_actions(data: &[u8]) -> Result<Vec<OfAction>, (u16, u16)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < data.len() {
        if off + 4 > data.len() {
            return Err((OFPET_BAD_ACTION, OFPBAC_BAD_LEN));
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if len < 8 || off + len > data.len() {
            return Err((OFPET_BAD_ACTION, OFPBAC_BAD_LEN));
        }
        if typ != OFPAT_OUTPUT || len < 16 {
            return Err((OFPET_BAD_ACTION, OFPBAC_BAD_TYPE));
        }
        let port = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        out.push(OfAction::Output(port));
        off += len;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Flow-mod parsing
// ---------------------------------------------------------------------------

struct FlowMod {
    cookie: u64,
    table_id: u8,
    command: u8,
    idle_timeout: u16,
    hard_timeout: u16,
    priority: u16,
    buffer_id: u32,
    out_port: u32,
    mat: OfMatch,
    actions: Vec<OfAction>,
    flags: u16,
}

fn parse_flow_mod(body: &[u8]) -> Result<FlowMod, (u16, u16)> {
    if body.len() < 40 {
        return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
    }
    let be64 = |b: &[u8]| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let be16 = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    let cookie = be64(&body[0..8]);
    let table_id = body[16];
    let command = body[17];
    let idle_timeout = be16(&body[18..20]);
    let hard_timeout = be16(&body[20..22]);
    let priority = be16(&body[22..24]);
    let buffer_id = be32(&body[24..28]);
    let out_port = be32(&body[28..32]);
    let flags = be16(&body[36..38]);
    let (mat, mlen) = parse_match(&body[40..])?;
    let mut off = 40 + mlen;
    let mut actions = Vec::new();
    while off + 4 <= body.len() {
        let typ = be16(&body[off..off + 2]);
        let ilen = be16(&body[off + 2..off + 4]) as usize;
        if ilen < 4 || off + ilen > body.len() {
            return Err((OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST));
        }
        let payload = &body[off + 4..off + ilen];
        match typ {
            OFPIT_APPLY_ACTIONS | OFPIT_WRITE_ACTIONS => {
                // The instruction header is followed by four pad bytes before
                // the action list (ofp_instruction_actions).
                if ilen < 8 {
                    return Err((OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST));
                }
                let parsed = parse_actions(&body[off + 8..off + ilen])?;
                actions.extend(parsed);
            }
            OFPIT_CLEAR_ACTIONS => actions.clear(),
            OFPIT_GOTO_TABLE => {
                // Only one table (0) exists; a goto to table 0 is a no-op,
                // anything else is unsupported.
                if payload.len() < 1 || payload[0] != 0 {
                    return Err((OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST));
                }
            }
            OFPIT_WRITE_METADATA | OFPIT_METER => {}
            _ => return Err((OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST)),
        }
        off += ilen;
    }
    Ok(FlowMod {
        cookie,
        table_id,
        command,
        idle_timeout,
        hard_timeout,
        priority,
        buffer_id,
        out_port,
        mat,
        actions,
        flags,
    })
}

// ---------------------------------------------------------------------------
// Controller session
// ---------------------------------------------------------------------------

pub fn spawn_manager(sw: Arc<Mutex<Switch>>, io: Arc<Io>) {
    thread::spawn(move || manager_loop(sw, io));
}

fn manager_loop(sw: Arc<Mutex<Switch>>, io: Arc<Io>) {
    let mut listener: Option<(u16, TcpListener)> = None;
    let mut last_error = String::new();

    while !crate::STOP.load(Ordering::SeqCst) {
        let cfg = {
            let g = lock(&sw);
            g.openflow.config.clone()
        };
        if !cfg.enabled {
            listener = None;
            shared_disconnect(&sw);
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        match &cfg.controller {
            Some((host, port)) => {
                listener = None;
                match connect_controller(host, *port) {
                    Ok(mut stream) => {
                        last_error.clear();
                        let remote = format!("{}:{}", host, port);
                        log(
                            &sw,
                            &format!("openflow: connected to controller {}", remote),
                        );
                        run_session(&mut stream, &sw, &io, &remote, &cfg);
                        log(&sw, "openflow: controller session closed");
                    }
                    Err(e) => {
                        let msg = format!("openflow: controller {}:{}: {}", host, port, e);
                        if msg != last_error {
                            log(&sw, &msg);
                            last_error = msg;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            None => {
                let port = cfg.listening_port();
                if listener.as_ref().map(|(p, _)| *p) != Some(port) {
                    match TcpListener::bind(("0.0.0.0", port)) {
                        Ok(l) => {
                            let _ = l.set_nonblocking(true);
                            log(
                                &sw,
                                &format!("openflow: listening for a controller on tcp:{}", port),
                            );
                            listener = Some((port, l));
                        }
                        Err(e) => {
                            let msg = format!("openflow: cannot listen on tcp:{}: {}", port, e);
                            if msg != last_error {
                                log(&sw, &msg);
                                last_error = msg;
                            }
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    }
                }
                let Some((_, l)) = listener.as_ref() else {
                    continue;
                };
                match l.accept() {
                    Ok((mut stream, addr)) => {
                        let _ = stream.set_nonblocking(false);
                        let remote = addr.to_string();
                        log(&sw, &format!("openflow: controller {} connected", remote));
                        run_session(&mut stream, &sw, &io, &remote, &cfg);
                        log(&sw, "openflow: controller session closed");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        log(&sw, &format!("openflow: accept failed: {}", e));
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }
    }
    shared_disconnect(&sw);
}

fn log(sw: &Arc<Mutex<Switch>>, msg: &str) {
    if let Ok(mut g) = sw.lock() {
        g.log_line(msg);
    }
}

fn shared_disconnect(sw: &Arc<Mutex<Switch>>) {
    if let Ok(g) = sw.lock() {
        g.openflow.shared.connected.store(false, Ordering::SeqCst);
        *lock(&g.openflow.shared.remote) = None;
    }
}

fn connect_controller(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("cannot resolve {}", host),
    );
    let addrs = (host, port).to_socket_addrs()?;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn config_changed(sw: &Arc<Mutex<Switch>>, expected: &OpenFlowConfig) -> bool {
    let g = lock(sw);
    g.openflow.config != *expected
}

fn run_session(
    stream: &mut TcpStream,
    sw: &Arc<Mutex<Switch>>,
    io: &Arc<Io>,
    remote: &str,
    expected: &OpenFlowConfig,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let shared = {
        let g = lock(sw);
        Arc::clone(&g.openflow.shared)
    };
    *lock(&shared.remote) = Some(remote.to_string());
    shared.connected.store(false, Ordering::SeqCst);

    if !write_msg(stream, &shared, of_msg(OFPT_HELLO, 0, &[])) {
        shared_disconnect(sw);
        return;
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut peer_hello = false;
    let mut tmp = [0u8; 8192];

    loop {
        if crate::STOP.load(Ordering::SeqCst) || config_changed(sw, expected) {
            break;
        }

        // Drain packet-ins/errors queued by the dataplane.
        let outbound: Vec<Vec<u8>> = {
            let mut q = lock(&shared.queue);
            let n = q.len().min(64);
            q.drain(..n).collect()
        };
        for msg in outbound {
            if !write_msg(stream, &shared, msg) {
                shared_disconnect(sw);
                return;
            }
        }

        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }

        while buf.len() >= 8 {
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if !(8..=u16::MAX as usize).contains(&len) {
                let _ = write_msg(
                    stream,
                    &shared,
                    error_msg(
                        OFPET_BAD_REQUEST,
                        OFPBRC_BAD_LEN,
                        0,
                        &buf[..buf.len().min(64)],
                    ),
                );
                shared_disconnect(sw);
                return;
            }
            if buf.len() < len {
                break;
            }
            let msg: Vec<u8> = buf.drain(..len).collect();
            lock(&shared.stats).msgs_in += 1;
            if !process_message(&msg, stream, sw, &shared, io, &mut peer_hello) {
                shared_disconnect(sw);
                return;
            }
        }
    }
    shared_disconnect(sw);
}

fn write_msg(stream: &mut TcpStream, shared: &OfShared, msg: Vec<u8>) -> bool {
    if stream.write_all(&msg).is_err() {
        return false;
    }
    lock(&shared.stats).msgs_out += 1;
    true
}

fn error_msg(typ: u16, code: u16, xid: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend_from_slice(&typ.to_be_bytes());
    body.extend_from_slice(&code.to_be_bytes());
    body.extend_from_slice(data);
    of_msg(OFPT_ERROR, xid, &body)
}

fn send_error(
    stream: &mut TcpStream,
    shared: &OfShared,
    typ: u16,
    code: u16,
    xid: u32,
    raw: &[u8],
) {
    let data = &raw[..raw.len().min(64)];
    lock(&shared.stats).errors += 1;
    let _ = write_msg(stream, shared, error_msg(typ, code, xid, data));
}

/// Process one complete OpenFlow message.  Returns false to end the session.
fn process_message(
    msg: &[u8],
    stream: &mut TcpStream,
    sw: &Arc<Mutex<Switch>>,
    shared: &Arc<OfShared>,
    io: &Arc<Io>,
    peer_hello: &mut bool,
) -> bool {
    if msg.len() < 8 {
        return true;
    }
    let version = msg[0];
    let typ = msg[1];
    let xid = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let body = &msg[8..];

    if version != OF_VERSION {
        if typ == OFPT_HELLO {
            send_error(
                stream,
                shared,
                OFPET_HELLO_FAILED,
                OFPHFC_INCOMPATIBLE,
                xid,
                msg,
            );
            return false;
        }
        send_error(
            stream,
            shared,
            OFPET_BAD_REQUEST,
            OFPBRC_BAD_VERSION,
            xid,
            msg,
        );
        return true;
    }

    match typ {
        OFPT_HELLO => {
            *peer_hello = true;
            shared.connected.store(true, Ordering::SeqCst);
        }
        OFPT_ECHO_REQUEST => {
            if !write_msg(stream, shared, of_msg(OFPT_ECHO_REPLY, xid, body)) {
                return false;
            }
        }
        OFPT_ECHO_REPLY => {}
        OFPT_FEATURES_REQUEST => {
            shared.connected.store(true, Ordering::SeqCst);
            let body = features_body(sw);
            if !write_msg(stream, shared, of_msg(OFPT_FEATURES_REPLY, xid, &body)) {
                return false;
            }
        }
        OFPT_FEATURES_REPLY => {
            shared.connected.store(true, Ordering::SeqCst);
        }
        OFPT_GET_CONFIG_REQUEST => {
            let mut b = Vec::with_capacity(4);
            b.extend_from_slice(&0u16.to_be_bytes()); // OFPC_FRAG_NORMAL
            b.extend_from_slice(&u16::MAX.to_be_bytes()); // miss_send_len
            if !write_msg(stream, shared, of_msg(OFPT_GET_CONFIG_REPLY, xid, &b)) {
                return false;
            }
        }
        OFPT_SET_CONFIG => {}
        OFPT_PACKET_OUT => {
            if let Err((et, ec)) = handle_packet_out(body, sw, shared, io) {
                send_error(stream, shared, et, ec, xid, msg);
            }
        }
        OFPT_FLOW_MOD => {
            if let Err((et, ec)) = handle_flow_mod(body, sw, shared, io) {
                send_error(stream, shared, et, ec, xid, msg);
            }
        }
        OFPT_MULTIPART_REQUEST => match build_multipart_reply(body, sw, shared, xid) {
            Ok(reply) => {
                if !write_msg(stream, shared, reply) {
                    return false;
                }
            }
            Err((et, ec)) => send_error(stream, shared, et, ec, xid, msg),
        },
        OFPT_BARRIER_REQUEST => {
            if !write_msg(stream, shared, of_msg(OFPT_BARRIER_REPLY, xid, &[])) {
                return false;
            }
        }
        OFPT_ROLE_REQUEST => {
            // Always answer with the EQUAL role; the switch supports a single
            // controller and has no role state.
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_be_bytes());
            b.extend_from_slice(&[0u8; 8]);
            if !write_msg(stream, shared, of_msg(OFPT_ROLE_REPLY, xid, &b)) {
                return false;
            }
        }
        OFPT_PORT_MOD => {
            if let Err((et, ec)) = handle_port_mod(body, sw) {
                send_error(stream, shared, et, ec, xid, msg);
            }
        }
        OFPT_TABLE_MOD => {}
        OFPT_EXPERIMENTER | OFPT_GROUP_MOD | OFPT_PORT_STATUS | OFPT_FLOW_REMOVED => {}
        _ => send_error(stream, shared, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE, xid, msg),
    }
    true
}

fn features_body(sw: &Arc<Mutex<Switch>>) -> Vec<u8> {
    let (dp, caps) = {
        let g = lock(sw);
        (
            g.openflow.config.datapath_id,
            OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | OFPC_QUEUE_STATS,
        )
    };
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(&dp.to_be_bytes());
    b.extend_from_slice(&(OFP_MAX_BUFFERS as u32).to_be_bytes());
    b.push(1); // n_tables
    b.push(0); // auxiliary_id
    b.extend_from_slice(&[0u8, 0u8]);
    b.extend_from_slice(&caps.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b
}

fn handle_packet_out(
    body: &[u8],
    sw: &Arc<Mutex<Switch>>,
    shared: &Arc<OfShared>,
    io: &Arc<Io>,
) -> Result<(), (u16, u16)> {
    if body.len() < 16 {
        return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
    }
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let be16 = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    let buffer_id = be32(&body[0..4]);
    let in_port = be32(&body[4..8]);
    let actions_len = be16(&body[8..10]) as usize;
    if 16 + actions_len > body.len() {
        return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
    }
    let actions = parse_actions(&body[16..16 + actions_len])?;

    let pkt = if buffer_id != OFP_NO_BUFFER {
        shared
            .take_buffer(buffer_id)
            .ok_or((OFPET_BAD_REQUEST, OFPBRC_BUFFER_UNKNOWN))?
    } else {
        let data = &body[16 + actions_len..];
        let Some(frame) = packet::parse(data) else {
            return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
        };
        let (vlan, pcp, dei) = match frame.tag {
            Some(t) if t.vid != 0 => (t.vid, t.pcp, t.dei),
            Some(t) => (1, t.pcp, t.dei),
            None => (1, 0, false),
        };
        Buffered::from_frame(in_port as usize, vlan, pcp, dei, &frame, data)
    };

    let mut g = lock(sw);
    apply_actions(&mut g, io, shared, &pkt, &actions);
    lock(&shared.stats).packet_out += 1;
    Ok(())
}

fn handle_flow_mod(
    body: &[u8],
    sw: &Arc<Mutex<Switch>>,
    shared: &Arc<OfShared>,
    io: &Arc<Io>,
) -> Result<(), (u16, u16)> {
    let fm = parse_flow_mod(body)?;
    if fm.table_id != 0 {
        return Err((OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID));
    }
    let now = Instant::now();
    let entry = FlowEntry {
        cookie: fm.cookie,
        priority: fm.priority,
        mat: fm.mat.clone(),
        actions: fm.actions.clone(),
        idle_timeout: fm.idle_timeout,
        hard_timeout: fm.hard_timeout,
        flags: fm.flags,
        created: now,
        last_used: now,
        packets: 0,
        bytes: 0,
    };

    match fm.command {
        OFPFC_ADD => {
            lock(&shared.flows).add(entry);
        }
        OFPFC_MODIFY | OFPFC_MODIFY_STRICT => {
            let strict = fm.command == OFPFC_MODIFY_STRICT;
            let mut flows = lock(&shared.flows);
            let changed = flows.modify(&fm.mat, Some(fm.priority), strict, &entry);
            if changed == 0 {
                flows.add(entry);
            }
        }
        OFPFC_DELETE | OFPFC_DELETE_STRICT => {
            let strict = fm.command == OFPFC_DELETE_STRICT;
            lock(&shared.flows).delete(&fm.mat, Some(fm.priority), strict, fm.out_port);
        }
        _ => return Err((OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND)),
    }
    lock(&shared.stats).flow_mods += 1;

    if fm.buffer_id != OFP_NO_BUFFER {
        if let Some(pkt) = shared.take_buffer(fm.buffer_id) {
            let mut g = lock(sw);
            apply_actions(&mut g, io, shared, &pkt, &fm.actions);
        }
    }
    Ok(())
}

fn handle_port_mod(body: &[u8], sw: &Arc<Mutex<Switch>>) -> Result<(), (u16, u16)> {
    if body.len() < 32 {
        return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
    }
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let port_no = be32(&body[0..4]);
    let config = be32(&body[12..16]);
    let mut g = lock(sw);
    let Some(p) = g.port_mut(port_no as usize) else {
        return Err((OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT));
    };
    p.admin_up = config & OFPPC_PORT_DOWN == 0;
    Ok(())
}

// ---------------------------------------------------------------------------
// Multipart replies
// ---------------------------------------------------------------------------

fn build_multipart_reply(
    body: &[u8],
    sw: &Arc<Mutex<Switch>>,
    shared: &Arc<OfShared>,
    xid: u32,
) -> Result<Vec<u8>, (u16, u16)> {
    if body.len() < 8 {
        return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_LEN));
    }
    let mtype = u16::from_be_bytes([body[0], body[1]]);
    let entries = match mtype {
        OFPMP_DESC => desc_body(sw),
        OFPMP_PORT_DESC => port_desc_body(sw),
        OFPMP_FLOW => flow_stats_body(shared),
        OFPMP_AGGREGATE => aggregate_body(shared),
        OFPMP_TABLE => table_stats_body(shared),
        OFPMP_PORT_STATS => port_stats_body(sw),
        // The switch has no groups, meters or multiple tables.  Empty
        // replies are valid for these and keep controllers happy.
        OFPMP_GROUP | OFPMP_GROUP_DESC | OFPMP_GROUP_FEATURES | OFPMP_METER
        | OFPMP_METER_CONFIG | OFPMP_METER_FEATURES | OFPMP_TABLE_FEATURES => Vec::new(),
        _ => return Err((OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART)),
    };
    let mut reply = Vec::with_capacity(8 + entries.len());
    reply.extend_from_slice(&mtype.to_be_bytes());
    reply.extend_from_slice(&0u16.to_be_bytes()); // flags
    reply.extend_from_slice(&0u32.to_be_bytes()); // pad
    reply.extend_from_slice(&entries);
    Ok(of_msg(OFPT_MULTIPART_REPLY, xid, &reply))
}

fn desc_body(sw: &Arc<Mutex<Switch>>) -> Vec<u8> {
    let (host, version, dp) = {
        let g = lock(sw);
        (
            g.hostname.clone(),
            g.version.to_string(),
            g.openflow.config.datapath_id,
        )
    };
    let mut b = Vec::with_capacity(1056);
    fixed_string(&mut b, "switch", 256);
    fixed_string(&mut b, "Educational 802.1Q switch", 256);
    fixed_string(&mut b, &version, 256);
    fixed_string(&mut b, &format!("{:012x}", dp), 32);
    fixed_string(&mut b, &host, 256);
    b
}

fn fixed_string(out: &mut Vec<u8>, s: &str, n: usize) {
    let bytes = s.as_bytes();
    let take = bytes.len().min(n.saturating_sub(1));
    out.extend_from_slice(&bytes[..take]);
    out.resize(out.len() + (n - take), 0);
}

fn port_features(speed: u32) -> u32 {
    let speed_feature = match speed {
        0..=10 => OFPPF_10MB_HD | OFPPF_10MB_FD,
        11..=100 => OFPPF_100MB_HD | OFPPF_100MB_FD,
        101..=1000 => OFPPF_1GB_HD | OFPPF_1GB_FD,
        _ => OFPPF_10GB_FD,
    };
    speed_feature | OFPPF_COPPER | OFPPF_AUTONEG
}

fn port_desc_body(sw: &Arc<Mutex<Switch>>) -> Vec<u8> {
    let g = lock(sw);
    let mut out = Vec::new();
    for p in &g.ports {
        let mut config = 0u32;
        if !p.admin_up {
            config |= OFPPC_PORT_DOWN;
        }
        let mut state = 0u32;
        if !p.link_up {
            state |= OFPPS_LINK_DOWN;
        }
        if p.counters.err_disabled {
            state |= OFPPS_BLOCKED;
        } else if p.link_up && p.admin_up {
            state |= OFPPS_LIVE;
        }
        let feats = port_features(p.speed);
        out.extend_from_slice(&(p.index as u32).to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&g.system_mac);
        out.extend_from_slice(&[0u8; 2]);
        fixed_string(&mut out, &p.ifname, 16);
        out.extend_from_slice(&config.to_be_bytes());
        out.extend_from_slice(&state.to_be_bytes());
        out.extend_from_slice(&feats.to_be_bytes());
        out.extend_from_slice(&feats.to_be_bytes());
        out.extend_from_slice(&feats.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(p.speed.saturating_mul(1000)).to_be_bytes());
        out.extend_from_slice(&(p.speed.saturating_mul(1000)).to_be_bytes());
    }
    out
}

fn flow_stats_body(shared: &Arc<OfShared>) -> Vec<u8> {
    let now = Instant::now();
    let flows = lock(&shared.flows);
    let mut out = Vec::new();
    for e in &flows.entries {
        let mbytes = encode_match(&e.mat);
        let abytes = encode_actions(&e.actions);
        let instr_len = if e.actions.is_empty() {
            0
        } else {
            4 + abytes.len()
        };
        let len = 48 + mbytes.len() + instr_len;
        let dur = now.duration_since(e.created);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.push(0); // table_id
        out.push(0);
        out.extend_from_slice(&(dur.as_secs() as u32).to_be_bytes());
        out.extend_from_slice(&(dur.subsec_nanos()).to_be_bytes());
        out.extend_from_slice(&e.priority.to_be_bytes());
        out.extend_from_slice(&e.idle_timeout.to_be_bytes());
        out.extend_from_slice(&e.hard_timeout.to_be_bytes());
        out.extend_from_slice(&e.flags.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&e.cookie.to_be_bytes());
        out.extend_from_slice(&e.packets.to_be_bytes());
        out.extend_from_slice(&e.bytes.to_be_bytes());
        out.extend_from_slice(&mbytes);
        if !e.actions.is_empty() {
            out.extend_from_slice(&OFPIT_APPLY_ACTIONS.to_be_bytes());
            out.extend_from_slice(&(instr_len as u16).to_be_bytes());
            out.extend_from_slice(&abytes);
        }
    }
    out
}

fn aggregate_body(shared: &Arc<OfShared>) -> Vec<u8> {
    let flows = lock(&shared.flows);
    let (packets, bytes, count) = flows.aggregate();
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&packets.to_be_bytes());
    out.extend_from_slice(&bytes.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out
}

fn table_stats_body(shared: &Arc<OfShared>) -> Vec<u8> {
    let flows = lock(&shared.flows);
    let stats = lock(&shared.stats);
    let mut out = Vec::with_capacity(24);
    out.push(0); // table 0
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&(flows.entries.len() as u32).to_be_bytes());
    out.extend_from_slice(&stats.lookups.to_be_bytes());
    out.extend_from_slice(&stats.matched.to_be_bytes());
    out
}

fn port_stats_body(sw: &Arc<Mutex<Switch>>) -> Vec<u8> {
    let g = lock(sw);
    let uptime = g.uptime.elapsed().as_secs() as u32;
    let mut out = Vec::new();
    for p in &g.ports {
        let c = &p.counters;
        out.extend_from_slice(&(p.index as u32).to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&c.rx_packets.to_be_bytes());
        out.extend_from_slice(&c.tx_packets.to_be_bytes());
        out.extend_from_slice(&c.rx_bytes.to_be_bytes());
        out.extend_from_slice(&c.tx_bytes.to_be_bytes());
        out.extend_from_slice(&c.drops.to_be_bytes()); // rx_dropped
        out.extend_from_slice(&0u64.to_be_bytes()); // tx_dropped
        out.extend_from_slice(&c.rx_errors.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes()); // tx_errors
        out.extend_from_slice(&0u64.to_be_bytes()); // rx_frame_err
        out.extend_from_slice(&0u64.to_be_bytes()); // rx_over_err
        out.extend_from_slice(&0u64.to_be_bytes()); // rx_crc_err
        out.extend_from_slice(&0u64.to_be_bytes()); // collisions
        out.extend_from_slice(&uptime.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

pub fn show(sw: &Switch) -> String {
    let c = &sw.openflow.config;
    let shared = &sw.openflow.shared;
    let mut out = String::new();
    out.push_str("OpenFlow 1.3 status\n");
    out.push_str(&format!(
        "  Feature:      {}\n",
        if c.enabled { "enabled" } else { "disabled" }
    ));
    out.push_str(&format!("  Datapath ID:  {:016x}\n", c.datapath_id));
    match &c.controller {
        Some((h, p)) => out.push_str(&format!("  Controller:   {}:{} (active)\n", h, p)),
        None => out.push_str(&format!(
            "  Controller:   listening on tcp:{} (passive)\n",
            c.listening_port()
        )),
    }
    out.push_str(&format!(
        "  Fail mode:    {}\n",
        match c.fail_mode {
            FailMode::Standalone => "standalone",
            FailMode::Secure => "secure",
        }
    ));
    let connected = shared.connected.load(Ordering::SeqCst);
    let remote = lock(&shared.remote).clone();
    let state = if !c.enabled {
        "disabled".to_string()
    } else if connected {
        format!("connected to {}", remote.unwrap_or_else(|| "-".into()))
    } else if c.controller.is_some() {
        "disconnected (retrying)".to_string()
    } else {
        "waiting for controller".to_string()
    };
    out.push_str(&format!("  Session:      {}\n", state));
    let flows = shared.flow_count();
    let st = lock(&shared.stats).clone();
    out.push_str(&format!("  Flow entries: {}\n", flows));
    out.push_str(&format!(
        "  Messages:     {} in, {} out; errors {}\n",
        st.msgs_in, st.msgs_out, st.errors
    ));
    out.push_str(&format!(
        "  Packet-in:    {}   Packet-out: {}   Flow-mods: {}\n",
        st.packet_in, st.packet_out, st.flow_mods
    ));
    out.push_str(&format!(
        "  Lookups:      {} matched, {} total\n",
        st.matched, st.lookups
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    fn test_switch() -> Switch {
        let mut sw = Switch::new(
            "of-test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/openflow"),
        );
        sw.features.stp = false;
        for i in 1..=3 {
            sw.add_port(&format!("eth{}", i));
        }
        for p in sw.ports.iter_mut() {
            p.link_up = true;
        }
        sw.openflow.config.enabled = true;
        sw.features.openflow = true;
        sw
    }

    #[test]
    fn match_roundtrip() {
        let m = OfMatch {
            in_port: Some(2),
            eth_dst: Some(A),
            eth_src: Some(B),
            eth_type: Some(packet::ETHERTYPE_IPV4),
            vlan_vid: Some(OFPVID_PRESENT | 10),
            vlan_pcp: Some(3),
            ip_proto: Some(6),
            ipv4_src: Some([10, 0, 0, 1]),
            ipv4_dst: Some([10, 0, 0, 2]),
        };
        let bytes = encode_match(&m);
        let (decoded, used) = parse_match(&bytes).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn flow_priority_and_delete() {
        let mut t = FlowTable::default();
        let mk = |prio, vlan| FlowEntry {
            cookie: 0,
            priority: prio,
            mat: OfMatch {
                vlan_vid: Some(OFPVID_PRESENT | vlan),
                ..Default::default()
            },
            actions: vec![OfAction::Output(2)],
            idle_timeout: 0,
            hard_timeout: 0,
            flags: 0,
            created: Instant::now(),
            last_used: Instant::now(),
            packets: 0,
            bytes: 0,
        };
        t.add(mk(10, 10));
        t.add(mk(20, 10));
        let pkt = Buffered {
            in_port: 1,
            vlan: 10,
            pcp: 0,
            dei: false,
            dst: A,
            src: B,
            ethertype: 0x0800,
            payload: vec![0; 20],
            wire: vec![],
        };
        let pos = t.lookup(&pkt.view()).unwrap();
        assert_eq!(t.entries[pos].priority, 20);

        let removed = t.delete(&OfMatch::default(), Some(0), false, OFPP_ANY);
        assert_eq!(removed, 2);
        assert!(t.entries.is_empty());
    }

    #[test]
    fn flow_mod_adds_and_forwards() {
        let io = Io::capture();
        let sw = Arc::new(Mutex::new(test_switch()));
        let shared = {
            let g = lock(&sw);
            Arc::clone(&g.openflow.shared)
        };

        // Install: in_port 1, vlan 10 -> output 2.
        let mat = OfMatch {
            in_port: Some(1),
            vlan_vid: Some(OFPVID_PRESENT | 10),
            ..Default::default()
        };
        let bytes = encode_match(&mat);
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_be_bytes()); // cookie
        body.extend_from_slice(&0u64.to_be_bytes()); // cookie mask
        body.push(0); // table
        body.push(OFPFC_ADD);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&100u16.to_be_bytes());
        body.extend_from_slice(&OFP_NO_BUFFER.to_be_bytes());
        body.extend_from_slice(&OFPP_ANY.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes()); // out_group
        body.extend_from_slice(&0u16.to_be_bytes()); // flags
        body.extend_from_slice(&[0u8, 0u8]);
        body.extend_from_slice(&bytes);
        let actions = encode_actions(&[OfAction::Output(2)]);
        body.extend_from_slice(&OFPIT_APPLY_ACTIONS.to_be_bytes());
        body.extend_from_slice(&((8 + actions.len()) as u16).to_be_bytes());
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&actions);

        handle_flow_mod(&body, &sw, &shared, &io).unwrap();
        assert_eq!(shared.flow_count(), 1);

        let wire = packet::build(A, B, None, packet::ETHERTYPE_IPV4, &[0u8; 20]);
        let frame = packet::parse(&wire).unwrap();
        let mut g = lock(&sw);
        let verdict = process_ingress(&mut g, &io, 1, 10, 0, false, &frame, &wire);
        assert!(matches!(verdict, Verdict::Consumed));
        let captured = io.take_captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, 2);
        assert_eq!(captured[0].1, wire);
    }

    #[test]
    fn table_miss_buffers_packet_in() {
        let io = Io::capture();
        let mut sw = test_switch();
        let shared = Arc::clone(&sw.openflow.shared);
        shared.connected.store(true, Ordering::SeqCst);

        let frame = packet::build(
            packet::MAC_BROADCAST,
            A,
            None,
            packet::ETHERTYPE_IPV4,
            &[0u8; 20],
        );
        let parsed = packet::parse(&frame).unwrap();
        let verdict = process_ingress(&mut sw, &io, 1, 10, 0, false, &parsed, &frame);
        assert!(matches!(verdict, Verdict::Consumed));
        let q = lock(&shared.queue);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0][1], OFPT_PACKET_IN);
    }

    #[test]
    fn cli_config_and_persistence() {
        let mut sw = Switch::new(
            "of-test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/openflow"),
        );
        sw.add_port("eth1");
        let mut s = crate::cli::Session::new();
        crate::cli::execute(&mut sw, &mut s, "configure terminal");

        // OpenFlow is a feature: configuration is refused until it is enabled.
        let out = crate::cli::execute(&mut sw, &mut s, "openflow controller 192.0.2.10 6653");
        assert!(out.starts_with('%'));
        assert!(out.contains("openflow"));

        crate::cli::execute(&mut sw, &mut s, "feature enable openflow");
        let out = crate::cli::execute(&mut sw, &mut s, "openflow controller 192.0.2.10 6653");
        assert!(!out.starts_with('%'));
        crate::cli::execute(&mut sw, &mut s, "openflow fail-mode secure");
        crate::cli::execute(&mut sw, &mut s, "end");
        assert_eq!(
            sw.openflow.config.controller,
            Some(("192.0.2.10".to_string(), 6653))
        );
        assert_eq!(sw.openflow.config.fail_mode, FailMode::Secure);
        let text = crate::cli::running_config(&sw);
        assert!(text.contains("feature enable openflow"));
        assert!(text.contains("openflow controller 192.0.2.10 6653"));
        assert!(text.contains("openflow fail-mode secure"));
        assert!(crate::cli::execute(&mut sw, &mut s, "show openflow").contains("OpenFlow 1.3"));

        let mut loaded = Switch::new(
            "of-test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/openflow"),
        );
        loaded.add_port("eth1");
        crate::cli::load_config(&mut loaded, &text);
        assert!(loaded.features.openflow);
        assert!(loaded.openflow.config.enabled);
        assert_eq!(
            loaded.openflow.config.controller,
            Some(("192.0.2.10".to_string(), 6653))
        );
        assert_eq!(loaded.openflow.config.fail_mode, FailMode::Secure);

        let mut s = crate::cli::Session::new();
        crate::cli::execute(&mut loaded, &mut s, "configure terminal");
        crate::cli::execute(&mut loaded, &mut s, "feature disable openflow");
        assert!(!loaded.features.openflow);
        assert!(!loaded.openflow.config.enabled);
        assert_eq!(loaded.openflow.shared.flow_count(), 0);
    }

    #[test]
    fn fail_mode_without_controller() {
        let io = Io::capture();
        let mut sw = test_switch();
        let wire = packet::build(A, B, None, packet::ETHERTYPE_IPV4, &[0u8; 20]);
        let frame = packet::parse(&wire).unwrap();

        sw.openflow.config.fail_mode = FailMode::Standalone;
        let verdict = process_ingress(&mut sw, &io, 1, 10, 0, false, &frame, &wire);
        assert!(matches!(verdict, Verdict::Native));

        sw.openflow.config.fail_mode = FailMode::Secure;
        let verdict = process_ingress(&mut sw, &io, 1, 10, 0, false, &frame, &wire);
        assert!(matches!(verdict, Verdict::Consumed));
        assert!(lock(&sw.openflow.shared.queue).is_empty());
    }
}
