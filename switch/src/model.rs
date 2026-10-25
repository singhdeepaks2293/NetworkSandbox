//! Switch configuration model: VLANs, ports, MAC table and global options.
//!
//! The model is deliberately plain data; protocol engines live in [`crate::stp`]
//! and the packet path in [`crate::dataplane`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::lldp::LldpState;
use crate::md5;
use crate::packet::{
    format_mac, mac_to_u64, BridgeId, MstConfigId, MST_CONFIG_DIGEST_KEY, MST_MAX_INSTANCES,
};
use crate::stp::{self, StpState};

pub const DEFAULT_PRIORITY: u16 = 32768;
pub const MAX_VLAN_ID: u16 = crate::packet::VLAN_VID_MAX;
pub const DEFAULT_MAC_AGING_SECS: u16 = 300;
pub const DEFAULT_HELLO_TIME: u16 = 2;
pub const DEFAULT_MAX_AGE: u16 = 20;
pub const DEFAULT_FORWARD_DELAY: u16 = 15;
pub const DEFAULT_MAX_HOPS: u8 = 20;
pub const MAX_MSTID: u16 = MST_MAX_INSTANCES;
pub const MST_DEFAULT_PRIORITY: u16 = DEFAULT_PRIORITY;
/// Port priority defaults to 128 for the CIST and for every MSTI.
pub const DEFAULT_PORT_PRIORITY: u8 = 128;

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_mac(self.0))
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// VLAN bit set
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
pub struct VlanSet {
    bits: [u64; 64],
}

impl VlanSet {
    pub fn none() -> Self {
        VlanSet { bits: [0; 64] }
    }

    pub fn all() -> Self {
        let mut s = VlanSet::none();
        for v in 1..=MAX_VLAN_ID {
            s.insert(v);
        }
        s
    }

    pub fn insert(&mut self, vlan: u16) {
        if (1..=MAX_VLAN_ID).contains(&vlan) {
            self.bits[(vlan / 64) as usize] |= 1u64 << (vlan % 64);
        }
    }

    pub fn remove(&mut self, vlan: u16) {
        if (1..=MAX_VLAN_ID).contains(&vlan) {
            self.bits[(vlan / 64) as usize] &= !(1u64 << (vlan % 64));
        }
    }

    pub fn contains(&self, vlan: u16) -> bool {
        if !(1..=MAX_VLAN_ID).contains(&vlan) {
            return false;
        }
        self.bits[(vlan / 64) as usize] & (1u64 << (vlan % 64)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|b| *b == 0)
    }

    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        (1..=MAX_VLAN_ID).filter(move |v| self.contains(*v))
    }

    /// Parse `1-5,10,20-30` into a set.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut set = VlanSet::none();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((a, b)) = part.split_once('-') {
                let a: u16 = a.trim().parse().map_err(|_| format!("bad VLAN list '{}'", s))?;
                let b: u16 = b.trim().parse().map_err(|_| format!("bad VLAN list '{}'", s))?;
                if a > b || a < 1 || b > MAX_VLAN_ID {
                    return Err(format!("bad VLAN range '{}-{}'", a, b));
                }
                for v in a..=b {
                    set.insert(v);
                }
            } else {
                let v: u16 = part.parse().map_err(|_| format!("bad VLAN id '{}'", part))?;
                if !(1..=MAX_VLAN_ID).contains(&v) {
                    return Err(format!("VLAN id {} out of range", v));
                }
                set.insert(v);
            }
        }
        Ok(set)
    }
}

impl Default for VlanSet {
    fn default() -> Self {
        VlanSet::all()
    }
}

impl fmt::Display for VlanSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        let mut ranges: Vec<String> = Vec::new();
        let mut start: Option<u16> = None;
        let mut prev: u16 = 0;
        for v in self.iter() {
            match start {
                None => {
                    start = Some(v);
                    prev = v;
                }
                Some(_) if v == prev + 1 => prev = v,
                Some(s) => {
                    if s == prev {
                        ranges.push(format!("{}", s));
                    } else {
                        ranges.push(format!("{}-{}", s, prev));
                    }
                    start = Some(v);
                    prev = v;
                }
            }
        }
        if let Some(s) = start {
            if s == prev {
                ranges.push(format!("{}", s));
            } else {
                ranges.push(format!("{}-{}", s, prev));
            }
        }
        f.write_str(&ranges.join(","))
    }
}

impl fmt::Debug for VlanSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// VLANs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VlanState {
    Active,
    Suspended,
}

impl VlanState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VlanState::Active => "active",
            VlanState::Suspended => "suspend",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub state: VlanState,
}

impl Vlan {
    pub fn new(id: u16) -> Self {
        let name = if id == 1 {
            "default".to_string()
        } else {
            format!("VLAN{:04}", id)
        };
        Vlan {
            id,
            name,
            state: VlanState::Active,
        }
    }
}

// ---------------------------------------------------------------------------
// Spanning tree configuration
// ---------------------------------------------------------------------------

/// Spanning-tree protocol selected for the bridge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StpMode {
    /// IEEE 802.1D STP (version 0 configuration/TCN BPDUs).
    Stp,
    /// IEEE 802.1Q common spanning tree carried in STP BPDUs.
    Cst,
    /// IEEE 802.1Q-2005 Multiple Spanning Tree Protocol.
    Mstp,
}

impl Default for StpMode {
    fn default() -> Self {
        // MSTP is available through `feature enable mstp`; until then the
        // bridge runs classic IEEE 802.1D STP with a single tree.
        StpMode::Stp
    }
}

impl StpMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StpMode::Stp => "stp",
            StpMode::Cst => "cst",
            StpMode::Mstp => "mstp",
        }
    }

    pub fn is_mstp(&self) -> bool {
        *self == StpMode::Mstp
    }
}

/// IEEE 802.1Q-2005 spanning-tree parameters.  Timers and the CIST bridge
/// priority are global; MSTI priorities live in [`MstConfig`].
#[derive(Clone, Debug)]
pub struct StpConfig {
    pub mode: StpMode,
    pub priority: u16,
    pub hello: u16,
    pub max_age: u16,
    pub forward_delay: u16,
    pub max_hops: u8,
}

impl Default for StpConfig {
    fn default() -> Self {
        StpConfig {
            mode: StpMode::default(),
            priority: DEFAULT_PRIORITY,
            hello: DEFAULT_HELLO_TIME,
            max_age: DEFAULT_MAX_AGE,
            forward_delay: DEFAULT_FORWARD_DELAY,
            max_hops: DEFAULT_MAX_HOPS,
        }
    }
}

// ---------------------------------------------------------------------------
// MST configuration
// ---------------------------------------------------------------------------

/// One MSTI: its bridge priority and the VLANs allocated to it.
#[derive(Clone, Debug)]
pub struct MstiConfig {
    pub id: u16,
    /// Bridge priority for this MSTI (multiple of 4096; the low 12 bits are
    /// the system ID extension and are always the MSTID).
    pub priority: u16,
    /// VIDs allocated to this MSTI.  VIDs not present here belong to the CIST.
    pub vlans: VlanSet,
}

impl MstiConfig {
    pub fn new(id: u16) -> Self {
        MstiConfig {
            id,
            priority: MST_DEFAULT_PRIORITY,
            vlans: VlanSet::none(),
        }
    }
}

/// The MST Configuration Identifier components plus the VID to MSTID table.
#[derive(Clone, Debug)]
pub struct MstConfig {
    /// Configuration name (up to 32 octets).
    pub name: String,
    pub revision: u16,
    pub instances: BTreeMap<u16, MstiConfig>,
}

impl MstConfig {
    /// The recommended default: configuration name derived from the bridge
    /// address, revision 0, and every VID mapped to the CIST.
    pub fn new(system_mac: [u8; 6]) -> Self {
        MstConfig {
            name: format_mac(system_mac),
            revision: 0,
            instances: BTreeMap::new(),
        }
    }

    /// MSTID for a VID.  The CIST is MSTID 0.
    pub fn mstid_for_vlan(&self, vlan: u16) -> u16 {
        if !(1..=MAX_VLAN_ID).contains(&vlan) {
            return 0;
        }
        for inst in self.instances.values() {
            if inst.vlans.contains(vlan) {
                return inst.id;
            }
        }
        0
    }

    /// 4096-entry VID to MSTID table in network byte order, as defined in
    /// IEEE 802.1Q-2005 13.7: element 0 is 0, elements 1..4094 are the MSTID
    /// for VIDs 1..4094, and element 4095 is 0.
    pub fn digest(&self) -> [u8; 16] {
        let mut table = Vec::with_capacity(4096 * 2);
        table.extend_from_slice(&0u16.to_be_bytes());
        for vid in 1..=MAX_VLAN_ID {
            table.extend_from_slice(&self.mstid_for_vlan(vid).to_be_bytes());
        }
        table.extend_from_slice(&0u16.to_be_bytes());
        md5::hmac_md5(&MST_CONFIG_DIGEST_KEY, &table)
    }

    pub fn config_id(&self) -> MstConfigId {
        MstConfigId::new(&self.name, self.revision, self.digest())
    }

    pub fn ensure_instance(&mut self, id: u16) -> &mut MstiConfig {
        self.instances
            .entry(id)
            .or_insert_with(|| MstiConfig::new(id))
    }

    /// Replace the VLAN allocation of `id`, removing those VIDs from any
    /// other MSTI (a VID belongs to exactly one tree).
    pub fn set_instance_vlans(&mut self, id: u16, vlans: VlanSet) {
        for inst in self.instances.values_mut() {
            if inst.id != id {
                for v in vlans.iter() {
                    inst.vlans.remove(v);
                }
            }
        }
        self.ensure_instance(id).vlans = vlans;
    }

    pub fn remove_instance(&mut self, id: u16) {
        self.instances.remove(&id);
    }

    /// True if any configured MSTI exists (MSTP requires at least two in a
    /// conformant MST Bridge, but the CIST always exists).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortMode {
    Access,
    Trunk,
}

impl PortMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortMode::Access => "access",
            PortMode::Trunk => "trunk",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrunkCfg {
    pub native_vlan: u16,
    pub allowed: VlanSet,
}

/// Per-MSTI port parameters.  The CIST has its own fields on [`Port`].
#[derive(Clone, Copy, Debug)]
pub struct MstiPortConfig {
    /// Port priority (0..255); only the four most significant bits are
    /// encoded in an MSTI Configuration Message.
    pub priority: u8,
    /// Internal port path cost override.
    pub cost: Option<u32>,
}

impl Default for MstiPortConfig {
    fn default() -> Self {
        MstiPortConfig {
            priority: DEFAULT_PORT_PRIORITY,
            cost: None,
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Counters {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub drops: u64,
    pub bpdu_rx: u64,
    pub bpdu_tx: u64,
    /// True when bpduguard put the port into err-disabled state.
    pub err_disabled: bool,
}

#[derive(Clone, Debug)]
pub struct Port {
    /// Linux interface name, e.g. `eth1`.
    pub ifname: String,
    /// Cisco-style display name, e.g. `Gi0/1`.
    pub name: String,
    /// Stable 1-based index used by STP, the MAC table and the dataplane.
    pub index: usize,
    pub description: String,
    pub admin_up: bool,
    pub link_up: bool,
    pub mode: PortMode,
    pub access_vlan: u16,
    pub trunk: TrunkCfg,
    pub portfast: bool,
    pub bpduguard: bool,
    pub stp_enabled: bool,
    /// CIST port priority (0..255).
    pub stp_priority: u8,
    /// CIST external port path cost override.
    pub stp_cost: Option<u32>,
    /// Per-MSTI port priority and internal path cost.
    pub msti: BTreeMap<u16, MstiPortConfig>,
    /// Configured speed in Mbps (used for the STP path cost).
    pub speed: u32,
    pub counters: Counters,
    pub last_change: Instant,
}

impl Port {
    pub fn new(index: usize, ifname: &str) -> Self {
        Port {
            ifname: ifname.to_string(),
            name: cisco_name(index, ifname),
            index,
            description: String::new(),
            admin_up: true,
            link_up: false,
            mode: PortMode::Access,
            access_vlan: 1,
            trunk: TrunkCfg {
                native_vlan: 1,
                allowed: VlanSet::all(),
            },
            portfast: false,
            bpduguard: false,
            stp_enabled: true,
            stp_priority: DEFAULT_PORT_PRIORITY,
            stp_cost: None,
            msti: BTreeMap::new(),
            speed: 1000,
            counters: Counters::default(),
            last_change: Instant::now(),
        }
    }

    /// Port VLAN ID: the access VLAN, or the native VLAN on a trunk.
    pub fn pvid(&self) -> u16 {
        match self.mode {
            PortMode::Access => self.access_vlan,
            PortMode::Trunk => self.trunk.native_vlan,
        }
    }

    /// Is `vlan` carried by this port (tagged or untagged)?
    pub fn carries(&self, vlan: u16) -> bool {
        match self.mode {
            PortMode::Access => self.access_vlan == vlan,
            PortMode::Trunk => {
                vlan == self.trunk.native_vlan || self.trunk.allowed.contains(vlan)
            }
        }
    }

    /// IEEE 802.1D external path cost derived from the configured speed.
    pub fn stp_cost(&self) -> u32 {
        match self.speed {
            0..=10 => 100,
            11..=100 => 19,
            101..=1000 => 4,
            1001..=10000 => 2,
            _ => 1,
        }
    }

    /// IEEE 802.1Q-2005 Table 13-3 internal path cost.
    pub fn internal_cost(&self) -> u32 {
        match self.speed {
            0..=10 => 2_000_000,
            11..=100 => 200_000,
            101..=1000 => 20_000,
            1001..=10000 => 2_000,
            _ => 200,
        }
    }

    /// CIST external port path cost, including a management override.
    pub fn cist_external_cost(&self) -> u32 {
        self.stp_cost.unwrap_or_else(|| self.stp_cost())
    }

    /// CIST internal port path cost, including a management override.
    pub fn cist_internal_cost(&self) -> u32 {
        self.stp_cost.unwrap_or_else(|| self.internal_cost())
    }

    pub fn msti_priority(&self, mstid: u16) -> u8 {
        self.msti
            .get(&mstid)
            .map(|c| c.priority)
            .unwrap_or(DEFAULT_PORT_PRIORITY)
    }

    pub fn msti_cost(&self, mstid: u16) -> u32 {
        self.msti
            .get(&mstid)
            .and_then(|c| c.cost)
            .unwrap_or_else(|| self.internal_cost())
    }

    pub fn oper_up(&self) -> bool {
        self.admin_up && self.link_up && !self.counters.err_disabled
    }

    pub fn status_str(&self) -> &'static str {
        if self.counters.err_disabled {
            "err-disabled"
        } else if !self.admin_up {
            "admin-down"
        } else if self.link_up {
            "connected"
        } else {
            "notconnect"
        }
    }
}

/// Name a port the way IOS would: eth1 -> Gi0/1, eth12 -> Gi0/12.
pub fn cisco_name(index: usize, ifname: &str) -> String {
    let digits: String = ifname
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let num = digits.parse::<usize>().unwrap_or(index);
    format!("Gi0/{}", num.max(1))
}

/// Normalise user input to a Linux interface name, accepting Cisco style.
pub fn normalize_ifname(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if lower.starts_with("eth") || lower.starts_with("en") || lower == "lo" {
        return lower;
    }
    // Gi0/3, GigabitEthernet0/3 -> eth3
    if let Some(pos) = input.rfind('/') {
        let num = &input[pos + 1..];
        if let Ok(n) = num.parse::<usize>() {
            return format!("eth{}", n);
        }
    }
    input.to_string()
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Features {
    pub vlan: bool,
    pub stp: bool,
    pub mstp: bool,
    pub trunking: bool,
    pub mac_learning: bool,
    pub portfast: bool,
    pub bpdu_guard: bool,
    pub lldp: bool,
    pub telnet: bool,
}

impl Default for Features {
    fn default() -> Self {
        Features {
            vlan: true,
            stp: true,
            mstp: false,
            trunking: true,
            mac_learning: true,
            portfast: false,
            bpdu_guard: false,
            lldp: false,
            telnet: false,
        }
    }
}

impl Features {
    pub fn get(&self, name: &str) -> Option<bool> {
        match name {
            "vlan" => Some(self.vlan),
            "stp" => Some(self.stp),
            "mstp" => Some(self.mstp),
            "trunking" => Some(self.trunking),
            "mac-learning" => Some(self.mac_learning),
            "portfast" => Some(self.portfast),
            "bpdu-guard" | "bpduguard" => Some(self.bpdu_guard),
            "lldp" => Some(self.lldp),
            "telnet" => Some(self.telnet),
            _ => None,
        }
    }

    pub fn set(&mut self, name: &str, value: bool) -> Result<(), String> {
        match name {
            "vlan" => self.vlan = value,
            "stp" => self.stp = value,
            "mstp" => self.mstp = value,
            "trunking" => self.trunking = value,
            "mac-learning" => self.mac_learning = value,
            "portfast" => self.portfast = value,
            "bpdu-guard" | "bpduguard" => self.bpdu_guard = value,
            "lldp" => self.lldp = value,
            "telnet" => self.telnet = value,
            _ => return Err(format!("unknown feature '{}'", name)),
        }
        Ok(())
    }

    pub fn names() -> &'static [&'static str] {
        &[
            "vlan",
            "stp",
            "mstp",
            "trunking",
            "mac-learning",
            "portfast",
            "bpdu-guard",
            "lldp",
            "telnet",
        ]
    }
}

// ---------------------------------------------------------------------------
// MAC address table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacEntry {
    pub port: usize,
    pub static_entry: bool,
    pub learned: Instant,
}

#[derive(Default)]
pub struct MacTable {
    pub entries: HashMap<(u16, [u8; 6]), MacEntry>,
}

impl MacTable {
    pub fn learn(&mut self, vlan: u16, mac: [u8; 6], port: usize, now: Instant) -> Option<usize> {
        let key = (vlan, mac);
        let old = self.entries.get(&key).map(|e| e.port);
        self.entries.insert(
            key,
            MacEntry {
                port,
                static_entry: false,
                learned: now,
            },
        );
        old
    }

    pub fn lookup(&self, vlan: u16, mac: [u8; 6]) -> Option<usize> {
        self.entries.get(&(vlan, mac)).map(|e| e.port)
    }

    pub fn age(&mut self, now: Instant, aging: Duration) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.static_entry || now.duration_since(e.learned) < aging);
        before - self.entries.len()
    }

    pub fn clear_dynamic(&mut self) {
        self.entries.retain(|_, e| e.static_entry);
    }
}

// ---------------------------------------------------------------------------
// Switch
// ---------------------------------------------------------------------------

pub struct Switch {
    pub hostname: String,
    pub version: &'static str,
    pub system_mac: [u8; 6],
    pub features: Features,
    pub stp_config: StpConfig,
    pub mst: MstConfig,
    pub stp: StpState,
    pub vlans: BTreeMap<u16, Vlan>,
    pub ports: Vec<Port>,
    pub mac_table: MacTable,
    pub mac_aging: u16,
    pub lldp: LldpState,
    pub startup_path: PathBuf,
    pub dirty: bool,
    pub uptime: Instant,
    pub log: VecDeque<String>,
    pub logging_enabled: bool,
}

impl Switch {
    pub fn new(hostname: &str, system_mac: [u8; 6], startup_path: PathBuf) -> Self {
        let mut vlans = BTreeMap::new();
        vlans.insert(1, Vlan::new(1));
        let mut sw = Switch {
            hostname: hostname.to_string(),
            version: concat!("SWITCH-1.0 (", env!("CARGO_PKG_VERSION"), ")"),
            system_mac,
            features: Features::default(),
            stp_config: StpConfig::default(),
            mst: MstConfig::new(system_mac),
            stp: StpState::new(),
            vlans,
            ports: Vec::new(),
            mac_table: MacTable::default(),
            mac_aging: DEFAULT_MAC_AGING_SECS,
            lldp: LldpState::default(),
            startup_path,
            dirty: false,
            uptime: Instant::now(),
            log: VecDeque::new(),
            logging_enabled: true,
        };
        sw.log_line("switch: system initialised");
        sw
    }

    pub fn log_line(&mut self, msg: &str) {
        let line = format!("*{:>10}: %{}", uptime_secs(self.uptime), msg);
        if self.logging_enabled {
            eprintln!("{}", line);
        }
        self.log.push_back(line);
        while self.log.len() > 500 {
            self.log.pop_front();
        }
    }

    pub fn add_port(&mut self, ifname: &str) -> usize {
        if let Some(idx) = self.port_by_name(ifname) {
            return idx;
        }
        let index = self.ports.len() + 1;
        self.ports.push(Port::new(index, ifname));
        if self.features.stp {
            stp::sync_ports(self);
        }
        index
    }

    /// Resolve `eth1`, `Gi0/1`, `GigabitEthernet0/1` etc. to a port index.
    pub fn port_by_name(&self, name: &str) -> Option<usize> {
        let norm = normalize_ifname(name);
        let lower = name.to_ascii_lowercase();
        self.ports
            .iter()
            .find(|p| {
                p.ifname == norm
                    || p.ifname.eq_ignore_ascii_case(&lower)
                    || p.name.eq_ignore_ascii_case(name)
                    || p.name.eq_ignore_ascii_case(&lower)
            })
            .map(|p| p.index)
    }

    pub fn port(&self, index: usize) -> Option<&Port> {
        self.ports.get(index.checked_sub(1)?)
    }

    pub fn port_mut(&mut self, index: usize) -> Option<&mut Port> {
        self.ports.get_mut(index.checked_sub(1)?)
    }

    pub fn has_vlan(&self, vlan: u16) -> bool {
        self.vlans
            .get(&vlan)
            .map(|v| v.state == VlanState::Active)
            .unwrap_or(false)
    }

    pub fn vlan_name(&self, vlan: u16) -> String {
        self.vlans
            .get(&vlan)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn bridge_priority(&self) -> u16 {
        self.stp_config.priority & 0xf000
    }

    /// IEEE 802.1Q-2005 bridge identifier for the CIST (system ID extension 0).
    pub fn bridge_id(&self) -> BridgeId {
        BridgeId::new(self.bridge_priority(), self.system_mac)
    }

    /// Bridge identifier for an MSTI: its configured priority plus the MSTID
    /// in the 12-bit system ID extension.
    pub fn msti_bridge_id(&self, mstid: u16) -> BridgeId {
        let priority = self
            .mst
            .instances
            .get(&mstid)
            .map(|i| i.priority & 0xf000)
            .unwrap_or(MST_DEFAULT_PRIORITY & 0xf000);
        BridgeId::new(priority | (mstid & 0x0fff), self.system_mac)
    }

    /// STP forwarding decision for a port and VLAN.  In MSTP mode the VLAN is
    /// mapped to its MSTID and the corresponding tree's state is used.
    pub fn is_forwarding(&self, port: usize, vlan: u16) -> bool {
        let Some(p) = self.port(port) else {
            return false;
        };
        if !p.oper_up() || !p.stp_enabled {
            return false;
        }
        if !self.features.stp {
            return true;
        }
        let mstid = if self.stp_config.mode.is_mstp() {
            self.mst.mstid_for_vlan(vlan)
        } else {
            0
        };
        stp::is_forwarding_mst(self, port, mstid)
    }

    /// Ports that can carry a VLAN in the data plane, in index order.
    pub fn vlan_ports(&self, vlan: u16) -> Vec<usize> {
        self.ports
            .iter()
            .filter(|p| p.oper_up() && p.carries(vlan) && self.is_forwarding(p.index, vlan))
            .map(|p| p.index)
            .collect()
    }

    pub fn short_uptime(&self) -> String {
        let s = uptime_secs(self.uptime);
        format!(
            "{} weeks, {} days, {} hours, {} minutes",
            s / 604800,
            (s % 604800) / 86400,
            (s % 86400) / 3600,
            (s % 3600) / 60
        )
    }

    /// sysObject-ish identifier used in `show version`.
    pub fn serial(&self) -> String {
        format!("SW{:012X}", mac_to_u64(self.system_mac) & 0xffff_ffff_ffff)
    }
}

pub fn uptime_secs(start: Instant) -> u64 {
    start.elapsed().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlanset_parse_and_render() {
        let s = VlanSet::parse("1-3,10,20-22").unwrap();
        assert_eq!(s.count(), 7);
        assert!(s.contains(2) && s.contains(21));
        assert!(!s.contains(4));
        assert_eq!(s.to_string(), "1-3,10,20-22");
        assert_eq!(VlanSet::parse("0").unwrap_err().len() > 0, true);
        assert_eq!(VlanSet::parse("30-20").unwrap_err().len() > 0, true);
        assert_eq!(VlanSet::all().count(), 4094);
    }

    #[test]
    fn port_pvid_and_carries() {
        let mut p = Port::new(1, "eth1");
        assert_eq!(p.pvid(), 1);
        assert!(p.carries(1));
        assert!(!p.carries(2));
        p.mode = PortMode::Trunk;
        p.trunk.native_vlan = 99;
        p.trunk.allowed = VlanSet::parse("10,20-30").unwrap();
        assert_eq!(p.pvid(), 99);
        assert!(p.carries(99) && p.carries(25));
        assert!(!p.carries(40));
    }

    #[test]
    fn cisco_names() {
        assert_eq!(cisco_name(1, "eth1"), "Gi0/1");
        assert_eq!(cisco_name(3, "eth12"), "Gi0/12");
        assert_eq!(normalize_ifname("Gi0/4"), "eth4");
        assert_eq!(normalize_ifname("GigabitEthernet0/4"), "eth4");
        assert_eq!(normalize_ifname("eth7"), "eth7");
    }

    #[test]
    fn mac_aging_respects_static() {
        let now = Instant::now();
        let mut t = MacTable::default();
        t.learn(10, [0, 1, 2, 3, 4, 5], 1, now - Duration::from_secs(400));
        t.entries.insert(
            (10, [0, 1, 2, 3, 4, 6]),
            MacEntry {
                port: 2,
                static_entry: true,
                learned: now,
            },
        );
        assert_eq!(t.age(now, Duration::from_secs(300)), 1);
        assert_eq!(t.entries.len(), 1);
    }
}
