//! IEEE 802.1Q-2005 Multiple Spanning Tree Protocol (MSTP).
//!
//! The bridge runs a CIST (MSTID 0) and up to 64 MSTIs.  CIST information is
//! carried in the RST-compatible part of an MST BPDU; each MSTI is carried in
//! a 16-octet MSTI Configuration Message (Figure 14-2).  All trees share one
//! transmit timer and one BPDU per port.
//!
//! The implementation follows the priority-vector definitions of clauses
//! 13.9-13.11:
//!
//! * a CIST vector is `(root, external cost, regional root, internal cost,
//!   designated bridge, designated port)`;
//! * an MSTI vector is `(regional root, internal cost, designated bridge,
//!   designated port)`.
//!
//! Port roles are Root, Designated, Alternate, Backup, Master and Disabled.
//! A Master Port is a CIST Root Port attached to another MST Region; for an
//! MSTI it plays the part of a Root Port and forwards when the CIST forwards.
//!
//! IEEE 802.1D STP and IEEE 802.1Q CST operation are retained as selectable
//! compatibility modes (`spanning-tree mode stp|cst`).  MSTP is the default.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::model::{Features, Port, Switch};
use crate::packet::{
    self, secs_to_timer, timer_to_duration, Bpdu, BridgeId, MstPayload, MstiMessage,
    BPDU_FLAG_FORWARDING, BPDU_FLAG_LEARNING, BPDU_FLAG_MASTER, BPDU_FLAG_PROPOSAL,
    BPDU_FLAG_ROLE_SHIFT, BPDU_FLAG_TC, BPDU_FLAG_TCACK, BPDU_TYPE_RST, BPDU_VERSION_MSTP,
    MST_MAX_INSTANCES,
};

/// Port states.  `Blocking` is the MSTP Discarding state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortState {
    Disabled,
    Blocking,
    Listening,
    Learning,
    Forwarding,
}

impl PortState {
    pub fn short(&self) -> &'static str {
        match self {
            PortState::Disabled => "DIS",
            PortState::Blocking => "BLK",
            PortState::Listening => "LSN",
            PortState::Learning => "LRN",
            PortState::Forwarding => "FWD",
        }
    }

    pub fn long(&self) -> &'static str {
        match self {
            PortState::Disabled => "disabled",
            PortState::Blocking => "discarding",
            PortState::Listening => "listening",
            PortState::Learning => "learning",
            PortState::Forwarding => "forwarding",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Root,
    Designated,
    Alternate,
    Backup,
    Master,
    Disabled,
}

impl Role {
    pub fn short(&self) -> &'static str {
        match self {
            Role::Root => "Root",
            Role::Designated => "Desg",
            Role::Alternate => "Altn",
            Role::Backup => "Back",
            Role::Master => "Mstr",
            Role::Disabled => "Dis",
        }
    }

    /// Encoding used in BPDU flag bits 3..4 (14.2.1).
    pub fn bits(&self) -> u8 {
        match self {
            Role::Master => 0,
            Role::Alternate | Role::Backup => 1,
            Role::Root => 2,
            Role::Designated => 3,
            Role::Disabled => 1,
        }
    }

}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub bpdu: Bpdu,
    /// True when the BPDU was sent by a bridge in the same MST Region.
    pub internal: bool,
    pub received: Instant,
    pub expires: Instant,
}

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub role: Role,
    pub state: PortState,
    pub peer: Option<PeerInfo>,
    pub transition_at: Option<Instant>,
    pub desired_forwarding: bool,
}

impl Default for PortInfo {
    fn default() -> Self {
        PortInfo {
            role: Role::Disabled,
            state: PortState::Disabled,
            peer: None,
            transition_at: None,
            desired_forwarding: false,
        }
    }
}

/// One spanning-tree instance.  `mstid == 0` is the CIST.
#[derive(Clone, Debug)]
pub struct Instance {
    pub mstid: u16,
    pub bridge_id: BridgeId,
    /// CIST root identifier, or the MSTI regional root identifier.
    pub root_id: BridgeId,
    /// CIST regional root identifier (equal to `root_id` for an MSTI).
    pub regional_root_id: BridgeId,
    /// CIST external root path cost (zero for an MSTI).
    pub external_cost: u32,
    /// CIST internal root path cost, or MSTI internal root path cost.
    pub internal_cost: u32,
    /// Sum of external and internal cost, for display.
    pub root_cost: u32,
    pub root_port: Option<usize>,
    pub is_root: bool,
    pub hello: u16,
    pub max_age: u16,
    pub forward_delay: u16,
    pub remaining_hops: u8,
    /// Index 0 is unused, index N belongs to port index N.
    pub ports: Vec<PortInfo>,
    pub last_hello: Instant,
    pub tc_until: Option<Instant>,
    pub ack_until: Option<Instant>,
    pub tcn_pending: bool,
    pub tcn_tx: bool,
    pub changes: u64,
    pub topo_changes: u64,
}

impl Instance {
    fn new(
        mstid: u16,
        bridge_id: BridgeId,
        hello: u16,
        max_age: u16,
        forward_delay: u16,
        max_hops: u8,
    ) -> Self {
        Instance {
            mstid,
            bridge_id,
            root_id: bridge_id,
            regional_root_id: bridge_id,
            external_cost: 0,
            internal_cost: 0,
            root_cost: 0,
            root_port: None,
            is_root: true,
            hello,
            max_age,
            forward_delay,
            remaining_hops: max_hops,
            ports: Vec::new(),
            // Force a BPDU on the first tick after the instance is created.
            last_hello: Instant::now()
                .checked_sub(Duration::from_secs(forward_delay.max(1) as u64 + 1))
                .unwrap_or_else(Instant::now),
            tc_until: None,
            ack_until: None,
            tcn_pending: false,
            tcn_tx: false,
            changes: 0,
            topo_changes: 0,
        }
    }

    pub fn fwd_delay(&self) -> Duration {
        Duration::from_secs(self.forward_delay.max(1) as u64)
    }

    pub fn tc_active(&self, now: Instant) -> bool {
        self.tc_until.map(|t| now < t).unwrap_or(false)
    }

    pub fn port(&self, index: usize) -> Option<&PortInfo> {
        self.ports.get(index).filter(|_| index > 0)
    }

    pub fn is_cist(&self) -> bool {
        self.mstid == 0
    }

    pub fn label(&self) -> String {
        if self.mstid == 0 {
            "CIST".to_string()
        } else {
            format!("MSTI {}", self.mstid)
        }
    }
}

pub struct StpState {
    /// The CIST.  `None` when STP is disabled.
    pub instance: Option<Instance>,
    /// Configured MSTIs, keyed by MSTID.
    pub mstis: BTreeMap<u16, Instance>,
    pub debug: bool,
    pub events: u64,
}

impl StpState {
    pub fn new() -> Self {
        StpState {
            instance: None,
            mstis: BTreeMap::new(),
            debug: false,
            events: 0,
        }
    }

    pub fn instance(&self) -> Option<&Instance> {
        self.instance.as_ref()
    }

    pub fn msti(&self, mstid: u16) -> Option<&Instance> {
        if mstid == 0 {
            self.instance.as_ref()
        } else {
            self.mstis.get(&mstid)
        }
    }

}

impl Default for StpState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub enum Action {
    Send { port: usize, bpdu: Bpdu },
}

#[derive(Default)]
pub struct Outcome {
    pub actions: Vec<Action>,
    /// Human-readable events for `show logging`.
    pub events: Vec<String>,
}

impl Outcome {
    fn log(&mut self, msg: String) {
        self.events.push(msg);
    }
}

/// Legacy CIST port identifier (priority 128, 12-bit port number).
pub fn port_id(index: usize) -> u16 {
    0x8000 | ((index as u16) & 0x0fff)
}

/// Port identifier with an explicit 8-bit priority.
pub fn port_id_with_priority(priority: u8, index: usize) -> u16 {
    ((priority as u16) << 8) | ((index as u16) & 0x0fff)
}

/// Create or refresh the CIST and every configured MSTI.
pub fn sync(sw: &mut Switch) {
    if !sw.features.stp {
        sw.stp.instance = None;
        sw.stp.mstis.clear();
        return;
    }
    let mode = sw.stp_config.mode;
    let hello = sw.stp_config.hello.max(1);
    let max_age = sw.stp_config.max_age.max(1);
    let forward_delay = sw.stp_config.forward_delay.max(1);
    let max_hops = sw.stp_config.max_hops.max(1);
    let port_count = sw.ports.len() + 1;
    let cist_bridge_id = sw.bridge_id();

    let msti_ids: Vec<(u16, BridgeId)> = if mode.is_mstp() {
        sw.mst
            .instances
            .keys()
            .copied()
            .filter(|id| *id >= 1 && *id <= MST_MAX_INSTANCES)
            .map(|id| (id, sw.msti_bridge_id(id)))
            .collect()
    } else {
        Vec::new()
    };

    let inst = sw.stp.instance.get_or_insert_with(|| {
        Instance::new(0, cist_bridge_id, hello, max_age, forward_delay, max_hops)
    });
    inst.mstid = 0;
    inst.bridge_id = cist_bridge_id;
    inst.hello = hello;
    inst.max_age = max_age;
    inst.forward_delay = forward_delay;
    if inst.ports.len() < port_count {
        inst.ports.resize_with(port_count, PortInfo::default);
    }

    sw.stp.mstis.retain(|id, _| {
        mode.is_mstp() && msti_ids.iter().any(|(candidate, _)| candidate == id)
    });
    for (id, bridge_id) in msti_ids {
        let inst = sw.stp.mstis.entry(id).or_insert_with(|| {
            Instance::new(id, bridge_id, hello, max_age, forward_delay, max_hops)
        });
        inst.mstid = id;
        inst.bridge_id = bridge_id;
        inst.hello = hello;
        inst.max_age = max_age;
        inst.forward_delay = forward_delay;
        if inst.ports.len() < port_count {
            inst.ports.resize_with(port_count, PortInfo::default);
        }
    }
}

/// Kept for callers that just added a port.
pub fn sync_ports(sw: &mut Switch) {
    sync(sw);
}

/// Discard all runtime spanning-tree state.  IEEE 802.1Q-2005 requires this
/// when the MST Configuration Identifier changes.
pub fn reset(sw: &mut Switch) {
    sw.stp.instance = None;
    sw.stp.mstis.clear();
}

/// Re-synchronise the instances and immediately re-run the election, so a CLI
/// `show` right after a configuration change reflects the new state.
pub fn refresh(sw: &mut Switch) {
    sync(sw);
    let now = Instant::now();
    let out = recompute(sw, now);
    for e in out.events {
        sw.log_line(&e);
    }
}

/// CIST forwarding decision.
pub fn is_forwarding(sw: &Switch, port: usize) -> bool {
    if !sw.features.stp {
        return true;
    }
    sw.stp
        .instance
        .as_ref()
        .and_then(|i| i.port(port))
        .map(|p| p.state == PortState::Forwarding)
        .unwrap_or(false)
}

/// Forwarding decision for one MSTID (0 is the CIST).
pub fn is_forwarding_mst(sw: &Switch, port: usize, mstid: u16) -> bool {
    let Some(p) = sw.port(port) else {
        return false;
    };
    if !p.oper_up() || !p.stp_enabled {
        return false;
    }
    if !sw.features.stp {
        return true;
    }
    if mstid == 0 || !sw.stp_config.mode.is_mstp() {
        return is_forwarding(sw, port);
    }
    match sw.stp.mstis.get(&mstid) {
        Some(inst) => inst
            .port(port)
            .map(|pi| pi.state == PortState::Forwarding)
            .unwrap_or(false),
        // A VLAN mapped to an MSTI that has no runtime instance falls back to
        // the CIST rather than black-holing traffic.
        None => is_forwarding(sw, port),
    }
}

pub fn port_state(sw: &Switch, port: usize) -> PortState {
    sw.stp
        .instance
        .as_ref()
        .and_then(|i| i.port(port))
        .map(|p| p.state)
        .unwrap_or(PortState::Disabled)
}

pub fn port_state_mst(sw: &Switch, port: usize, mstid: u16) -> PortState {
    if mstid == 0 || !sw.stp_config.mode.is_mstp() {
        return port_state(sw, port);
    }
    sw.stp
        .mstis
        .get(&mstid)
        .and_then(|i| i.port(port))
        .map(|p| p.state)
        .unwrap_or_else(|| port_state(sw, port))
}

pub fn port_role(sw: &Switch, port: usize) -> Option<Role> {
    sw.stp
        .instance
        .as_ref()
        .and_then(|i| i.port(port))
        .map(|p| p.role)
}

#[allow(dead_code)] // used by tests and available for per-instance diagnostics
pub fn port_role_mst(sw: &Switch, port: usize, mstid: u16) -> Option<Role> {
    if mstid == 0 || !sw.stp_config.mode.is_mstp() {
        return port_role(sw, port);
    }
    sw.stp
        .mstis
        .get(&mstid)
        .and_then(|i| i.port(port))
        .map(|p| p.role)
        .or_else(|| port_role(sw, port))
}

fn port_usable(ports: &[Port], features: &Features, index: usize) -> bool {
    if !features.stp {
        return false;
    }
    ports
        .get(index.saturating_sub(1))
        .map(|p| p.oper_up() && p.stp_enabled)
        .unwrap_or(false)
}

/// True if the port's configured role is edge/portfast (and the feature is on).
fn is_edge(ports: &[Port], features: &Features, index: usize) -> bool {
    features.portfast
        && ports
            .get(index.saturating_sub(1))
            .map(|p| p.portfast)
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Priority vectors
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct CistVector {
    root: BridgeId,
    external_cost: u32,
    regional_root: BridgeId,
    internal_cost: u32,
    designated_bridge: BridgeId,
    designated_port: u16,
    rx_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct MstiVector {
    regional_root: BridgeId,
    internal_cost: u32,
    designated_bridge: BridgeId,
    designated_port: u16,
    rx_port: u16,
}

impl PeerInfo {
    /// CIST message priority vector as received (13.10).
    fn cist_message(&self, _own: BridgeId, rx_port: u16) -> CistVector {
        let bpdu = &self.bpdu;
        match &bpdu.mst {
            Some(mst) => CistVector {
                root: bpdu.root_id,
                external_cost: bpdu.root_path_cost,
                regional_root: bpdu.bridge_id,
                internal_cost: if self.internal {
                    mst.internal_root_path_cost
                } else {
                    0
                },
                designated_bridge: mst.cist_bridge_id,
                designated_port: bpdu.port_id,
                rx_port,
            },
            None => CistVector {
                root: bpdu.root_id,
                external_cost: bpdu.root_path_cost,
                regional_root: bpdu.bridge_id,
                internal_cost: 0,
                designated_bridge: bpdu.bridge_id,
                designated_port: bpdu.port_id,
                rx_port,
            },
        }
    }

    /// CIST root path priority vector (13.10).
    fn cist_root_path(
        &self,
        own: BridgeId,
        external_cost: u32,
        internal_cost: u32,
        rx_port: u16,
    ) -> CistVector {
        let mut v = self.cist_message(own, rx_port);
        if self.internal && self.bpdu.mst.is_some() {
            v.internal_cost = v.internal_cost.saturating_add(internal_cost);
        } else {
            v.external_cost = v.external_cost.saturating_add(external_cost);
            v.regional_root = own;
            v.internal_cost = 0;
        }
        v
    }

    /// Remaining hops for the CIST (or `None` when the message must be
    /// discarded because the hop count reached zero).
    fn cist_hops(&self, max_hops: u8) -> Option<u8> {
        match &self.bpdu.mst {
            Some(mst) if self.internal => {
                if mst.remaining_hops == 0 {
                    None
                } else {
                    Some(mst.remaining_hops.saturating_sub(1).max(1))
                }
            }
            _ => Some(max_hops),
        }
    }

    fn msti_message(&self, mstid: u16, rx_port: u16) -> Option<MstiVector> {
        let mst = self.bpdu.mst.as_ref()?;
        let msg = mst.msti.iter().find(|m| m.mstid() == mstid)?;
        let mac = mst.cist_bridge_id.mac();
        let bridge_priority = ((msg.bridge_priority as u16) << 8) | (mstid & 0x0fff);
        let port_number = self.bpdu.port_id & 0x0fff;
        let port_priority = (msg.port_priority as u16) << 8;
        Some(MstiVector {
            regional_root: msg.regional_root_id,
            internal_cost: msg.internal_root_path_cost,
            designated_bridge: BridgeId::new(bridge_priority, mac),
            designated_port: port_priority | port_number,
            rx_port,
        })
    }

    fn msti_root_path(&self, mstid: u16, cost: u32, rx_port: u16) -> Option<MstiVector> {
        let mut v = self.msti_message(mstid, rx_port)?;
        v.internal_cost = v.internal_cost.saturating_add(cost);
        Some(v)
    }

    fn msti_hops(&self, mstid: u16) -> Option<u8> {
        let mst = self.bpdu.mst.as_ref()?;
        let msg = mst.msti.iter().find(|m| m.mstid() == mstid)?;
        if msg.remaining_hops == 0 {
            None
        } else {
            Some(msg.remaining_hops.saturating_sub(1).max(1))
        }
    }
}

// ---------------------------------------------------------------------------
// Election
// ---------------------------------------------------------------------------

fn update_forwarding(
    pi: &mut PortInfo,
    desired: bool,
    edge: bool,
    fwd: Duration,
    now: Instant,
) -> bool {
    let was_forwarding = pi.state == PortState::Forwarding;
    pi.desired_forwarding = desired;
    if !desired {
        pi.transition_at = None;
        if pi.state != PortState::Disabled {
            pi.state = PortState::Blocking;
        }
        return was_forwarding;
    }
    if pi.state == PortState::Forwarding {
        return false;
    }
    if edge {
        pi.state = PortState::Forwarding;
        pi.transition_at = None;
        return true;
    }
    if pi.state == PortState::Blocking || pi.state == PortState::Disabled {
        pi.state = PortState::Listening;
        pi.transition_at = Some(now + fwd);
    } else if pi.transition_at.is_none() {
        // A port can inherit the Listening state from a mirrored boundary
        // transition without a timer of its own (13.12(e)).  If it then
        // becomes a normal designated or root port, re-arm the timer so it
        // cannot stay in Listening forever.
        pi.transition_at = Some(now + fwd);
    }
    false
}

fn set_tc(inst: &mut Instance, now: Instant) {
    let hold = Duration::from_secs(inst.max_age as u64 + inst.forward_delay as u64);
    inst.tc_until = Some(now + hold);
    inst.topo_changes += 1;
    inst.last_hello = now
        .checked_sub(Duration::from_secs(inst.hello.max(1) as u64))
        .unwrap_or(now);
}

/// CIST election and role assignment.  Returns true if any port's forwarding
/// state changed.
fn recompute_cist(
    inst: &mut Instance,
    ports: &[Port],
    features: &Features,
    now: Instant,
    out: &mut Outcome,
) -> bool {
    let own = inst.bridge_id;
    let fwd = inst.fwd_delay();
    let max_hops = inst.remaining_hops.max(1);
    let was: Vec<bool> = inst
        .ports
        .iter()
        .map(|p| p.state == PortState::Forwarding)
        .collect();

    // 1. Expire neighbour information.
    for pi in inst.ports.iter_mut().skip(1) {
        if let Some(peer) = &pi.peer {
            if now >= peer.expires {
                pi.peer = None;
            }
        }
    }

    // 2. Select the best root path vector.
    let bridge_vector = CistVector {
        root: own,
        external_cost: 0,
        regional_root: own,
        internal_cost: 0,
        designated_bridge: own,
        designated_port: 0,
        rx_port: 0,
    };
    let mut best: Option<(usize, CistVector, u8)> = None;
    for (i, pi) in inst.ports.iter().enumerate().skip(1) {
        if !port_usable(ports, features, i) {
            continue;
        }
        let Some(peer) = &pi.peer else { continue };
        let Some(hops) = peer.cist_hops(max_hops) else {
            continue;
        };
        let v = peer.cist_root_path(
            own,
            ports[i - 1].cist_external_cost(),
            ports[i - 1].cist_internal_cost(),
            port_id_with_priority(ports[i - 1].stp_priority, i),
        );
        if v.designated_bridge == own {
            continue;
        }
        if v < bridge_vector && best.map(|(_, bv, _)| v < bv).unwrap_or(true) {
            best = Some((i, v, hops));
        }
    }

    let (root_vector, root_port, remaining_hops) = match best {
        Some((idx, v, hops)) => (v, Some(idx), hops),
        None => (bridge_vector, None, max_hops),
    };
    let is_root = root_port.is_none();

    if inst.root_id != root_vector.root
        || inst.root_port != root_port
        || inst.external_cost != root_vector.external_cost
        || inst.internal_cost != root_vector.internal_cost
        || inst.regional_root_id != root_vector.regional_root
    {
        let old_root = inst.root_id;
        inst.root_id = root_vector.root;
        inst.external_cost = root_vector.external_cost;
        inst.internal_cost = root_vector.internal_cost;
        inst.regional_root_id = root_vector.regional_root;
        inst.root_cost = root_vector.external_cost.saturating_add(root_vector.internal_cost);
        inst.root_port = root_port;
        inst.is_root = is_root;
        inst.remaining_hops = remaining_hops;
        inst.changes += 1;
        if old_root != root_vector.root {
            out.log(format!(
                "MSTP: CIST root bridge is {} (cost {})",
                root_vector.root, inst.root_cost
            ));
        }
        if let Some(rp) = root_port {
            out.log(format!(
                "MSTP: CIST root port is {}",
                ports.get(rp - 1).map(|p| p.name.as_str()).unwrap_or("?")
            ));
        }
        set_tc(inst, now);
    }

    // 3. Assign roles and port states.
    for i in 1..inst.ports.len() {
        let usable = port_usable(ports, features, i);
        let edge = is_edge(ports, features, i);
        let pi = &mut inst.ports[i];
        if !usable {
            pi.role = Role::Disabled;
            pi.desired_forwarding = false;
            pi.transition_at = None;
            pi.state = PortState::Disabled;
            continue;
        }
        let designated = CistVector {
            root: root_vector.root,
            external_cost: root_vector.external_cost,
            regional_root: root_vector.regional_root,
            internal_cost: root_vector.internal_cost,
            designated_bridge: own,
            designated_port: port_id_with_priority(ports[i - 1].stp_priority, i),
            rx_port: port_id_with_priority(ports[i - 1].stp_priority, i),
        };
        if Some(i) == root_port {
            pi.role = Role::Root;
            update_forwarding(pi, true, edge, fwd, now);
        } else if let Some(peer) = &pi.peer {
            let msg = peer.cist_message(
                own,
                port_id_with_priority(ports[i - 1].stp_priority, i),
            );
            if msg < designated {
                pi.role = if msg.designated_bridge == own {
                    Role::Backup
                } else {
                    Role::Alternate
                };
                update_forwarding(pi, false, edge, fwd, now);
            } else {
                pi.role = Role::Designated;
                update_forwarding(pi, true, edge, fwd, now);
            }
        } else {
            pi.role = Role::Designated;
            update_forwarding(pi, true, edge, fwd, now);
        }
    }

    let mut changed = false;
    for (i, pi) in inst.ports.iter().enumerate().skip(1) {
        let forwarding = pi.state == PortState::Forwarding;
        if was.get(i).copied().unwrap_or(false) != forwarding {
            changed = true;
            if forwarding {
                out.log(format!(
                    "MSTP: {} {} moved to forwarding ({})",
                    inst.label(),
                    ports.get(i - 1).map(|p| p.name.as_str()).unwrap_or("?"),
                    pi.role.short()
                ));
            } else {
                out.log(format!(
                    "MSTP: {} {} stopped forwarding ({})",
                    inst.label(),
                    ports.get(i - 1).map(|p| p.name.as_str()).unwrap_or("?"),
                    pi.role.short()
                ));
            }
        }
    }
    if changed {
        set_tc(inst, now);
    }
    changed
}

/// MSTI election and role assignment.  The CIST instance supplies the shared
/// peer information and the boundary-port roles.
fn recompute_msti(
    inst: &mut Instance,
    cist: &Instance,
    ports: &[Port],
    features: &Features,
    now: Instant,
    out: &mut Outcome,
) -> bool {
    let mstid = inst.mstid;
    let own = inst.bridge_id;
    let fwd = inst.fwd_delay();
    let max_hops = inst.remaining_hops.max(1);
    let was: Vec<bool> = inst
        .ports
        .iter()
        .map(|p| p.state == PortState::Forwarding)
        .collect();

    let bridge_vector = MstiVector {
        regional_root: own,
        internal_cost: 0,
        designated_bridge: own,
        designated_port: 0,
        rx_port: 0,
    };
    let mut best: Option<(usize, MstiVector, u8)> = None;
    for (i, cist_pi) in cist.ports.iter().enumerate().skip(1) {
        if !port_usable(ports, features, i) {
            continue;
        }
        let Some(peer) = &cist_pi.peer else { continue };
        if !peer.internal || peer.bpdu.mst.is_none() {
            continue;
        }
        let Some(hops) = peer.msti_hops(mstid) else {
            continue;
        };
        let Some(v) = peer.msti_root_path(
            mstid,
            ports[i - 1].msti_cost(mstid),
            port_id_with_priority(ports[i - 1].msti_priority(mstid), i),
        ) else {
            continue;
        };
        if v.designated_bridge == own {
            continue;
        }
        if v < bridge_vector && best.map(|(_, bv, _)| v < bv).unwrap_or(true) {
            best = Some((i, v, hops));
        }
    }

    let (root_vector, root_port, remaining_hops) = match best {
        Some((idx, v, hops)) => (v, Some(idx), hops),
        None => (bridge_vector, None, max_hops),
    };
    let is_root = root_port.is_none();

    if inst.root_id != root_vector.regional_root
        || inst.root_port != root_port
        || inst.internal_cost != root_vector.internal_cost
    {
        let old_root = inst.root_id;
        inst.root_id = root_vector.regional_root;
        inst.regional_root_id = root_vector.regional_root;
        inst.external_cost = 0;
        inst.internal_cost = root_vector.internal_cost;
        inst.root_cost = root_vector.internal_cost;
        inst.root_port = root_port;
        inst.is_root = is_root;
        inst.remaining_hops = remaining_hops;
        inst.changes += 1;
        if old_root != root_vector.regional_root {
            out.log(format!(
                "MSTP: {} regional root is {} (cost {})",
                inst.label(),
                root_vector.regional_root,
                inst.root_cost
            ));
        }
        if let Some(rp) = root_port {
            out.log(format!(
                "MSTP: {} root port is {}",
                inst.label(),
                ports.get(rp - 1).map(|p| p.name.as_str()).unwrap_or("?")
            ));
        }
        set_tc(inst, now);
    }

    for i in 1..inst.ports.len() {
        let usable = port_usable(ports, features, i);
        let edge = is_edge(ports, features, i);
        let cist_pi = cist.ports.get(i);
        let boundary = cist_pi
            .and_then(|p| p.peer.as_ref())
            .map(|p| !p.internal)
            .unwrap_or(false);
        let pi = &mut inst.ports[i];
        if !usable {
            pi.role = Role::Disabled;
            pi.desired_forwarding = false;
            pi.transition_at = None;
            pi.state = PortState::Disabled;
            continue;
        }

        // At a boundary, MSTI roles and states mirror the CIST (13.12(e)-(h),
        // 13.13(f)).  A CIST Root Port attached to another region is the
        // MSTI Master Port.
        if boundary {
            let cist_role = cist_pi.map(|p| p.role).unwrap_or(Role::Disabled);
            pi.role = if cist_role == Role::Root {
                Role::Master
            } else {
                cist_role
            };
            let cist_state = cist_pi.map(|p| p.state).unwrap_or(PortState::Disabled);
            pi.state = cist_state;
            pi.desired_forwarding = matches!(
                cist_state,
                PortState::Listening | PortState::Learning | PortState::Forwarding
            );
            pi.transition_at = None;
            continue;
        }

        let designated = MstiVector {
            regional_root: root_vector.regional_root,
            internal_cost: root_vector.internal_cost,
            designated_bridge: own,
            designated_port: port_id_with_priority(ports[i - 1].msti_priority(mstid), i),
            rx_port: port_id_with_priority(ports[i - 1].msti_priority(mstid), i),
        };
        if Some(i) == root_port {
            pi.role = Role::Root;
            update_forwarding(pi, true, edge, fwd, now);
        } else if let Some(peer) = cist_pi.and_then(|p| p.peer.as_ref()) {
            match peer.msti_message(
                mstid,
                port_id_with_priority(ports[i - 1].msti_priority(mstid), i),
            ) {
                Some(msg) if msg < designated => {
                    pi.role = if msg.designated_bridge == own {
                        Role::Backup
                    } else {
                        Role::Alternate
                    };
                    update_forwarding(pi, false, edge, fwd, now);
                }
                _ => {
                    pi.role = Role::Designated;
                    update_forwarding(pi, true, edge, fwd, now);
                }
            }
        } else {
            pi.role = Role::Designated;
            update_forwarding(pi, true, edge, fwd, now);
        }
    }

    let mut changed = false;
    for (i, pi) in inst.ports.iter().enumerate().skip(1) {
        let forwarding = pi.state == PortState::Forwarding;
        if was.get(i).copied().unwrap_or(false) != forwarding {
            changed = true;
            if forwarding {
                out.log(format!(
                    "MSTP: {} {} moved to forwarding ({})",
                    inst.label(),
                    ports.get(i - 1).map(|p| p.name.as_str()).unwrap_or("?"),
                    pi.role.short()
                ));
            } else {
                out.log(format!(
                    "MSTP: {} {} stopped forwarding ({})",
                    inst.label(),
                    ports.get(i - 1).map(|p| p.name.as_str()).unwrap_or("?"),
                    pi.role.short()
                ));
            }
        }
    }
    if changed {
        set_tc(inst, now);
    }
    changed
}

/// Re-run the election for the CIST and every MSTI and move ports through the
/// listening/learning/forwarding states.
pub fn recompute(sw: &mut Switch, now: Instant) -> Outcome {
    let mut out = Outcome::default();
    if !sw.features.stp {
        return out;
    }
    sync(sw);

    let mstids: Vec<u16> = if sw.stp_config.mode.is_mstp() {
        sw.stp.mstis.keys().copied().collect()
    } else {
        Vec::new()
    };

    let Switch {
        stp,
        ports,
        features,
        ..
    } = sw;
    let StpState {
        instance, mstis, ..
    } = stp;

    let Some(cist) = instance.as_mut() else {
        return out;
    };
    let cist_changed = recompute_cist(cist, ports, features, now, &mut out);

    for id in mstids {
        let Some(inst) = mstis.get_mut(&id) else {
            continue;
        };
        let changed = recompute_msti(inst, cist, ports, features, now, &mut out);
        if cist_changed && !changed {
            // A CIST topology change is a topology change for every MSTI at
            // the boundary, so refresh their TC timers too.
            set_tc(inst, now);
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

/// Process a received STP, RST or MST configuration BPDU.
pub fn on_config(sw: &mut Switch, port: usize, rx: &Bpdu, now: Instant) -> Outcome {
    let mut out = Outcome::default();
    if !sw.features.stp {
        return out;
    }

    let Some(p) = sw.port(port).cloned() else {
        return out;
    };

    // BPDU guard: a BPDU on an edge port shuts it down.
    if sw.features.bpdu_guard && sw.features.portfast && p.portfast && p.bpduguard {
        if let Some(pm) = sw.port_mut(port) {
            pm.counters.err_disabled = true;
            pm.counters.drops += 1;
            pm.last_change = now;
        }
        sw.log_line(&format!(
            "SPANTREE: BPDU received on portfast port {}, port disabled (bpduguard)",
            p.name
        ));
        sync(sw);
        return out;
    }

    let is_mst = rx.is_mst();
    let is_rst = rx.is_rst();
    let is_st = rx.version == packet::BPDU_VERSION_STP && rx.bpdu_type == packet::BPDU_TYPE_CONFIG;
    if !(is_mst || is_rst || is_st) {
        if sw.stp.debug {
            sw.log_line(&format!(
                "MSTP dbg: ignore unsupported BPDU version {} type {} on {}",
                rx.version, rx.bpdu_type, p.name
            ));
        }
        return out;
    }

    let designated_bridge = rx
        .mst
        .as_ref()
        .map(|m| m.cist_bridge_id)
        .unwrap_or(rx.bridge_id);
    let our_port_id = port_id_with_priority(p.stp_priority, port);
    if designated_bridge == sw.bridge_id() && rx.port_id == our_port_id {
        // Our own BPDU reflected back at us: never believe it.
        if sw.stp.debug {
            sw.log_line(&format!("MSTP dbg: ignore own BPDU on {}", p.name));
        }
        return out;
    }
    if rx.max_age == 0 || rx.hello_time == 0 {
        if sw.stp.debug {
            sw.log_line(&format!("MSTP dbg: ignore zero-timer BPDU on {}", p.name));
        }
        return out;
    }
    if !is_mst && rx.msg_age >= rx.max_age {
        out.log(format!(
            "MSTP: ignoring expired BPDU from {} on {}",
            designated_bridge, p.name
        ));
        return out;
    }

    let own_config = sw.mst.config_id();
    let internal = is_mst
        && rx
            .mst
            .as_ref()
            .map(|m| m.config_id == own_config)
            .unwrap_or(false);

    if sw.stp.debug {
        sw.log_line(&format!(
            "MSTP dbg: accept {} BPDU on {} from bridge {} ({})",
            if is_mst { "MST" } else if is_rst { "RST" } else { "ST" },
            p.name,
            designated_bridge,
            if internal { "internal" } else { "external" }
        ));
    }

    // RSTP/MSTP information is refreshed after three Hello Times; STP
    // information expires with Message Age.
    let hold = if is_mst || is_rst {
        timer_to_duration(rx.hello_time) * 3
    } else {
        timer_to_duration(rx.max_age.saturating_sub(rx.msg_age))
    };
    // Clamp insane advertised ages so a broken neighbour can't freeze us.
    let max_hold = Duration::from_secs(60 * 5);
    let expires = now + hold.min(max_hold);

    sync(sw);
    if let Some(inst) = sw.stp.instance.as_mut() {
        if inst.ports.len() < sw.ports.len() + 1 {
            inst.ports.resize_with(sw.ports.len() + 1, PortInfo::default);
        }
        if let Some(pi) = inst.ports.get_mut(port) {
            pi.peer = Some(PeerInfo {
                bpdu: rx.clone(),
                internal,
                received: now,
                expires,
            });
        }
    }

    let mut res = recompute(sw, now);
    out.events.append(&mut res.events);

    // Topology change flags.  MSTP carries CIST and per-MSTI TCs in BPDUs.
    if rx.flags & BPDU_FLAG_TC != 0 {
        if let Some(inst) = sw.stp.instance.as_mut() {
            set_tc(inst, now);
            out.log("MSTP: CIST topology change received".to_string());
        }
    }
    if let Some(mst) = &rx.mst {
        for msg in &mst.msti {
            if msg.flags & BPDU_FLAG_TC != 0 {
                if let Some(inst) = sw.stp.mstis.get_mut(&msg.mstid()) {
                    set_tc(inst, now);
                    out.log(format!(
                        "MSTP: {} topology change received",
                        inst.label()
                    ));
                }
            }
        }
    }

    // If we are the designated bridge on this port, answer a possibly
    // inferior BPDU immediately (helps convergence and loop detection).
    let designated = sw
        .stp
        .instance
        .as_ref()
        .and_then(|i| i.port(port))
        .map(|pi| pi.role == Role::Designated && pi.state != PortState::Blocking)
        .unwrap_or(false);

    if designated {
        let tc = sw
            .stp
            .instance
            .as_ref()
            .map(|i| i.tc_active(now))
            .unwrap_or(false);
        let bpdu = build_bpdu(sw, port, tc, false, now);
        out.actions.push(Action::Send { port, bpdu });
    }

    // Acknowledged TCN (STP compatibility).
    if !is_mst && rx.topology_change_ack() {
        if let Some(inst) = sw.stp.instance.as_mut() {
            inst.tcn_pending = false;
        }
    }

    out
}

/// Process a received topology-change notification (STP compatibility).
pub fn on_tcn(sw: &mut Switch, port: usize, now: Instant) -> Outcome {
    let mut out = Outcome::default();
    if !sw.features.stp {
        return out;
    }
    if sw.port(port).is_none() {
        return out;
    }
    let mstp = sw.stp_config.mode.is_mstp();
    let priorities: Vec<u8> = sw.ports.iter().map(|p| p.stp_priority).collect();
    let Some(inst) = sw.stp.instance.as_mut() else {
        return out;
    };

    set_tc(inst, now);
    inst.ack_until = Some(now + Duration::from_secs(inst.hello.max(1) as u64 * 2));
    out.log("MSTP: CIST topology change notification received".to_string());

    if mstp {
        // MSTP propagates topology changes in the TC flag, not with TCN
        // BPDUs.  The next periodic BPDU carries the flag.
        inst.last_hello = now
            .checked_sub(Duration::from_secs(inst.hello.max(1) as u64))
            .unwrap_or(now);
        return out;
    }

    if let Some(rp) = inst.root_port {
        out.actions.push(Action::Send {
            port: rp,
            bpdu: Bpdu::tcn(port_id_with_priority(
                priorities.get(rp.saturating_sub(1)).copied().unwrap_or(128),
                rp,
            )),
        });
        inst.tcn_pending = true;
    } else {
        // We are the root: force a config BPDU with the TC flag.
        inst.last_hello = now - Duration::from_secs(inst.hello.max(1) as u64);
    }
    out
}

// ---------------------------------------------------------------------------
// Transmit
// ---------------------------------------------------------------------------

fn state_flags(state: PortState) -> u8 {
    let mut flags = 0;
    if matches!(state, PortState::Learning | PortState::Forwarding) {
        flags |= BPDU_FLAG_LEARNING;
    }
    if state == PortState::Forwarding {
        flags |= BPDU_FLAG_FORWARDING;
    }
    flags
}

/// Build the BPDU to transmit on `port`.  MSTP sends one MST BPDU carrying the
/// CIST and every MSTI.
fn build_bpdu(sw: &Switch, port: usize, tc: bool, tca: bool, now: Instant) -> Bpdu {
    let Some(cist) = sw.stp.instance.as_ref() else {
        return Bpdu::config(
            sw.bridge_id(),
            0,
            sw.bridge_id(),
            port_id(port),
            0,
            secs_to_timer(sw.stp_config.max_age),
            secs_to_timer(sw.stp_config.hello),
            secs_to_timer(sw.stp_config.forward_delay),
        );
    };
    let Some(p) = sw.port(port) else {
        return Bpdu::config(
            cist.root_id,
            cist.root_cost,
            cist.bridge_id,
            port_id(port),
            0,
            secs_to_timer(cist.max_age),
            secs_to_timer(cist.hello),
            secs_to_timer(cist.forward_delay),
        );
    };
    let our_port_id = port_id_with_priority(p.stp_priority, port);

    if !sw.stp_config.mode.is_mstp() {
        let mut bpdu = Bpdu::config(
            cist.root_id,
            cist.external_cost,
            cist.bridge_id,
            our_port_id,
            0,
            secs_to_timer(cist.max_age),
            secs_to_timer(cist.hello),
            secs_to_timer(cist.forward_delay),
        );
        if tc {
            bpdu.flags |= BPDU_FLAG_TC;
        }
        if tca {
            bpdu.flags |= BPDU_FLAG_TCACK;
        }
        return bpdu;
    }

    let cist_state = cist.port(port).map(|pi| pi.state).unwrap_or(PortState::Blocking);
    let cist_role = cist.port(port).map(|pi| pi.role).unwrap_or(Role::Disabled);
    let mut flags = state_flags(cist_state) | (cist_role.bits() << BPDU_FLAG_ROLE_SHIFT);
    if tc {
        flags |= BPDU_FLAG_TC;
    }
    // A designated port may solicit an agreement after a topology change.
    if cist_role == Role::Designated && cist_state != PortState::Forwarding {
        flags |= BPDU_FLAG_PROPOSAL;
    }

    let msti_messages = build_msti_messages(sw, port, now);

    Bpdu {
        protocol_id: 0,
        version: BPDU_VERSION_MSTP,
        bpdu_type: BPDU_TYPE_RST,
        flags,
        root_id: cist.root_id,
        root_path_cost: cist.external_cost,
        bridge_id: cist.regional_root_id,
        port_id: our_port_id,
        msg_age: 0,
        max_age: secs_to_timer(cist.max_age),
        hello_time: secs_to_timer(cist.hello),
        forward_delay: secs_to_timer(cist.forward_delay),
        version_1_length: 0,
        mst: Some(MstPayload {
            config_id: sw.mst.config_id(),
            internal_root_path_cost: cist.internal_cost,
            cist_bridge_id: cist.bridge_id,
            remaining_hops: cist.remaining_hops,
            msti: msti_messages,
        }),
    }
}

fn build_msti_messages(sw: &Switch, port: usize, now: Instant) -> Vec<MstiMessage> {
    let Some(p) = sw.port(port) else {
        return Vec::new();
    };
    let mut messages = Vec::new();
    for (id, inst) in &sw.stp.mstis {
        let pi = inst.port(port);
        let state = pi.map(|p| p.state).unwrap_or(PortState::Blocking);
        let role = pi.map(|p| p.role).unwrap_or(Role::Disabled);
        let mut flags = state_flags(state) | (role.bits() << BPDU_FLAG_ROLE_SHIFT);
        if inst.tc_active(now) {
            flags |= BPDU_FLAG_TC;
        }
        if state != PortState::Forwarding && role == Role::Designated {
            flags |= BPDU_FLAG_PROPOSAL;
        }
        // The Master flag signals that this MSTI reaches the CST through a
        // Master Port in this Region (13.24.5).
        let has_master = inst.ports.iter().skip(1).any(|pi| pi.role == Role::Master);
        if has_master && matches!(role, Role::Root | Role::Designated) {
            flags |= BPDU_FLAG_MASTER;
        }
        let bridge_priority = ((inst.bridge_id.priority() >> 8) as u8) & 0xf0;
        let port_priority = p.msti_priority(*id) & 0xf0;
        messages.push(MstiMessage {
            flags,
            regional_root_id: inst.root_id,
            internal_root_path_cost: inst.internal_cost,
            bridge_priority,
            port_priority,
            remaining_hops: inst.remaining_hops,
        });
        if messages.len() >= MST_MAX_INSTANCES as usize {
            break;
        }
    }
    messages
}

/// Periodic work: election, state timers, hellos and TCN retransmission.
pub fn tick(sw: &mut Switch, now: Instant) -> Outcome {
    let mut out = Outcome::default();
    if !sw.features.stp {
        return out;
    }
    sync(sw);

    // Election first (picks up link changes and expired peers).
    let mut res = recompute(sw, now);
    out.events.append(&mut res.events);
    out.actions.append(&mut res.actions);

    let mstp = sw.stp_config.mode.is_mstp();
    let priorities: Vec<u8> = sw.ports.iter().map(|p| p.stp_priority).collect();
    let msti_ids: Vec<u16> = sw.stp.mstis.keys().copied().collect();

    // State transitions for the CIST and every MSTI.
    {
        let Switch {
            stp,
            ports,
            features,
            ..
        } = sw;
        let StpState {
            instance, mstis, ..
        } = stp;
        let Some(cist) = instance.as_mut() else {
            return out;
        };
        advance_tree(cist, ports, features, now, &mut out, false);
        for id in &msti_ids {
            if let Some(inst) = mstis.get_mut(id) {
                advance_tree(inst, ports, features, now, &mut out, true);
            }
        }
    }

    // TCN propagation (STP/CST compatibility only).
    if !mstp {
        let Some(inst) = sw.stp.instance.as_mut() else {
            return out;
        };
        if inst.tcn_tx {
            inst.tcn_tx = false;
            inst.tcn_pending = true;
            if let Some(rp) = inst.root_port {
                out.actions.push(Action::Send {
                    port: rp,
                    bpdu: Bpdu::tcn(port_id_with_priority(
                        priorities.get(rp.saturating_sub(1)).copied().unwrap_or(128),
                        rp,
                    )),
                });
            }
        }
        if let Some(until) = inst.tc_until {
            if now >= until {
                inst.tc_until = None;
            }
        }
        if let Some(until) = inst.ack_until {
            if now >= until {
                inst.ack_until = None;
            }
        }
        if inst.tcn_pending {
            if let Some(rp) = inst.root_port {
                if now.duration_since(inst.last_hello)
                    >= Duration::from_secs(inst.hello.max(1) as u64)
                {
                    inst.last_hello = now;
                    out.actions.push(Action::Send {
                        port: rp,
                        bpdu: Bpdu::tcn(port_id_with_priority(
                            priorities.get(rp.saturating_sub(1)).copied().unwrap_or(128),
                            rp,
                        )),
                    });
                }
            } else {
                inst.tcn_pending = false;
            }
        }
    } else {
        // Expire TC timers on all trees.
        if let Some(inst) = sw.stp.instance.as_mut() {
            if inst.tc_until.map(|u| now >= u).unwrap_or(false) {
                inst.tc_until = None;
            }
        }
        for inst in sw.stp.mstis.values_mut() {
            if inst.tc_until.map(|u| now >= u).unwrap_or(false) {
                inst.tc_until = None;
            }
        }
    }

    // Hello timer: one BPDU per port that is designated for the CIST or for
    // any MSTI.  An MSTI can be designated on a port that is Alternate for
    // the CIST, so the CIST role alone is not enough (13.31).
    let msti_tx_ports: Vec<bool> = (0..=sw.ports.len())
        .map(|i| {
            sw.stp.mstis.values().any(|inst| {
                inst.port(i)
                    .map(|p| {
                        p.role == Role::Designated
                            && !matches!(p.state, PortState::Blocking | PortState::Disabled)
                    })
                    .unwrap_or(false)
            })
        })
        .collect();
    {
        let Some(inst) = sw.stp.instance.as_mut() else {
            return out;
        };
        let hello = Duration::from_secs(inst.hello.max(1) as u64);
        if now.duration_since(inst.last_hello) >= hello {
            inst.last_hello = now;
            let tc = inst.tc_active(now);
            let tca = inst.ack_until.map(|u| now < u).unwrap_or(false);
            let mut sends = Vec::new();
            for (i, pi) in inst.ports.iter().enumerate().skip(1) {
                let cist_designated = pi.role == Role::Designated
                    && !matches!(pi.state, PortState::Blocking | PortState::Disabled);
                // A root port transmits a BPDU carrying the TC flag while a
                // topology change is being propagated towards the root.
                let cist_root_tc = pi.role == Role::Root && tc;
                let msti_designated = msti_tx_ports.get(i).copied().unwrap_or(false);
                if cist_designated || cist_root_tc || msti_designated {
                    sends.push(i);
                }
            }
            for port in sends {
                let bpdu = build_bpdu(sw, port, tc, tca, now);
                out.actions.push(Action::Send { port, bpdu });
            }
        }
    }

    out
}

fn advance_tree(
    inst: &mut Instance,
    ports: &[Port],
    _features: &Features,
    now: Instant,
    out: &mut Outcome,
    msti: bool,
) {
    let fwd = inst.fwd_delay();
    let label = inst.label();
    let mut moved_to_forwarding = false;
    for (i, pi) in inst.ports.iter_mut().enumerate().skip(1) {
        if !pi.desired_forwarding {
            continue;
        }
        let Some(at) = pi.transition_at else { continue };
        if now < at {
            continue;
        }
        match pi.state {
            PortState::Listening => {
                pi.state = PortState::Learning;
                pi.transition_at = Some(now + fwd);
            }
            PortState::Learning => {
                pi.state = PortState::Forwarding;
                pi.transition_at = None;
                inst.changes += 1;
                moved_to_forwarding = true;
                out.log(format!(
                    "MSTP: {} {} now forwarding ({})",
                    label,
                    ports.get(i - 1).map(|p| p.name.as_str()).unwrap_or("?"),
                    pi.role.short()
                ));
            }
            _ => {
                pi.transition_at = None;
            }
        }
    }
    if moved_to_forwarding {
        set_tc(inst, now);
        if !msti {
            // A CIST topology change is also a topology change for the IST
            // and is propagated to the MSTIs by their TC flags.
            inst.tcn_tx = true;
        }
    }
}

/// Encode an action into an IEEE 802.1Q-2005 wire frame.
///
/// CIST and MSTI information is carried in one untagged MST BPDU regardless
/// of the egress port's access/trunk configuration.
pub fn encode_action(sw: &Switch, action: &Action) -> Vec<u8> {
    let Action::Send { port, bpdu } = action;
    if sw.port(*port).is_none() {
        return Vec::new();
    }
    packet::encode_stp(bpdu, sw.system_mac)
}

// Keep the imported names used by debug/CLI helpers.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MstConfig, PortMode, StpMode, Switch, Vlan, VlanSet};
    use crate::packet::MstConfigId;
    use std::path::PathBuf;

    fn sw_with_ports(n: usize) -> Switch {
        let mut sw = Switch::new(
            "sw",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/x"),
        );
        sw.features.portfast = true;
        for i in 1..=n {
            sw.add_port(&format!("eth{}", i));
            let p = sw.port_mut(i).unwrap();
            p.link_up = true;
            p.mode = PortMode::Trunk;
            p.trunk.allowed = VlanSet::all();
        }
        sync(&mut sw);
        sw
    }

    /// Opt a test bridge into MSTP (the product default is STP until the
    /// feature is enabled).
    fn enable_mstp(sw: &mut Switch) {
        sw.features.mstp = true;
        sw.stp_config.mode = StpMode::Mstp;
    }

    fn bpdu_from(root: BridgeId, cost: u32, bridge: BridgeId, port: u16, age: u16) -> Bpdu {
        Bpdu::config(
            root,
            cost,
            bridge,
            port,
            age,
            secs_to_timer(20),
            secs_to_timer(2),
            secs_to_timer(15),
        )
    }

    #[test]
    fn becomes_root_without_neighbours() {
        let mut sw = sw_with_ports(2);
        let now = Instant::now();
        let out = tick(&mut sw, now);
        let inst = sw.stp.instance().unwrap();
        assert!(inst.is_root);
        assert_eq!(inst.root_id, sw.bridge_id());
        // Designated ports start listening, not forwarding.
        assert_eq!(inst.port(1).unwrap().state, PortState::Listening);
        assert!(out
            .actions
            .iter()
            .any(|a| matches!(a, Action::Send { port: 1, .. })));
    }

    #[test]
    fn superior_bpdu_becomes_root_port() {
        let mut sw = sw_with_ports(2);
        let now = Instant::now();
        let upstream = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let rx = bpdu_from(upstream, 0, upstream, 0x8001, 0);
        let out = on_config(&mut sw, 1, &rx, now);
        assert!(out.events.iter().any(|e| e.contains("root port")));
        let inst = sw.stp.instance().unwrap();
        assert_eq!(inst.root_port, Some(1));
        assert_eq!(inst.root_id, upstream);
        assert_eq!(inst.port(1).unwrap().role, Role::Root);
        assert_eq!(inst.port(2).unwrap().role, Role::Designated);
    }

    #[test]
    fn inferior_bpdu_keeps_us_designated() {
        let mut sw = sw_with_ports(1);
        let now = Instant::now();
        let us = sw.bridge_id();
        let worse = BridgeId::new(40960, [0xbb; 6]);
        let rx = bpdu_from(worse, 4, worse, 0x8001, 0);
        let out = on_config(&mut sw, 1, &rx, now);
        let inst = sw.stp.instance().unwrap();
        assert_eq!(inst.root_id, us);
        assert_eq!(inst.port(1).unwrap().role, Role::Designated);
        // We should answer with our own superior BPDU.
        assert!(out
            .actions
            .iter()
            .any(|a| matches!(a, Action::Send { port: 1, .. })));
    }

    #[test]
    fn forwarding_after_two_forward_delays() {
        let mut sw = sw_with_ports(1);
        sw.stp.instance = None;
        let now = Instant::now();
        // Short timers for the test.
        sw.stp_config.forward_delay = 1;
        sync(&mut sw);
        let _ = recompute(&mut sw, now);
        assert_eq!(port_state(&sw, 1), PortState::Listening);
        let _ = tick(&mut sw, now + Duration::from_millis(1100));
        assert_eq!(port_state(&sw, 1), PortState::Learning);
        let _ = tick(&mut sw, now + Duration::from_millis(2300));
        assert_eq!(port_state(&sw, 1), PortState::Forwarding);
    }

    #[test]
    fn portfast_skips_timers() {
        let mut sw = sw_with_ports(1);
        sw.port_mut(1).unwrap().portfast = true;
        let now = Instant::now();
        sw.stp.instance = None;
        sync(&mut sw);
        let _ = recompute(&mut sw, now);
        assert_eq!(port_state(&sw, 1), PortState::Forwarding);
    }

    #[test]
    fn alternate_port_blocks() {
        let mut sw = sw_with_ports(2);
        let now = Instant::now();
        let upstream = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let rx = bpdu_from(upstream, 0, upstream, 0x8001, 0);
        let _ = on_config(&mut sw, 1, &rx, now);
        // A second, redundant link to the same root: same cost, but the
        // tie-break on the sender's port id makes this one an alternate.
        let rx2 = bpdu_from(upstream, 0, upstream, 0x8002, 0);
        let _ = on_config(&mut sw, 2, &rx2, now);
        assert_eq!(
            sw.stp.instance().unwrap().port(2).unwrap().role,
            Role::Alternate
        );
        assert_eq!(port_state(&sw, 2), PortState::Blocking);
    }

    #[test]
    fn bpdu_guard_err_disables_edge_port() {
        let mut sw = sw_with_ports(1);
        sw.features.bpdu_guard = true;
        sw.port_mut(1).unwrap().portfast = true;
        sw.port_mut(1).unwrap().bpduguard = true;
        let now = Instant::now();
        let upstream = BridgeId::new(32768, [0xaa; 6]);
        let rx = bpdu_from(upstream, 0, upstream, 0x8001, 0);
        let _ = on_config(&mut sw, 1, &rx, now);
        assert!(sw.port(1).unwrap().counters.err_disabled);
        assert!(!sw.is_forwarding(1, 1));
    }

    #[test]
    fn encode_mstp_bpdu_is_untagged_and_carries_msti() {
        let mut sw = sw_with_ports(1);
        enable_mstp(&mut sw);
        sw.port_mut(1).unwrap().mode = PortMode::Access;
        sw.mst.set_instance_vlans(1, VlanSet::parse("10,20").unwrap());
        sw.mst.ensure_instance(1).priority = 4096;
        sync(&mut sw);
        let now = Instant::now();
        let out = tick(&mut sw, now);
        let a = out
            .actions
            .iter()
            .find(|a| matches!(a, Action::Send { port: 1, .. }))
            .unwrap();
        let wire = encode_action(&sw, a);
        let f = packet::parse(&wire).unwrap();
        assert_eq!(f.dst, packet::MAC_STP);
        assert!(f.tag.is_none(), "MST BPDUs must be untagged");
        assert!(packet::is_bpdu(&f));
        let bpdu = packet::decode_bpdu(&f).unwrap();
        assert!(bpdu.is_mst());
        assert_eq!(bpdu.version, packet::BPDU_VERSION_MSTP);
        let mst = bpdu.mst.unwrap();
        assert_eq!(mst.config_id, sw.mst.config_id());
        assert_eq!(mst.msti.len(), 1);
        assert_eq!(mst.msti[0].mstid(), 1);
        assert_eq!(mst.msti[0].regional_root_id, sw.msti_bridge_id(1));
    }

    #[test]
    fn common_instance_covers_all_vlans() {
        let mut sw = Switch::new(
            "sw",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/x"),
        );
        sw.features.portfast = true;
        sw.add_port("eth1");
        sw.port_mut(1).unwrap().link_up = true;
        sw.port_mut(1).unwrap().portfast = true;
        sw.port_mut(1).unwrap().access_vlan = 10;
        sw.vlans.insert(10, Vlan::new(10));
        sync(&mut sw);
        assert!(sw.stp.instance().is_some(), "CIST instance");
        assert_eq!(sw.mst.mstid_for_vlan(10), 0);

        refresh(&mut sw);
        assert!(sw.is_forwarding(1, 10));
        assert_eq!(port_state(&sw, 1), PortState::Forwarding);
        assert_eq!(sw.bridge_id().priority(), 32768);
    }

    #[test]
    fn stp_disabled_has_no_instance() {
        let mut sw = sw_with_ports(1);
        sw.features.stp = false;
        sync(&mut sw);
        assert!(sw.stp.instance().is_none());
        assert!(sw.stp.mstis.is_empty());
        assert!(sw.is_forwarding(1, 1));
    }

    #[test]
    fn mst_configuration_digest_matches_standard_vectors() {
        let mut sw = sw_with_ports(1);
        // All VIDs in the CIST.
        assert_eq!(
            format_digest(&sw.mst.digest()),
            "AC36177F50283CD4B83821D8AB26DE62"
        );
        // All VIDs in MSTID 1.
        sw.mst.set_instance_vlans(1, VlanSet::all());
        assert_eq!(
            format_digest(&sw.mst.digest()),
            "E13A80F11ED0856ACD4EE3476941C73B"
        );
        // Every VID maps to (VID modulo 32) + 1.
        sw.mst.instances.clear();
        for id in 1..=32 {
            let mut set = VlanSet::none();
            for v in 1..=crate::model::MAX_VLAN_ID {
                if ((v % 32) + 1) == id {
                    set.insert(v);
                }
            }
            sw.mst.ensure_instance(id).vlans = set;
        }
        assert_eq!(
            format_digest(&sw.mst.digest()),
            "9D145C267DBE9FB5D893441BE3BA08CE"
        );
    }

    fn format_digest(d: &[u8; 16]) -> String {
        d.iter().map(|b| format!("{:02X}", b)).collect()
    }

    #[test]
    fn mstid_mapping_and_exclusivity() {
        let mut mst = MstConfig::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        mst.set_instance_vlans(1, VlanSet::parse("10-20").unwrap());
        mst.set_instance_vlans(2, VlanSet::parse("15,30").unwrap());
        assert_eq!(mst.mstid_for_vlan(10), 1);
        assert_eq!(mst.mstid_for_vlan(15), 2, "later allocation wins");
        assert_eq!(mst.mstid_for_vlan(20), 1);
        assert_eq!(mst.mstid_for_vlan(30), 2);
        assert_eq!(mst.mstid_for_vlan(40), 0);
        assert_eq!(mst.instances[&1].vlans.to_string(), "10-14,16-20");
    }

    #[test]
    fn msti_election_uses_regional_vectors() {
        let mut sw = sw_with_ports(2);
        enable_mstp(&mut sw);
        // Put both switches in the same region by construction; inject an
        // MST BPDU from a peer in the same region.
        sw.mst.set_instance_vlans(1, VlanSet::parse("10").unwrap());
        sync(&mut sw);
        let now = Instant::now();
        let peer_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let peer_bridge = BridgeId::new(32768, peer_mac);
        let peer_msti_bridge = BridgeId::new(4096 | 1, peer_mac);
        let msg = MstiMessage {
            flags: 0,
            regional_root_id: peer_msti_bridge,
            internal_root_path_cost: 0,
            bridge_priority: ((peer_msti_bridge.priority() >> 8) as u8) & 0xf0,
            port_priority: 0x80,
            remaining_hops: 20,
        };
        let bpdu = Bpdu {
            protocol_id: 0,
            version: BPDU_VERSION_MSTP,
            bpdu_type: BPDU_TYPE_RST,
            flags: 0,
            root_id: peer_bridge,
            root_path_cost: 0,
            bridge_id: peer_bridge,
            port_id: 0x8001,
            msg_age: 0,
            max_age: secs_to_timer(20),
            hello_time: secs_to_timer(2),
            forward_delay: secs_to_timer(15),
            version_1_length: 0,
            mst: Some(MstPayload {
                config_id: sw.mst.config_id(),
                internal_root_path_cost: 0,
                cist_bridge_id: peer_bridge,
                remaining_hops: 20,
                msti: vec![msg],
            }),
        };
        let _ = on_config(&mut sw, 1, &bpdu, now);
        let inst = sw.stp.msti(1).unwrap();
        assert_eq!(inst.root_id, peer_msti_bridge);
        assert_eq!(inst.root_port, Some(1));
        assert_eq!(inst.port(1).unwrap().role, Role::Root);
        assert_eq!(inst.port(2).unwrap().role, Role::Designated);
    }

    #[test]
    fn two_bridges_share_a_region_but_elect_different_cist_and_msti_roots() {
        fn region_switch(mac: [u8; 6]) -> Switch {
            let mut sw = Switch::new(
                "sw",
                mac,
                PathBuf::from("/tmp/opencode/switch-test/region"),
            );
            sw.features.portfast = true;
            for i in 1..=2 {
                sw.add_port(&format!("eth{}", i));
                let p = sw.port_mut(i).unwrap();
                p.link_up = true;
                p.mode = PortMode::Trunk;
                p.trunk.allowed = VlanSet::all();
            }
            sw.stp_config.forward_delay = 1;
            sw.stp_config.hello = 1;
            enable_mstp(&mut sw);
            sw.mst.name = "REGION".to_string();
            sw.mst.revision = 1;
            sw.mst.set_instance_vlans(1, VlanSet::parse("10").unwrap());
            sw
        }

        let mut sw1 = region_switch([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mut sw2 = region_switch([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        // CIST: sw2 wins.  MSTI 1: sw1 wins.
        sw1.stp_config.priority = 32768;
        sw2.stp_config.priority = 4096;
        sw1.mst.ensure_instance(1).priority = 4096;
        sw2.mst.ensure_instance(1).priority = 8192;
        sync(&mut sw1);
        sync(&mut sw2);

        let base = Instant::now();
        for round in 0..6u64 {
            let now = base + Duration::from_millis(round * 1100);
            let a = tick(&mut sw1, now);
            let b = tick(&mut sw2, now);
            for Action::Send { port, bpdu } in a.actions {
                let _ = on_config(&mut sw2, port, &bpdu, now);
            }
            for Action::Send { port, bpdu } in b.actions {
                let _ = on_config(&mut sw1, port, &bpdu, now);
            }
        }

        let cist2 = sw2.stp.instance().unwrap();
        assert!(cist2.is_root);
        assert_eq!(cist2.root_id, sw2.bridge_id());
        let cist1 = sw1.stp.instance().unwrap();
        assert!(!cist1.is_root);
        assert_eq!(cist1.root_id, sw2.bridge_id());
        assert!(cist1.root_port.is_some());

        let msti1_on_sw1 = sw1.stp.msti(1).unwrap();
        let msti1_on_sw2 = sw2.stp.msti(1).unwrap();
        assert!(msti1_on_sw1.is_root);
        assert_eq!(msti1_on_sw1.root_id, sw1.msti_bridge_id(1));
        assert_eq!(msti1_on_sw2.root_id, sw1.msti_bridge_id(1));
        assert!(msti1_on_sw2.root_port.is_some());
        assert_eq!(sw1.mst.digest(), sw2.mst.digest());
    }

    #[test]
    fn master_port_for_boundary_root() {
        let mut sw = sw_with_ports(2);
        enable_mstp(&mut sw);
        sw.mst.set_instance_vlans(1, VlanSet::parse("10").unwrap());
        sync(&mut sw);
        let now = Instant::now();
        // An STP BPDU from another region becomes the CIST root on port 1.
        let peer = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let rx = bpdu_from(peer, 0, peer, 0x8001, 0);
        let _ = on_config(&mut sw, 1, &rx, now);
        assert_eq!(sw.stp.instance().unwrap().root_port, Some(1));
        // Port 1 is a Master Port for MSTI 1 and forwards with the CIST.
        assert_eq!(port_role_mst(&sw, 1, 1), Some(Role::Master));
        // Port 2 is designated for the MSTI and is not blocked by the CIST.
        assert_eq!(port_role_mst(&sw, 2, 1), Some(Role::Designated));
        assert_eq!(port_state_mst(&sw, 2, 1), PortState::Listening);
    }

    #[test]
    fn per_vlan_forwarding_uses_msti_state() {
        let mut sw = sw_with_ports(2);
        enable_mstp(&mut sw);
        sw.mst.set_instance_vlans(1, VlanSet::parse("10").unwrap());
        sw.vlans.insert(10, Vlan::new(10));
        sw.vlans.insert(20, Vlan::new(20));
        for p in sw.ports.iter_mut() {
            p.portfast = true;
        }
        sync(&mut sw);
        let now = Instant::now();
        let _ = recompute(&mut sw, now);
        assert!(sw.is_forwarding(1, 20));
        // Force the MSTI to block while the CIST forwards.
        if let Some(inst) = sw.stp.mstis.get_mut(&1) {
            inst.ports[1].state = PortState::Blocking;
        }
        assert!(sw.is_forwarding(1, 20), "CIST-mapped VLAN still forwards");
        assert!(!sw.is_forwarding(1, 10), "MSTI-mapped VLAN is blocked");
    }

    #[test]
    fn mst_config_id_roundtrip() {
        let id = MstConfigId::new("region-a", 7, [0xab; 16]);
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), 51);
        assert_eq!(bytes[0], 0);
        let decoded = MstConfigId::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, id);
        assert_eq!(decoded.name_str(), "region-a");
    }
    #[test]
    fn listening_port_without_a_timer_is_rearmed() {
        // A mirrored boundary transition can copy the CIST Listening state
        // without a timer of its own (13.12(e)).  Once the port becomes a
        // normal designated port, the timer must be re-armed or it would stay
        // in Listening forever.
        let mut pi = PortInfo::default();
        pi.state = PortState::Listening;
        pi.transition_at = None;
        let now = Instant::now();
        let fwd = Duration::from_secs(15);
        update_forwarding(&mut pi, true, false, fwd, now);
        assert_eq!(pi.state, PortState::Listening);
        assert_eq!(pi.transition_at, Some(now + fwd));
    }

}
