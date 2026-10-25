//! IEEE 802.1AB LLDP (Link Layer Discovery Protocol).
//!
//! Implements single-frame LLDPDUs as specified by IEEE 802.1AB-2026: the
//! mandatory Chassis ID, Port ID, Time To Live and End TLVs plus the optional
//! port/system description, system capabilities and management address TLVs.
//! The 2021/2026 multiframe and YANG additions are management/extensions and
//! are deliberately out of scope.
//!
//! LLDP is strictly link-local: frames are consumed on ingress, never learned,
//! flooded or forwarded, and they are accepted regardless of STP state.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dataplane::Io;
use crate::model::{Port, Switch};
use crate::packet::{self, L2Frame};

/// LLDP EtherType.
pub const ETHERTYPE_LLDP: u16 = 0x88cc;
/// "Nearest bridge" LLDP multicast destination.
pub const MAC_LLDP: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];

pub const TX_INTERVAL_SECS: u16 = 30;
pub const TX_HOLD: u16 = 4;
/// Initial burst of advertisements, one per second.
pub const FAST_START_COUNT: u8 = 4;

const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESC: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESC: u8 = 6;
const TLV_SYSTEM_CAPS: u8 = 7;
const TLV_MGMT_ADDR: u8 = 8;

const CAP_BRIDGE: u16 = 0x0004;

// ---------------------------------------------------------------------------
// Identifiers and decoded LLDPDU
// ---------------------------------------------------------------------------

/// A chassis or port identifier: a one-byte subtype plus its raw value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LldpId {
    pub subtype: u8,
    pub value: Vec<u8>,
}

impl LldpId {
    fn new(subtype: u8, value: &[u8]) -> Self {
        LldpId {
            subtype,
            value: value.to_vec(),
        }
    }

    /// Human-readable chassis ID. Subtype 4 is a MAC address; the textual
    /// subtypes are rendered as UTF-8 and everything else as hex.
    pub fn chassis_text(&self) -> String {
        match self.subtype {
            4 if self.value.len() == 6 => mac_text(&self.value),
            1 | 2 | 3 | 5 | 6 | 7 => text_value(&self.value),
            _ => hex(&self.value),
        }
    }

    /// Human-readable port ID. For port IDs subtype 3 (not 4) is a MAC
    /// address; subtype 5/6/7 are textual.
    pub fn port_text(&self) -> String {
        match self.subtype {
            3 if self.value.len() == 6 => mac_text(&self.value),
            1 | 2 | 5 | 6 | 7 => text_value(&self.value),
            _ => hex(&self.value),
        }
    }

    pub fn chassis_subtype_name(&self) -> &'static str {
        match self.subtype {
            1 => "chassis component",
            2 => "interface alias",
            3 => "port component",
            4 => "MAC address",
            5 => "network address",
            6 => "interface name",
            7 => "locally assigned",
            _ => "unknown",
        }
    }

    pub fn port_subtype_name(&self) -> &'static str {
        match self.subtype {
            1 => "interface alias",
            2 => "port component",
            3 => "MAC address",
            4 => "network address",
            5 => "interface name",
            6 => "agent circuit ID",
            7 => "locally assigned",
            _ => "unknown",
        }
    }
}

/// A validated, single-frame LLDPDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lldpdu {
    pub chassis: LldpId,
    pub port: LldpId,
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities: u16,
    pub enabled_capabilities: u16,
    pub management_addresses: Vec<String>,
}

fn mac_text(bytes: &[u8]) -> String {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(bytes);
    packet::format_mac(mac)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

fn text_value(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .trim_end_matches('\0')
        .to_string()
}

/// Encode one TLV. Values longer than 511 octets are truncated to the
/// 9-bit length field; LLDPDU construction keeps them well below that.
fn write_tlv(out: &mut Vec<u8>, typ: u8, value: &[u8]) {
    let value = &value[..value.len().min(511)];
    let header = (((typ as u16) & 0x7f) << 9) | value.len() as u16;
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
}

/// Build the LLDPDU advertised on `port`.
pub fn encode(sw: &Switch, port: &Port) -> Vec<u8> {
    let mut du = Vec::with_capacity(128);

    let mut chassis = vec![4u8]; // MAC address subtype
    chassis.extend_from_slice(&sw.system_mac);
    write_tlv(&mut du, TLV_CHASSIS_ID, &chassis);

    let mut port_id = vec![5u8]; // interface name subtype
    port_id.extend_from_slice(port.ifname.as_bytes());
    write_tlv(&mut du, TLV_PORT_ID, &port_id);

    write_tlv(&mut du, TLV_TTL, &sw.lldp.ttl().to_be_bytes());

    if !port.description.is_empty() {
        write_tlv(&mut du, TLV_PORT_DESC, port.description.as_bytes());
    }
    write_tlv(&mut du, TLV_SYSTEM_NAME, sw.hostname.as_bytes());
    write_tlv(&mut du, TLV_SYSTEM_DESC, sw.version.as_bytes());

    let mut caps = Vec::with_capacity(4);
    caps.extend_from_slice(&CAP_BRIDGE.to_be_bytes());
    caps.extend_from_slice(&CAP_BRIDGE.to_be_bytes());
    write_tlv(&mut du, TLV_SYSTEM_CAPS, &caps);

    write_tlv(&mut du, TLV_END, &[]);
    du
}

/// Build a complete untagged Ethernet frame carrying the port's LLDPDU.
pub fn frame(sw: &Switch, port: &Port) -> Vec<u8> {
    let du = encode(sw, port);
    packet::pad(packet::build(
        MAC_LLDP,
        sw.system_mac,
        None,
        ETHERTYPE_LLDP,
        &du,
    ))
}

fn parse_id(value: &[u8]) -> Result<LldpId, &'static str> {
    if value.len() < 2 {
        return Err("identifier TLV too short");
    }
    Ok(LldpId::new(value[0], &value[1..]))
}

fn parse_management_address(value: &[u8]) -> Option<String> {
    // address-string-length (1), then that many octets: address-subtype (1)
    // plus the address itself, followed by ifindex (4) and OID length (1+).
    if value.len() < 2 {
        return None;
    }
    let alen = value[0] as usize;
    if alen < 1 || 1 + alen > value.len() {
        return None;
    }
    let subtype = value[1];
    let addr = &value[2..1 + alen];
    Some(match (subtype, addr.len()) {
        (1, 4) => format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
        (2, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(addr);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        (6, 6) => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(addr);
            packet::format_mac(mac)
        }
        _ => hex(addr),
    })
}

/// Decode and validate an LLDPDU. Unknown and organisational TLVs are
/// ignored; the four mandatory TLVs must be present.
pub fn decode(payload: &[u8]) -> Result<Lldpdu, &'static str> {
    let mut off = 0usize;
    let mut chassis: Option<LldpId> = None;
    let mut port: Option<LldpId> = None;
    let mut ttl: Option<u16> = None;
    let mut port_description = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut capabilities = 0u16;
    let mut enabled_capabilities = 0u16;
    let mut management_addresses = Vec::new();
    let mut ended = false;

    while off + 2 <= payload.len() {
        let header = u16::from_be_bytes([payload[off], payload[off + 1]]);
        let typ = (header >> 9) as u8;
        let len = (header & 0x01ff) as usize;
        off += 2;
        if off + len > payload.len() {
            return Err("TLV length overruns LLDPDU");
        }
        let value = &payload[off..off + len];
        off += len;

        if typ == TLV_END {
            if len != 0 {
                return Err("end TLV has a non-zero length");
            }
            ended = true;
            break;
        }

        match typ {
            TLV_CHASSIS_ID => chassis = Some(parse_id(value)?),
            TLV_PORT_ID => port = Some(parse_id(value)?),
            TLV_TTL => {
                if len != 2 {
                    return Err("TTL TLV must be two octets");
                }
                ttl = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            TLV_PORT_DESC => port_description = Some(text_value(value)),
            TLV_SYSTEM_NAME => system_name = Some(text_value(value)),
            TLV_SYSTEM_DESC => system_description = Some(text_value(value)),
            TLV_SYSTEM_CAPS => {
                if len != 4 {
                    return Err("system capabilities TLV must be four octets");
                }
                capabilities = u16::from_be_bytes([value[0], value[1]]);
                enabled_capabilities = u16::from_be_bytes([value[2], value[3]]);
            }
            TLV_MGMT_ADDR => {
                if let Some(address) = parse_management_address(value) {
                    management_addresses.push(address);
                }
            }
            _ => {} // unknown, organisational (LLDP-MED, ...) or reserved
        }
    }

    if !ended {
        return Err("missing end TLV");
    }
    let chassis = chassis.ok_or("missing chassis ID TLV")?;
    let port = port.ok_or("missing port ID TLV")?;
    let ttl = ttl.ok_or("missing TTL TLV")?;

    Ok(Lldpdu {
        chassis,
        port,
        ttl,
        port_description,
        system_name,
        system_description,
        capabilities,
        enabled_capabilities,
        management_addresses,
    })
}

// ---------------------------------------------------------------------------
// Neighbour and per-port state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LldpNeighbor {
    pub chassis: LldpId,
    pub port: LldpId,
    pub ttl: u16,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
    pub capabilities: u16,
    pub enabled_capabilities: u16,
    pub management_addresses: Vec<String>,
    pub last_seen: Instant,
}

impl LldpNeighbor {
    pub fn system_label(&self) -> String {
        match &self.system_name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => self.chassis.chassis_text(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LldpPort {
    pub neighbor: Option<LldpNeighbor>,
    /// When the next advertisement is due; `None` means "send at the next tick".
    pub next_tx: Option<Instant>,
    /// Remaining one-second fast-start advertisements.
    pub fast_left: u8,
    pub tx_frames: u64,
    pub rx_frames: u64,
    pub rx_errors: u64,
    pub ageouts: u64,
}

#[derive(Debug)]
pub struct LldpState {
    pub tx_interval: u16,
    pub hold: u16,
    pub ports: HashMap<usize, LldpPort>,
}

impl Default for LldpState {
    fn default() -> Self {
        LldpState {
            tx_interval: TX_INTERVAL_SECS,
            hold: TX_HOLD,
            ports: HashMap::new(),
        }
    }
}

impl LldpState {
    /// Transmit TTL = message tx interval × hold multiplier.
    pub fn ttl(&self) -> u16 {
        self.tx_interval.saturating_mul(self.hold)
    }

    pub fn port(&self, index: usize) -> Option<&LldpPort> {
        self.ports.get(&index)
    }

    pub fn neighbor_count(&self) -> usize {
        self.ports.values().filter(|p| p.neighbor.is_some()).count()
    }

    pub fn total_tx(&self) -> u64 {
        self.ports.values().map(|p| p.tx_frames).sum()
    }

    pub fn total_rx(&self) -> u64 {
        self.ports.values().map(|p| p.rx_frames).sum()
    }

    pub fn total_errors(&self) -> u64 {
        self.ports.values().map(|p| p.rx_errors).sum()
    }

    pub fn total_ageouts(&self) -> u64 {
        self.ports.values().map(|p| p.ageouts).sum()
    }

    pub fn clear(&mut self) {
        self.ports.clear();
    }
}

/// A link just came up: clear stale state and advertise immediately.
pub fn link_up(sw: &mut Switch, port: usize, now: Instant) {
    if !sw.features.lldp {
        return;
    }
    let state = sw.lldp.ports.entry(port).or_default();
    state.neighbor = None;
    state.fast_left = FAST_START_COUNT;
    state.next_tx = Some(now);
}

/// A link went down: its neighbour is no longer reachable.
pub fn link_down(sw: &mut Switch, port: usize) {
    if let Some(state) = sw.lldp.ports.get_mut(&port) {
        state.neighbor = None;
        state.next_tx = None;
        state.fast_left = 0;
    }
}

/// Consume one received LLDP frame. LLDP frames are never forwarded.
pub fn on_frame(sw: &mut Switch, port: usize, frame: &L2Frame<'_>, now: Instant) {
    if frame.ethertype != ETHERTYPE_LLDP {
        return;
    }
    let local = sw
        .port(port)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| port.to_string());

    let decoded = match decode(frame.payload) {
        Ok(d) => d,
        Err(_) => {
            let state = sw.lldp.ports.entry(port).or_default();
            state.rx_frames += 1;
            state.rx_errors += 1;
            return;
        }
    };

    let state = sw.lldp.ports.entry(port).or_default();
    state.rx_frames += 1;

    if decoded.ttl == 0 {
        // Shutdown LLDPDU: withdraw the neighbour.
        let had = state.neighbor.take().is_some();
        if had {
            sw.log_line(&format!("LLDP: neighbor on {} withdrawn", local));
        }
        return;
    }

    let neighbor = LldpNeighbor {
        chassis: decoded.chassis,
        port: decoded.port,
        ttl: decoded.ttl,
        system_name: decoded.system_name,
        system_description: decoded.system_description,
        port_description: decoded.port_description,
        capabilities: decoded.capabilities,
        enabled_capabilities: decoded.enabled_capabilities,
        management_addresses: decoded.management_addresses,
        last_seen: now,
    };

    let changed = match &state.neighbor {
        Some(old) => {
            old.chassis != neighbor.chassis
                || old.port != neighbor.port
                || old.system_name != neighbor.system_name
        }
        None => true,
    };
    let msg = if changed {
        Some(format!(
            "LLDP: neighbor {} on {} ({} via {})",
            neighbor.system_label(),
            local,
            neighbor.port.port_text(),
            neighbor.chassis.chassis_text()
        ))
    } else {
        None
    };
    state.neighbor = Some(neighbor);
    if let Some(msg) = msg {
        sw.log_line(&msg);
    }
}

/// Advertise on every operational port and age out silent neighbours.
pub fn tick(sw: &mut Switch, io: &Io, now: Instant) {
    if !sw.features.lldp {
        return;
    }

    let ports: Vec<usize> = sw
        .ports
        .iter()
        .filter(|p| p.oper_up())
        .map(|p| p.index)
        .collect();

    for index in ports {
        let due = match sw.lldp.port(index).and_then(|p| p.next_tx) {
            Some(at) => now >= at,
            None => true,
        };
        if !due {
            continue;
        }
        let Some(port) = sw.port(index) else {
            continue;
        };
        let wire = frame(sw, port);
        io.send(index, &wire);
        if let Some(port) = sw.port_mut(index) {
            port.counters.tx_packets += 1;
            port.counters.tx_bytes += wire.len() as u64;
        }

        let interval = sw.lldp.tx_interval;
        let state = sw.lldp.ports.entry(index).or_default();
        if state.tx_frames == 0 && state.next_tx.is_none() {
            // First advertisement on this port starts the fast-start burst.
            state.fast_left = FAST_START_COUNT;
        }
        state.tx_frames += 1;
        if state.fast_left > 0 {
            state.fast_left -= 1;
            state.next_tx = Some(now + Duration::from_secs(1));
        } else {
            state.next_tx = Some(now + Duration::from_secs(interval as u64));
        }
    }

    age(sw, now);
}

fn age(sw: &mut Switch, now: Instant) {
    let mut expired = Vec::new();
    for (index, state) in sw.lldp.ports.iter_mut() {
        let Some(neighbor) = &state.neighbor else {
            continue;
        };
        let deadline = Duration::from_secs(neighbor.ttl as u64);
        if now.saturating_duration_since(neighbor.last_seen) >= deadline {
            state.neighbor = None;
            state.ageouts += 1;
            expired.push(*index);
        }
    }
    for index in expired {
        let local = sw
            .port(index)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| index.to_string());
        sw.log_line(&format!("LLDP: neighbor on {} aged out", local));
    }
}

/// Describe capability bits as a comma-separated list.
pub fn capabilities_text(bits: u16) -> String {
    const NAMES: &[(u16, &str)] = &[
        (0x0001, "other"),
        (0x0002, "repeater"),
        (0x0004, "bridge"),
        (0x0008, "wlan-ap"),
        (0x0010, "router"),
        (0x0020, "telephone"),
        (0x0040, "docsis"),
        (0x0080, "station"),
        (0x0100, "cvlan"),
        (0x0200, "svlan"),
        (0x0400, "tpmr"),
    ];
    let mut out = Vec::new();
    for &(bit, name) in NAMES {
        if bits & bit != 0 {
            out.push(name);
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Switch;
    use std::path::PathBuf;

    fn test_switch(name: &str, mac: [u8; 6]) -> Switch {
        let mut sw = Switch::new(
            name,
            mac,
            PathBuf::from("/tmp/opencode/switch-test/startup"),
        );
        sw.features.lldp = true;
        sw.add_port("eth1");
        sw.add_port("eth2");
        for p in sw.ports.iter_mut() {
            p.link_up = true;
        }
        sw
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sw = test_switch("sw1", [0x02, 0, 0, 0, 0, 0x0a]);
        let du = encode(&sw, sw.port(1).unwrap());
        let decoded = decode(&du).unwrap();
        assert_eq!(decoded.chassis.subtype, 4);
        assert_eq!(decoded.chassis.value, vec![0x02, 0, 0, 0, 0, 0x0a]);
        assert_eq!(decoded.port.subtype, 5);
        assert_eq!(decoded.port.value, b"eth1".to_vec());
        assert_eq!(decoded.ttl, 120);
        assert_eq!(decoded.system_name.as_deref(), Some("sw1"));
        assert_eq!(decoded.capabilities & CAP_BRIDGE, CAP_BRIDGE);
        assert_eq!(decoded.enabled_capabilities & CAP_BRIDGE, CAP_BRIDGE);

        let wire = frame(&sw, sw.port(1).unwrap());
        assert_eq!(&wire[0..6], &MAC_LLDP);
        assert_eq!(u16::from_be_bytes([wire[12], wire[13]]), ETHERTYPE_LLDP);
        assert!(wire.len() >= 60);
        let parsed = packet::parse(&wire).unwrap();
        assert_eq!(parsed.ethertype, ETHERTYPE_LLDP);
        assert_eq!(decode(parsed.payload).unwrap(), decoded);
    }

    #[test]
    fn rejects_malformed_llldpdu() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0, 0]).is_err(), "missing mandatory TLVs");
        // Truncated TLV length.
        assert!(decode(&[0x02, 0x07, 0x04, 0x02]).is_err());
        // End TLV with a payload.
        let sw = test_switch("sw1", [2, 0, 0, 0, 0, 1]);
        let mut du = encode(&sw, sw.port(1).unwrap());
        let end = du.len() - 2;
        du[end + 1] = 1;
        assert!(decode(&du).is_err());
    }

    #[test]
    fn tick_sends_immediately_then_fast_start() {
        let io = Io::capture();
        let mut sw = test_switch("sw1", [0x02, 0, 0, 0, 0, 0x0a]);
        let now = Instant::now();
        tick(&mut sw, &io, now);
        let frames = io.take_captured();
        assert_eq!(frames.len(), 2, "one advertisement per operational port");
        for (_, wire) in &frames {
            assert_eq!(&wire[0..6], &MAC_LLDP);
        }

        // Next advertisement is one second later (fast start).
        tick(&mut sw, &io, now + Duration::from_millis(500));
        assert!(io.take_captured().is_empty());
        tick(&mut sw, &io, now + Duration::from_secs(1));
        assert_eq!(io.take_captured().len(), 2);
    }

    #[test]
    fn neighbor_is_learned_and_aged() {
        let io = Io::capture();
        let mut local = test_switch("sw1", [0x02, 0, 0, 0, 0, 0x0a]);
        let peer = test_switch("sw2", [0x02, 0, 0, 0, 0, 0x0b]);
        // Advertise eth2 from the peer and give it a short TTL.
        let mut peer = peer;
        peer.lldp.tx_interval = 1;
        peer.lldp.hold = 2;
        let wire = frame(&peer, peer.port(2).unwrap());
        let parsed = packet::parse(&wire).unwrap();
        let now = Instant::now();
        on_frame(&mut local, 1, &parsed, now);

        let n = local.lldp.port(1).unwrap().neighbor.as_ref().unwrap();
        assert_eq!(n.system_name.as_deref(), Some("sw2"));
        assert_eq!(n.port.port_text(), "eth2");
        assert_eq!(n.ttl, 2);
        assert_eq!(local.lldp.neighbor_count(), 1);
        // LLDP must not create a MAC table entry.
        assert!(local
            .mac_table
            .lookup(1, [0x02, 0, 0, 0, 0, 0x0b])
            .is_none());

        tick(&mut local, &io, now + Duration::from_secs(1));
        assert_eq!(local.lldp.neighbor_count(), 1);
        tick(&mut local, &io, now + Duration::from_secs(2));
        assert_eq!(local.lldp.neighbor_count(), 0);
        assert_eq!(local.lldp.total_ageouts(), 1);
    }

    #[test]
    fn ttl_zero_withdraws_neighbor() {
        let mut local = test_switch("sw1", [0x02, 0, 0, 0, 0, 0x0a]);
        let peer = test_switch("sw2", [0x02, 0, 0, 0, 0, 0x0b]);
        let mut wire = frame(&peer, peer.port(1).unwrap());
        let parsed = packet::parse(&wire).unwrap();
        on_frame(&mut local, 1, &parsed, Instant::now());
        assert_eq!(local.lldp.neighbor_count(), 1);

        // Rewrite the TTL TLV in the LLDPDU to zero and re-wrap the frame.
        fn ttl_value_offset(du: &[u8]) -> usize {
            let mut off = 0;
            while off + 2 <= du.len() {
                let typ = du[off] >> 1;
                let len = (((du[off] as usize) & 1) << 8) | du[off + 1] as usize;
                if typ == TLV_TTL {
                    return off + 2;
                }
                off += 2 + len;
            }
            panic!("no TTL TLV");
        }
        let mut du = encode(&peer, peer.port(1).unwrap());
        let offset = ttl_value_offset(&du);
        du[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
        wire = packet::pad(packet::build(
            MAC_LLDP,
            peer.system_mac,
            None,
            ETHERTYPE_LLDP,
            &du,
        ));
        let parsed = packet::parse(&wire).unwrap();
        on_frame(&mut local, 1, &parsed, Instant::now());
        assert_eq!(local.lldp.neighbor_count(), 0);
    }

    #[test]
    fn management_addresses_and_mac_port_id() {
        // Layout captured from lldpd 1.0.17: MAC port ID plus IPv4 and IPv6
        // management addresses (including the interface-number fields).
        let mut du = Vec::new();
        write_tlv(
            &mut du,
            TLV_CHASSIS_ID,
            &[4, 0xaa, 0xc1, 0xab, 0x9a, 0x7d, 0x24],
        );
        write_tlv(
            &mut du,
            TLV_PORT_ID,
            &[3, 0xaa, 0xc1, 0xab, 0x9a, 0x7d, 0x24],
        );
        write_tlv(&mut du, TLV_TTL, &120u16.to_be_bytes());
        write_tlv(
            &mut du,
            TLV_MGMT_ADDR,
            &[
                0x05, 0x01, 0xac, 0x14, 0x14, 0x02, 0x02, 0, 0, 0, 0x02, 0x00,
            ],
        );
        write_tlv(
            &mut du,
            TLV_MGMT_ADDR,
            &[
                0x11, 0x02, 0x20, 0x01, 0x01, 0x72, 0x00, 0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x02, 0, 0, 0, 0x02, 0x00,
            ],
        );
        write_tlv(&mut du, TLV_END, &[]);

        let decoded = decode(&du).unwrap();
        assert_eq!(decoded.port.port_text(), "aac1.ab9a.7d24");
        assert_eq!(
            decoded.management_addresses,
            vec!["172.20.20.2", "2001:172:20:20::2"]
        );
    }

    #[test]
    fn capabilities_render() {
        assert_eq!(capabilities_text(0), "none");
        assert_eq!(capabilities_text(CAP_BRIDGE), "bridge");
        assert_eq!(capabilities_text(CAP_BRIDGE | 0x0080), "bridge, station");
    }
}
