//! Ethernet II / IEEE 802.3, IEEE 802.1Q-2005, LLC/SNAP and STP BPDU
//! encoding/decoding.
//!
//! Frames are decoded once on ingress into an [`L2Frame`] that borrows the
//! receive buffer.  Inside the switch a frame is represented by its untagged
//! header plus an optional VLAN tag; tags are added again on trunk egress.
//!
//! Spanning-tree wire formats are the standards-based IEEE 802.1D
//! configuration/TCN BPDUs, RST BPDUs, and IEEE 802.1Q-2005 MST BPDUs
//! (Figure 14-1) used by an MST Bridge.  Cisco PVST+ framing
//! (01:00:0c:cc:cc:cd + SNAP 00:00:0c:01:0b) is deliberately not supported.

use std::fmt;

#[allow(dead_code)] // used by tests and by callers building broadcast frames
pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];
/// IEEE 802.1D BPDU destination (used by the 802.1Q common spanning tree).
pub const MAC_STP: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];

/// IEEE 802.1D reserved multicast range (01:80:C2:00:00:00 .. 0F).
pub fn is_reserved_multicast(mac: &[u8; 6]) -> bool {
    mac[0] == 0x01
        && mac[1] == 0x80
        && mac[2] == 0xc2
        && mac[3] == 0
        && mac[4] == 0
        && mac[5] <= 0x0f
}

/// IEEE 802.1Q VLAN tag protocol identifier.
pub const VLAN_TPID: u16 = 0x8100;
#[allow(dead_code)]
pub const ETHERTYPE_IPV4: u16 = 0x0800;
#[allow(dead_code)]
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const VLAN_VID_MASK: u16 = 0x0fff;
pub const VLAN_PCP_MASK: u16 = 0xe000;
pub const VLAN_DEI_MASK: u16 = 0x1000;
/// Largest usable VLAN identifier (802.1Q-2005, 12-bit VID).
pub const VLAN_VID_MAX: u16 = 4094;
/// 0xFFF is reserved by IEEE 802.1Q-2005 and must never be used as a VLAN.
pub const VLAN_VID_RESERVED: u16 = 4095;
/// VID 0 denotes a priority-tagged frame; the PVID supplies the VLAN.
pub const VLAN_VID_PRIORITY_TAG: u16 = 0;

pub const LLC_DSAP_STP: u8 = 0x42;
pub const LLC_SSAP_STP: u8 = 0x42;
pub const LLC_CONTROL_UI: u8 = 0x03;

pub const BPDU_TYPE_CONFIG: u8 = 0x00;
pub const BPDU_TYPE_RST: u8 = 0x02;
pub const BPDU_TYPE_TCN: u8 = 0x80;

/// CIST flags (IEEE 802.1Q-2005, 14.6).  The same bit positions carry the
/// per-MSTI flags in an MSTI Configuration Message, except that bit 8 is the
/// Master flag there instead of Topology Change Acknowledge.
pub const BPDU_FLAG_TC: u8 = 0x01;
pub const BPDU_FLAG_PROPOSAL: u8 = 0x02;
#[allow(dead_code)] // part of the documented flag layout
pub const BPDU_FLAG_ROLE_MASK: u8 = 0x0c;
pub const BPDU_FLAG_ROLE_SHIFT: u8 = 2;
pub const BPDU_FLAG_LEARNING: u8 = 0x10;
pub const BPDU_FLAG_FORWARDING: u8 = 0x20;
#[allow(dead_code)] // part of the documented flag layout
pub const BPDU_FLAG_AGREEMENT: u8 = 0x40;
pub const BPDU_FLAG_TCACK: u8 = 0x80;
/// MSTI flags use bit 8 for the Master flag.
pub const BPDU_FLAG_MASTER: u8 = 0x80;

pub const BPDU_VERSION_STP: u8 = 0x00;
pub const BPDU_VERSION_RSTP: u8 = 0x02;
pub const BPDU_VERSION_MSTP: u8 = 0x03;

/// Number of octets in the fixed MST BPDU header (through the CIST remaining
/// hops field), including the Version 3 Length itself.
pub const MST_BPDU_BASE_LEN: usize = 102;
/// Number of octets in one MSTI Configuration Message.
pub const MSTI_MESSAGE_LEN: usize = 16;
/// Maximum number of MSTIs carried in one MST BPDU (802.1Q-2005, 13.14).
pub const MST_MAX_INSTANCES: u16 = 64;

/// Fixed key from IEEE 802.1Q-2005 Table 13-1.
pub const MST_CONFIG_DIGEST_KEY: [u8; 16] = [
    0x13, 0xAC, 0x06, 0xA6, 0x2E, 0x47, 0xFD, 0x51, 0xF9, 0x5D, 0x2B, 0xA2, 0x43, 0xCD, 0x03,
    0x46,
];

pub const TIMER_SCALE: u32 = 256;

/// An IEEE 802.1Q tag control information field.
///
/// ```text
///   bits 15..13  priority code point (PCP)
///   bit  12      drop eligible indicator (DEI, formerly CFI)
///   bits 11..0   VLAN identifier (VID)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct VlanTag {
    pub pcp: u8,
    pub dei: bool,
    pub vid: u16,
}

impl VlanTag {
    pub const fn new(vid: u16) -> Self {
        VlanTag {
            pcp: 0,
            dei: false,
            vid,
        }
    }

    pub const fn with_pcp(vid: u16, pcp: u8, dei: bool) -> Self {
        VlanTag { pcp, dei, vid }
    }

    /// Decode a 16-bit tag control information field.
    pub fn from_tci(tci: u16) -> Self {
        VlanTag {
            pcp: ((tci & VLAN_PCP_MASK) >> 13) as u8,
            dei: tci & VLAN_DEI_MASK != 0,
            vid: tci & VLAN_VID_MASK,
        }
    }

    /// Encode the tag control information field.
    pub fn tci(&self) -> u16 {
        ((self.pcp as u16 & 0x7) << 13)
            | (if self.dei { VLAN_DEI_MASK } else { 0 })
            | (self.vid & VLAN_VID_MASK)
    }

    /// A priority-tagged frame carries no VLAN identifier; the port PVID
    /// supplies the VLAN for forwarding.
    pub fn is_priority_tag(&self) -> bool {
        self.vid == VLAN_VID_PRIORITY_TAG
    }

    /// VID 4095 is reserved and must be discarded by a VLAN bridge.
    pub fn is_reserved(&self) -> bool {
        self.vid == VLAN_VID_RESERVED
    }
}

/// Convert whole seconds to the 1/256 s units used in BPDUs.
pub fn secs_to_timer(secs: u16) -> u16 {
    (secs as u32 * TIMER_SCALE).min(u16::MAX as u32) as u16
}

/// Convert a BPDU timer value to whole seconds (rounded down, minimum 1).
/// Used by the protocol unit tests; runtime code keeps timers in seconds.
#[cfg(test)]
pub fn timer_to_secs(timer: u16) -> u16 {
    ((timer as u32) / TIMER_SCALE).max(1) as u16
}

/// Convert a BPDU timer value to a `Duration` (rounded up).
pub fn timer_to_duration(timer: u16) -> std::time::Duration {
    let ms = (timer as u64 * 1000 + TIMER_SCALE as u64 - 1) / TIMER_SCALE as u64;
    std::time::Duration::from_millis(ms)
}

pub fn mac_to_u64(mac: [u8; 6]) -> u64 {
    let mut v = 0u64;
    for b in mac {
        v = (v << 8) | b as u64;
    }
    v
}

pub fn u64_to_mac(v: u64) -> [u8; 6] {
    [
        ((v >> 40) & 0xff) as u8,
        ((v >> 32) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ]
}

/// Parse a MAC address in `aabb.ccdd.eeff` or `aa:bb:cc:dd:ee:ff` form.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// 8-byte bridge identifier: 2-byte priority followed by the 6-byte MAC.
///
/// IEEE 802.1Q-2005 allocates the low 12 bits of the priority field as the
/// system ID extension: zero for the CIST and the MSTID for an MSTI.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct BridgeId(pub u64);

impl BridgeId {
    pub fn new(priority: u16, mac: [u8; 6]) -> Self {
        BridgeId(((priority as u64) << 48) | mac_to_u64(mac))
    }

    pub fn priority(&self) -> u16 {
        (self.0 >> 48) as u16
    }

    pub fn mac(&self) -> [u8; 6] {
        u64_to_mac(self.0)
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        Some(BridgeId(u64::from_be_bytes(a)))
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.mac();
        write!(
            f,
            "{:04x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            self.priority(),
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        )
    }
}

impl fmt::Debug for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A decoded (untagged view of a) layer-2 frame.
#[derive(Clone, Copy, Debug)]
pub struct L2Frame<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// IEEE 802.1Q tag if the frame arrived tagged.  VID 0 means
    /// priority-tagged; the PVID supplies the forwarding VLAN.
    pub tag: Option<VlanTag>,
    /// EtherType, or the 802.3 length when the value is <= 1500.
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> L2Frame<'a> {
    pub fn is_8023(&self) -> bool {
        self.ethertype <= 1500
    }

    /// VLAN identifier carried in the tag, if any.
    /// Convenience accessor used by tests and diagnostics.
    #[allow(dead_code)]
    pub fn vlan(&self) -> Option<u16> {
        self.tag.map(|t| t.vid)
    }

    /// PCP/DEI of a tagged frame (zero for untagged frames).
    /// Convenience accessor used by tests and diagnostics.
    #[allow(dead_code)]
    pub fn priority(&self) -> (u8, bool) {
        match self.tag {
            Some(t) => (t.pcp, t.dei),
            None => (0, false),
        }
    }
}

/// Parse an Ethernet frame, transparently unwrapping a single 802.1Q tag.
pub fn parse(data: &[u8]) -> Option<L2Frame<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);

    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    let mut tag = None;
    if ethertype == VLAN_TPID {
        if data.len() < 18 {
            return None;
        }
        let tci = u16::from_be_bytes([data[14], data[15]]);
        tag = Some(VlanTag::from_tci(tci));
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        offset = 18;
    }
    Some(L2Frame {
        dst,
        src,
        tag,
        ethertype,
        payload: &data[offset..],
    })
}

/// Build an Ethernet frame with an optional IEEE 802.1Q tag.
pub fn build_tagged(
    dst: [u8; 6],
    src: [u8; 6],
    tag: Option<VlanTag>,
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    if let Some(tag) = tag {
        out.extend_from_slice(&VLAN_TPID.to_be_bytes());
        out.extend_from_slice(&tag.tci().to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build an Ethernet frame, optionally inserting a tag with the given VID.
/// PCP/DEI default to zero; use [`build_tagged`] to preserve priority.
pub fn build(
    dst: [u8; 6],
    src: [u8; 6],
    vlan: Option<u16>,
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_tagged(dst, src, vlan.map(VlanTag::new), ethertype, payload)
}

/// Fill an 802.3 frame up to the 60-byte minimum (without FCS).
pub fn pad(mut frame: Vec<u8>) -> Vec<u8> {
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    frame
}

/// The 51-octet MST Configuration Identifier (IEEE 802.1Q-2005, 13.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MstConfigId {
    /// Format selector, always 0 for this standard.
    pub format: u8,
    /// NUL padded configuration name.
    pub name: [u8; 32],
    pub revision: u16,
    /// HMAC-MD5 over the VID to MSTID table.
    pub digest: [u8; 16],
}

impl Default for MstConfigId {
    fn default() -> Self {
        MstConfigId {
            format: 0,
            name: [0; 32],
            revision: 0,
            digest: [0; 16],
        }
    }
}

impl MstConfigId {
    pub fn new(name: &str, revision: u16, digest: [u8; 16]) -> Self {
        MstConfigId {
            format: 0,
            name: encode_name(name),
            revision,
            digest,
        }
    }

    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|b| *b == 0).unwrap_or(32);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }

    pub fn to_bytes(&self) -> [u8; 51] {
        let mut out = [0u8; 51];
        out[0] = self.format;
        out[1..33].copy_from_slice(&self.name);
        out[33..35].copy_from_slice(&self.revision.to_be_bytes());
        out[35..51].copy_from_slice(&self.digest);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 51 {
            return None;
        }
        let mut name = [0u8; 32];
        name.copy_from_slice(&b[1..33]);
        let mut digest = [0u8; 16];
        digest.copy_from_slice(&b[35..51]);
        Some(MstConfigId {
            format: b[0],
            name,
            revision: u16::from_be_bytes([b[33], b[34]]),
            digest,
        })
    }
}

/// Encode a configuration name into the fixed 32-octet field.
pub fn encode_name(name: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in name.as_bytes().iter().take(32).enumerate() {
        out[i] = *b;
    }
    out
}

/// One 16-octet MSTI Configuration Message (IEEE 802.1Q-2005, Figure 14-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MstiMessage {
    pub flags: u8,
    pub regional_root_id: BridgeId,
    pub internal_root_path_cost: u32,
    /// Bridge priority octet: bits 5..8 carry the four most significant bits.
    pub bridge_priority: u8,
    /// Port priority octet: bits 5..8 carry the four most significant bits.
    pub port_priority: u8,
    pub remaining_hops: u8,
}

impl MstiMessage {
    /// MSTID carried in the low 12 bits of the regional root identifier.
    pub fn mstid(&self) -> u16 {
        ((self.regional_root_id.0 >> 48) & 0x0fff) as u16
    }

    #[allow(dead_code)] // exercised by codec tests and available to callers
    pub fn set_mstid(&mut self, mstid: u16) {
        let mac = self.regional_root_id.mac();
        let priority = (self.regional_root_id.priority() & 0xf000) | (mstid & 0x0fff);
        self.regional_root_id = BridgeId::new(priority, mac);
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = self.flags;
        out[1..9].copy_from_slice(&self.regional_root_id.to_bytes());
        out[9..13].copy_from_slice(&self.internal_root_path_cost.to_be_bytes());
        out[13] = self.bridge_priority;
        out[14] = self.port_priority;
        out[15] = self.remaining_hops;
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        Some(MstiMessage {
            flags: b[0],
            regional_root_id: BridgeId::from_bytes(&b[1..9])?,
            internal_root_path_cost: u32::from_be_bytes([b[9], b[10], b[11], b[12]]),
            bridge_priority: b[13],
            port_priority: b[14],
            remaining_hops: b[15],
        })
    }
}

/// The MST-specific part of an MST BPDU (octets 37 onward).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MstPayload {
    pub config_id: MstConfigId,
    pub internal_root_path_cost: u32,
    pub cist_bridge_id: BridgeId,
    pub remaining_hops: u8,
    pub msti: Vec<MstiMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Bpdu {
    pub protocol_id: u16,
    pub version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: BridgeId,
    pub root_path_cost: u32,
    /// For MST BPDUs this is the CIST Regional Root Identifier; for ST/RST
    /// BPDUs it is the Designated Bridge Identifier.
    pub bridge_id: BridgeId,
    pub port_id: u16,
    pub msg_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
    /// Version 1 Length octet (RST/MST BPDUs).
    pub version_1_length: u8,
    /// Present only for a validated MST BPDU.
    pub mst: Option<MstPayload>,
}

impl Bpdu {
    pub fn config(
        root_id: BridgeId,
        root_path_cost: u32,
        bridge_id: BridgeId,
        port_id: u16,
        msg_age: u16,
        max_age: u16,
        hello_time: u16,
        forward_delay: u16,
    ) -> Self {
        Bpdu {
            protocol_id: 0,
            version: BPDU_VERSION_STP,
            bpdu_type: BPDU_TYPE_CONFIG,
            flags: 0,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            msg_age,
            max_age,
            hello_time,
            forward_delay,
            version_1_length: 0,
            mst: None,
        }
    }

    pub fn tcn(port_id: u16) -> Self {
        Bpdu {
            protocol_id: 0,
            version: BPDU_VERSION_STP,
            bpdu_type: BPDU_TYPE_TCN,
            port_id,
            ..Default::default()
        }
    }

    pub fn is_tcn(&self) -> bool {
        self.bpdu_type == BPDU_TYPE_TCN
    }

    pub fn is_rst(&self) -> bool {
        self.bpdu_type == BPDU_TYPE_RST && self.version == BPDU_VERSION_RSTP
    }

    pub fn is_mst(&self) -> bool {
        self.bpdu_type == BPDU_TYPE_RST && self.version >= BPDU_VERSION_MSTP && self.mst.is_some()
    }

    pub fn topology_change_ack(&self) -> bool {
        self.flags & BPDU_FLAG_TCACK != 0
    }

    /// Serialize the BPDU body only (no LLC, no Ethernet header).
    pub fn encode_body(&self) -> Vec<u8> {
        if self.is_tcn() {
            let mut v = Vec::with_capacity(4);
            v.extend_from_slice(&self.protocol_id.to_be_bytes());
            v.push(self.version);
            v.push(self.bpdu_type);
            return v;
        }
        let mut v = Vec::with_capacity(MST_BPDU_BASE_LEN);
        v.extend_from_slice(&self.protocol_id.to_be_bytes());
        v.push(self.version);
        v.push(self.bpdu_type);
        v.push(self.flags);
        v.extend_from_slice(&self.root_id.to_bytes());
        v.extend_from_slice(&self.root_path_cost.to_be_bytes());
        v.extend_from_slice(&self.bridge_id.to_bytes());
        v.extend_from_slice(&self.port_id.to_be_bytes());
        v.extend_from_slice(&self.msg_age.to_be_bytes());
        v.extend_from_slice(&self.max_age.to_be_bytes());
        v.extend_from_slice(&self.hello_time.to_be_bytes());
        v.extend_from_slice(&self.forward_delay.to_be_bytes());

        let is_rst_or_mst =
            self.bpdu_type == BPDU_TYPE_RST && self.version >= BPDU_VERSION_RSTP;
        if !is_rst_or_mst {
            return v;
        }
        v.push(self.version_1_length);
        if self.version < BPDU_VERSION_MSTP {
            return v;
        }
        let Some(mst) = &self.mst else {
            return v;
        };
        let msti_len = mst.msti.len().min(MST_MAX_INSTANCES as usize) * MSTI_MESSAGE_LEN;
        let v3_len = 64 + msti_len;
        v.extend_from_slice(&(v3_len as u16).to_be_bytes());
        v.extend_from_slice(&mst.config_id.to_bytes());
        v.extend_from_slice(&mst.internal_root_path_cost.to_be_bytes());
        v.extend_from_slice(&mst.cist_bridge_id.to_bytes());
        v.push(mst.remaining_hops);
        for msg in mst.msti.iter().take(MST_MAX_INSTANCES as usize) {
            v.extend_from_slice(&msg.to_bytes());
        }
        v
    }

    /// Parse a BPDU body (starting at the protocol id) using the validation
    /// rules of IEEE 802.1Q-2005, 14.4.
    pub fn decode_body(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        if u16::from_be_bytes([b[0], b[1]]) != 0 {
            return None;
        }
        let version = b[2];
        let bpdu_type = b[3];

        // 14.4 a) and b): STP Configuration / TCN.  The version is not
        // checked for these two forms.
        if bpdu_type == BPDU_TYPE_CONFIG {
            if b.len() < 35 {
                return None;
            }
            let mut out = Bpdu {
                protocol_id: 0,
                version,
                bpdu_type,
                ..Default::default()
            };
            decode_config_fields(&mut out, b)?;
            return Some(out);
        }
        if bpdu_type == BPDU_TYPE_TCN {
            if b.len() < 4 {
                return None;
            }
            return Some(Bpdu {
                protocol_id: 0,
                version,
                bpdu_type,
                ..Default::default()
            });
        }
        if bpdu_type != BPDU_TYPE_RST || b.len() < 36 {
            return None;
        }

        // 14.4 c): RST BPDU.
        let mut out = Bpdu {
            protocol_id: 0,
            version,
            bpdu_type,
            ..Default::default()
        };
        decode_config_fields(&mut out, b)?;
        out.version_1_length = b[35];

        // 14.4 d)/e): only a well-formed version 3 BPDU is an MST BPDU;
        // otherwise it is decoded as an RST BPDU.
        if version >= BPDU_VERSION_MSTP && out.version_1_length == 0 && b.len() >= MST_BPDU_BASE_LEN
        {
            let v3_len = u16::from_be_bytes([b[36], b[37]]) as usize;
            if v3_len >= 64 && (v3_len - 64) % MSTI_MESSAGE_LEN == 0 {
                let count = (v3_len - 64) / MSTI_MESSAGE_LEN;
                if count <= MST_MAX_INSTANCES as usize && b.len() >= 38 + v3_len {
                    let config_id = MstConfigId::from_bytes(&b[38..89])?;
                    let internal_root_path_cost =
                        u32::from_be_bytes([b[89], b[90], b[91], b[92]]);
                    let cist_bridge_id = BridgeId::from_bytes(&b[93..101])?;
                    let remaining_hops = b[101];
                    let mut msti = Vec::with_capacity(count);
                    for i in 0..count {
                        let off = MST_BPDU_BASE_LEN + i * MSTI_MESSAGE_LEN;
                        msti.push(MstiMessage::from_bytes(&b[off..off + MSTI_MESSAGE_LEN])?);
                    }
                    out.mst = Some(MstPayload {
                        config_id,
                        internal_root_path_cost,
                        cist_bridge_id,
                        remaining_hops,
                        msti,
                    });
                }
            }
        }
        Some(out)
    }
}

fn decode_config_fields(out: &mut Bpdu, b: &[u8]) -> Option<()> {
    out.flags = b[4];
    out.root_id = BridgeId::from_bytes(&b[5..13])?;
    out.root_path_cost = u32::from_be_bytes([b[13], b[14], b[15], b[16]]);
    out.bridge_id = BridgeId::from_bytes(&b[17..25])?;
    out.port_id = u16::from_be_bytes([b[25], b[26]]);
    out.msg_age = u16::from_be_bytes([b[27], b[28]]);
    out.max_age = u16::from_be_bytes([b[29], b[30]]);
    out.hello_time = u16::from_be_bytes([b[31], b[32]]);
    out.forward_delay = u16::from_be_bytes([b[33], b[34]]);
    Some(())
}

/// Does this frame look like an IEEE 802.1D BPDU?
///
/// A valid STP BPDU is untagged, addressed to `01:80:C2:00:00:00`, and
/// carries the LLC header `42 42 03` (DSAP/SSAP/UI).  PVST+ SNAP frames and
/// tagged BPDUs are rejected.
pub fn is_bpdu(frame: &L2Frame<'_>) -> bool {
    if frame.dst != MAC_STP || frame.tag.is_some() {
        return false;
    }
    if !frame.is_8023() || frame.payload.len() < 4 {
        return false;
    }
    let p = frame.payload;
    p[0] == LLC_DSAP_STP && p[1] == LLC_SSAP_STP && p[2] == LLC_CONTROL_UI
}

/// Extract the BPDU body from a frame that passed [`is_bpdu`].
pub fn decode_bpdu(frame: &L2Frame<'_>) -> Option<Bpdu> {
    if !is_bpdu(frame) {
        return None;
    }
    Bpdu::decode_body(&frame.payload[3..])
}

/// Encode a spanning-tree BPDU (untagged, `42 42 03` LLC).
///
/// IEEE 802.1Q-2005 bridges send CIST and MSTI information in a single
/// untagged MST BPDU on every port, independent of the port's VLAN
/// configuration.
pub fn encode_stp(bpdu: &Bpdu, src: [u8; 6]) -> Vec<u8> {
    let body = bpdu.encode_body();
    let mut payload = Vec::with_capacity(body.len() + 3);
    payload.extend_from_slice(&[LLC_DSAP_STP, LLC_SSAP_STP, LLC_CONTROL_UI]);
    payload.extend_from_slice(&body);
    let len = payload.len() as u16;
    pad(build(MAC_STP, src, None, len, &payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    #[test]
    fn parse_untagged() {
        let f = build(MAC_B, MAC_A, None, ETHERTYPE_IPV4, &[1, 2, 3, 4]);
        let p = parse(&f).unwrap();
        assert_eq!(p.dst, MAC_B);
        assert_eq!(p.src, MAC_A);
        assert_eq!(p.tag, None);
        assert_eq!(p.vlan(), None);
        assert_eq!(p.ethertype, ETHERTYPE_IPV4);
        assert_eq!(p.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn parse_tagged_fields() {
        let tag = VlanTag::with_pcp(100, 5, true);
        let f = build_tagged(MAC_BROADCAST, MAC_A, Some(tag), ETHERTYPE_ARP, &[9; 28]);
        let p = parse(&f).unwrap();
        assert_eq!(p.vlan(), Some(100));
        assert_eq!(p.tag, Some(tag));
        assert_eq!(p.priority(), (5, true));
        assert_eq!(p.ethertype, ETHERTYPE_ARP);
        assert_eq!(p.payload.len(), 28);
    }

    #[test]
    fn vlan_tci_roundtrip() {
        for (pcp, dei, vid) in [(0u8, false, 1u16), (7, true, 4094), (3, false, 0)] {
            let tag = VlanTag::with_pcp(vid, pcp, dei);
            let decoded = VlanTag::from_tci(tag.tci());
            assert_eq!(decoded, tag);
        }
        assert!(VlanTag::new(0).is_priority_tag());
        assert!(VlanTag::new(4095).is_reserved());
        assert!(!VlanTag::new(4094).is_reserved());
    }

    #[test]
    fn parse_short_rejected() {
        assert!(parse(&[0u8; 13]).is_none());
        assert!(parse(&[]).is_none());
        let mut truncated_tag = [0u8; 17];
        truncated_tag[12] = 0x81;
        truncated_tag[13] = 0x00;
        assert!(parse(&truncated_tag).is_none()); // tag missing its TCI
    }

    #[test]
    fn mac_text_roundtrip() {
        assert_eq!(format_mac(MAC_A), "0011.2233.4455");
        assert_eq!(parse_mac("0011.2233.4455"), Some(MAC_A));
        assert_eq!(parse_mac("00:11:22:33:44:55"), Some(MAC_A));
        assert_eq!(parse_mac("bogus"), None);
    }

    #[test]
    fn bridge_id_packs_priority_and_mac() {
        let b = BridgeId::new(32768, MAC_A);
        assert_eq!(b.priority(), 32768);
        assert_eq!(b.mac(), MAC_A);
        assert_eq!(BridgeId::from_bytes(&b.to_bytes()), Some(b));
        // A common spanning tree has no per-VLAN system-id-extension.
        assert_eq!(b.to_bytes()[0..2], 0x8000u16.to_be_bytes());
    }

    fn sample_bpdu() -> Bpdu {
        Bpdu {
            protocol_id: 0,
            version: 0,
            bpdu_type: BPDU_TYPE_CONFIG,
            flags: BPDU_FLAG_TC,
            root_id: BridgeId::new(32768, MAC_A),
            root_path_cost: 19,
            bridge_id: BridgeId::new(32768, MAC_B),
            port_id: 0x8002,
            msg_age: 0,
            max_age: 20 * 256,
            hello_time: 2 * 256,
            forward_delay: 15 * 256,
            ..Default::default()
        }
    }

    #[test]
    fn stp_8021d_roundtrip() {
        let b = sample_bpdu();
        let wire = encode_stp(&b, MAC_A);
        let f = parse(&wire).unwrap();
        assert_eq!(f.dst, MAC_STP);
        assert!(f.tag.is_none(), "CST BPDUs are untagged");
        assert!(is_bpdu(&f));
        assert_eq!(decode_bpdu(&f).unwrap(), b);
        assert!(wire.len() >= 60);
        assert_eq!(f.payload[0..3], [0x42, 0x42, 0x03]);
    }

    #[test]
    fn tcn_roundtrip() {
        let b = Bpdu::tcn(0x8001);
        let wire = encode_stp(&b, MAC_A);
        let f = parse(&wire).unwrap();
        let got = decode_bpdu(&f).unwrap();
        assert!(got.is_tcn());
        // A TCN BPDU is only 4 bytes long: no port id on the wire.
        assert_eq!(got.bpdu_type, BPDU_TYPE_TCN);
    }

    #[test]
    fn tagged_bpdu_rejected() {
        let b = sample_bpdu();
        let body = b.encode_body();
        let mut payload = vec![0x42, 0x42, 0x03];
        payload.extend_from_slice(&body);
        let wire = build(MAC_STP, MAC_A, Some(10), payload.len() as u16, &payload);
        let f = parse(&wire).unwrap();
        assert!(!is_bpdu(&f), "802.1D BPDUs must not be VLAN tagged");
    }

    #[test]
    fn cisco_pvst_snap_is_not_bpdu() {
        // 01:00:0c:cc:cc:cd, AA AA 03, SNAP 00 00 0C 01 0B: Cisco PVST+.
        let mut payload = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x0b];
        payload.extend_from_slice(&sample_bpdu().encode_body());
        let wire = build(
            [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd],
            MAC_A,
            None,
            payload.len() as u16,
            &payload,
        );
        let f = parse(&wire).unwrap();
        assert!(!is_bpdu(&f), "PVST+ framing is not an IEEE 802.1D BPDU");

        // A tagged SNAP frame addressed to the standard multicast group is
        // not accepted either.
        let wire2 = build(MAC_STP, MAC_A, Some(10), payload.len() as u16, &payload);
        let f2 = parse(&wire2).unwrap();
        assert!(!is_bpdu(&f2));
    }

    #[test]
    fn garbage_not_bpdu() {
        let wire = build(MAC_STP, MAC_A, None, ETHERTYPE_IPV4, &[0u8; 40]);
        let f = parse(&wire).unwrap();
        assert!(!is_bpdu(&f));
        let wire2 = build(MAC_STP, MAC_A, None, 40, &[0x42, 0x42, 0x03, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0]);
        let f2 = parse(&wire2).unwrap();
        assert!(is_bpdu(&f2));
        assert!(decode_bpdu(&f2).is_none()); // too short for a config BPDU
    }

    #[test]
    fn mst_bpdu_roundtrip_carries_cist_and_mstis() {
        let config = MstConfigId::new("region-a", 3, [0x11; 16]);
        let mut m1 = MstiMessage {
            flags: BPDU_FLAG_FORWARDING | (3 << BPDU_FLAG_ROLE_SHIFT),
            regional_root_id: BridgeId::new(0x1000 | 1, MAC_B),
            internal_root_path_cost: 20000,
            bridge_priority: 0x10,
            port_priority: 0x80,
            remaining_hops: 19,
        };
        m1.set_mstid(1);
        let m2 = MstiMessage {
            flags: BPDU_FLAG_LEARNING,
            regional_root_id: BridgeId::new(0x2000 | 2, MAC_B),
            internal_root_path_cost: 40000,
            bridge_priority: 0x20,
            port_priority: 0x90,
            remaining_hops: 18,
        };
        let b = Bpdu {
            protocol_id: 0,
            version: BPDU_VERSION_MSTP,
            bpdu_type: BPDU_TYPE_RST,
            flags: BPDU_FLAG_FORWARDING | BPDU_FLAG_AGREEMENT,
            root_id: BridgeId::new(0x1000, MAC_A),
            root_path_cost: 19,
            bridge_id: BridgeId::new(0x1000, MAC_B),
            port_id: 0x8001,
            msg_age: 0,
            max_age: 20 * 256,
            hello_time: 2 * 256,
            forward_delay: 15 * 256,
            version_1_length: 0,
            mst: Some(MstPayload {
                config_id: config,
                internal_root_path_cost: 20000,
                cist_bridge_id: BridgeId::new(0x1000, MAC_B),
                remaining_hops: 20,
                msti: vec![m1, m2],
            }),
        };

        let body = b.encode_body();
        assert_eq!(body.len(), MST_BPDU_BASE_LEN + 2 * MSTI_MESSAGE_LEN);
        assert_eq!(body[35], 0, "Version 1 Length");
        assert_eq!(
            u16::from_be_bytes([body[36], body[37]]) as usize,
            64 + 2 * MSTI_MESSAGE_LEN
        );
        let decoded = Bpdu::decode_body(&body).unwrap();
        assert!(decoded.is_mst());
        assert_eq!(decoded, b);
        assert_eq!(decoded.mst.as_ref().unwrap().msti[0].mstid(), 1);
        assert_eq!(decoded.mst.as_ref().unwrap().msti[1].mstid(), 2);

        // The MST BPDU is still an untagged 802.1Q frame on the wire.
        let wire = encode_stp(&b, MAC_A);
        let f = parse(&wire).unwrap();
        assert_eq!(f.dst, MAC_STP);
        assert!(f.tag.is_none());
        assert!(is_bpdu(&f));
        assert_eq!(decode_bpdu(&f).unwrap(), b);
    }

    #[test]
    fn malformed_version3_body_decodes_as_rst() {
        let b = sample_bpdu();
        let mut body = b.encode_body();
        body[2] = BPDU_VERSION_MSTP;
        body[3] = BPDU_TYPE_RST;
        body.push(0); // Version 1 Length
        body.extend_from_slice(&63u16.to_be_bytes()); // invalid Version 3 Length
        let decoded = Bpdu::decode_body(&body).unwrap();
        assert_eq!(decoded.bpdu_type, BPDU_TYPE_RST);
        assert!(decoded.mst.is_none());
        assert!(!decoded.is_mst());
    }

    #[test]
    fn timer_units() {
        assert_eq!(secs_to_timer(2), 512);
        assert_eq!(timer_to_secs(512), 2);
        assert_eq!(timer_to_duration(512).as_secs(), 2);
    }
}
