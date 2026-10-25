//! Linux `AF_PACKET` dataplane: one RX socket and one TX socket per port.
//!
//! The switch keeps frames in an *untagged* internal form.  Trunk egress
//! re-inserts the 802.1Q tag; access egress always sends untagged.  There are
//! no VLAN sub-interfaces and no kernel bridge: forwarding, learning and
//! flooding are implemented here so that the STP state machine fully controls
//! the data path.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::lldp;
use crate::model::{MacAddr, PortMode, Switch};
use crate::packet::{self, VlanTag};
use crate::stp::{self, Action, PortState};

const ETH_P_ALL: u16 = 0x0003;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const PACKET_AUXDATA: libc::c_int = 8;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
const ETHERTYPE_VLAN: u16 = 0x8100;

/// Kernel auxiliary data attached to a packet: VLAN tags are stripped by the
/// NIC/veth before the frame reaches an AF_PACKET socket, and the tag is
/// delivered here instead.  (This is why `tcpdump` can print the tag while a
/// plain `recv()` sees an untagged frame.)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

/// Read the stripped 802.1Q tag from a `recvmsg()` control message, if any.
fn aux_vlan(msg: &libc::msghdr) -> Option<(u16, u16)> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_PACKET && hdr.cmsg_type == PACKET_AUXDATA {
            let aux = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const TpacketAuxdata)
            };
            if aux.tp_status & TP_STATUS_VLAN_VALID != 0 {
                let tpid = if aux.tp_status & TP_STATUS_VLAN_TPID_VALID != 0 {
                    aux.tp_vlan_tpid
                } else {
                    ETHERTYPE_VLAN
                };
                return Some((tpid, aux.tp_vlan_tci));
            }
            return None;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

pub struct Io {
    enabled: bool,
    capture: bool,
    tx: Mutex<HashMap<usize, RawFd>>,
    captured: Mutex<Vec<(usize, Vec<u8>)>>,
    /// Ports whose sockets could not be opened; retried only on demand.
    warned: Mutex<HashSet<usize>>,
}

impl Io {
    pub fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Io {
            enabled,
            capture: false,
            tx: Mutex::new(HashMap::new()),
            captured: Mutex::new(Vec::new()),
            warned: Mutex::new(HashSet::new()),
        })
    }

    /// Test/simulation IO that records every transmitted frame instead of
    /// writing to a socket.
    #[cfg(test)]
    pub fn capture() -> Arc<Self> {
        Arc::new(Io {
            enabled: false,
            capture: true,
            tx: Mutex::new(HashMap::new()),
            captured: Mutex::new(Vec::new()),
            warned: Mutex::new(HashSet::new()),
        })
    }

    #[cfg(test)]
    pub fn take_captured(&self) -> Vec<(usize, Vec<u8>)> {
        match self.captured.lock() {
            Ok(mut c) => std::mem::take(&mut *c),
            Err(_) => Vec::new(),
        }
    }

    pub fn tx_socket(&self, port: usize) -> Option<RawFd> {
        self.tx.lock().ok().and_then(|m| m.get(&port).copied())
    }

    pub fn has_port(&self, port: usize) -> bool {
        self.tx_socket(port).is_some()
    }

    fn warn_once(&self, port: usize) {
        if let Ok(mut w) = self.warned.lock() {
            w.insert(port);
        }
    }

    fn is_warned(&self, port: usize) -> bool {
        self.warned.lock().map(|w| w.contains(&port)).unwrap_or(false)
    }

    pub fn send(&self, port: usize, frame: &[u8]) {
        if self.capture {
            if let Ok(mut c) = self.captured.lock() {
                c.push((port, frame.to_vec()));
            }
        }
        let Some(fd) = self.tx_socket(port) else {
            return;
        };
        unsafe {
            libc::send(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            );
        }
    }

    pub fn close_all(&self) {
        if let Ok(mut m) = self.tx.lock() {
            for (_, fd) in m.drain() {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

fn cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

pub fn ifindex(ifname: &str) -> Option<u32> {
    let c = cstring(ifname)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Is the interface administratively up and has carrier?
pub fn iface_up(ifname: &str) -> bool {
    let admin = fs::read_to_string(format!("/sys/class/net/{}/flags", ifname))
        .ok()
        .and_then(|s| {
            let s = s.trim();
            let s = s.strip_prefix("0x").unwrap_or(s);
            u32::from_str_radix(s, 16).ok()
        })
        .map(|f| f & 0x1 != 0)
        .unwrap_or_else(|| ifindex(ifname).is_some());
    if !admin {
        return false;
    }
    match fs::read_to_string(format!("/sys/class/net/{}/operstate", ifname)) {
        Ok(s) => {
            let s = s.trim();
            s == "up" || s == "unknown"
        }
        Err(_) => ifindex(ifname).is_some(),
    }
}

/// All non-loopback interfaces, sorted naturally by their trailing number.
pub fn list_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            // Predictable defaults: eth* / en* only; use --ports for anything
            // else. eth0 is normally the management interface (containerlab).
            if name == "eth0" || !(name.starts_with("eth") || name.starts_with("en")) {
                continue;
            }
            names.push(name);
        }
    }
    names.sort_by_key(|n| {
        let num: String = n.chars().rev().take_while(|c| c.is_ascii_digit()).collect();
        let num: String = num.chars().rev().collect();
        num.parse::<u32>().unwrap_or(u32::MAX)
    });
    names
}

fn open_socket(ifname: &str) -> io::Result<RawFd> {
    let idx = ifindex(ifname).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {} not found", ifname),
        )
    })?;

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (ETH_P_ALL as u16).to_be() as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Don't loop our own transmitted frames back into the RX path.
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        // Ask the kernel to tell us about VLAN tags it stripped on receive.
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_AUXDATA,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Wake up periodically so the thread can notice shutdown.
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = idx as libc::c_int;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// Open the sockets for a port and start its RX thread.
pub fn attach(sw: &Arc<Mutex<Switch>>, io: &Arc<Io>, port: usize, ifname: &str) {
    if !io.enabled {
        if let Ok(mut s) = sw.lock() {
            s.log_line(&format!(
                "dataplane: simulation mode, not attaching {}",
                ifname
            ));
        }
        return;
    }
    let rx = match open_socket(ifname) {
        Ok(fd) => fd,
        Err(e) => {
            if let Ok(mut s) = sw.lock() {
                s.log_line(&format!("dataplane: cannot open {}: {}", ifname, e));
            }
            io.warn_once(port);
            return;
        }
    };
    let tx = match open_socket(ifname) {
        Ok(fd) => fd,
        Err(e) => {
            if let Ok(mut s) = sw.lock() {
                s.log_line(&format!("dataplane: cannot open TX {}: {}", ifname, e));
            }
            unsafe { libc::close(rx) };
            io.warn_once(port);
            return;
        }
    };
    if let Ok(mut m) = io.tx.lock() {
        m.insert(port, tx);
    }

    let sw2 = Arc::clone(sw);
    let io2 = Arc::clone(io);
    let name = ifname.to_string();
    let _ = thread::Builder::new()
        .name(format!("rx-{}", ifname))
        .spawn(move || rx_loop(sw2, io2, port, rx, &name));
}

/// Attach any configured port whose Linux interface now exists.  Containers
/// often create their data interfaces after the daemon has started, so this is
/// called periodically (and at startup) instead of opening sockets only once.
pub fn attach_missing(sw: &Arc<Mutex<Switch>>, io: &Arc<Io>) {
    if !io.enabled {
        return;
    }
    let ports: Vec<(usize, String)> = match sw.lock() {
        Ok(s) => s.ports.iter().map(|p| (p.index, p.ifname.clone())).collect(),
        Err(_) => return,
    };
    for (idx, ifname) in ports {
        if io.has_port(idx) || io.is_warned(idx) {
            continue;
        }
        // Nothing to do until the kernel knows the interface.
        if ifindex(&ifname).is_none() {
            continue;
        }
        attach(sw, io, idx, &ifname);
    }
}

fn rx_loop(sw: Arc<Mutex<Switch>>, io: Arc<Io>, port: usize, fd: RawFd, ifname: &str) {
    let mut buf = vec![0u8; 65_536];
    // Aligned control buffer for the PACKET_AUXDATA cmsg (VLAN tag).
    let mut control = [0 as libc::c_long; 16];
    loop {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                _ => {
                    if let Ok(mut s) = sw.lock() {
                        s.log_line(&format!("dataplane: {} RX error: {}", ifname, err));
                    }
                    break;
                }
            }
        }
        if n == 0 {
            continue;
        }
        let mut n = n as usize;
        // Re-insert the 802.1Q header stripped by the kernel.
        if n >= 14 && n + 4 <= buf.len() {
            if let Some((tpid, tci)) = aux_vlan(&msg) {
                buf.copy_within(12..n, 16);
                buf[12..14].copy_from_slice(&tpid.to_be_bytes());
                buf[14..16].copy_from_slice(&tci.to_be_bytes());
                n += 4;
            }
        }
        if let Ok(mut s) = sw.lock() {
            handle_frame(&mut s, &io, port, &buf[..n]);
        }
    }
    unsafe { libc::close(fd) };
}

fn bump(sw: &mut Switch, port: usize, f: impl FnOnce(&mut crate::model::Counters)) {
    if let Some(p) = sw.port_mut(port) {
        f(&mut p.counters);
    }
}

/// Handle one received frame on `port` (index starts at 1).
pub fn handle_frame(sw: &mut Switch, io: &Io, port: usize, data: &[u8]) {
    let now = Instant::now();
    let Some(p) = sw.port(port).cloned() else {
        return;
    };
    if !p.oper_up() {
        return;
    }
    bump(sw, port, |c| {
        c.rx_packets += 1;
        c.rx_bytes += data.len() as u64;
    });

    let Some(frame) = packet::parse(data) else {
        bump(sw, port, |c| c.rx_errors += 1);
        return;
    };

    // ---- BPDUs are consumed locally, never switched -----------------------
    // MSTP carries the CIST and every MSTI in one untagged MST BPDU, so this
    // check happens before any VLAN classification.
    if packet::is_bpdu(&frame) {
        bump(sw, port, |c| c.bpdu_rx += 1);
        let Some(bpdu) = packet::decode_bpdu(&frame) else {
            bump(sw, port, |c| c.rx_errors += 1);
            return;
        };
        if sw.stp.debug {
            sw.log_line(&format!(
                "STP dbg: rx {} src {} version {} bpdutype {} root {} cost {} bridge {} prio {:04x} age {} max {} hello {}",
                p.name,
                packet::format_mac(frame.src),
                bpdu.version,
                bpdu.bpdu_type,
                bpdu.root_id,
                bpdu.root_path_cost,
                bpdu.bridge_id,
                bpdu.port_id,
                bpdu.msg_age,
                bpdu.max_age,
                bpdu.hello_time
            ));
        }
        let out = if bpdu.is_tcn() {
            stp::on_tcn(sw, port, now)
        } else {
            stp::on_config(sw, port, &bpdu, now)
        };
        run_outcome(sw, io, out);
        return;
    }

    // ---- LLDP is link-local and never switched -----------------------------
    if frame.ethertype == lldp::ETHERTYPE_LLDP {
        if sw.features.lldp {
            lldp::on_frame(sw, port, &frame, now);
        } else {
            bump(sw, port, |c| c.drops += 1);
        }
        return;
    }

    // ---- IEEE 802.1Q ingress rules -----------------------------------------
    //  * untagged frame                -> PVID
    //  * priority-tagged frame (VID 0) -> PVID, PCP/DEI retained
    //  * tagged frame                  -> tagged VLAN, trunk ports only
    //  * VID 4095                      -> reserved, discard
    let (ingress_vlan, pcp, dei) = if sw.features.vlan {
        match frame.tag {
            Some(tag) if tag.is_reserved() => {
                bump(sw, port, |c| c.drops += 1);
                return;
            }
            Some(tag) if !tag.is_priority_tag() => {
                if p.mode != PortMode::Trunk || !p.carries(tag.vid) {
                    bump(sw, port, |c| c.drops += 1);
                    return;
                }
                (tag.vid, tag.pcp, tag.dei)
            }
            Some(tag) => (p.pvid(), tag.pcp, tag.dei),
            None => (p.pvid(), 0, false),
        }
    } else {
        (1, 0, false)
    };

    // ---- ingress filtering -------------------------------------------------
    if sw.features.vlan {
        if !p.carries(ingress_vlan) {
            bump(sw, port, |c| c.drops += 1);
            return;
        }
        if !sw.has_vlan(ingress_vlan) {
            bump(sw, port, |c| c.drops += 1);
            return;
        }
    }

    // 802.1D link-local multicast (LLDP, LACP, ...) is never flooded.
    if packet::is_reserved_multicast(&frame.dst) {
        bump(sw, port, |c| c.drops += 1);
        return;
    }

    // ---- STP state gating ---------------------------------------------------
    // Each VLAN is mapped to its MSTID; CIST-mapped VLANs use the CIST state
    // and MSTI-mapped VLANs use their own instance's state.
    let mstid = if sw.features.stp && sw.stp_config.mode.is_mstp() {
        sw.mst.mstid_for_vlan(ingress_vlan)
    } else {
        0
    };
    if sw.features.stp {
        match stp::port_state_mst(sw, port, mstid) {
            PortState::Forwarding => {}
            PortState::Learning => {
                learn(sw, ingress_vlan, frame.src, port, now);
                bump(sw, port, |c| c.drops += 1);
                return;
            }
            _ => {
                bump(sw, port, |c| c.drops += 1);
                return;
            }
        }
    }

    // ---- learning -----------------------------------------------------------
    if sw.features.mac_learning {
        learn(sw, ingress_vlan, frame.src, port, now);
    }

    // ---- forwarding decision ------------------------------------------------
    let dst_mac = MacAddr(frame.dst);
    let known = if !dst_mac.is_multicast() && sw.features.mac_learning {
        sw.mac_table.lookup(ingress_vlan, frame.dst)
    } else {
        None
    };

    let egress: Vec<usize> = match known {
        Some(out) if out != port => {
            if sw.port(out).map(|p| p.oper_up()).unwrap_or(false) {
                vec![out]
            } else {
                sw.vlan_ports(ingress_vlan)
            }
        }
        _ => sw.vlan_ports(ingress_vlan),
    };

    let mut sent = 0usize;
    for out in egress {
        if out == port {
            continue;
        }
        let Some(op) = sw.port(out).cloned() else {
            continue;
        };
        if !op.carries(ingress_vlan) || !op.oper_up() {
            continue;
        }
        if !sw.is_forwarding(out, ingress_vlan) {
            continue;
        }
        // Trunks carry non-native VLANs tagged; access ports and the native
        // VLAN are untagged.  PCP/DEI are preserved on tagged egress.
        let tag = if op.mode == PortMode::Trunk && ingress_vlan != op.trunk.native_vlan {
            Some(VlanTag::with_pcp(ingress_vlan, pcp, dei))
        } else {
            None
        };
        let wire = packet::build_tagged(frame.dst, frame.src, tag, frame.ethertype, frame.payload);
        io.send(out, &wire);
        bump(sw, out, |c| {
            c.tx_packets += 1;
            c.tx_bytes += wire.len() as u64;
        });
        sent += 1;
    }
    if sent == 0 {
        bump(sw, port, |c| c.drops += 1);
    }
}

fn learn(sw: &mut Switch, vlan: u16, src: [u8; 6], port: usize, now: Instant) {
    if src[0] & 1 != 0 || src == [0; 6] {
        return;
    }
    if let Some(old) = sw.mac_table.learn(vlan, src, port, now) {
        if old != port {
            let name = sw
                .port(port)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| port.to_string());
            let oldname = sw
                .port(old)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| old.to_string());
            let mac = packet::format_mac(src);
            sw.log_line(&format!(
                "MAC[{}]: {} moved {} -> {}",
                vlan, mac, oldname, name
            ));
        }
    }
}

/// Send the BPDUs produced by the STP engine.
pub fn run_outcome(sw: &mut Switch, io: &Io, out: stp::Outcome) {
    for e in out.events {
        sw.log_line(&e);
    }
    for a in out.actions {
        let Action::Send { port, .. } = &a;
        if !sw.port(*port).map(|p| p.oper_up()).unwrap_or(false) {
            continue;
        }
        let wire = stp::encode_action(sw, &a);
        if wire.is_empty() {
            continue;
        }
        io.send(*port, &wire);
        bump(sw, *port, |c| {
            c.tx_packets += 1;
            c.tx_bytes += wire.len() as u64;
            c.bpdu_tx += 1;
        });
    }
}

/// Poll carrier state for every port; returns true if anything changed.
pub fn poll_links(sw: &mut Switch) -> bool {
    let mut changed = false;
    let mut transitions = Vec::new();
    let now = Instant::now();
    for p in sw.ports.iter_mut() {
        let up = iface_up(&p.ifname);
        if up != p.link_up {
            p.link_up = up;
            p.last_change = now;
            transitions.push((p.index, up));
            changed = true;
        }
    }
    if changed {
        stp::refresh(sw);
        for (index, up) in transitions {
            if up {
                lldp::link_up(sw, index, now);
            } else {
                lldp::link_down(sw, index);
            }
        }
    }
    changed
}

/// Convenience used by the daemon tick thread.
pub fn tick(sw: &mut Switch, io: &Io, now: Instant) {
    let out = stp::tick(sw, now);
    run_outcome(sw, io, out);
    lldp::tick(sw, io, now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Vlan, VlanSet};
    use crate::packet::{Bpdu, BridgeId};
    use std::path::PathBuf;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    fn sim_switch(n: usize) -> Switch {
        let mut sw = Switch::new(
            "test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/startup"),
        );
        sw.features.stp = false; // pure forwarding tests
        for i in 1..=n {
            sw.add_port(&format!("eth{}", i));
        }
        for p in sw.ports.iter_mut() {
            p.link_up = true;
        }
        sw
    }

    fn inject(sw: &mut Switch, io: &Io, port: usize, dst: [u8; 6], src: [u8; 6], payload: &[u8]) {
        let wire = packet::build(dst, src, None, packet::ETHERTYPE_IPV4, payload);
        handle_frame(sw, io, port, &wire);
    }

    #[test]
    fn floods_then_learns_and_forwards_unicast() {
        let io = Io::capture();
        let mut sw = sim_switch(3);
        inject(&mut sw, &io, 1, packet::MAC_BROADCAST, A, &[1, 2, 3, 4]);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 2);
        assert!(cap.iter().any(|(p, _)| *p == 2));
        assert!(cap.iter().any(|(p, _)| *p == 3));
        assert_eq!(sw.mac_table.lookup(1, A), Some(1));

        // B answers: only the port where A was learned gets the frame.
        inject(&mut sw, &io, 2, A, B, &[5, 6, 7, 8]);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, 1);
        assert_eq!(sw.mac_table.lookup(1, B), Some(2));
    }

    #[test]
    fn vlan_isolation() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.vlans.insert(20, Vlan::new(20));
        sw.port_mut(1).unwrap().access_vlan = 10;
        sw.port_mut(2).unwrap().access_vlan = 20;

        inject(&mut sw, &io, 1, packet::MAC_BROADCAST, A, &[0; 40]);
        assert!(io.take_captured().is_empty());
        assert!(sw.mac_table.lookup(10, A).is_some());

        // Unknown VLAN ingress is dropped.
        sw.port_mut(1).unwrap().access_vlan = 99;
        inject(&mut sw, &io, 1, packet::MAC_BROADCAST, B, &[0; 40]);
        assert!(io.take_captured().is_empty());
    }

    #[test]
    fn trunk_egress_tags_non_native_vlan() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.port_mut(1).unwrap().access_vlan = 10;
        {
            let p = sw.port_mut(2).unwrap();
            p.mode = PortMode::Trunk;
            p.trunk.native_vlan = 1;
            p.trunk.allowed = VlanSet::parse("10").unwrap();
        }
        inject(&mut sw, &io, 1, packet::MAC_BROADCAST, A, &[0; 40]);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, 2);
        let f = packet::parse(&cap[0].1).unwrap();
        assert_eq!(f.vlan(), Some(10));
        assert_eq!(f.tag.unwrap().pcp, 0);

        // Traffic on the native VLAN leaves untagged.
        sw.port_mut(2).unwrap().trunk.native_vlan = 10;
        inject(&mut sw, &io, 1, packet::MAC_BROADCAST, A, &[0; 40]);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(packet::parse(&cap[0].1).unwrap().vlan(), None);
    }

    #[test]
    fn tagged_ingress_is_switched_into_access_vlan() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.port_mut(1).unwrap().mode = PortMode::Trunk;
        sw.port_mut(1).unwrap().trunk.allowed = VlanSet::parse("10").unwrap();
        sw.port_mut(2).unwrap().access_vlan = 10;

        let wire = packet::build(
            packet::MAC_BROADCAST,
            A,
            Some(10),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, 2);
        assert_eq!(packet::parse(&cap[0].1).unwrap().vlan(), None);
        assert!(sw.mac_table.lookup(10, A).is_some());
    }

    #[test]
    fn access_port_discards_tagged_frames() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.port_mut(1).unwrap().access_vlan = 10;
        sw.port_mut(2).unwrap().access_vlan = 10;

        // An access port is an untagged member; a tagged frame is filtered.
        let wire = packet::build(
            packet::MAC_BROADCAST,
            A,
            Some(10),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        assert!(io.take_captured().is_empty());
        assert!(sw.mac_table.lookup(10, A).is_none());
    }

    #[test]
    fn priority_tag_uses_pvid_and_preserves_pcp() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.port_mut(1).unwrap().access_vlan = 10;
        {
            let p = sw.port_mut(2).unwrap();
            p.mode = PortMode::Trunk;
            p.trunk.allowed = VlanSet::parse("10").unwrap();
        }

        // VID 0 is a priority tag: forwarding uses the PVID (10), and the
        // PCP/DEI are carried to the tagged trunk egress.
        let tag = VlanTag::with_pcp(0, 6, true);
        let wire = packet::build_tagged(
            packet::MAC_BROADCAST,
            A,
            Some(tag),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, 2);
        let f = packet::parse(&cap[0].1).unwrap();
        assert_eq!(f.vlan(), Some(10));
        assert_eq!(f.priority(), (6, true));
        assert!(sw.mac_table.lookup(10, A).is_some());
    }

    #[test]
    fn reserved_vid_is_discarded() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.port_mut(1).unwrap().mode = PortMode::Trunk;
        let wire = packet::build(
            packet::MAC_BROADCAST,
            A,
            Some(packet::VLAN_VID_RESERVED),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        assert!(io.take_captured().is_empty());
        assert_eq!(sw.port(1).unwrap().counters.drops, 1);
    }

    #[test]
    fn unknown_tagged_vlan_is_dropped() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.vlans.insert(10, Vlan::new(10));
        sw.port_mut(1).unwrap().mode = PortMode::Trunk;
        sw.port_mut(1).unwrap().trunk.allowed = VlanSet::parse("10").unwrap();
        let wire = packet::build(
            packet::MAC_BROADCAST,
            A,
            Some(20),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        assert!(io.take_captured().is_empty());
    }

    #[test]
    fn blocked_port_drops_data_but_still_handles_bpdus() {
        use crate::stp::{self, PortState};
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.features.stp = true;
        sw.features.portfast = true;
        sw.port_mut(1).unwrap().portfast = true;
        stp::sync(&mut sw);
        let _ = stp::tick(&mut sw, Instant::now());
        // Port 1 is forwarding after portfast, port 2 too; force 2 to blocking.
        sw.stp.instance.as_mut().unwrap().ports[2].state = PortState::Blocking;

        inject(&mut sw, &io, 2, packet::MAC_BROADCAST, B, &[0; 40]);
        assert!(io.take_captured().is_empty());

        let upstream = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let b = Bpdu::config(upstream, 0, upstream, 0x8001, 0, 5120, 512, 3840);
        let wire = packet::encode_stp(&b, A);
        handle_frame(&mut sw, &io, 1, &wire);
        assert_eq!(sw.stp.instance().unwrap().root_port, Some(1));
        let _ = io.take_captured();

        // An inferior BPDU on the designated port is answered immediately.
        let worse = BridgeId::new(40960, [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let b2 = Bpdu::config(worse, 4, worse, 0x8001, 0, 5120, 512, 3840);
        let wire2 = packet::encode_stp(&b2, A);
        handle_frame(&mut sw, &io, 2, &wire2);
        let cap = io.take_captured();
        assert!(!cap.is_empty());
        assert_eq!(cap[0].0, 2);
        // The answer is a standard untagged CST BPDU.
        let f = packet::parse(&cap[0].1).unwrap();
        assert_eq!(f.dst, packet::MAC_STP);
        assert!(f.tag.is_none());
        assert!(packet::is_bpdu(&f));
    }

    #[test]
    fn bpdu_guard_disables_port() {
        let io = Io::capture();
        let mut sw = sim_switch(1);
        sw.features.stp = true;
        sw.features.portfast = true;
        sw.features.bpdu_guard = true;
        {
            let p = sw.port_mut(1).unwrap();
            p.portfast = true;
            p.bpduguard = true;
        }
        let upstream = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let b = Bpdu::config(upstream, 0, upstream, 0x8001, 0, 5120, 512, 3840);
        let wire = packet::encode_stp(&b, A);
        handle_frame(&mut sw, &io, 1, &wire);
        assert!(sw.port(1).unwrap().counters.err_disabled);
        assert!(!sw.port(1).unwrap().oper_up());
    }

    #[test]
    fn lldp_is_consumed_and_not_learned() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        sw.features.lldp = true;

        let mut peer = Switch::new(
            "peer",
            B,
            PathBuf::from("/tmp/opencode/switch-test/peer-startup"),
        );
        peer.add_port("eth9");
        let wire = lldp::frame(&peer, peer.port(1).unwrap());
        handle_frame(&mut sw, &io, 1, &wire);

        assert!(io.take_captured().is_empty(), "LLDP must not be flooded");
        assert!(sw.mac_table.lookup(1, B).is_none(), "LLDP must not be learned");
        assert_eq!(sw.lldp.neighbor_count(), 1);
        assert_eq!(sw.port(1).unwrap().counters.rx_packets, 1);

        // With the feature disabled the frame is still consumed (dropped),
        // never forwarded.
        let mut disabled = sim_switch(2);
        handle_frame(&mut disabled, &io, 1, &wire);
        assert!(io.take_captured().is_empty());
        assert_eq!(disabled.lldp.neighbor_count(), 0);
        assert_eq!(disabled.port(1).unwrap().counters.drops, 1);
    }

    #[test]
    fn reserved_multicast_is_not_flooded() {
        let io = Io::capture();
        let mut sw = sim_switch(2);
        let lldp = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
        inject(&mut sw, &io, 1, lldp, A, &[0; 40]);
        assert!(io.take_captured().is_empty());
    }
}

#[cfg(test)]
mod ieee8021q_dataplane_tests {
    use super::*;
    use crate::model::{StpMode, Vlan, VlanSet};
    use crate::packet::{Bpdu, BridgeId};
    use std::path::PathBuf;

    #[test]
    fn cst_forwards_on_data_vlans() {
        let io = Io::capture();
        let mut sw = Switch::new(
            "test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/startup"),
        );
        for i in 1..=2 {
            sw.add_port(&format!("eth{}", i));
        }
        sw.vlans.insert(10, Vlan::new(10));
        sw.features.portfast = true;
        sw.features.stp = true;
        for p in sw.ports.iter_mut() {
            p.link_up = true;
            p.access_vlan = 10;
            p.portfast = true;
        }
        sw.stp.instance = None;
        stp::refresh(&mut sw);

        let wire = packet::build(
            packet::MAC_BROADCAST,
            [0x02, 0, 0, 0, 0, 0x0a],
            None,
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, 2);
        assert_eq!(packet::parse(&cap[0].1).unwrap().vlan(), None);
        assert!(sw.mac_table.lookup(10, [0x02, 0, 0, 0, 0, 0x0a]).is_some());
    }

    #[test]
    fn per_msti_state_gates_only_its_vlans() {
        let io = Io::capture();
        let mut sw = Switch::new(
            "test",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/startup"),
        );
        for i in 1..=3 {
            sw.add_port(&format!("eth{}", i));
        }
        sw.features.stp = true;
        sw.features.mstp = true;
        sw.stp_config.mode = StpMode::Mstp;
        sw.features.portfast = true;
        sw.features.trunking = true;
        for v in [10u16, 20] {
            sw.vlans.insert(v, Vlan::new(v));
        }
        for p in sw.ports.iter_mut() {
            p.link_up = true;
            p.mode = PortMode::Trunk;
            p.trunk.allowed = VlanSet::parse("10,20").unwrap();
            p.portfast = true;
        }
        // VLAN 10 runs on MSTI 1; VLAN 20 stays on the CIST.
        sw.mst.set_instance_vlans(1, VlanSet::parse("10").unwrap());
        stp::refresh(&mut sw);

        // The CIST forwards everywhere.  MSTI 1 blocks eth2 while eth1 and
        // eth3 forward.
        if let Some(cist) = sw.stp.instance.as_mut() {
            for pi in cist.ports.iter_mut().skip(1) {
                pi.state = stp::PortState::Forwarding;
            }
        }
        let inst = sw.stp.mstis.get_mut(&1).unwrap();
        inst.ports[1].state = stp::PortState::Forwarding;
        inst.ports[2].state = stp::PortState::Blocking;
        inst.ports[3].state = stp::PortState::Forwarding;

        let a = [0x02, 0, 0, 0, 0, 0x0a];
        let tag10 = packet::VlanTag::new(10);
        let wire = packet::build_tagged(
            packet::MAC_BROADCAST,
            a,
            Some(tag10),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 1, "MSTI 1 blocks the second trunk");
        assert_eq!(cap[0].0, 3);

        let tag20 = packet::VlanTag::new(20);
        let wire = packet::build_tagged(
            packet::MAC_BROADCAST,
            a,
            Some(tag20),
            packet::ETHERTYPE_IPV4,
            &[0; 40],
        );
        handle_frame(&mut sw, &io, 1, &wire);
        let cap = io.take_captured();
        assert_eq!(cap.len(), 2, "the CIST still forwards on both trunks");
        assert!(cap.iter().any(|(p, _)| *p == 2));
        assert!(cap.iter().any(|(p, _)| *p == 3));
    }

    #[test]
    fn standard_stp_bpdu_selects_peer_root_on_trunk() {
        let io = Io::capture();
        let mut sw = Switch::new(
            "sw1",
            [0x02, 0xde, 0x19, 0x5d, 0x0a, 0x12],
            PathBuf::from("/tmp/opencode/switch-test/startup"),
        );
        sw.features.stp = true;
        for i in 1..=3 {
            let name = format!("eth{}", i);
            sw.add_port(&name);
        }
        for p in sw.ports.iter_mut() {
            p.link_up = true;
            p.mode = PortMode::Trunk;
            p.trunk.allowed = VlanSet::all();
            p.trunk.native_vlan = 1;
        }
        sw.vlans.insert(10, Vlan::new(10));
        stp::sync(&mut sw);
        stp::refresh(&mut sw);

        // Standards-based IEEE 802.1D BPDU from a peer (untagged).
        let peer = BridgeId::new(32768, [0x02, 0xdd, 0x19, 0x5d, 0x0a, 0x11]);
        let bpdu = Bpdu::config(
            peer,
            0,
            peer,
            0x8001,
            0,
            5120,
            512,
            3840,
        );
        let wire = packet::encode_stp(&bpdu, [0x02, 0xdd, 0x19, 0x5d, 0x0a, 0x11]);
        let f = packet::parse(&wire).unwrap();
        assert_eq!(f.dst, packet::MAC_STP);
        assert!(f.tag.is_none());
        assert!(packet::is_bpdu(&f));

        handle_frame(&mut sw, &io, 1, &wire);
        let inst = sw.stp.instance().unwrap();
        assert_eq!(inst.root_id, peer);
        assert_eq!(inst.root_port, Some(1));
        // A CST BPDU applies to every VLAN, not just VLAN 1.  The other
        // trunk port is designated and starts listening.
        assert_eq!(stp::port_role(&sw, 3), Some(stp::Role::Designated));
        assert_eq!(stp::port_state(&sw, 3), stp::PortState::Listening);
        assert_eq!(stp::port_role(&sw, 1), Some(stp::Role::Root));
    }
}
