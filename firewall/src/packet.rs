//! Minimal Ethernet / IPv4 / TCP / UDP / ICMP / ARP parsing and checksums.
//!
//! Everything works on borrowed byte slices so the dataplane can rewrite a
//! frame in place: decrement TTL, translate addresses and ports, then fix up
//! the checksums.

use std::net::Ipv4Addr;

pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub fn write_u16(buf: &mut [u8], off: usize, value: u16) {
    let bytes = value.to_be_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
}

pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn read_mac(buf: &[u8], off: usize) -> [u8; 6] {
    [
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
    ]
}

pub fn write_mac(buf: &mut [u8], off: usize, mac: [u8; 6]) {
    buf[off..off + 6].copy_from_slice(&mac);
}

pub fn ethertype(frame: &[u8]) -> u16 {
    if frame.len() < ETH_HEADER_LEN {
        return 0;
    }
    let mut off = 12;
    let mut etype = read_u16(frame, off);
    // Walk a single 802.1Q tag so tagged lab traffic still parses.
    if etype == ETHERTYPE_VLAN && frame.len() >= 18 {
        off += 4;
        etype = read_u16(frame, off);
    }
    etype
}

pub fn add_bytes(mut sum: u64, bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u64;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u64) << 8;
    }
    sum
}

pub fn fold_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 packet view over a mutable slice, starting at the IP header.
pub struct Ipv4<'a> {
    pub data: &'a mut [u8],
}

impl<'a> Ipv4<'a> {
    pub fn parse(data: &'a mut [u8]) -> Option<Ipv4<'a>> {
        if data.len() < 20 {
            return None;
        }
        if data[0] >> 4 != 4 {
            return None;
        }
        let ihl = (data[0] & 0x0f) as usize * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }
        let total = read_u16(data, 2) as usize;
        if total < ihl || total > data.len() {
            return None;
        }
        Some(Ipv4 { data })
    }

    pub fn header_len(&self) -> usize {
        (self.data[0] & 0x0f) as usize * 4
    }

    pub fn total_len(&self) -> usize {
        read_u16(self.data, 2) as usize
    }

    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.data[8] = ttl;
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(read_u32(self.data, 12))
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(read_u32(self.data, 16))
    }

    pub fn set_src(&mut self, ip: Ipv4Addr) {
        self.data[12..16].copy_from_slice(&ip.octets());
    }

    pub fn set_dst(&mut self, ip: Ipv4Addr) {
        self.data[16..20].copy_from_slice(&ip.octets());
    }

    pub fn checksum_valid(&self) -> bool {
        let hlen = self.header_len();
        let mut sum = add_bytes(0, &self.data[..hlen]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    pub fn recompute_header_checksum(&mut self) {
        let hlen = self.header_len();
        write_u16(self.data, 10, 0);
        let sum = add_bytes(0, &self.data[..hlen]);
        write_u16(self.data, 10, fold_checksum(sum));
    }

    pub fn transport(&self) -> &[u8] {
        let hlen = self.header_len();
        &self.data[hlen..self.total_len()]
    }

    /// Source and destination port of a TCP/UDP header.
    pub fn ports(&self) -> Option<(u16, u16)> {
        match self.protocol() {
            PROTO_TCP | PROTO_UDP => {
                let t = self.transport();
                if t.len() < 4 {
                    return None;
                }
                Some((read_u16(t, 0), read_u16(t, 2)))
            }
            _ => None,
        }
    }

    pub fn tcp_syn(&self) -> bool {
        if self.protocol() != PROTO_TCP {
            return false;
        }
        let t = self.transport();
        t.len() >= 14 && t[13] & 0x02 != 0 && t[13] & 0x10 == 0
    }

    /// TCP flag byte (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10).
    pub fn tcp_flags(&self) -> Option<u8> {
        if self.protocol() != PROTO_TCP {
            return None;
        }
        let t = self.transport();
        if t.len() < 14 {
            return None;
        }
        Some(t[13])
    }

    /// True for the first or any later fragment of a fragmented datagram.
    pub fn is_fragment(&self) -> bool {
        read_u16(self.data, 6) & 0x3fff != 0
    }

    /// Validate transport header lengths that the policy engine relies on.
    /// Fragments are rejected separately because their transport header is
    /// incomplete and cannot be validated here.
    pub fn transport_sane(&self) -> bool {
        let t = self.transport();
        match self.protocol() {
            PROTO_TCP => {
                if t.len() < 20 {
                    return false;
                }
                let data_offset = (t[12] >> 4) as usize * 4;
                data_offset >= 20 && data_offset <= t.len()
            }
            PROTO_UDP => {
                if t.len() < 8 {
                    return false;
                }
                let udp_len = read_u16(t, 4) as usize;
                udp_len >= 8 && udp_len <= t.len()
            }
            PROTO_ICMP => t.len() >= 8,
            _ => true,
        }
    }

    /// Validate the TCP/UDP pseudo-header checksum and the ICMP checksum.
    /// A zero UDP checksum means the sender omitted it, which IPv4 permits.
    pub fn transport_checksum_valid(&self) -> bool {
        let t = self.transport();
        let sum = match self.protocol() {
            PROTO_TCP | PROTO_UDP => {
                let len = if self.protocol() == PROTO_UDP {
                    if t.len() < 8 {
                        return false;
                    }
                    if read_u16(t, 6) == 0 {
                        return true;
                    }
                    read_u16(t, 4) as usize
                } else {
                    t.len()
                };
                if len > t.len() {
                    return false;
                }
                let t = &t[..len];
                let mut sum = 0;
                sum = add_bytes(sum, &self.src().octets());
                sum = add_bytes(sum, &self.dst().octets());
                sum += self.protocol() as u64;
                sum += len as u64;
                add_bytes(sum, t)
            }
            PROTO_ICMP => add_bytes(0, t),
            _ => return true,
        };
        let mut folded = sum;
        while folded >> 16 != 0 {
            folded = (folded & 0xffff) + (folded >> 16);
        }
        folded as u16 == 0xffff
    }

    pub fn icmp_type(&self) -> Option<u8> {
        if self.protocol() != PROTO_ICMP {
            return None;
        }
        self.transport().first().copied()
    }

    pub fn set_source_port(&mut self, port: u16) {
        if self.protocol() == PROTO_TCP || self.protocol() == PROTO_UDP {
            let hlen = self.header_len();
            write_u16(self.data, hlen, port);
        }
    }

    pub fn set_destination_port(&mut self, port: u16) {
        if self.protocol() == PROTO_TCP || self.protocol() == PROTO_UDP {
            let hlen = self.header_len();
            write_u16(self.data, hlen + 2, port);
        }
    }

    pub fn recompute_transport_checksum(&mut self) {
        let proto = self.protocol();
        if proto != PROTO_TCP && proto != PROTO_UDP {
            return;
        }
        let hlen = self.header_len();
        let total = self.total_len();
        let src = self.src().octets();
        let dst = self.dst().octets();
        let mut sum = 0;
        sum = add_bytes(sum, &src);
        sum = add_bytes(sum, &dst);
        sum += proto as u64;
        sum += (total - hlen) as u64;
        let checksum_off = hlen
            + match proto {
                PROTO_TCP => 16,
                _ => 6,
            };
        if checksum_off + 2 > total {
            return;
        }
        write_u16(self.data, checksum_off, 0);
        sum = add_bytes(sum, &self.data[hlen..total]);
        let csum = fold_checksum(sum);
        // A computed UDP checksum of zero means "no checksum" in IPv4; send
        // 0xffff instead so the receiver still validates the packet.
        let csum = if proto == PROTO_UDP && csum == 0 {
            0xffff
        } else {
            csum
        };
        write_u16(self.data, checksum_off, csum);
    }

    /// Rewrite the ICMP echo request in place into an echo reply.
    pub fn make_icmp_echo_reply(&mut self) -> bool {
        if self.protocol() != PROTO_ICMP {
            return false;
        }
        let hlen = self.header_len();
        let total = self.total_len();
        if total < hlen + 8 {
            return false;
        }
        if self.data[hlen] != 8 {
            return false;
        }
        self.data[hlen] = 0;
        write_u16(self.data, hlen + 2, 0);
        let sum = add_bytes(0, &self.data[hlen..total]);
        write_u16(self.data, hlen + 2, fold_checksum(sum));
        true
    }
}

/// Wrap an IPv4 packet (header already filled in, checksums not yet set) in an
/// Ethernet frame and fix the IP header checksum.
fn finish_frame(dst_mac: [u8; 6], src_mac: [u8; 6], ip_packet: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip_packet.len());
    frame.extend_from_slice(&[0u8; ETH_HEADER_LEN]);
    frame.extend_from_slice(&ip_packet);
    write_mac(&mut frame, 0, dst_mac);
    write_mac(&mut frame, 6, src_mac);
    write_u16(&mut frame, 12, ETHERTYPE_IPV4);
    if let Some(mut ip) = Ipv4::parse(&mut frame[ETH_HEADER_LEN..]) {
        ip.recompute_header_checksum();
    }
    frame
}

fn ipv4_header(total: usize, proto: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    write_u16(&mut h, 2, total as u16);
    h[8] = 64;
    h[9] = proto;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    h
}

/// Build an ICMP error (time exceeded, destination unreachable, ...) that
/// quotes the offending packet's IP header plus its first eight bytes.
/// `original` is the offending IP packet starting at its IP header.
pub fn build_icmp_error(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    original: &[u8],
) -> Vec<u8> {
    let hlen = if original.len() >= 20 {
        ((original[0] & 0x0f) as usize * 4).min(original.len())
    } else {
        original.len()
    };
    let quote_len = (hlen + 8).min(original.len());
    let total = 20 + 8 + quote_len;
    let mut pkt = ipv4_header(total, PROTO_ICMP, src_ip, dst_ip);
    let mut icmp = vec![0u8; 8];
    icmp[0] = icmp_type;
    icmp[1] = code;
    icmp.extend_from_slice(&original[..quote_len]);
    let csum = fold_checksum(add_bytes(0, &icmp));
    write_u16(&mut icmp, 2, csum);
    pkt.extend_from_slice(&icmp);
    finish_frame(dst_mac, src_mac, pkt)
}

/// Build a TCP RST that answers `seg_*`, the segment being refused.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_rst(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    ack_flag: bool,
) -> Vec<u8> {
    let mut pkt = ipv4_header(40, PROTO_TCP, src_ip, dst_ip);
    let mut tcp = vec![0u8; 20];
    write_u16(&mut tcp, 0, src_port);
    write_u16(&mut tcp, 2, dst_port);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = if ack_flag { 0x14 } else { 0x04 };
    pkt.extend_from_slice(&tcp);
    let mut frame = finish_frame(dst_mac, src_mac, pkt);
    if let Some(mut ip) = Ipv4::parse(&mut frame[ETH_HEADER_LEN..]) {
        ip.recompute_transport_checksum();
    }
    frame
}

pub fn icmp_identity(ip: &Ipv4) -> u16 {
    if ip.protocol() != PROTO_ICMP {
        return 0;
    }
    let t = ip.transport();
    if t.len() < 6 {
        return 0;
    }
    read_u16(t, 4)
}

pub struct ArpInfo {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

pub fn parse_arp(data: &[u8]) -> Option<ArpInfo> {
    if data.len() < 28 {
        return None;
    }
    if read_u16(data, 0) != 1 || read_u16(data, 2) != ETHERTYPE_IPV4 {
        return None;
    }
    if data[4] != 6 || data[5] != 4 {
        return None;
    }
    Some(ArpInfo {
        operation: read_u16(data, 6),
        sender_mac: read_mac(data, 8),
        sender_ip: Ipv4Addr::from(read_u32(data, 14)),
        target_ip: Ipv4Addr::from(read_u32(data, 24)),
    })
}

pub fn build_arp(
    out: &mut [u8],
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    operation: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> usize {
    if out.len() < ETH_HEADER_LEN + 28 {
        return 0;
    }
    write_mac(out, 0, dst_mac);
    write_mac(out, 6, src_mac);
    write_u16(out, 12, ETHERTYPE_ARP);
    let arp = &mut out[ETH_HEADER_LEN..];
    write_u16(arp, 0, 1);
    write_u16(arp, 2, ETHERTYPE_IPV4);
    arp[4] = 6;
    arp[5] = 4;
    write_u16(arp, 6, operation);
    write_mac(arp, 8, sender_mac);
    arp[14..18].copy_from_slice(&sender_ip.octets());
    write_mac(arp, 18, target_mac);
    arp[24..28].copy_from_slice(&target_ip.octets());
    ETH_HEADER_LEN + 28
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        write_u16(&mut p, 2, (20 + 8) as u16);
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 2).octets());
        p[20] = 8; // echo request
        p[24] = 0x12;
        p[25] = 0x34;
        let mut ip = Ipv4::parse(&mut p).unwrap();
        let hlen = ip.header_len();
        ip.recompute_header_checksum();
        let sum = add_bytes(0, &ip.data[hlen..]);
        write_u16(ip.data, hlen + 2, fold_checksum(sum));
        p
    }

    #[test]
    fn ipv4_checksum_roundtrip() {
        let mut p = sample_ipv4();
        let ip = Ipv4::parse(&mut p).unwrap();
        assert!(ip.checksum_valid());
        assert_eq!(ip.src(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ip.dst(), Ipv4Addr::new(192, 0, 2, 2));
    }

    #[test]
    fn ttl_decrement_and_checksum() {
        let mut p = sample_ipv4();
        let mut ip = Ipv4::parse(&mut p).unwrap();
        ip.set_ttl(63);
        ip.recompute_header_checksum();
        let ip = Ipv4::parse(&mut p).unwrap();
        assert_eq!(ip.ttl(), 63);
        assert!(ip.checksum_valid());
    }

    #[test]
    fn icmp_reply_flips_type() {
        let mut p = sample_ipv4();
        let mut ip = Ipv4::parse(&mut p).unwrap();
        assert!(ip.make_icmp_echo_reply());
        assert_eq!(ip.transport()[0], 0);
        let sum = add_bytes(0, ip.transport());
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn corrupt_transport_checksum_is_rejected() {
        let mut p = sample_ipv4();
        let mut ip = Ipv4::parse(&mut p).unwrap();
        ip.recompute_header_checksum();
        assert!(ip.transport_checksum_valid());
        ip.data[ip.header_len() + 2] ^= 0xff;
        let ip = Ipv4::parse(&mut p).unwrap();
        assert!(!ip.transport_checksum_valid());
    }

    #[test]
    fn malformed_transport_headers_are_rejected() {
        let mut p = sample_ipv4();
        p.resize(40, 0);
        write_u16(&mut p, 2, 40);
        p[9] = PROTO_TCP;
        p[32] = 5 << 4;
        {
            let ip = Ipv4::parse(&mut p).unwrap();
            assert!(ip.transport_sane());
            assert!(!ip.transport_checksum_valid());
        }
        p[32] = 0;
        let ip = Ipv4::parse(&mut p).unwrap();
        assert!(!ip.transport_sane());
        p[9] = PROTO_UDP;
        let ip = Ipv4::parse(&mut p).unwrap();
        assert!(!ip.transport_sane());
    }

    #[test]
    fn udp_checksum_is_valid_after_rewrite() {
        let mut p = vec![0u8; 20 + 8 + 3];
        p[0] = 0x45;
        write_u16(&mut p, 2, (20 + 8 + 3) as u16);
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        write_u16(&mut p, 20, 1234);
        write_u16(&mut p, 22, 53);
        write_u16(&mut p, 24, (8 + 3) as u16);
        p[28] = 1;
        p[29] = 2;
        p[30] = 3;
        let mut ip = Ipv4::parse(&mut p).unwrap();
        ip.set_src(Ipv4Addr::new(10, 0, 0, 9));
        ip.set_source_port(40000);
        ip.recompute_header_checksum();
        ip.recompute_transport_checksum();
        let ip = Ipv4::parse(&mut p).unwrap();
        assert!(ip.checksum_valid());
        let t = ip.transport();
        let mut sum = 0;
        sum = add_bytes(sum, &ip.src().octets());
        sum = add_bytes(sum, &ip.dst().octets());
        sum += PROTO_UDP as u64 + t.len() as u64;
        sum = add_bytes(sum, t);
        assert_eq!(sum as u16, 0xffff);
        assert_eq!(ip.ports().unwrap().0, 40000);
    }

    #[test]
    fn arp_roundtrip() {
        let mut buf = vec![0u8; 64];
        let n = build_arp(
            &mut buf,
            [0xff; 6],
            [2, 0, 0, 0, 0, 1],
            1,
            [2, 0, 0, 0, 0, 1],
            Ipv4Addr::new(10, 0, 0, 1),
            [0; 6],
            Ipv4Addr::new(10, 0, 0, 2),
        );
        assert_eq!(n, 42);
        let info = parse_arp(&buf[ETH_HEADER_LEN..n]).unwrap();
        assert_eq!(info.operation, 1);
        assert_eq!(info.target_ip, Ipv4Addr::new(10, 0, 0, 2));
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;

    fn original() -> Vec<u8> {
        let mut pkt = ipv4_header(
            28,
            PROTO_UDP,
            "10.0.0.2".parse().unwrap(),
            "192.0.2.9".parse().unwrap(),
        );
        pkt.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
        let mut frame = finish_frame([1; 6], [2; 6], pkt);
        frame.drain(..ETH_HEADER_LEN);
        frame
    }

    #[test]
    fn icmp_error_quotes_original_and_checksums() {
        let orig = original();
        let mut frame = build_icmp_error(
            [1; 6],
            [2; 6],
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            11,
            0,
            &orig,
        );
        assert_eq!(ethertype(&frame), ETHERTYPE_IPV4);
        let ip = Ipv4::parse(&mut frame[ETH_HEADER_LEN..]).unwrap();
        assert!(ip.checksum_valid());
        assert_eq!(ip.protocol(), PROTO_ICMP);
        let icmp = ip.transport();
        assert_eq!(icmp[0], 11);
        assert_eq!(&icmp[8..], &orig[..28]);
        let sum = add_bytes(0, icmp);
        assert_eq!(fold_checksum(sum), 0);
    }

    #[test]
    fn tcp_rst_has_valid_checksums() {
        let mut frame = build_tcp_rst(
            [1; 6],
            [2; 6],
            "192.0.2.9".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            40000,
            0,
            1001,
            true,
        );
        let ip = Ipv4::parse(&mut frame[ETH_HEADER_LEN..]).unwrap();
        assert!(ip.checksum_valid());
        assert_eq!(ip.tcp_flags(), Some(0x14));
        let t = ip.transport().to_vec();
        let mut sum = 0u64;
        sum = add_bytes(sum, &ip.src().octets());
        sum = add_bytes(sum, &ip.dst().octets());
        sum += PROTO_TCP as u64;
        sum += t.len() as u64;
        sum = add_bytes(sum, &t);
        assert_eq!(fold_checksum(sum), 0);
    }

    #[test]
    fn parsers_survive_truncated_and_pseudo_random_input() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for len in 0..256usize {
            let mut bytes = vec![0u8; len];
            for b in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            assert!(ethertype(&bytes) <= u16::MAX);
            let _ = parse_arp(&bytes);
            let mut copy = bytes;
            if let Some(ip) = Ipv4::parse(&mut copy) {
                let _ = ip.ports();
                let _ = ip.tcp_flags();
                let _ = ip.icmp_type();
                let _ = icmp_identity(&ip);
                let _ = ip.is_fragment();
                let _ = ip.transport_sane();
                let _ = ip.transport_checksum_valid();
            }
        }
    }

    #[test]
    fn detects_fragments() {
        let mut orig = original();
        assert!(!Ipv4::parse(&mut orig).unwrap().is_fragment());
        orig[6] = 0x20; // more-fragments
        assert!(Ipv4::parse(&mut orig).unwrap().is_fragment());
        orig[6] = 0x00;
        orig[7] = 0x08; // non-zero offset
        assert!(Ipv4::parse(&mut orig).unwrap().is_fragment());
    }
}
