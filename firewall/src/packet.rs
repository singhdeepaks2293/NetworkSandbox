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
