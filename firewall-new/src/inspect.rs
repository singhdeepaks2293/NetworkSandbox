//! Lightweight application inspection used by the security profiles.
//!
//! This is deliberately bounded per packet: HTTP `Host` and TLS ClientHello
//! SNI are extracted when they fit in one segment, and IPS/AV signatures are
//! literal byte patterns. It is not a TCP reassembly engine, so split headers
//! are not inspected.

use crate::packet::{read_u16, Ipv4, PROTO_TCP, PROTO_UDP};

pub fn payload<'a>(ip: &'a Ipv4<'_>) -> &'a [u8] {
    let transport = ip.transport();
    match ip.protocol() {
        PROTO_TCP => {
            if transport.len() < 20 {
                return &[];
            }
            let offset = ((transport[12] >> 4) as usize) * 4;
            if offset < 20 || offset > transport.len() {
                return &[];
            }
            &transport[offset..]
        }
        PROTO_UDP => {
            if transport.len() < 8 {
                return &[];
            }
            &transport[8..]
        }
        _ => &[],
    }
}

pub fn decode_pattern(pattern: &str) -> Vec<u8> {
    let bytes = pattern.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'x' | b'X' if i + 3 < bytes.len() => {
                    let hex = &pattern[i + 2..i + 4];
                    if let Ok(value) = u8::from_str_radix(hex, 16) {
                        out.push(value);
                        i += 4;
                        continue;
                    }
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

pub fn pattern_matches(payload: &[u8], pattern: &str) -> bool {
    let needle = decode_pattern(pattern);
    if needle.is_empty() {
        return false;
    }
    payload.windows(needle.len()).any(|window| window == needle)
}

fn starts_with_method(payload: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    METHODS
        .iter()
        .any(|method| payload.len() >= method.len() && payload.starts_with(method))
}

pub fn http_host(payload: &[u8]) -> Option<String> {
    if !starts_with_method(payload) {
        return None;
    }
    let window = &payload[..payload.len().min(8192)];
    let mut offset = 0;
    while let Some(found) = find_ci(&window[offset..], b"\r\nhost:") {
        let header_start = offset + found + b"\r\nhost:".len();
        let mut value_start = header_start;
        while value_start < window.len()
            && (window[value_start] == b' ' || window[value_start] == b'\t')
        {
            value_start += 1;
        }
        let mut end = value_start;
        while end < window.len() && window[end] != b'\r' && window[end] != b'\n' {
            end += 1;
        }
        if end > value_start {
            return String::from_utf8(window[value_start..end].to_vec()).ok();
        }
        offset = header_start;
    }
    None
}

fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

fn read16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(read_u16(data, offset))
}

pub fn tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1)=22 handshake, version(2), length(2).
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let record_len = read_u16(payload, 3) as usize;
    let record_end = (5 + record_len).min(payload.len());
    if record_end < 9 || payload[5] != 0x01 {
        return None;
    }
    let handshake_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | payload[8] as usize;
    let body = &payload[9..(9 + handshake_len).min(record_end)];
    if body.len() < 34 {
        return None;
    }
    // version(2) + random(32)
    let mut offset = 34;
    let session_len = *body.get(offset)? as usize;
    offset += 1 + session_len;
    let suites_len = read16(body, offset)? as usize;
    offset += 2 + suites_len;
    let compression_len = *body.get(offset)? as usize;
    offset += 1 + compression_len;
    if offset + 2 > body.len() {
        return None;
    }
    let extensions_len = read16(body, offset)? as usize;
    offset += 2;
    let end = (offset + extensions_len).min(body.len());
    while offset + 4 <= end {
        let ext_type = read16(body, offset)?;
        let ext_len = read16(body, offset + 2)? as usize;
        let ext_start = offset + 4;
        let ext_end = ext_start + ext_len;
        if ext_end > end {
            return None;
        }
        if ext_type == 0 {
            let ext = &body[ext_start..ext_end];
            if ext.len() < 5 {
                return None;
            }
            let list_len = read16(ext, 0)? as usize;
            if list_len + 2 > ext.len() || ext[2] != 0 {
                return None;
            }
            let name_len = read16(ext, 3)? as usize;
            if 5 + name_len > ext.len() {
                return None;
            }
            return String::from_utf8(ext[5..5 + name_len].to_vec()).ok();
        }
        offset = ext_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_escapes() {
        assert_eq!(decode_pattern("a\\x00b\\n"), b"a\x00b\n".to_vec());
    }

    #[test]
    fn finds_http_host() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: test\r\nHost: example.com\r\n\r\n";
        assert_eq!(http_host(request).as_deref(), Some("example.com"));
    }

    #[test]
    fn ignores_non_http() {
        assert!(http_host(b"\x16\x03\x01\x00\x00").is_none());
    }

    #[test]
    fn reads_udp_payload() {
        let mut data = vec![0u8; 20 + 8 + 3];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&(31u16).to_be_bytes());
        data[9] = PROTO_UDP;
        data[20 + 8..].copy_from_slice(b"abc");
        let ip = Ipv4::parse(&mut data).unwrap();
        assert_eq!(payload(&ip), b"abc");
        assert!(pattern_matches(payload(&ip), "abc"));
    }
}
