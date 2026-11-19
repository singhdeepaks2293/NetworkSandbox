//! TLS inspection (SSL decryption, "forward proxy" mode).
//!
//! The firewall sits between a client and a server as a man in the middle
//! that the client has agreed to trust by installing the firewall's CA:
//!
//! 1. The client's ClientHello is held. The firewall connects to the real
//!    server with the same SNI and **verifies its certificate first** against
//!    the public roots (plus any configured extra roots). A server that fails
//!    verification is never impersonated: the flow is blocked.
//! 2. Only then is the client's handshake answered, with a certificate for the
//!    same name forged on the fly and signed by the firewall's CA.
//! 3. Plaintext in both directions is inspected: the HTTP request line and
//!    Host (so URL filtering sees full URLs, not only the SNI), IPS
//!    signatures on requests and antivirus signatures on responses.
//! 4. A block sends an HTTP 403 replacement page inside the client's TLS
//!    session and closes the connection.
//!
//! Exempt hosts (banking, health, certificate-pinned apps) and non-TLS
//! traffic pass through unmodified.
//!
//! Status: this engine works on byte streams and is tested with real rustls
//! clients and servers. It is not yet connected to the packet dataplane,
//! which first needs to terminate TCP on both sides (a userspace TCP proxy).

// Most of this module is exercised only by its tests until the dataplane's
// TCP proxy uses it.
#![cfg_attr(not(test), allow(dead_code))]

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

// ----------------------------------------------------------------------- CA

/// The firewall's inspection CA. Clients must trust its certificate.
pub struct Ca {
    pub cert_pem: String,
    issuer: rcgen::Certificate,
    key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "NetworkSandbox NGFW");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = rcgen::date_time_ymd(2025, 1, 1);
    p.not_after = rcgen::date_time_ymd(2035, 1, 1);
    p
}

impl Ca {
    /// A new CA: returns it and its private key in PEM (store it 0600).
    pub fn generate(common_name: &str) -> Result<(Ca, String), String> {
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let key_pem = key.serialize_pem();
        let cert = ca_params(common_name).self_signed(&key).map_err(|e| e.to_string())?;
        let cert_pem = cert.pem();
        Ok((Ca { cert_pem, issuer: cert, key, cache: Mutex::new(HashMap::new()) }, key_pem))
    }

    /// Load a CA made by [`Ca::generate`]: the issuer identity is rebuilt
    /// from the name and key, which is all that signing leaves needs.
    pub fn load(common_name: &str, cert_pem: &str, key_pem: &str) -> Result<Ca, String> {
        let key = KeyPair::from_pem(key_pem).map_err(|e| format!("CA key: {e}"))?;
        let issuer = ca_params(common_name).self_signed(&key).map_err(|e| e.to_string())?;
        Ok(Ca { cert_pem: cert_pem.to_string(), issuer, key, cache: Mutex::new(HashMap::new()) })
    }

    /// A certificate for `host`, signed by this CA (cached per name).
    pub fn forge(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let host = host.to_ascii_lowercase();
        if let Some(ck) = self.cache.lock().unwrap().get(&host) {
            return Ok(ck.clone());
        }
        let mut p = CertificateParams::new(vec![host.clone()]).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.as_str());
        p.distinguished_name = dn;
        p.not_before = rcgen::date_time_ymd(2025, 1, 1);
        p.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf = p.signed_by(&leaf_key, &self.issuer, &self.key).map_err(|e| e.to_string())?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing = rustls::crypto::ring::sign::any_supported_type(&der).map_err(|e| e.to_string())?;
        let ca_der = CertificateDer::from(self.issuer.der().to_vec());
        let ck = Arc::new(CertifiedKey::new(vec![leaf.der().clone(), ca_der], signing));
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(host, ck.clone());
        Ok(ck)
    }
}

#[derive(Debug)]
struct Forger(Arc<Ca>, Mutex<Option<String>>);

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ca")
    }
}

impl ResolvesServerCert for Forger {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().map(str::to_string).or_else(|| self.1.lock().unwrap().clone())?;
        self.0.forge(&name).ok()
    }
}

// --------------------------------------------------------------- inspection

/// What inspection sees of a decrypted request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub host: String,
    pub path: String,
}

/// Policy hooks: return `Some(reason)` to block.
pub trait Inspector: Send {
    fn request(&self, req: &Request, bytes: &[u8]) -> Option<String>;
    fn response(&self, bytes: &[u8]) -> Option<String>;
}

pub fn parse_request(buf: &[u8]) -> Option<Request> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().split(':').next().unwrap_or("").to_ascii_lowercase())
        .unwrap_or_default();
    Some(Request { method, host, path })
}

/// The replacement page sent inside the client's TLS session.
pub fn block_page(reason: &str) -> Vec<u8> {
    let body = format!(
        "<html><head><title>Blocked</title></head><body><h1>Access blocked</h1><p>This request was blocked by the firewall's security policy.</p><p>Reason: {}</p></body></html>\n",
        reason.replace('<', "&lt;")
    );
    format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
}

// -------------------------------------------------------------- interceptor

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// Waiting for the first client bytes.
    Detect,
    /// Not TLS, or exempt: bytes are relayed unchanged.
    PassThrough(String),
    /// Verifying the server before answering the client.
    UpstreamHandshake,
    Decrypting,
    Blocked(String),
    Closed,
}

/// Bytes to send after one input.
#[derive(Debug, Default)]
pub struct Out {
    pub to_client: Vec<u8>,
    pub to_server: Vec<u8>,
    /// Close both connections after sending.
    pub close: bool,
}

pub struct Settings {
    pub ca: Arc<Ca>,
    /// Hosts (and their subdomains) never decrypted.
    pub exempt: Vec<String>,
    /// Extra trust anchors for upstream servers (e.g. an internal PKI).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

pub struct Interceptor {
    settings: Arc<Settings>,
    inspector: Box<dyn Inspector>,
    pub mode: Mode,
    pub sni: Option<String>,
    held_hello: Vec<u8>,
    client: Option<ServerConnection>,
    server: Option<ClientConnection>,
    request_buf: Vec<u8>,
    inspected_request: bool,
    response_window: Vec<u8>,
}

fn host_matches(host: &str, pattern: &str) -> bool {
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn drain_tls<C: std::ops::DerefMut<Target = rustls::ConnectionCommon<S>>, S: rustls::SideData>(conn: &mut C) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

impl Interceptor {
    pub fn new(settings: Arc<Settings>, inspector: Box<dyn Inspector>) -> Interceptor {
        Interceptor {
            settings,
            inspector,
            mode: Mode::Detect,
            sni: None,
            held_hello: Vec::new(),
            client: None,
            server: None,
            request_buf: Vec::new(),
            inspected_request: false,
            response_window: Vec::new(),
        }
    }

    fn block(&mut self, reason: String) -> Out {
        let mut out = Out { close: true, ..Out::default() };
        if let Some(c) = self.client.as_mut().filter(|c| !c.is_handshaking()) {
            let _ = c.writer().write_all(&block_page(&reason));
            c.send_close_notify();
            out.to_client = drain_tls(c);
        }
        self.mode = Mode::Blocked(reason);
        out
    }

    /// Bytes arriving from the client.
    pub fn from_client(&mut self, data: &[u8]) -> Out {
        match &self.mode {
            Mode::PassThrough(_) => return Out { to_server: data.to_vec(), ..Out::default() },
            Mode::Blocked(_) | Mode::Closed => return Out { close: true, ..Out::default() },
            Mode::Detect => {
                self.held_hello.extend_from_slice(data);
                let h = &self.held_hello;
                if h.len() < 5 || h[0] != 0x16 {
                    return self.pass_through("not TLS");
                }
                let record = 5 + usize::from(u16::from_be_bytes([h[3], h[4]]));
                if h.len() < record && h.len() < 16 * 1024 {
                    return Out::default(); // wait for the whole ClientHello
                }
                let sni = crate::inspect::tls_sni(h);
                let Some(sni) = sni else { return self.pass_through("no SNI") };
                self.sni = Some(sni.clone());
                if self.settings.exempt.iter().any(|e| host_matches(&sni, e)) {
                    return self.pass_through("exempt");
                }
                return self.start_upstream(&sni);
            }
            Mode::UpstreamHandshake => {
                self.held_hello.extend_from_slice(data);
                return Out::default();
            }
            Mode::Decrypting => {}
        }
        let client = self.client.as_mut().expect("decrypting has both sides");
        if client.read_tls(&mut &data[..]).is_err() {
            return self.block("client TLS error".into());
        }
        let client_closed = match client.process_new_packets() {
            Ok(io) => io.peer_has_closed(),
            Err(_) => return self.block("client TLS error".into()),
        };
        let mut plain = Vec::new();
        let _ = client.reader().read_to_end(&mut plain);
        let mut out = Out { to_client: drain_tls(client), ..Out::default() };
        if !plain.is_empty() {
            if !self.inspected_request {
                self.request_buf.extend_from_slice(&plain);
                if let Some(mut req) = parse_request(&self.request_buf) {
                    self.inspected_request = true;
                    if req.host.is_empty() {
                        req.host = self.sni.clone().unwrap_or_default();
                    }
                    if let Some(reason) = self.inspector.request(&req, &self.request_buf) {
                        let mut b = self.block(reason);
                        b.to_client = [out.to_client, b.to_client].concat();
                        return b;
                    }
                } else if self.request_buf.len() > 16 * 1024 {
                    self.inspected_request = true; // not HTTP, or a huge header
                }
            } else if let Some(reason) = self.inspector.request(&Request::default(), &plain) {
                let mut b = self.block(reason);
                b.to_client = [out.to_client, b.to_client].concat();
                return b;
            }
            let server = self.server.as_mut().expect("decrypting");
            let _ = server.writer().write_all(&plain);
            out.to_server = drain_tls(server);
        }
        if client_closed {
            let server = self.server.as_mut().expect("decrypting");
            server.send_close_notify();
            out.to_server.extend(drain_tls(server));
            out.close = true;
            self.mode = Mode::Closed;
        }
        out
    }

    /// Bytes arriving from the server.
    pub fn from_server(&mut self, data: &[u8]) -> Out {
        match &self.mode {
            Mode::PassThrough(_) => return Out { to_client: data.to_vec(), ..Out::default() },
            Mode::Blocked(_) | Mode::Closed => return Out { close: true, ..Out::default() },
            Mode::Detect => return Out::default(),
            _ => {}
        }
        let server = self.server.as_mut().expect("upstream exists");
        if let Err(e) = server.read_tls(&mut &data[..]).map_err(|e| e.to_string()).and_then(|_| server.process_new_packets().map(|_| ()).map_err(|e| e.to_string())) {
            // Certificate verification failures land here.
            return self.block(format!("upstream certificate or TLS error: {e}"));
        }
        let mut out = Out { to_server: drain_tls(self.server.as_mut().expect("upstream")), ..Out::default() };
        if self.mode == Mode::UpstreamHandshake {
            if self.server.as_ref().expect("upstream").is_handshaking() {
                return out;
            }
            // Upstream verified: now answer the client with a forged certificate.
            let mut cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Forger(self.settings.ca.clone(), Mutex::new(self.sni.clone()))));
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let mut client = match ServerConnection::new(Arc::new(cfg)) {
                Ok(c) => c,
                Err(e) => return self.block(format!("cannot start client TLS: {e}")),
            };
            let hello = std::mem::take(&mut self.held_hello);
            if client.read_tls(&mut &hello[..]).is_err() || client.process_new_packets().is_err() {
                return self.block("client TLS error".into());
            }
            out.to_client = drain_tls(&mut client);
            self.client = Some(client);
            self.mode = Mode::Decrypting;
        }
        let server = self.server.as_mut().expect("upstream");
        let mut plain = Vec::new();
        let _ = server.reader().read_to_end(&mut plain);
        if !plain.is_empty() {
            self.response_window.extend_from_slice(&plain);
            if let Some(reason) = self.inspector.response(&self.response_window) {
                let mut b = self.block(reason);
                b.to_server = out.to_server;
                return b;
            }
            let keep = self.response_window.len().saturating_sub(4096);
            self.response_window.drain(..keep);
            let client = self.client.as_mut().expect("decrypting");
            let _ = client.writer().write_all(&plain);
            out.to_client.extend(drain_tls(client));
        }
        out
    }

    fn pass_through(&mut self, why: &str) -> Out {
        self.mode = Mode::PassThrough(why.into());
        Out { to_server: std::mem::take(&mut self.held_hello), ..Out::default() }
    }

    fn start_upstream(&mut self, sni: &str) -> Out {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for r in &self.settings.extra_roots {
            let _ = roots.add(r.clone());
        }
        let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = match ServerName::try_from(sni.to_string()) {
            Ok(n) => n,
            Err(_) => return self.pass_through("SNI is not a valid name"),
        };
        let mut server = match ClientConnection::new(Arc::new(cfg), name) {
            Ok(c) => c,
            Err(e) => return self.block(format!("cannot start upstream TLS: {e}")),
        };
        let first = drain_tls(&mut server);
        self.server = Some(server);
        self.mode = Mode::UpstreamHandshake;
        Out { to_server: first, ..Out::default() }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A "public" CA and a server certificate it issued, for test servers.
    pub(crate) fn public_server(host: &str) -> (CertificateDer<'static>, Arc<ServerConfig>) {
        let (ca, _) = Ca::generate("Test Public Root").unwrap();
        let ck = ca.forge(host).unwrap();
        let root = CertificateDer::from(ca.issuer.der().to_vec());
        let cfg = ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(Fixed(ck)));
        (root, Arc::new(cfg))
    }

    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);
    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    pub(crate) struct Rules;
    impl Inspector for Rules {
        fn request(&self, req: &Request, bytes: &[u8]) -> Option<String> {
            if req.path.starts_with("/admin") {
                return Some(format!("url-filter: {}{}", req.host, req.path));
            }
            bytes.windows(11).any(|w| w == b"/etc/passwd").then(|| "ips: path traversal".to_string())
        }
        fn response(&self, bytes: &[u8]) -> Option<String> {
            bytes.windows(5).any(|w| w == b"EICAR").then(|| "av: EICAR test file".to_string())
        }
    }

    pub(crate) fn client_trusting(ca_pem: &str, host: &str) -> ClientConnection {
        let mut roots = RootCertStore::empty();
        let der = rustls_pemfile::certs(&mut ca_pem.as_bytes()).next().unwrap().unwrap();
        roots.add(der).unwrap();
        let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        ClientConnection::new(Arc::new(cfg), ServerName::try_from(host.to_string()).unwrap()).unwrap()
    }

    /// Drive client <-> interceptor <-> server until quiet. Returns the
    /// plaintext each end received.
    fn run(mitm: &mut Interceptor, client: &mut ClientConnection, server: &mut ServerConnection, request: &[u8], response: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let _ = client.writer().write_all(request);
        let (mut at_client, mut at_server) = (Vec::new(), Vec::new());
        let mut responded = false;
        for _ in 0..50 {
            let c2m = drain_tls(client);
            let mut to_server = Vec::new();
            let mut to_client = Vec::new();
            if !c2m.is_empty() {
                let o = mitm.from_client(&c2m);
                to_server.extend(o.to_server);
                to_client.extend(o.to_client);
            }
            if !to_server.is_empty() {
                server.read_tls(&mut &to_server[..]).unwrap();
                server.process_new_packets().unwrap();
                let mut p = Vec::new();
                let _ = server.reader().read_to_end(&mut p);
                if !p.is_empty() {
                    at_server.extend(&p);
                    if !responded {
                        server.writer().write_all(response).unwrap();
                        responded = true;
                    }
                }
            }
            let s2m = drain_tls(server);
            if !s2m.is_empty() {
                let o = mitm.from_server(&s2m);
                to_client.extend(o.to_client);
                if !o.to_server.is_empty() {
                    server.read_tls(&mut &o.to_server[..]).unwrap();
                    let _ = server.process_new_packets();
                }
            }
            if !to_client.is_empty() {
                client.read_tls(&mut &to_client[..]).unwrap();
                if client.process_new_packets().is_err() {
                    break;
                }
                let mut p = Vec::new();
                let _ = client.reader().read_to_end(&mut p);
                at_client.extend(p);
            }
            if c2m.is_empty() && s2m.is_empty() && to_client.is_empty() && to_server.is_empty() {
                break;
            }
        }
        (at_client, at_server)
    }

    fn setup(host: &str, trust_upstream: bool, exempt: Vec<String>) -> (Interceptor, ClientConnection, ServerConnection, String) {
        let (ca, _) = Ca::generate("Firewall Inspection CA").unwrap();
        let ca_pem = ca.cert_pem.clone();
        let (root, scfg) = public_server(host);
        let settings = Arc::new(Settings { ca: Arc::new(ca), exempt, extra_roots: if trust_upstream { vec![root] } else { vec![] } });
        (Interceptor::new(settings, Box::new(Rules)), client_trusting(&ca_pem, host), ServerConnection::new(scfg).unwrap(), ca_pem)
    }

    #[test]
    fn decrypts_inspects_and_relays() {
        let (mut m, mut c, mut s, _) = setup("shop.example", true, vec![]);
        let (at_client, at_server) = run(&mut m, &mut c, &mut s, b"GET /cart HTTP/1.1\r\nHost: shop.example\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(m.mode, Mode::Decrypting);
        assert!(at_server.starts_with(b"GET /cart HTTP/1.1"), "request reached the server");
        assert!(at_client.ends_with(b"ok"), "response reached the client: {:?}", String::from_utf8_lossy(&at_client));
        // The client saw a certificate issued by the firewall's CA for the right name.
        let chain = c.peer_certificates().unwrap();
        assert_eq!(chain.len(), 2, "forged leaf + firewall CA");
    }

    #[test]
    fn blocks_url_path_with_a_replacement_page() {
        let (mut m, mut c, mut s, _) = setup("shop.example", true, vec![]);
        let (at_client, at_server) = run(&mut m, &mut c, &mut s, b"GET /admin/users HTTP/1.1\r\nHost: shop.example\r\n\r\n", b"");
        assert!(matches!(&m.mode, Mode::Blocked(r) if r.contains("shop.example/admin/users")), "{:?}", m.mode);
        assert!(at_server.is_empty(), "nothing reached the server");
        assert!(String::from_utf8_lossy(&at_client).starts_with("HTTP/1.1 403 Forbidden"), "{:?}", String::from_utf8_lossy(&at_client));
    }

    #[test]
    fn antivirus_on_decrypted_downloads() {
        let (mut m, mut c, mut s, _) = setup("files.example", true, vec![]);
        let (at_client, _) = run(&mut m, &mut c, &mut s, b"GET /f HTTP/1.1\r\nHost: files.example\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nX5O!P%@AP EICAR-STANDARD");
        assert!(matches!(&m.mode, Mode::Blocked(r) if r.contains("EICAR")));
        assert!(!String::from_utf8_lossy(&at_client).contains("X5O!P"), "malware never reached the client");
    }

    #[test]
    fn untrusted_upstream_is_never_impersonated() {
        let (mut m, mut c, mut s, _) = setup("evil.example", false, vec![]);
        let (at_client, at_server) = run(&mut m, &mut c, &mut s, b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n", b"");
        assert!(matches!(&m.mode, Mode::Blocked(r) if r.contains("certificate")), "{:?}", m.mode);
        assert!(at_client.is_empty() && at_server.is_empty());
        assert!(c.peer_certificates().is_none(), "the client never received a forged certificate");
    }

    #[test]
    fn exempt_hosts_pass_through_unchanged() {
        let (mut m, mut c, _, _) = setup("bank.example", true, vec!["bank.example".into()]);
        let first = drain_tls(&mut c);
        let o = m.from_client(&first);
        assert_eq!(m.mode, Mode::PassThrough("exempt".into()));
        assert_eq!(o.to_server, first, "the ClientHello is relayed byte for byte");
        assert!(o.to_client.is_empty(), "no forged certificate is offered");
    }

    #[test]
    fn plain_http_passes_through() {
        let (mut m, _, _, _) = setup("x.example", true, vec![]);
        let o = m.from_client(b"GET / HTTP/1.1\r\nHost: x.example\r\n\r\n");
        assert_eq!(m.mode, Mode::PassThrough("not TLS".into()));
        assert!(o.to_server.starts_with(b"GET /"));
    }

    #[test]
    fn ca_round_trips_and_forges_per_name() {
        let (ca, key_pem) = Ca::generate("Lab CA").unwrap();
        let again = Ca::load("Lab CA", &ca.cert_pem, &key_pem).unwrap();
        let ck = again.forge("www.example.org").unwrap();
        // A client that trusts the original CA PEM accepts certificates from the reloaded CA.
        let mut roots = RootCertStore::empty();
        roots.add(rustls_pemfile::certs(&mut ca.cert_pem.as_bytes()).next().unwrap().unwrap()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build().unwrap();
        let now = rustls::pki_types::UnixTime::now();
        use rustls::client::danger::ServerCertVerifier;
        verifier
            .verify_server_cert(&ck.cert[0], &ck.cert[1..], &ServerName::try_from("www.example.org").unwrap(), &[], now)
            .expect("forged leaf verifies against the original CA");
        assert!(Arc::ptr_eq(&again.forge("www.example.org").unwrap(), &ck), "cached");
    }
}
