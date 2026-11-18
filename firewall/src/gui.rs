//! HTTP management server and embedded single-page UI.

use crate::auth::{Auth, Role, Session};
use crate::dataplane::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_BODY: usize = 2 * 1024 * 1024;
const PRODUCT: &str = "VELA NGFW";
const VERSION: &str = "0.1.0";

pub fn serve(engine: Arc<Engine>, auth: Arc<Auth>) {
    let port = engine.cfg.read().unwrap().settings.gui_port;
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gui: cannot listen on port {port}: {e}");
            return;
        }
    };
    println!("gui: listening on http://0.0.0.0:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let engine = engine.clone();
                let auth = auth.clone();
                std::thread::spawn(move || handle(&engine, &auth, stream));
            }
            Err(e) => eprintln!("gui: accept: {e}"),
        }
    }
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl Response {
    fn new(status: u16, content_type: &'static str, body: String) -> Response {
        Response {
            status,
            content_type,
            body: body.into_bytes(),
            headers: Vec::new(),
        }
    }

    fn json(status: u16, value: Value) -> Response {
        Response::new(status, "application/json", value.to_string())
    }

    fn text(status: u16, value: String) -> Response {
        Response::new(status, "text/plain; charset=utf-8", value)
    }

    fn html(value: &str) -> Response {
        Response::new(200, "text/html; charset=utf-8", value.to_string())
    }

    fn header(mut self, key: &str, value: &str) -> Response {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    fn error(status: u16, message: &str) -> Response {
        Response::json(status, json!({"ok": false, "error": message}))
    }
}

struct Authn {
    session: Session,
    via_cookie: bool,
}

fn handle(engine: &Engine, auth: &Auth, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = split_target(&target);
    let mut headers = HashMap::new();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) => {
                if header == "\r\n" || header == "\n" {
                    break;
                }
                if let Some((key, value)) = header.split_once(':') {
                    let key = key.trim().to_ascii_lowercase();
                    let value = value.trim().to_string();
                    if key == "content-length" {
                        length = value.parse().unwrap_or(0);
                    }
                    headers.insert(key, value);
                }
            }
            Err(_) => return,
        }
    }
    if length > MAX_BODY {
        let _ = send(&mut stream, Response::error(413, "request body too large"));
        return;
    }
    let mut body = vec![0u8; length];
    if length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let request = Request {
        method,
        path,
        query,
        headers,
        body,
    };
    let response = route(engine, auth, &request);
    let _ = send(&mut stream, response);
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, raw) = target.split_once('?').unwrap_or((target, ""));
    let mut query = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(k), percent_decode(v));
    }
    (path.to_string(), query)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn route(engine: &Engine, auth: &Auth, req: &Request) -> Response {
    if req.method == "GET" && (req.path == "/" || req.path == "/index.html") {
        return Response::html(INDEX_HTML);
    }
    if req.path == "/healthz" || req.path == "/api/v1/health" {
        return Response::json(
            200,
            json!({"status": "ok", "product": PRODUCT, "version": VERSION}),
        );
    }
    if req.path == "/api/v1/auth/login" && req.method == "POST" {
        return login(auth, req);
    }
    let Some(authn) = authenticate(auth, req) else {
        return Response::error(401, "authentication required").header(
            "WWW-Authenticate",
            "Bearer realm=\"vela\", Cookie realm=\"vela\"",
        );
    };
    if is_write(&req.method) && authn.via_cookie {
        let supplied = req.headers.get("x-vela-csrf").map(String::as_str).unwrap_or("");
        if supplied.is_empty() || supplied != authn.session.csrf {
            return Response::error(403, "missing or invalid CSRF token");
        }
    }
    let path = req.path.as_str();
    match (req.method.as_str(), path) {
        ("GET", "/api/v1/auth/me") => Response::json(
            200,
            json!({
                "username": authn.session.username,
                "role": authn.session.role,
                "csrf": authn.session.csrf,
                "expires_in": authn.session.expires.saturating_duration_since(std::time::Instant::now()).as_secs(),
            }),
        ),
        ("POST", "/api/v1/auth/logout") => {
            if let Some(token) = session_cookie(req) {
                auth.logout(&token);
            }
            Response::json(200, json!({"ok": true})).header(
                "Set-Cookie",
                "vela_session=deleted; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            )
        }
        ("POST", "/api/v1/auth/password") => change_password(auth, &authn.session, req),
        ("GET", "/api/state" | "/api/v1/state" | "/api/v1/system") => {
            Response::new(200, "application/json", system_json(engine, &authn.session))
        }
        ("GET", "/api/config" | "/api/v1/configuration/running") => {
            Response::text(200, engine.running_text())
        }
        ("GET", "/api/v1/configuration") => Response::json(
            200,
            json!({
                "revision": engine.config_revision(),
                "staged": engine.candidate_text().is_some(),
                "running": engine.running_text(),
                "candidate": engine.candidate_text(),
                "diff": engine.config_diff(),
            }),
        ),
        ("GET", "/api/v1/configuration/candidate") => {
            Response::text(200, engine.candidate_text().unwrap_or_default())
        }
        ("POST", "/api/v1/configuration/candidate" | "/api/config") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            let text = request_config_text(req);
            match engine.stage_config(&text) {
                Ok(()) => {
                    auth.audit(
                        &authn.session.username,
                        "config.stage",
                        &format!("{} bytes", text.len()),
                    );
                    Response::json(
                        200,
                        json!({"ok": true, "staged": true, "diff": engine.config_diff()}),
                    )
                }
                Err(e) => Response::error(422, &e),
            }
        }
        ("DELETE", "/api/v1/configuration/candidate") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            engine.discard_candidate();
            auth.audit(&authn.session.username, "config.discard", "");
            Response::json(200, json!({"ok": true, "staged": false}))
        }
        ("GET", "/api/v1/configuration/diff") => Response::text(200, engine.config_diff()),
        ("POST", "/api/v1/configuration/commit") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            match engine.commit_candidate() {
                Ok(()) => {
                    auth.audit(&authn.session.username, "config.commit", "");
                    Response::json(
                        200,
                        json!({"ok": true, "revision": engine.config_revision()}),
                    )
                }
                Err(e) => {
                    auth.audit(&authn.session.username, "config.commit.failed", &e);
                    Response::error(422, &e)
                }
            }
        }
        ("POST", "/api/v1/configuration/rollback") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            match engine.rollback_config() {
                Ok(_) => {
                    auth.audit(&authn.session.username, "config.rollback", "");
                    Response::json(
                        200,
                        json!({"ok": true, "revision": engine.config_revision()}),
                    )
                }
                Err(e) => Response::error(409, &e),
            }
        }
        ("GET", "/api/v1/configuration/backup") => {
            Response::json(200, json!({
                "product": PRODUCT,
                "version": VERSION,
                "exported": now(),
                "revision": engine.config_revision(),
                "config": engine.running_text(),
            }))
        }
        ("POST", "/api/v1/configuration/restore") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            match serde_json::from_slice::<Value>(&req.body) {
                Ok(value) => {
                    let text = value
                        .get("config")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    match engine.stage_config(&text).and_then(|_| engine.commit_candidate()) {
                        Ok(()) => {
                            auth.audit(&authn.session.username, "config.restore", "");
                            Response::json(200, json!({"ok": true, "revision": engine.config_revision()}))
                        }
                        Err(e) => Response::error(422, &e),
                    }
                }
                Err(_) => Response::error(400, "expected JSON object with config"),
            }
        }
        ("GET", "/api/sessions" | "/api/v1/sessions") => {
            Response::new(200, "application/json", sessions_json(engine, &req.query))
        }
        ("GET", "/api/logs" | "/api/v1/logs") => {
            Response::new(200, "application/json", logs_json(engine, &req.query))
        }
        ("GET", "/api/v1/interfaces") => {
            let state: Value = serde_json::from_str(&state_json(engine)).unwrap_or(Value::Null);
            Response::json(200, json!({"interfaces": state["interfaces"]}))
        }
        ("GET", "/api/v1/zones") => Response::json(200, json!({"zones": zones_value(engine)})),
        ("GET", "/api/v1/routes") => Response::json(200, json!({"routes": routes_value(engine)})),
        ("GET", "/api/v1/policies") => Response::json(200, json!({"policies": policies_value(engine)})),
        ("GET", "/api/v1/nat") => Response::json(200, json!({"rules": nat_value(engine)})),
        ("GET", "/api/v1/objects") => Response::json(200, json!({"objects": objects_value(engine)})),
        ("GET", "/api/v1/security") => Response::json(200, json!({"security": security_value(engine)})),
        ("GET", "/api/v1/monitoring") => {
            Response::json(200, json!({"monitoring": monitoring_value(engine)}))
        }
        ("GET", "/api/v1/vpn") => Response::json(
            200,
            json!({
                "supported": false,
                "wireguard": {"state": "not_implemented"},
                "ipsec": {"state": "not_implemented"},
                "detail": "VPN orchestration is not implemented in this build"
            }),
        ),
        ("GET", "/api/v1/administrators") => match auth.list_admins(&authn.session) {
            Ok(admins) => Response::json(200, json!({"administrators": admins})),
            Err(e) => Response::error(403, &e),
        },
        ("POST", "/api/v1/administrators") => add_admin(auth, &authn.session, req),
        ("GET", "/api/v1/audit") => {
            let limit = req.query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200);
            Response::json(200, json!({"events": auth.audit_records(&authn.session, limit)}))
        }
        _ if path.starts_with("/api/v1/administrators/") => {
            admin_subroute(auth, &authn.session, req, path)
        }
        _ => Response::error(404, "not found"),
    }
}

fn login(auth: &Auth, req: &Request) -> Response {
    let value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "expected JSON credentials"),
    };
    let username = value.get("username").and_then(Value::as_str).unwrap_or("");
    let password = value.get("password").and_then(Value::as_str).unwrap_or("");
    match auth.login(username, password) {
        Ok((token, session)) => {
            let cookie = format!(
                "vela_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{}",
                if secure_cookie() { "; Secure" } else { "" }
            );
            Response::json(
                200,
                json!({
                    "ok": true,
                    "username": session.username,
                    "role": session.role,
                    "csrf": session.csrf,
                }),
            )
            .header("Set-Cookie", &cookie)
        }
        Err(e) => {
            auth.audit(username, "login.failed", &e);
            let status = if e.starts_with("too many") { 429 } else { 401 };
            Response::error(status, &e)
        }
    }
}

fn change_password(auth: &Auth, session: &Session, req: &Request) -> Response {
    let value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "expected JSON object"),
    };
    let current = value.get("current").and_then(Value::as_str).unwrap_or("");
    let new = value.get("password").and_then(Value::as_str).unwrap_or("");
    match auth.change_password(session, &session.username, Some(current), new) {
        Ok(()) => Response::json(200, json!({"ok": true})),
        Err(e) => Response::error(400, &e),
    }
}

fn add_admin(auth: &Auth, session: &Session, req: &Request) -> Response {
    let value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "expected JSON object"),
    };
    let username = value.get("username").and_then(Value::as_str).unwrap_or("");
    let password = value.get("password").and_then(Value::as_str).unwrap_or("");
    let role = value
        .get("role")
        .and_then(Value::as_str)
        .and_then(Role::parse)
        .unwrap_or(Role::Auditor);
    match auth.add_admin(session, username, password, role) {
        Ok(()) => Response::json(201, json!({"ok": true})),
        Err(e) => Response::error(400, &e),
    }
}

fn admin_subroute(auth: &Auth, session: &Session, req: &Request, path: &str) -> Response {
    let rest = path.trim_start_matches("/api/v1/administrators/");
    let mut parts = rest.split('/');
    let username = parts.next().unwrap_or("");
    let action = parts.next();
    let id = parts.next();
    match (req.method.as_str(), action, id) {
        ("DELETE", None, None) => match auth.delete_admin(session, username) {
            Ok(()) => Response::json(200, json!({"ok": true})),
            Err(e) => Response::error(400, &e),
        },
        ("POST", Some("tokens"), None) => {
            let value: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return Response::error(400, "expected JSON object"),
            };
            let name = value.get("name").and_then(Value::as_str).unwrap_or("api");
            let role = value
                .get("role")
                .and_then(Value::as_str)
                .and_then(Role::parse)
                .unwrap_or(session.role);
            match auth.create_api_token(session, username, name, role) {
                Ok(token) => Response::json(201, json!({"ok": true, "token": token})),
                Err(e) => Response::error(400, &e),
            }
        }
        ("DELETE", Some("tokens"), Some(id)) => {
            match auth.revoke_token(session, username, id) {
                Ok(()) => Response::json(200, json!({"ok": true})),
                Err(e) => Response::error(400, &e),
            }
        }
        _ => Response::error(404, "not found"),
    }
}

fn authenticate(auth: &Auth, req: &Request) -> Option<Authn> {
    if let Some(header) = req.headers.get("authorization") {
        if let Some(token) = header.strip_prefix("Bearer ") {
            if let Some(session) = auth.authenticate_api_token(token.trim()) {
                return Some(Authn { session, via_cookie: false });
            }
        }
    }
    if let Some(token) = session_cookie(req) {
        if let Some(session) = auth.session(&token) {
            return Some(Authn { session, via_cookie: true });
        }
    }
    None
}

fn session_cookie(req: &Request) -> Option<String> {
    req.headers
        .get("cookie")?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("vela_session=").map(str::to_string))
}

fn secure_cookie() -> bool {
    std::env::var("VELA_SECURE_COOKIE").map(|v| v == "1").unwrap_or(false)
}

fn is_write(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn request_config_text(req: &Request) -> String {
    let body = String::from_utf8_lossy(&req.body).to_string();
    if let Ok(value) = serde_json::from_str::<Value>(&body) {
        if let Some(text) = value.get("config").and_then(Value::as_str) {
            return text.to_string();
        }
    }
    body
}

fn send(stream: &mut TcpStream, mut response: Response) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        response.status, response.content_type, response.body.len()
    );
    head.push_str("X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n");
    if response.content_type.starts_with("text/html") {
        head.push_str("Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'\r\n");
    }
    for (key, value) in response.headers.drain(..) {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)
}

fn mac_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn state_json(engine: &Engine) -> String {
    let stats = engine.stats.lock().unwrap();
    let cfg = engine.cfg.read().unwrap();
    let interfaces: Vec<Value> = cfg
        .interfaces
        .iter()
        .map(|i| {
            let counters = stats.ifaces.get(&i.name);
            json!({
                "name": i.name,
                "vdom": i.vdom,
                "zone": i.zone,
                "address": i.address.map(|a| a.to_string()).unwrap_or_else(|| "-".to_string()),
                "mac": i.mac.map(mac_string).unwrap_or_else(|| "-".to_string()),
                "mtu": i.mtu,
                "rx": counters.map(|s| s.rx_packets).unwrap_or(0),
                "tx": counters.map(|s| s.tx_packets).unwrap_or(0),
                "rx_bytes": counters.map(|s| s.rx_bytes).unwrap_or(0),
                "tx_bytes": counters.map(|s| s.tx_bytes).unwrap_or(0),
                "drop": counters.map(|s| s.dropped).unwrap_or(0),
            })
        })
        .collect();
    let policies: Vec<Value> = cfg
        .policies
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "vdom": p.vdom,
                "src_zone": p.src_zone,
                "dst_zone": p.dst_zone,
                "src": p.src.to_string(),
                "dst": p.dst.to_string(),
                "proto": p.proto.to_string(),
                "dst_port": p.dst_port,
                "service": p.service,
                "action": p.action.as_str(),
                "nat": p.nat,
                "app": p.app,
                "url": p.url,
                "ips": p.ips,
                "av": p.av,
                "shaper": p.shaper,
                "logging": p.log,
            })
        })
        .collect();
    let mut vdoms = std::collections::BTreeSet::new();
    vdoms.insert("root".to_string());
    vdoms.extend(cfg.vdoms.iter().cloned());
    vdoms.extend(cfg.interfaces.iter().map(|i| i.vdom.clone()));
    vdoms.extend(cfg.policies.iter().map(|p| p.vdom.clone()));
    let value = json!({
        "hostname": cfg.settings.hostname,
        "config": cfg.to_text(),
        "uptime": engine.uptime_secs(),
        "accepted": stats.accepted,
        "denied": stats.denied,
        "arp_misses": stats.arp_misses,
        "errors": stats.errors,
        "sessions": engine.sessions.lock().unwrap().len(),
        "interfaces": interfaces,
        "policies": policies,
        "vdoms": vdoms.into_iter().collect::<Vec<String>>(),
        "current_vdom": cfg.current_vdom,
        "logging": cfg.settings.logging,
    });
    value.to_string()
}

fn sessions_json(engine: &Engine, query: &HashMap<String, String>) -> String {
    let vdom_filter = query.get("vdom").map(String::as_str).unwrap_or("");
    let text_filter = query.get("q").map(|q| q.to_ascii_lowercase()).unwrap_or_default();
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(500)
        .min(5000);
    let offset = query
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let now = std::time::Instant::now();
    let entries = engine.sessions.lock().unwrap().entries();
    let mut rows = Vec::new();
    for session in entries {
        if !vdom_filter.is_empty() && session.key.vdom != vdom_filter {
            continue;
        }
        let mut nat = Vec::new();
        if let Some((ip, port)) = session.nat_src {
            nat.push(format!("snat {ip}:{port}"));
        }
        if let Some((ip, port)) = session.nat_dst {
            nat.push(format!("dnat {ip}:{port}"));
        }
        let nat = if nat.is_empty() {
            "-".to_string()
        } else {
            nat.join(" / ")
        };
        let row = json!({
            "vdom": session.key.vdom,
            "proto": session.key.proto,
            "src": session.key.src.to_string(),
            "sport": session.key.sport,
            "dst": session.key.dst.to_string(),
            "dport": session.key.dport,
            "nat": nat,
            "policy": session.policy_id,
            "shaper": session.shaper,
            "ttl": session.expires.saturating_duration_since(now).as_secs(),
        });
        if !text_filter.is_empty()
            && !row.to_string().to_ascii_lowercase().contains(&text_filter)
        {
            continue;
        }
        rows.push(row);
    }
    let total = rows.len();
    let page: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
    json!({"sessions": page, "total": total, "offset": offset, "limit": limit}).to_string()
}

fn logs_json(engine: &Engine, query: &HashMap<String, String>) -> String {
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);
    let offset = query
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let filter = query
        .get("q")
        .or_else(|| query.get("filter"))
        .map(|q| q.to_ascii_lowercase())
        .unwrap_or_default();
    let logs = engine.logs.lock().unwrap();
    let matched: Vec<Value> = logs
        .iter()
        .filter(|line| filter.is_empty() || line.to_ascii_lowercase().contains(&filter))
        .map(|line| Value::String(line.clone()))
        .collect();
    let total = matched.len();
    let page: Vec<Value> = matched.into_iter().skip(offset).take(limit).collect();
    json!({"logs": page, "total": total, "offset": offset, "limit": limit, "buffer": logs.len()})
        .to_string()
}

fn system_json(engine: &Engine, session: &Session) -> String {
    let mut value: Value = serde_json::from_str(&state_json(engine)).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.insert("product".into(), json!(PRODUCT));
        map.insert("version".into(), json!(VERSION));
        map.insert("revision".into(), json!(engine.config_revision()));
        map.insert("user".into(), json!(session.username));
        map.insert("role".into(), json!(session.role.as_str()));
        map.insert("reporting".into(), monitoring_value(engine));
    }
    value.to_string()
}

fn monitoring_value(engine: &Engine) -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let load = load.split_whitespace().next().unwrap_or("0").to_string();
    let mut mem_total = 0u64;
    let mut mem_available = 0u64;
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("MemTotal:") {
                mem_total = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
            }
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                mem_available = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
            }
        }
    }
    let (disk_total, disk_free) = disk_usage();
    let stats = engine.stats.lock().unwrap();
    let rx: u64 = stats.ifaces.values().map(|s| s.rx_bytes).sum();
    let tx: u64 = stats.ifaces.values().map(|s| s.tx_bytes).sum();
    json!({
        "cpu_count": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "load1": load,
        "memory_total_kb": mem_total,
        "memory_available_kb": mem_available,
        "disk_total_bytes": disk_total,
        "disk_free_bytes": disk_free,
        "rx_bytes": rx,
        "tx_bytes": tx,
        "accepted": stats.accepted,
        "denied": stats.denied,
        "arp_misses": stats.arp_misses,
        "errors": stats.errors,
        "sessions": engine.sessions.lock().unwrap().len(),
        "uptime": engine.uptime_secs(),
    })
}

fn disk_usage() -> (u64, u64) {
    let Ok(path) = std::ffi::CString::new("/") else {
        return (0, 0);
    };
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut buf) } == 0 {
        (
            (buf.f_blocks as u64).saturating_mul(buf.f_frsize as u64),
            (buf.f_bavail as u64).saturating_mul(buf.f_frsize as u64),
        )
    } else {
        (0, 0)
    }
}

fn zones_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    let mut zones = std::collections::BTreeSet::new();
    for iface in &cfg.interfaces {
        zones.insert(iface.zone.clone());
    }
    for zone in &cfg.zones {
        zones.insert(zone.name.clone());
    }
    Value::Array(zones.into_iter().map(Value::String).collect())
}

fn routes_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    Value::Array(cfg.routes.iter().map(|r| json!({
        "vdom": r.vdom,
        "interface": r.interface,
        "gateway": r.via.map(|v| v.to_string()),
    })).collect())
}

fn policies_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    Value::Array(cfg.policies.iter().map(|p| json!({
        "id": p.id,
        "vdom": p.vdom,
        "src_zone": p.src_zone,
        "dst_zone": p.dst_zone,
        "src": p.src.to_string(),
        "dst": p.dst.to_string(),
        "proto": p.proto.to_string(),
        "dst_port": p.dst_port,
        "service": p.service,
        "action": p.action.as_str(),
        "nat": p.nat,
        "app": p.app,
        "url": p.url,
        "ips": p.ips,
        "av": p.av,
        "shaper": p.shaper,
        "logging": p.log,
    })).collect())
}

fn nat_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    let rules: Vec<Value> = cfg.dnat.iter().map(|d| json!({
        "id": d.id,
        "vdom": d.vdom,
        "proto": d.proto.to_string(),
        "dst": d.dst.to_string(),
        "dst_port": d.dst_port,
        "to_ip": d.to_ip.to_string(),
        "to_port": d.to_port,
    })).collect();
    Value::Array(rules)
}

fn objects_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    json!({
        "addresses": cfg.addresses.iter().map(|a| json!({
            "name": a.name,
            "entries": a.entries.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "address_groups": cfg.address_groups.iter().map(|g| json!({"name": g.name, "members": g.members})).collect::<Vec<_>>(),
        "services": cfg.services.iter().map(|s| json!({"name": s.name, "proto": s.proto.to_string(), "port": s.port})).collect::<Vec<_>>(),
        "applications": cfg.apps.iter().map(|a| json!({"name": a.name, "proto": a.proto.to_string(), "port": a.port})).collect::<Vec<_>>(),
        "url_filters": cfg.url_filters.iter().map(|u| json!({"name": u.name, "block": u.block})).collect::<Vec<_>>(),
        "shapers": cfg.shapers.iter().map(|s| json!({"name": s.name, "kbps": s.kbps})).collect::<Vec<_>>(),
    })
}

fn security_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    json!({
        "ips_profiles": cfg.ips_profiles.iter().map(|p| json!({"name": p.name, "patterns": p.patterns})).collect::<Vec<_>>(),
        "av_profiles": cfg.av_profiles.iter().map(|p| json!({"name": p.name, "patterns": p.patterns})).collect::<Vec<_>>(),
        "url_filters": cfg.url_filters.len(),
        "zones": cfg.zones.iter().map(|z| json!({"name": z.name, "syn_flood": z.syn_flood, "icmp_flood": z.icmp_flood})).collect::<Vec<_>>(),
        "tls_inspection": {"state": "not_implemented"},
        "vpn": {"state": "not_implemented"},
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VELA NGFW</title>
<style>
:root{
  --navy:#0d2b3e;--navy2:#123a52;--navy3:#16465f;--edge:#e35b45;
  --canvas:#eef2f5;--panel:#ffffff;--line:#d7dee5;--ink:#1d2a35;
  --muted:#6b7c8c;--blue:#1f6feb;--green:#12965c;--red:#cd3d3d;
  --amber:#b7791f;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--canvas);color:var(--ink);font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
button,input,select,textarea{font:inherit}
.topbar{height:52px;background:linear-gradient(90deg,var(--navy),var(--navy2));color:#eaf2f8;display:flex;align-items:center;gap:18px;padding:0 18px;border-bottom:3px solid var(--edge)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.02em;font-size:15px;white-space:nowrap}
.brand .mark{width:26px;height:26px;border:2px solid #fff;border-radius:5px;display:grid;place-items:center;font-size:13px;background:var(--edge);border-color:var(--edge)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#9fc0d4}
.topmeta{display:flex;align-items:center;gap:16px;margin-left:auto;font-size:12px;color:#c8dbe8}
.statusdot{width:8px;height:8px;border-radius:50%;background:#35d07f;display:inline-block;margin-right:6px;box-shadow:0 0 0 3px rgba(53,208,127,.15)}
.topbar button{background:transparent;border:1px solid rgba(255,255,255,.25);color:#eaf2f8;border-radius:4px;padding:6px 10px;cursor:pointer}
.topbar button:hover{background:rgba(255,255,255,.08)}
.layout{display:flex;min-height:calc(100% - 55px)}
.sidebar{width:232px;flex:0 0 232px;background:var(--navy);color:#c8d8e4;padding:10px 0 30px;overflow:auto}
.sidebar .group{border-bottom:1px solid rgba(255,255,255,.07)}
.sidebar .ghead{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;font-size:10px;text-transform:uppercase;letter-spacing:.13em;color:#7fa2b8;cursor:pointer;user-select:none}
.sidebar .ghead:hover{color:#dbe9f2}
.sidebar .ghead .chev{transition:transform .15s;font-size:9px}
.sidebar .group.closed .ghead .chev{transform:rotate(-90deg)}
.sidebar .group.closed .items{display:none}
.sidebar .item{display:flex;align-items:center;gap:9px;padding:8px 16px 8px 20px;cursor:pointer;font-size:12.5px;border-left:3px solid transparent;color:#c8d8e4}
.sidebar .item:hover{background:rgba(255,255,255,.05);color:#fff}
.sidebar .item.active{background:var(--navy3);border-left-color:var(--edge);color:#fff;font-weight:600}
.sidebar .item .ico{width:14px;text-align:center;opacity:.8}
.sidebar .badge{margin-left:auto;background:rgba(255,255,255,.13);border-radius:9px;padding:1px 7px;font-size:10px}
.main{flex:1;min-width:0;padding:18px 22px 36px}
.crumbs{font-size:11px;color:var(--muted);margin-bottom:6px}
.crumbs span{color:#9aa9b6}
.pagebar{display:flex;align-items:flex-end;gap:16px;margin-bottom:14px;flex-wrap:wrap}
.pagebar h1{font-size:21px;font-weight:600;margin:0;letter-spacing:-.01em}
.pagebar .sub{color:var(--muted);font-size:12px;margin-top:3px}
.actions{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{background:var(--blue);color:#fff;border:0;border-radius:4px;padding:7px 13px;cursor:pointer;font-weight:500}
.btn:hover{filter:brightness(1.07)}
.btn.secondary{background:#fff;color:#2b3a47;border:1px solid #b9c5cf}
.btn.secondary:hover{background:#f5f8fa}
.btn.danger{background:var(--red)}
.btn.ghost{background:transparent;color:#2b3a47;border:1px solid #b9c5cf}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;box-shadow:0 1px 2px rgba(20,40,60,.05)}
.card .chead{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--line);font-weight:600;font-size:13px}
.card .chead .hint{margin-left:auto;color:var(--muted);font-weight:400;font-size:11px}
.card .cbody{padding:14px}
.grid{display:grid;gap:14px}
.grid.cols-4{grid-template-columns:repeat(4,minmax(0,1fr))}
.grid.cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.grid.cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}
@media(max-width:1150px){.grid.cols-4{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){.grid.cols-2,.grid.cols-3{grid-template-columns:1fr}.sidebar{width:190px;flex-basis:190px}}
.metric{display:flex;align-items:center;gap:12px;padding:14px 16px}
.metric .ring{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff;flex:0 0 auto}
.metric .ring.ok{background:var(--green)}.metric .ring.bad{background:var(--red)}.metric .ring.info{background:var(--blue)}.metric .ring.warn{background:var(--amber)}
.metric b{display:block;font-size:20px;line-height:1.1}
.metric span{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}
.hero{display:flex;align-items:center;gap:18px;padding:16px 18px;background:linear-gradient(90deg,#f4f8fb,#fff)}
.hero .shield{width:52px;height:52px;border-radius:8px;background:var(--navy2);color:#fff;display:grid;place-items:center;font-size:23px;font-weight:700}
.hero h2{margin:0 0 3px;font-size:16px}
.hero p{margin:0;color:var(--muted);font-size:12px}
.hero .right{margin-left:auto;text-align:right;font-size:11px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#f4f7f9;color:#526475;text-align:left;font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td{padding:8px 10px;border-bottom:1px solid #e8edf1;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#f7fafc}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
.chip{display:inline-flex;align-items:center;gap:5px;border-radius:10px;padding:2px 8px;font-size:10.5px;font-weight:600;letter-spacing:.02em}
.chip.ok{background:#e3f5ec;color:#0c7a49}.chip.bad{background:#fbe7e7;color:#a92828}
.chip.info{background:#e8f0fd;color:#1c56b5}.chip.muted{background:#eef1f4;color:#5d6d7c}
.chip.warn{background:#fbf1dd;color:#8a5a12}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:6px}
.dot.on{background:var(--green)}.dot.off{background:#aab6c0}
.toolrow{display:flex;gap:10px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);background:#fbfcfd;flex-wrap:wrap}
.toolrow input[type=search],.toolrow input[type=text]{border:1px solid #bcc8d2;border-radius:4px;padding:6px 9px;min-width:220px;background:#fff}
.toolrow label{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:11.5px}
.empty{padding:30px 16px;text-align:center;color:var(--muted)}
.notice{padding:10px 14px;border-left:3px solid var(--blue);background:#eef4fd;color:#274a72;font-size:12px;margin-bottom:14px}
code.kbd{background:#eef1f4;border:1px solid #d5dce2;border-radius:3px;padding:1px 5px;font-family:ui-monospace,monospace;font-size:11px}
textarea{width:100%;min-height:460px;background:#0f1c26;color:#d9e7f1;border:1px solid #263d4d;border-radius:5px;padding:12px;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}
.formrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
.msg{min-height:18px;font-size:12px;color:var(--muted);margin-top:8px}
dialog{border:0;border-radius:8px;padding:0;width:min(760px,92vw);box-shadow:0 18px 60px rgba(10,30,45,.35)}
dialog::backdrop{background:rgba(10,25,38,.45)}
dialog .dhead{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line);font-weight:600;font-size:15px}
dialog .dhead button{margin-left:auto;background:transparent;border:0;font-size:18px;cursor:pointer;color:var(--muted)}
dialog .dbody{padding:16px 18px}
dialog .dfoot{display:flex;justify-content:flex-end;gap:8px;padding:12px 18px;border-top:1px solid var(--line);background:#fafcfd}
.logrow td{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
.toast{position:fixed;right:18px;bottom:18px;background:#193244;color:#fff;padding:10px 14px;border-radius:5px;font-size:12px;box-shadow:0 8px 30px rgba(0,0,0,.25);opacity:0;transform:translateY(8px);transition:.2s;pointer-events:none;z-index:40}
.toast.show{opacity:1;transform:none}
.toast.bad{background:#8e2a2a}
.legend{display:flex;gap:14px;color:var(--muted);font-size:11px;flex-wrap:wrap}
.loginwrap{position:fixed;inset:0;background:linear-gradient(135deg,#0a2130,#123a52);display:grid;place-items:center;z-index:100;padding:20px}
.loginwrap[hidden]{display:none}
.loginbox{width:min(390px,100%);background:#fff;border-radius:10px;padding:26px 26px 22px;box-shadow:0 24px 80px rgba(0,0,0,.38)}
.loginbox .mark{width:44px;height:44px;border-radius:8px;background:var(--edge);color:#fff;display:grid;place-items:center;font-size:22px;font-weight:700;margin-bottom:12px}
.loginbox h2{margin:0 0 4px;font-size:20px}
.loginbox p{margin:0 0 18px;color:var(--muted);font-size:12px}
.loginbox label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:12px 0 5px}
.loginbox input{width:100%;border:1px solid #b9c5cf;border-radius:5px;padding:9px 10px;background:#fff}
.loginbox .btn{width:100%;margin-top:18px;padding:10px}
.loginerr{min-height:18px;margin-top:10px;color:#b02a2a;font-size:12px}
.loginfoot{margin-top:16px;color:#8294a2;font-size:11px;text-align:center}
</style>
</head>
<body>
<div id="login" class="loginwrap" hidden>
  <form class="loginbox" id="login-form" autocomplete="on">
    <div class="mark">V</div>
    <h2>VELA NGFW</h2>
    <p>Sign in to manage firewall policy, VDOMs and monitoring.</p>
    <label for="login-user">Administrator</label>
    <input id="login-user" name="username" autocomplete="username" required autofocus>
    <label for="login-pass">Password</label>
    <input id="login-pass" name="password" type="password" autocomplete="current-password" required>
    <div class="loginerr" id="login-err"></div>
    <button class="btn" type="submit" id="login-submit">Sign in</button>
    <div class="loginfoot">Authorized access only. Sessions expire after 8 hours.</div>
  </form>
</div>
<div class="topbar">
  <div class="brand"><div class="mark">V</div><div>VELA NGFW<small>Network Security Platform</small></div></div>
  <div class="topmeta">
    <span><span class="statusdot"></span><span id="top-host">loading</span></span>
    <span id="top-model">VM-01</span>
    <span id="top-uptime">up --</span>
    <label style="display:flex;align-items:center;gap:6px">VDOM
      <select id="vdom-select" style="background:#0b2534;color:#eaf2f8;border:1px solid rgba(255,255,255,.28);border-radius:4px;padding:5px 8px">
        <option value="all">Global (all VDOMs)</option>
      </select>
    </label>
    <span id="top-user">signed out</span>
    <button id="refresh">Refresh</button>
    <button id="logout">Sign out</button>
  </div>
</div>
<div class="layout">
  <aside class="sidebar" id="nav">
    <div class="group"><div class="ghead">Dashboard <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="dashboard"><span class="ico">◧</span>Status</div>
    </div></div>
    <div class="group"><div class="ghead">Network <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="interfaces"><span class="ico">▤</span>Interfaces</div>
      <div class="item" data-page="routing"><span class="ico">⇄</span>Static Routing</div>
    </div></div>
    <div class="group"><div class="ghead">Policy &amp; Objects <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="policies"><span class="ico">☰</span>Firewall Policy<span class="badge" id="badge-policies">0</span></div>
      <div class="item" data-page="addresses"><span class="ico">◎</span>Addresses<span class="badge" id="badge-addresses">0</span></div>
      <div class="item" data-page="services"><span class="ico">◇</span>Services<span class="badge" id="badge-services">0</span></div>
      <div class="item" data-page="dnat"><span class="ico">↦</span>Virtual IPs / DNAT<span class="badge" id="badge-dnat">0</span></div>
      <div class="item" data-page="shapers"><span class="ico">≋</span>Traffic Shapers<span class="badge" id="badge-shapers">0</span></div>
    </div></div>
    <div class="group"><div class="ghead">Security Profiles <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="urlfilters"><span class="ico">⌁</span>URL Filter</div>
      <div class="item" data-page="ips"><span class="ico">◈</span>IPS Signatures</div>
      <div class="item" data-page="av"><span class="ico">✚</span>Antivirus</div>
    </div></div>
    <div class="group"><div class="ghead">Monitor <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="sessions"><span class="ico">⇆</span>Session Table<span class="badge" id="badge-sessions">0</span></div>
      <div class="item" data-page="logs"><span class="ico">▦</span>Traffic Log</div>
    </div></div>
    <div class="group"><div class="ghead">System <span class="chev">v</span></div><div class="items">
      <div class="item" data-page="vdoms"><span class="ico">▥</span>Virtual Domains<span class="badge" id="badge-vdoms">0</span></div>
      <div class="item" data-page="config"><span class="ico">⚙</span>Configuration</div>
    </div></div>
  </aside>
  <main class="main">
    <div class="crumbs">VELA <span>/</span> <span id="crumb">Dashboard</span></div>
    <div class="pagebar"><div><h1 id="title">Status</h1><div class="sub" id="subtitle">System health and traffic overview</div></div><div class="actions" id="pageactions"></div></div>
    <div id="view"></div>
  </main>
</div>
<dialog id="editor">
  <div class="dhead"><span id="editor-title">Edit configuration</span><button id="editor-close" type="button">×</button></div>
  <div class="dbody">
    <div class="notice">Changes are validated and applied atomically. The full configuration language is accepted here; use the tables and pages to review the result.</div>
    <textarea id="cfg" spellcheck="false"></textarea>
    <div class="msg" id="editor-msg"></div>
  </div>
  <div class="dfoot"><button class="btn secondary" id="editor-reload" type="button">Reload from device</button><button class="btn" id="editor-save" type="button">Save &amp; Apply</button></div>
</dialog>
<div class="toast" id="toast"></div>
<script>
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const requestedVdom=new URLSearchParams(location.search).get('vdom');
const state={data:null,cfg:null,objects:null,page:'dashboard',sessions:[],logs:[],timer:null,logTimer:null,vdom:requestedVdom||'all'};
const nativeFetch=window.fetch.bind(window);
window.fetch=async function(input,init){
  const opts=Object.assign({},init||{});
  const method=String(opts.method||'GET').toUpperCase();
  const headers=new Headers(opts.headers||{});
  if(state.csrf&&method!=='GET'&&method!=='HEAD'&&method!=='OPTIONS')headers.set('X-VELA-CSRF',state.csrf);
  opts.headers=headers;
  const res=await nativeFetch(input,opts);
  if(res.status===401&&!String(input).includes('/auth/login'))showLogin();
  return res;
};
function showLogin(){
  const el=$('login'); if(el)el.hidden=false;
  const u=$('top-user'); if(u)u.textContent='signed out';
  setTimeout(()=>{const f=$('login-user');if(f)f.focus();},40);
}
function fmtRole(role){return String(role||'').replace(/_/g,' ');}
async function loadMe(){
  try{
    const r=await nativeFetch('/api/v1/auth/me',{cache:'no-store'});
    if(!r.ok){showLogin();return false;}
    const j=await r.json();
    state.csrf=j.csrf||''; state.user=j.username||''; state.role=j.role||'';
    $('top-user').textContent=state.user+' · '+fmtRole(state.role);
    $('login').hidden=true;
    return true;
  }catch(e){showLogin();return false;}
}
async function doLogin(ev){
  ev.preventDefault();
  const err=$('login-err'),btn=$('login-submit');
  err.textContent=''; btn.disabled=true; btn.textContent='Signing in…';
  try{
    const r=await nativeFetch('/api/v1/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:$('login-user').value.trim(),password:$('login-pass').value})});
    const j=await r.json().catch(()=>({error:'invalid response'}));
    if(!r.ok){err.textContent=r.status===429?'Too many attempts. Try again later.':(j.error||('Sign-in failed ('+r.status+')'));return;}
    state.csrf=j.csrf||''; state.user=j.username||''; state.role=j.role||'';
    $('login').hidden=true; $('top-user').textContent=state.user+' · '+fmtRole(state.role);
    $('login-pass').value='';
    await startApp();
  }catch(e){err.textContent='Management server unreachable';}
  finally{btn.disabled=false; btn.textContent='Sign in';}
}
async function doLogout(){
  try{await fetch('/api/v1/auth/logout',{method:'POST'});}catch(e){}
  state.csrf=''; state.user=''; state.role=''; state.data=null; state.cfg=null; state.objects=null;
  clearInterval(state.timer); showLogin();
}
async function startApp(){
  await loadState(); await loadSessions(); await loadLogs();
  if(!state.cfg)await loadCfg();
  state.objects=parseCfg(state.cfg);
  navigate((location.hash.replace(/^#\/?/,'')||'dashboard'));
  clearInterval(state.timer); state.timer=setInterval(async()=>{
    if(state.page==='logs'||state.page==='sessions'){await loadSessions();if(state.page==='logs')await loadLogs();}
    await loadState();
    if(['dashboard','interfaces','sessions','logs'].includes(state.page))render();
  },3000);
}
function scope(){return state.vdom||'all';}
function inScope(x){return scope()==='all'||x.vdom===scope();}

const pages={
  dashboard:['Status','System health and traffic overview'],
  interfaces:['Interfaces','Physical and logical interface status'],
  routing:['Static Routing','Default route and forwarding table'],
  policies:['Firewall Policy','Ordered security policies applied to transit traffic'],
  addresses:['Addresses','IPv4 host and subnet objects'],
  services:['Services','Protocol and port service objects'],
  dnat:['Virtual IPs / DNAT','Destination translation rules'],
  shapers:['Traffic Shapers','Per-policy bandwidth limits'],
  urlfilters:['URL Filter','HTTP host and TLS SNI allow/block lists'],
  ips:['IPS Signatures','Inline payload signatures'],
  av:['Antivirus','Inline malware signatures'],
  sessions:['Session Table','Live connection tracker entries'],
  logs:['Traffic Log','Recent policy and inspection events'],
  vdoms:['Virtual Domains','Independent policy, routing and NAT partitions'],
  config:['Configuration','Full device configuration']
};

function parseCfg(text){
  const o={interfaces:[],policies:[],addresses:[],groups:[],services:[],apps:[],urlfilters:[],ips:[],av:[],shapers:[],dnat:[],zones:[],routes:[],vdoms:[],settings:{}};
  let cur='root';
  for(const raw of (text||'').split('\n')){
    const line=raw.split('#')[0].trim(); if(!line) continue;
    const w=line.split(/\s+/); const key=w[0];
    const val=(name)=>{const i=w.indexOf(name);return i>=0?w[i+1]:''};
    if(key==='system'){o.settings[w[1]]=w[2];}
    else if(key==='vdom'){cur=w[1]||'root';if(!o.vdoms.includes(cur))o.vdoms.push(cur);}
    else if(key==='interface'){
      const i={name:w[1],vdom:cur,zone:val('zone'),address:val('address'),mac:val('mac'),mtu:val('mtu')};
      o.interfaces.push(i);
    }
    else if(key==='route'){o.routes.push({vdom:cur,interface:w[1],via:val('via')});}
    else if(key==='address'){o.addresses.push({name:w[1],entries:w.slice(2)});}
    else if(key==='address-group'){o.groups.push({name:w[1],members:w.slice(2)});}
    else if(key==='service'){o.services.push({name:w[1],proto:w[2],port:w[3]});}
    else if(key==='app-def'){o.apps.push({name:w[1],proto:w[2],port:w[3]});}
    else if(key==='url-filter'){o.urlfilters.push({name:w[1],action:w[2],entries:w.slice(3)});}
    else if(key==='ips-profile'){o.ips.push({name:w[1],patterns:[]});}
    else if(key==='ips-signature'){const p=o.ips.find(x=>x.name===w[1]); if(p)p.patterns.push(w.slice(3).join(' '));}
    else if(key==='av-profile'){o.av.push({name:w[1],patterns:[]});}
    else if(key==='av-signature'){const p=o.av.find(x=>x.name===w[1]); if(p)p.patterns.push(w.slice(3).join(' '));}
    else if(key==='shaper'){o.shapers.push({name:w[1],kbps:w[2]});}
    else if(key==='dnat'){o.dnat.push({id:w[1],vdom:cur,proto:w[2],dst:w[3],dport:w[4],to_ip:w[5],to_port:w[6]});}
    else if(key==='zone'){o.zones.push({name:w[1],vdom:cur,limit:w[2]+' '+w[3]});}
    else if(key==='policy'){
      const p={id:w[1],vdom:cur};
      for(let i=2;i<w.length;i++){
        const t=w[i];
        if(['permit','deny'].includes(t)) p.action=t;
        else if(t==='nat'||t==='log'||t==='nolog'){if(t==='nat')p.nat=true; if(t==='log')p.log=true;}
        else if(i%2===0){p[t]=w[i+1]||''; i++;}
      }
      o.policies.push(p);
    }
  }
  return o;
}
function chipAction(a){return a==='permit'?'<span class="chip ok">ACCEPT</span>':'<span class="chip bad">DENY</span>';}
function ifaceState(i){return i.address&&i.address!=='-'?'on':'off';}
function cards(){
  const s=state.data; if(!s) return '';
  const scopedSessions=(state.sessions||[]).filter(inScope);
  return `<div class="grid cols-4">
    <div class="card metric"><div class="ring ok">OK</div><div><b>${s.accepted}</b><span>Accepted packets</span></div></div>
    <div class="card metric"><div class="ring bad">!</div><div><b>${s.denied}</b><span>Denied packets</span></div></div>
    <div class="card metric"><div class="ring info">⇆</div><div><b>${scopedSessions.length}</b><span>Active sessions</span></div></div>
    <div class="card metric"><div class="ring warn">!</div><div><b>${s.errors+s.arp_misses}</b><span>Errors / ARP misses</span></div></div>
  </div>`;
}
function renderDashboard(){
  const s=state.data,o=state.objects;
  const ifaces=((s&&s.interfaces)||[]).filter(inScope);
  const scopedPolicies=((s&&s.policies)||[]).filter(inScope);
  const scopedSessions=(state.sessions||[]).filter(inScope);
  const scopedRoutes=(o?o.routes:[]).filter(inScope);
  const up=ifaces.filter(i=>i.address!=='—'&&i.address!=='-').length;
  return cards()+
  `<div class="grid cols-2" style="margin-top:14px">
    <div class="card"><div class="chead">System Information <span class="hint">control plane</span></div><div class="cbody">
      <div class="hero"><div class="shield">V</div><div><h2>${esc(s?s.hostname:'device')}</h2><p>Stateful inspection firewall · NGFW-VM</p></div><div class="right">Uptime<br><b>${s?fmtUptime(s.uptime):'--'}</b></div></div>
      <table style="margin-top:12px"><tbody>
        <tr><td>Firmware</td><td>VELA NGFW 0.1.0 (Rust)</td></tr>
        <tr><td>Mode</td><td>NAT / Route</td></tr>
        <tr><td>Virtual domains</td><td>${(o&&o.vdoms?o.vdoms.length:1)} total · viewing <b>${esc(scope()==='all'?'Global':scope())}</b></td></tr>
        <tr><td>Interfaces online</td><td>${up} of ${ifaces.length}</td></tr>
        <tr><td>Default route</td><td class="mono">${scopedRoutes.length?esc(scopedRoutes[0].interface+(scopedRoutes[0].via?' via '+scopedRoutes[0].via:'')):'not configured'}</td></tr>
        <tr><td>Logging</td><td>${o&&o.settings.logging==='on'?'<span class="chip ok">ENABLED</span>':'<span class="chip muted">DISABLED</span>'} <span class="mono">${o?esc(o.settings['log-format']||'text'):''}</span></td></tr>
      </tbody></table>
    </div></div>
    <div class="card"><div class="chead">Interface Status <span class="hint"><span class="dot on"></span>up <span class="dot off" style="margin-left:8px"></span>unassigned</span></div>
      <table><thead><tr><th>Interface</th><th>VDOM</th><th>Zone</th><th>Address</th><th class="num">RX</th><th class="num">TX</th></tr></thead><tbody>
      ${ifaces.map(i=>`<tr><td><span class="dot ${i.address&&i.address!=='-'?'on':'off'}"></span>${esc(i.name)}</td><td><span class="chip muted">${esc(i.vdom||'root')}</span></td><td>${esc(i.zone)}</td><td class="mono">${esc(i.address)}</td><td class="num">${i.rx}</td><td class="num">${i.tx}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No interfaces</td></tr>'}
      </tbody></table>
    </div>
  </div>
  <div class="grid cols-2" style="margin-top:14px">
    <div class="card"><div class="chead">Recent Security Events <span class="hint">latest 6</span></div>
      <table><thead><tr><th>Action</th><th>Source</th><th>Destination</th><th>Policy</th></tr></thead><tbody>
      ${(state.logs||[]).slice(-6).reverse().map(logRowBrief).join('')||'<tr><td colspan="4" class="empty">No events logged yet</td></tr>'}
      </tbody></table>
    </div>
    <div class="card"><div class="chead">Policy Summary <span class="hint">${scopedPolicies.length} policies</span></div>
      <table><thead><tr><th>VDOM</th><th>ID</th><th>From</th><th>To</th><th>Action</th><th>NAT</th></tr></thead><tbody>
      ${scopedPolicies.slice(0,6).map(p=>`<tr><td><span class="chip muted">${esc(p.vdom||'root')}</span></td><td>${p.id}</td><td>${esc(p.src_zone)}</td><td>${esc(p.dst_zone)}</td><td>${chipAction(p.action)}</td><td>${p.nat?'<span class="chip info">SNAT</span>':'—'}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No policies</td></tr>'}
      </tbody></table>
    </div>
  </div>`;
}
function fmtUptime(sec){sec=Number(sec)||0;const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m';}
function renderInterfaces(){
  const s=state.data;
  return `<div class="card"><div class="chead">Interface Status <span class="hint">configuration and counters</span></div>
  <table><thead><tr><th>Name</th><th>VDOM</th><th>Zone</th><th>Address</th><th>MAC</th><th class="num">RX packets</th><th class="num">TX packets</th><th class="num">Dropped</th></tr></thead><tbody>
  ${((s&&s.interfaces)||[]).filter(inScope).map(i=>`<tr><td><span class="dot ${i.address&&i.address!=='-'?'on':'off'}"></span><b>${esc(i.name)}</b></td><td><span class="chip muted">${esc(i.vdom||'root')}</span></td><td>${esc(i.zone)}</td><td class="mono">${esc(i.address)}</td><td class="mono">${esc(i.mac)}</td><td class="num">${i.rx}</td><td class="num">${i.tx}</td><td class="num">${i.drop}</td></tr>`).join('')||'<tr><td colspan="8" class="empty">No interfaces configured</td></tr>'}
  </tbody></table></div>`;
}
function renderRouting(){
  const o=state.objects;
  return `<div class="card"><div class="chead">Static Routing <span class="hint">default gateway</span></div>
  <table><thead><tr><th>VDOM</th><th>Destination</th><th>Interface</th><th>Gateway</th></tr></thead><tbody>
  ${o&&o.routes.filter(inScope).length?o.routes.filter(inScope).map(r=>`<tr><td><span class="chip muted">${esc(r.vdom||'root')}</span></td><td>0.0.0.0/0</td><td>${esc(r.interface)}</td><td class="mono">${esc(r.via||'connected')}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No default route configured</td></tr>'}
  </tbody></table></div>`;
}
function renderPolicies(){
  const s=state.data;
  return `<div class="card"><div class="toolrow"><input type="search" id="policy-search" placeholder="Search policies by zone, address, action"><label><input type="checkbox" id="auto-refresh" checked> Auto refresh</label><span class="legend" style="margin-left:auto"><span><span class="dot on"></span>permit</span><span><span class="dot off"></span>deny</span></span></div>
  <table><thead><tr><th>VDOM</th><th>ID</th><th>Source Zone</th><th>Source</th><th>Destination Zone</th><th>Destination</th><th>Service</th><th>Action</th><th>NAT</th><th>Security Profiles</th><th class="num">Log</th></tr></thead><tbody id="policy-rows">
  ${((s&&s.policies)||[]).filter(inScope).map(p=>`<tr data-search="${esc([p.vdom,p.id,p.src_zone,p.dst_zone,p.src,p.dst,p.action].join(' '))}"><td>${p.id}</td><td>${esc(p.src_zone)}</td><td class="mono">${esc(p.src)}</td><td>${esc(p.dst_zone)}</td><td class="mono">${esc(p.dst)}</td><td>${esc(p.proto)}${p.port!=='any'?' / '+esc(p.port):''}</td><td>${chipAction(p.action)}</td><td>${p.nat?'<span class="chip info">SNAT</span>':'—'}</td><td>${profileChips(p)}</td><td class="num">${p.logging?'<span class="chip ok">ON</span>':'<span class="chip muted">OFF</span>'}</td></tr>`).join('')||'<tr><td colspan="11" class="empty">No firewall policies in this VDOM. Use Create New to add one.</td></tr>'}
  </tbody></table></div>`;
}
function profileChips(p){
  const c=[];
  if(p.app)c.push('App:'+p.app); if(p.url)c.push('URL:'+p.url); if(p.ips)c.push('IPS:'+p.ips); if(p.av)c.push('AV:'+p.av); if(p.shaper)c.push('Shaper:'+p.shaper);
  return c.length?c.map(x=>`<span class="chip info">${esc(x)}</span>`).join(' '):'<span class="chip muted">none</span>';
}
function renderAddresses(){
  const o=state.objects;
  const rows=(o?o.addresses.map(a=>`<tr><td><b>${esc(a.name)}</b></td><td>${a.entries.length}</td><td class="mono">${esc(a.entries.join(', '))}</td><td><span class="chip muted">address</span></td></tr>`):[]).concat(o?o.groups.map(g=>`<tr><td><b>${esc(g.name)}</b></td><td>${g.members.length}</td><td class="mono">${esc(g.members.join(', '))}</td><td><span class="chip info">group</span></td></tr>`):[]);
  return tableCard('Address Objects','name, subnet or range',['Name','Entries','Value','Type'],rows);
}
function renderServices(){
  const o=state.objects;
  const rows=(o?o.services.map(s=>`<tr><td><b>${esc(s.name)}</b></td><td class="mono">${esc(s.proto)}</td><td class="mono">${esc(s.port)}</td><td><span class="chip muted">service</span></td></tr>`):[]).concat(o?o.apps.map(a=>`<tr><td><b>${esc(a.name)}</b></td><td class="mono">${esc(a.proto)}</td><td class="mono">${esc(a.port)}</td><td><span class="chip info">built-in app</span></td></tr>`):[]);
  return tableCard('Service Objects','protocol and port definitions',['Name','Protocol','Port','Type'],rows);
}
function renderDnat(){
  const o=state.objects;
  return tableCard('Virtual IPs / DNAT','destination translation rules',['VDOM','ID','Protocol','External','External Port','Internal Host','Internal Port'],o?o.dnat.filter(inScope).map(d=>`<tr><td><span class="chip muted">${esc(d.vdom||'root')}</span></td><td>${esc(d.id)}</td><td>${esc(d.proto)}</td><td class="mono">${esc(d.dst)}</td><td class="mono">${esc(d.dport)}</td><td class="mono">${esc(d.to_ip)}</td><td class="mono">${esc(d.to_port)}</td></tr>`):[]);
}
function renderShapers(){
  const o=state.objects;
  return tableCard('Traffic Shapers','egress rate limits',['Name','Rate','Use'],o?o.shapers.map(s=>`<tr><td><b>${esc(s.name)}</b></td><td class="mono">${esc(s.kbps)} kbps</td><td><span class="chip muted">policy shaper</span></td></tr>`):[]);
}
function renderUrlfilters(){
  const o=state.objects;
  return tableCard('URL Filter','HTTP host and TLS SNI matching',['Profile','Action','Entries'],o?o.urlfilters.map(u=>`<tr><td><b>${esc(u.name)}</b></td><td>${u.action==='block'?'<span class="chip bad">BLOCK</span>':'<span class="chip ok">ALLOW</span>'}</td><td class="mono">${esc(u.entries.join(', '))}</td></tr>`):[]);
}
function renderIps(){
  const o=state.objects;
  return tableCard('IPS Signatures','inline payload patterns',['Profile','Count','Signatures'],o?o.ips.map(p=>`<tr><td><b>${esc(p.name)}</b></td><td>${p.patterns.length}</td><td class="mono">${esc(p.patterns.join(' | '))}</td></tr>`):[]);
}
function renderAv(){
  const o=state.objects;
  return tableCard('Antivirus','inline malware patterns',['Profile','Count','Signatures'],o?o.av.map(p=>`<tr><td><b>${esc(p.name)}</b></td><td>${p.patterns.length}</td><td class="mono">${esc(p.patterns.join(' | '))}</td></tr>`):[]);
}
function tableCard(title,hint,heads,rows){
  return `<div class="card"><div class="chead">${title} <span class="hint">${esc(hint)}</span></div><table><thead><tr>${heads.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')||`<tr><td colspan="${heads.length}" class="empty">No entries configured</td></tr>`}</tbody></table></div>`;
}
function renderSessions(){
  const s=(state.sessions||[]).filter(inScope);
  return `<div class="card"><div class="toolrow"><input type="search" id="session-search" placeholder="Filter by address, port or NAT"><label><input type="checkbox" id="auto-refresh" checked> Auto refresh</label><span class="legend" style="margin-left:auto">${s.length} entries</span></div>
  <table><thead><tr><th>VDOM</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Translation</th><th class="num">TTL</th></tr></thead><tbody id="session-rows">
  ${s.map(x=>`<tr data-search="${esc([x.vdom,x.src,x.sport,x.dst,x.dport,x.nat].join(' '))}"><td><span class="chip muted">${esc(x.vdom||'root')}</span></td><td>${protoName(x.proto)}</td><td class="mono">${esc(x.src)}:${x.sport}</td><td class="mono">${esc(x.dst)}:${x.dport}</td><td class="mono">${esc(x.nat)}</td><td class="num">${x.ttl}s</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No active sessions</td></tr>'}
  </tbody></table></div>`;
}
function protoName(n){return ({6:'TCP',17:'UDP',1:'ICMP'})[n]||('proto '+n);}
function parseLog(line){
  if(line.trim().startsWith('{')){try{return JSON.parse(line);}catch(e){}}
  const m=line.match(/^(\S+) (\S+):(\d+) -> (\S+):(\d+) proto (\d+) \(([^)]*) -> ([^)]*)\)(?: policy (\d+))?(.*)$/);
  if(!m) return {raw:line,action:'event'};
  return {action:m[1],src:m[2],sport:m[3],dst:m[4],dport:m[5],proto:+m[6],from:m[7],to:m[8],policy:m[9]?+m[9]:null,note:(m[10]||'').trim()};
}
function logRowBrief(line){
  const e=parseLog(line);
  if(e.raw)return `<tr><td colspan="4" class="mono">${esc(e.raw)}</td></tr>`;
  return `<tr><td>${e.action==='accept'||e.action==='permit'?'<span class="chip ok">ACCEPT</span>':e.action==='deny'||e.action==='drop'?'<span class="chip bad">DENY</span>':`<span class="chip muted">${esc(e.action)}</span>`}</td><td class="mono">${esc(e.src)}:${esc(e.sport)}</td><td class="mono">${esc(e.dst)}:${esc(e.dport)}</td><td>${e.policy==null?'—':e.policy}${e.note?'<div style="color:#8a5a12;font-size:11px">'+esc(e.note)+'</div>':''}</td></tr>`;
}
function renderLogs(){
  const logs=state.logs||[];
  return `<div class="card"><div class="toolrow"><input type="search" id="log-search" placeholder="Filter events"><span class="legend" style="margin-left:auto">${logs.length} recent entries · buffer of 200</span><button class="btn secondary" id="log-clear" type="button">Clear filter</button></div>
  <table><thead><tr><th>Action</th><th>Source</th><th>Destination</th><th>Proto</th><th>Policy</th><th>From → To</th><th>Detail</th></tr></thead><tbody id="log-rows">
  ${logs.slice().reverse().map(line=>{const e=parseLog(line);if(e.raw)return `<tr class="logrow"><td colspan="7">${esc(e.raw)}</td></tr>`;return `<tr class="logrow" data-search="${esc(line)}"><td>${e.action==='accept'||e.action==='permit'?'<span class="chip ok">ACCEPT</span>':e.action==='deny'||e.action==='drop'?'<span class="chip bad">DENY</span>':`<span class="chip muted">${esc(e.action)}</span>`}</td><td>${esc(e.src)}:${esc(e.sport)}</td><td>${esc(e.dst)}:${esc(e.dport)}</td><td>${esc(e.proto)}</td><td>${e.policy==null?'—':e.policy}</td><td>${esc(e.from)} → ${esc(e.to)}</td><td>${esc(e.note||'—')}</td></tr>`;}).join('')||'<tr><td colspan="7" class="empty">No traffic log entries</td></tr>'}
  </tbody></table></div>`;
}
function renderVdoms(){
  const o=state.objects,s=state.data;
  const names=(o&&o.vdoms.length)?o.vdoms:((s&&s.vdoms.length)?s.vdoms:['root']);
  const rows=names.map(v=>{
    const ifaces=((s&&s.interfaces)||[]).filter(i=>i.vdom===v);
    const pols=((s&&s.policies)||[]).filter(p=>p.vdom===v);
    const dnats=(o?o.dnat:[]).filter(d=>d.vdom===v);
    const zones=(o?o.zones:[]).filter(z=>z.vdom===v);
    const route=(o?o.routes:[]).find(r=>r.vdom===v);
    return `<tr><td><b>${esc(v)}</b>${v==='root'?' <span class="chip info">default</span>':''}</td><td>${ifaces.length}</td><td>${pols.length}</td><td>${dnats.length}</td><td>${zones.length}</td><td class="mono">${route?esc(route.interface+(route.via?' via '+route.via:'')):'not configured'}</td><td><span class="chip ok">ACTIVE</span></td></tr>`;
  });
  return `<div class="notice">Each VDOM is an independent partition: interfaces, zones, routes, firewall policies, DNAT rules and sessions are scoped to it. Address, service and security-profile objects are shared. Select a VDOM from the top bar to work inside it, or Global to see every partition.</div>
  <div class="card"><div class="chead">Virtual Domains <span class="hint">${names.length} partition(s)</span></div>
  <table><thead><tr><th>VDOM</th><th>Interfaces</th><th>Policies</th><th>DNAT</th><th>Zones</th><th>Default route</th><th>Status</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
function renderConfig(){
  return `<div class="card"><div class="chead">Configuration Editor <span class="hint">validated on save</span></div><div class="cbody">
  <div class="notice">The configuration language is line based: <code class="kbd">interface</code>, <code class="kbd">address</code>, <code class="kbd">service</code>, <code class="kbd">policy</code>, <code class="kbd">dnat</code>, <code class="kbd">url-filter</code>, <code class="kbd">ips-profile</code>, <code class="kbd">av-profile</code>, <code class="kbd">shaper</code>. Reload pulls the running configuration; Save &amp; Apply replaces it atomically.</div>
  <textarea id="config-text" spellcheck="false">${esc(state.cfg||'')}</textarea>
  <div class="formrow"><button class="btn" id="config-save" type="button">Save &amp; Apply</button><button class="btn secondary" id="config-stage" type="button">Validate &amp; Stage</button><button class="btn secondary" id="config-diff" type="button">Preview Diff</button><button class="btn secondary" id="config-reload" type="button">Reload</button><span class="msg" id="config-msg"></span></div>
  <div class="formrow"><button class="btn ghost" id="config-discard" type="button">Discard Candidate</button><button class="btn ghost" id="config-rollback" type="button">Roll Back</button><button class="btn ghost" id="config-backup" type="button">Download Backup</button></div>
  <pre id="config-difftext" style="display:none;margin:12px 0 0;padding:12px;background:#0f1c26;color:#d9e7f1;border-radius:5px;max-height:280px;overflow:auto;font:12px/1.5 ui-monospace,monospace"></pre>
  </div></div>`;
}
const renderers={dashboard:renderDashboard,interfaces:renderInterfaces,routing:renderRouting,policies:renderPolicies,addresses:renderAddresses,services:renderServices,dnat:renderDnat,shapers:renderShapers,urlfilters:renderUrlfilters,ips:renderIps,av:renderAv,sessions:renderSessions,logs:renderLogs,vdoms:renderVdoms,config:renderConfig};

function actionsFor(page){
  if(page==='config')return '';
  if(page==='sessions')return '<button class="btn secondary" id="act-refresh" type="button">Refresh</button>';
  if(page==='logs')return '<button class="btn secondary" id="act-refresh" type="button">Refresh</button>';
  return '<button class="btn" id="act-new" type="button">Create New</button><button class="btn secondary" id="act-refresh" type="button">Refresh</button>';
}
function navigate(page){
  if(!pages[page])page='dashboard';
  state.page=page; location.hash='/'+page;
  $('title').textContent=pages[page][0]; $('subtitle').textContent=pages[page][1]; $('crumb').textContent=pages[page][0];
  document.querySelectorAll('.sidebar .item').forEach(el=>el.classList.toggle('active',el.dataset.page===page));
  $('pageactions').innerHTML=actionsFor(page);
  render();
}
function render(){
  const v=$('view');
  v.innerHTML=(renderers[state.page]||renderDashboard)();
  bindPage();
}
function bindPage(){
  const page=state.page;
  if(page==='policies'||page==='sessions'){
    const input=$('policy-search')||$('session-search');
    if(input)input.oninput=()=>{
      const q=input.value.toLowerCase();
      document.querySelectorAll('#'+(page==='policies'?'policy-rows':'session-rows')+' tr').forEach(tr=>{tr.style.display=(tr.dataset.search||'').toLowerCase().includes(q)?'':'none';});
    };
  }
  if(page==='logs'){
    const input=$('log-search');
    if(input)input.oninput=()=>{const q=input.value.toLowerCase();document.querySelectorAll('#log-rows tr').forEach(tr=>{tr.style.display=(tr.dataset.search||tr.textContent).toLowerCase().includes(q)?'':'none';});};
    const clear=$('log-clear'); if(clear)clear.onclick=()=>{if(input){input.value='';input.oninput();}};
  }
  if(page==='config'){
    const save=$('config-save'),stage=$('config-stage'),diff=$('config-diff'),reload=$('config-reload');
    if(save)save.onclick=saveConfig;
    if(stage)stage.onclick=stageConfig;
    if(diff)diff.onclick=showDiff;
    if(reload)reload.onclick=async()=>{await loadCfg();$('config-text').value=state.cfg||'';hideDiff();setMsg('config-msg','Configuration reloaded',false);};
    const discard=$('config-discard'),rollback=$('config-rollback'),backup=$('config-backup');
    if(discard)discard.onclick=discardCandidate;
    if(rollback)rollback.onclick=rollbackConfig;
    if(backup)backup.onclick=()=>{window.location='/api/v1/configuration/backup';};
  }
  const n=$('act-new'); if(n)n.onclick=openEditor;
  const r=$('act-refresh'); if(r)r.onclick=refresh;
}
async function refresh(){
  await Promise.all([loadState(),loadSessions()]);
  if(state.page==='logs')await loadLogs();
  render();
}
async function loadState(){
  try{
    const r=await fetch('/api/state',{cache:'no-store'}); if(!r.ok)throw new Error('state '+r.status);
    state.data=await r.json();
    state.cfg=state.data.config||state.cfg||'';
    state.objects=parseCfg(state.cfg);
    $('top-host').textContent=state.data.hostname;
    $('top-uptime').textContent='up '+fmtUptime(state.data.uptime);
    const o=state.objects;
    $('badge-policies').textContent=(state.data.policies||[]).length;
    $('badge-addresses').textContent=o.addresses.length+o.groups.length;
    $('badge-services').textContent=o.services.length+o.apps.length;
    $('badge-dnat').textContent=o.dnat.length;
    $('badge-shapers').textContent=o.shapers.length;
    $('badge-sessions').textContent=state.data.sessions;
    $('badge-vdoms').textContent=o.vdoms.length||1;
    syncVdomSelect(o.vdoms.length?o.vdoms:['root']);
  }catch(e){$('top-host').textContent='offline';}
}
function syncVdomSelect(names){
  const sel=$('vdom-select'); if(!sel)return;
  const wanted=['all'].concat(names);
  const current=state.vdom;
  sel.innerHTML=wanted.map(v=>`<option value="${esc(v)}">${v==='all'?'Global (all VDOMs)':esc(v)}</option>`).join('');
  sel.value=wanted.includes(current)?current:'all';
  state.vdom=sel.value;
}
async function loadSessions(){
  try{const r=await fetch('/api/sessions',{cache:'no-store'});const j=await r.json();state.sessions=j.sessions||[];state.data&&(state.data.sessions=state.sessions.length);}catch(e){}
}
async function loadLogs(){try{const r=await fetch('/api/logs',{cache:'no-store'});const j=await r.json();state.logs=j.logs||[];}catch(e){}}
async function loadCfg(){try{const r=await fetch('/api/config',{cache:'no-store'});state.cfg=await r.text();state.objects=parseCfg(state.cfg);}catch(e){}}
function setMsg(id,text,bad){const el=$(id);if(!el)return;el.textContent=text;el.style.color=bad?'#b02a2a':'#0c7a49';}
function toast(text,bad){const t=$('toast');t.textContent=text;t.className='toast show'+(bad?' bad':'');setTimeout(()=>t.className='toast',2600);}
function hideDiff(){const el=$('config-difftext');if(el){el.style.display='none';el.textContent='';}}
function showDiffText(text){const el=$('config-difftext');if(!el)return;el.style.display='block';el.textContent=text||'No differences between running and candidate configuration';}
async function stageOnly(text){
  const r=await fetch('/api/v1/configuration/candidate',{method:'POST',headers:{'content-type':'text/plain'},body:text});
  const j=await r.json().catch(()=>({error:'HTTP '+r.status}));
  return {ok:r.ok&&j.ok,error:j.error||('HTTP '+r.status)};
}
async function stageConfig(){
  const j=await stageOnly($('config-text').value);
  if(j.ok){setMsg('config-msg','Candidate validated and staged',false);toast('Candidate staged');await showDiff();}
  else{setMsg('config-msg','Error: '+j.error,true);toast('Rejected: '+j.error,true);}
}
async function showDiff(){
  const r=await fetch('/api/v1/configuration/diff',{cache:'no-store'});
  showDiffText(r.ok?await r.text():'Unable to load diff ('+r.status+')');
}
async function discardCandidate(){
  const r=await fetch('/api/v1/configuration/candidate',{method:'DELETE'});
  const j=await r.json().catch(()=>({error:'HTTP '+r.status}));
  if(r.ok&&j.ok){hideDiff();setMsg('config-msg','Candidate discarded',false);toast('Candidate discarded');}
  else setMsg('config-msg','Error: '+(j.error||r.status),true);
}
async function rollbackConfig(){
  if(!confirm('Restore the previous committed configuration?'))return;
  const r=await fetch('/api/v1/configuration/rollback',{method:'POST'});
  const j=await r.json().catch(()=>({error:'HTTP '+r.status}));
  if(r.ok&&j.ok){hideDiff();await loadState();await loadCfg();$('config-text').value=state.cfg||'';setMsg('config-msg','Rolled back to revision '+j.revision,false);toast('Configuration rolled back');render();}
  else setMsg('config-msg','Error: '+(j.error||r.status),true);
}
async function applyConfig(text){
  let r=await fetch('/api/v1/configuration/candidate',{method:'POST',headers:{'content-type':'text/plain'},body:text});
  let j=await r.json().catch(()=>({error:'HTTP '+r.status}));
  if(!r.ok||!j.ok)return {ok:false,error:j.error||('HTTP '+r.status)};
  r=await fetch('/api/v1/configuration/commit',{method:'POST'});
  j=await r.json().catch(()=>({error:'HTTP '+r.status}));
  return {ok:r.ok&&j.ok,error:j.error||('HTTP '+r.status),revision:j.revision};
}
async function saveConfig(){
  const text=$('config-text').value;
  const j=await applyConfig(text);
  if(j.ok){setMsg('config-msg','Configuration committed as revision '+j.revision,false);state.cfg=text;state.objects=parseCfg(text);toast('Configuration committed');await loadState();render();}
  else{setMsg('config-msg','Error: '+j.error,true);toast('Rejected: '+j.error,true);}
}
async function openEditor(){
  await loadCfg(); $('cfg').value=state.cfg||''; $('editor-msg').textContent=''; $('editor-title').textContent=pages[state.page][0]+' · configuration';
  $('editor').showModal(); $('cfg').focus();
}
async function saveEditor(){
  const text=$('cfg').value; const j=await applyConfig(text);
  if(j.ok){$('editor-msg').textContent='Configuration committed as revision '+j.revision;$('editor-msg').style.color='#0c7a49';state.cfg=text;state.objects=parseCfg(text);toast('Configuration committed');await refresh();setTimeout(()=>$('editor').close(),400);}
  else{$('editor-msg').textContent='Error: '+j.error;$('editor-msg').style.color='#b02a2a';}
}
$('vdom-select').onchange=(e)=>{state.vdom=e.target.value;const u=new URL(location.href);if(state.vdom==='all')u.searchParams.delete('vdom');else u.searchParams.set('vdom',state.vdom);history.replaceState(null,'',u);render();};
document.querySelectorAll('.sidebar .ghead').forEach(h=>h.onclick=()=>h.parentElement.classList.toggle('closed'));
document.querySelectorAll('.sidebar .item').forEach(el=>el.onclick=()=>navigate(el.dataset.page));
$('refresh').onclick=refresh;
$('editor-close').onclick=()=>$('editor').close();
$('editor-save').onclick=saveEditor;
$('editor-reload').onclick=async()=>{await loadCfg();$('cfg').value=state.cfg||'';};
window.addEventListener('hashchange',()=>{const p=location.hash.replace(/^#\/?/,'')||'dashboard';if(p!==state.page)navigate(p);});
$('login-form').onsubmit=doLogin;
$('logout').onclick=doLogout;
(async function boot(){ if(await loadMe())await startApp(); })();
</script>
</body>
</html>
"#;
