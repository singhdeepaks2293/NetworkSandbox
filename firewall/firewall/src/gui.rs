//! HTTP management server and embedded single-page UI.

use crate::auth::{Auth, Role, Session};
use crate::dataplane::Engine;
use rustls::{ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PRODUCT: &str = "VELA NGFW";
const VERSION: &str = "0.1.0";
const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;

#[derive(Clone, Copy)]
struct Limits {
    max_body: usize,
    rate: u32,
    burst: u32,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
struct Limiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl Limiter {
    fn allow(&self, ip: IpAddr, rate: u32, burst: u32) -> bool {
        if rate == 0 {
            return true;
        }
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let burst = burst.max(1) as f64;
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate as f64 / 60.0).min(burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn prune(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() > 4096 {
            let cutoff = Instant::now() - Duration::from_secs(600);
            buckets.retain(|_, bucket| bucket.last >= cutoff);
        }
    }
}

pub fn serve(engine: Arc<Engine>, auth: Arc<Auth>) {
    let (bind, port, tls, limits, hostname, config_path) = {
        let cfg = engine.cfg.read().unwrap();
        (
            cfg.settings.gui_bind,
            cfg.settings.gui_port,
            cfg.settings.tls,
            Limits {
                max_body: cfg.settings.max_body,
                rate: cfg.settings.api_rate,
                burst: cfg.settings.api_burst,
            },
            cfg.settings.hostname.clone(),
            engine.config_path.clone(),
        )
    };
    let tls_config = if tls {
        match crate::tls::server_config(
            config_path.as_deref(),
            &engine.cfg.read().unwrap().settings,
            &hostname,
        ) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                eprintln!("gui: TLS disabled: {e}");
                return;
            }
        }
    } else {
        None
    };
    let listener = match TcpListener::bind((bind, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gui: cannot listen on {bind}:{port}: {e}");
            return;
        }
    };
    let scheme = if tls { "https" } else { "http" };
    println!("gui: listening on {scheme}://{bind}:{port}");
    let limiter = Arc::new(Limiter::default());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let engine = engine.clone();
                let auth = auth.clone();
                let limiter = limiter.clone();
                let tls_config = tls_config.clone();
                std::thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .map(|a| a.ip())
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
                    limiter.prune();
                    if !limiter.allow(peer, limits.rate, limits.burst) {
                        if !tls {
                            let mut stream = stream;
                            let _ = send(
                                &mut stream,
                                Response::error(429, "request rate limit exceeded"),
                                tls,
                            );
                        }
                        return;
                    }
                    match tls_config {
                        Some(config) => {
                            let connection = match ServerConnection::new(config) {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!("gui: TLS setup: {e}");
                                    return;
                                }
                            };
                            let stream = StreamOwned::new(connection, stream);
                            handle(&engine, &auth, stream, tls, limits);
                        }
                        None => handle(&engine, &auth, stream, tls, limits),
                    }
                });
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

fn handle<S: Read + Write>(engine: &Engine, auth: &Auth, stream: S, tls: bool, limits: Limits) {
    let mut reader = BufReader::new(stream);
    let Some(request_line) = read_limited(&mut reader, MAX_LINE) else {
        return;
    };
    if request_line.len() > MAX_LINE {
        let _ = send(
            reader.get_mut(),
            Response::error(414, "request line too long"),
            tls,
        );
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() {
        let _ = send(
            reader.get_mut(),
            Response::error(400, "malformed request line"),
            tls,
        );
        return;
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        let _ = send(
            reader.get_mut(),
            Response::error(505, "HTTP version not supported"),
            tls,
        );
        return;
    }
    let (path, query) = split_target(&target);
    let mut headers = HashMap::new();
    let mut length = 0usize;
    for _ in 0..=MAX_HEADERS {
        let Some(header) = read_limited(&mut reader, MAX_LINE) else {
            return;
        };
        if header.len() > MAX_LINE {
            let _ = send(
                reader.get_mut(),
                Response::error(431, "header too large"),
                tls,
            );
            return;
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        let Some((key, value)) = header.split_once(':') else {
            let _ = send(
                reader.get_mut(),
                Response::error(400, "malformed header"),
                tls,
            );
            return;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            let _ = send(
                reader.get_mut(),
                Response::error(400, "malformed header name"),
                tls,
            );
            return;
        }
        if key == "content-length" {
            if headers.contains_key("content-length") {
                let _ = send(
                    reader.get_mut(),
                    Response::error(400, "duplicate content-length"),
                    tls,
                );
                return;
            }
            length = match value.parse() {
                Ok(n) => n,
                Err(_) => {
                    let _ = send(
                        reader.get_mut(),
                        Response::error(400, "invalid content-length"),
                        tls,
                    );
                    return;
                }
            };
        }
        if key == "transfer-encoding" {
            let _ = send(
                reader.get_mut(),
                Response::error(400, "transfer-encoding is not supported"),
                tls,
            );
            return;
        }
        headers.insert(key, value);
    }
    if headers.len() >= MAX_HEADERS {
        let _ = send(
            reader.get_mut(),
            Response::error(431, "too many headers"),
            tls,
        );
        return;
    }
    if length > limits.max_body {
        let _ = send(
            reader.get_mut(),
            Response::error(413, "request body too large"),
            tls,
        );
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
    let response = route(engine, auth, &request, tls);
    let _ = send(reader.get_mut(), response, tls);
}

fn read_limited<R: BufRead>(reader: &mut R, limit: usize) -> Option<String> {
    let mut line = String::new();
    let read = reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_line(&mut line)
        .ok()?;
    if read == 0 {
        return None;
    }
    Some(line)
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

/// 409 Conflict for an edit based on an outdated revision, 422 otherwise.
fn config_error_status(error: &str) -> u16 {
    if error.starts_with("configuration changed since") { 409 } else { 422 }
}

fn route(engine: &Engine, auth: &Auth, req: &Request, tls: bool) -> Response {
    if req.path.starts_with("/api/") && !origin_allowed(req, tls) {
        return Response::error(403, "cross-origin request rejected");
    }
    if req.method == "OPTIONS" {
        return Response::new(204, "text/plain", String::new());
    }
    if req.method == "GET" && (req.path == "/" || req.path == "/index.html") {
        return Response::html(UI_HTML);
    }
    if req.method == "GET" && req.path == "/ui/app.js" {
        return Response::new(200, "application/javascript; charset=utf-8", UI_JS.to_string());
    }
    if req.method == "GET" && req.path == "/ui/model.js" {
        return Response::new(200, "application/javascript; charset=utf-8", UI_MODEL_JS.to_string());
    }
    if req.method == "GET" && req.path == "/ui/app.css" {
        return Response::new(200, "text/css; charset=utf-8", UI_CSS.to_string());
    }
    if req.path == "/healthz" || req.path == "/api/v1/health" {
        // Truthful status: 503 whenever the engine is not enforcing on every
        // configured interface, so orchestrators and HA see a degraded node.
        // Problem details are only shown to authenticated callers.
        let problems = engine.enforcement_problems();
        let dataplane = engine.dataplane_status();
        let mut body = json!({
            "status": if problems.is_empty() { "ok" } else { "degraded" },
            "dataplane": dataplane,
            "product": PRODUCT,
            "version": VERSION,
        });
        if authenticate(auth, req).is_some() {
            body["problems"] = json!(problems);
        }
        return Response::json(if problems.is_empty() { 200 } else { 503 }, body);
    }
    if req.path == "/api/v1/auth/login" && req.method == "POST" {
        return login(auth, req, tls);
    }
    if req.path == "/api/v1/auth/password-reset" && req.method == "POST" {
        return reset_password(auth, req);
    }
    let Some(authn) = authenticate(auth, req) else {
        return Response::error(401, "authentication required").header(
            "WWW-Authenticate",
            "Bearer realm=\"vela\", Cookie realm=\"vela\"",
        );
    };
    if is_write(&req.method) && authn.via_cookie {
        let supplied = req
            .headers
            .get("x-vela-csrf")
            .map(String::as_str)
            .unwrap_or("");
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
            Response::json(200, json!({"ok": true}))
                .header("Set-Cookie", &session_cookie_header("deleted", 0, tls))
        }
        ("POST", "/api/v1/auth/logout-all") => {
            let count = auth.logout_all(&authn.session);
            Response::json(200, json!({"ok": true, "sessions_closed": count}))
                .header("Set-Cookie", &session_cookie_header("deleted", 0, tls))
        }
        ("POST", "/api/v1/auth/password") => change_password(auth, &authn.session, req),
        ("GET", "/api/state" | "/api/v1/state" | "/api/v1/system") => {
            Response::new(200, "application/json", system_json(engine, &authn.session))
        }
        ("GET", "/api/config" | "/api/v1/configuration/running") => {
            // Revision first: a client that edits this text and sends the
            // revision back as X-Config-Base is refused if a commit landed
            // in between (a commit bumps the revision after swapping config).
            let revision = engine.config_revision().to_string();
            Response::text(200, engine.running_text()).header("X-Config-Revision", &revision)
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
            let base = req.headers.get("x-config-base").and_then(|v| v.trim().parse::<u64>().ok());
            match engine.stage_config_from(base, &text) {
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
                Err(e) => Response::error(config_error_status(&e), &e),
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
        ("GET", "/api/v1/configuration/model") => {
            let source = req.query.get("source").map(String::as_str).unwrap_or("candidate");
            Response::json(200, config_model(engine, source))
        }
        ("POST", "/api/v1/configuration/edit") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            let value: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return Response::error(400, "expected JSON: {\"base\": n, \"edits\": [...]}"),
            };
            let edits: Result<Vec<crate::editor::Edit>, String> = match value["edits"].as_array() {
                Some(items) if !items.is_empty() && items.len() <= 200 => items.iter().map(crate::editor::Edit::from_json).collect(),
                _ => Err("edits must be a non-empty array of at most 200 edits".into()),
            };
            let edits = match edits {
                Ok(e) => e,
                Err(e) => return Response::error(400, &e),
            };
            let base = value["base"].as_u64();
            match engine.edit_candidate(base, &edits) {
                Ok(()) => {
                    let summary: Vec<String> = edits
                        .iter()
                        .map(|e| {
                            let target = if e.key.is_empty() { e.lines.first().cloned().unwrap_or_default() } else { e.key.clone() };
                            format!("{:?} {target}", e.mode).to_lowercase()
                        })
                        .collect();
                    auth.audit(&authn.session.username, "config.edit", &summary.join("; "));
                    Response::json(
                        200,
                        json!({"ok": true, "staged": true, "base": engine.candidate_base(), "changes": engine.pending_changes()}),
                    )
                }
                Err(e) => Response::error(config_error_status(&e), &e),
            }
        }
        ("GET", "/api/v1/tools/policy-match") => policy_match(engine, &req.query),
        ("GET", "/api/v1/ha") => {
            use crate::style::Store;
            Response::json(200, json!({"status": engine.ha_status(), "enabled": engine.cfg.read().unwrap().ha.enabled}))
        }
        ("POST", "/api/v1/ha/suspend" | "/api/v1/ha/resume") => {
            use crate::style::Store;
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            let suspend = req.path.ends_with("/suspend");
            match engine.ha_suspend(suspend) {
                Ok(()) => {
                    auth.audit(&authn.session.username, if suspend { "ha.suspend" } else { "ha.resume" }, "");
                    Response::json(200, json!({"ok": true, "status": engine.ha_status()}))
                }
                Err(e) => Response::error(409, &e),
            }
        }
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
                    Response::error(config_error_status(&e), &e)
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
        ("GET", "/api/v1/configuration/backup") => Response::json(
            200,
            json!({
                "product": PRODUCT,
                "version": VERSION,
                "exported": now(),
                "revision": engine.config_revision(),
                "config": engine.running_text(),
            }),
        ),
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
                    match engine
                        .stage_config(&text)
                        .and_then(|_| engine.commit_candidate())
                    {
                        Ok(()) => {
                            auth.audit(&authn.session.username, "config.restore", "");
                            Response::json(
                                200,
                                json!({"ok": true, "revision": engine.config_revision()}),
                            )
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
        ("GET", "/api/v1/policies") => {
            Response::json(200, json!({"policies": policies_value(engine)}))
        }
        ("GET", "/api/v1/user-id") => {
            let cfg = engine.cfg.read().unwrap().clone();
            let rows: Vec<Value> = engine
                .user_mappings(&cfg)
                .into_iter()
                .map(|(ip, user, source, left)| json!({"ip": ip, "user": user, "source": source, "expires_in": left}))
                .collect();
            Response::json(200, json!({"mappings": rows}))
        }
        ("POST", "/api/v1/user-id/login" | "/api/v1/user-id/logout") => {
            if !authn.session.role.can_write() {
                return Response::error(403, "role is read-only for configuration");
            }
            let value: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return Response::error(400, "body must be JSON: {\"ip\": \"a.b.c.d\", \"user\": \"name\", \"timeout\": seconds}"),
            };
            let Some(ip) = value["ip"].as_str().and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok()) else {
                return Response::error(400, "ip must be an IPv4 address");
            };
            if req.path.ends_with("/logout") {
                let removed = engine.user_logout(ip);
                auth.audit(&authn.session.username, "user-id.logout", &ip.to_string());
                return Response::json(200, json!({"ok": true, "removed": removed}));
            }
            let Some(user) = value["user"].as_str() else {
                return Response::error(400, "user is required");
            };
            let timeout = value["timeout"].as_u64().map(std::time::Duration::from_secs);
            match engine.user_login(ip, user, timeout) {
                Ok(()) => {
                    auth.audit(&authn.session.username, "user-id.login", &format!("{ip} {user}"));
                    Response::json(200, json!({"ok": true}))
                }
                Err(e) => Response::error(400, &e),
            }
        }
        ("GET", "/api/v1/nat") => Response::json(200, json!({"rules": nat_value(engine)})),
        ("GET", "/api/v1/objects") => {
            Response::json(200, json!({"objects": objects_value(engine)}))
        }
        ("GET", "/api/v1/security") => {
            Response::json(200, json!({"security": security_value(engine)}))
        }
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
            let limit = req
                .query
                .get("limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(200);
            Response::json(
                200,
                json!({"events": auth.audit_records(&authn.session, limit)}),
            )
        }
        _ if path.starts_with("/api/v1/administrators/") => {
            admin_subroute(auth, &authn.session, req, path)
        }
        _ => Response::error(404, "not found"),
    }
}

fn origin_allowed(req: &Request, tls: bool) -> bool {
    let Some(origin) = req.headers.get("origin") else {
        return true;
    };
    if origin == "null" {
        return false;
    }
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let expected = if tls { "https" } else { "http" };
    scheme == expected
        && req
            .headers
            .get("host")
            .map(|host| host == authority)
            .unwrap_or(false)
}

fn session_cookie_header(token: &str, max_age: u64, tls: bool) -> String {
    let secure = tls || secure_cookie();
    format!(
        "vela_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

fn login(auth: &Auth, req: &Request, tls: bool) -> Response {
    let value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "expected JSON credentials"),
    };
    let username = value.get("username").and_then(Value::as_str).unwrap_or("");
    let password = value.get("password").and_then(Value::as_str).unwrap_or("");
    match auth.login(username, password) {
        Ok((token, session)) => {
            let cookie = session_cookie_header(&token, 28_800, tls);
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

fn reset_password(auth: &Auth, req: &Request) -> Response {
    let value: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "expected JSON object"),
    };
    let token = value.get("token").and_then(Value::as_str).unwrap_or("");
    let password = value.get("password").and_then(Value::as_str).unwrap_or("");
    match auth.reset_password(token, password) {
        Ok(username) => Response::json(200, json!({"ok": true, "username": username})),
        Err(e) => Response::error(400, &e),
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
        ("GET", Some("tokens"), None) => match auth.list_tokens(session, username) {
            Ok(tokens) => Response::json(200, json!({"tokens": tokens})),
            Err(e) => Response::error(403, &e),
        },
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
            let days = value.get("expires_days").and_then(Value::as_u64);
            match auth.create_api_token(session, username, name, role, days) {
                Ok(token) => Response::json(201, json!({"ok": true, "token": token})),
                Err(e) => Response::error(400, &e),
            }
        }
        ("DELETE", Some("tokens"), Some(id)) => match auth.revoke_token(session, username, id) {
            Ok(()) => Response::json(200, json!({"ok": true})),
            Err(e) => Response::error(400, &e),
        },
        _ => Response::error(404, "not found"),
    }
}

fn authenticate(auth: &Auth, req: &Request) -> Option<Authn> {
    if let Some(header) = req.headers.get("authorization") {
        if let Some(token) = header.strip_prefix("Bearer ") {
            if let Some(session) = auth.authenticate_api_token(token.trim()) {
                return Some(Authn {
                    session,
                    via_cookie: false,
                });
            }
        }
    }
    if let Some(token) = session_cookie(req) {
        if let Some(session) = auth.session(&token) {
            return Some(Authn {
                session,
                via_cookie: true,
            });
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
    std::env::var("VELA_SECURE_COOKIE")
        .map(|v| v == "1")
        .unwrap_or(false)
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

fn send<S: Write>(stream: &mut S, mut response: Response, tls: bool) -> std::io::Result<()> {
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
        414 => "URI Too Long",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        response.status, response.content_type, response.body.len()
    );
    head.push_str("X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n");
    if tls {
        head.push_str("Strict-Transport-Security: max-age=31536000\r\n");
    }
    if response.content_type.starts_with("text/html") {
        head.push_str("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'\r\n");
    }
    for (key, value) in response.headers.drain(..) {
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
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
                "src_zone": p.src_zones.join(","),
                "dst_zone": p.dst_zones.join(","),
                "src": crate::model::addr_list_text(&p.src, p.negate_src),
                "dst": crate::model::addr_list_text(&p.dst, p.negate_dst),
                "proto": p.proto.to_string(),
                "dst_port": p.dst_port,
                "service": if p.services.is_empty() { None } else { Some(p.services.join(",")) },
                "action": p.action.as_str(),
                "enabled": p.enabled,
                "name": p.name,
                "nat": p.nat,
                "app": if p.apps.is_empty() { None } else { Some(p.apps.join(",")) },
                "group": p.group,
                "users": p.users,
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
    let text_filter = query
        .get("q")
        .map(|q| q.to_ascii_lowercase())
        .unwrap_or_default();
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
            "app": session.app.as_deref().unwrap_or("pending"),
            "user": session.user,
            "shaper": session.shaper,
            "ttl": session.expires.saturating_duration_since(now).as_secs(),
        });
        if !text_filter.is_empty() && !row.to_string().to_ascii_lowercase().contains(&text_filter) {
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
        let problems = engine.enforcement_problems();
        map.insert(
            "enforcement".into(),
            json!({
                "status": engine.dataplane_status(),
                "mode": if engine.kernel.is_some() { "kernel" } else { "userspace" },
                "problems": problems,
            }),
        );
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
                mem_total = v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0);
            }
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                mem_available = v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0);
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
    Value::Array(
        cfg.routes
            .iter()
            .map(|r| {
                json!({
                    "vdom": r.vdom,
                    "interface": r.interface,
                    "gateway": r.via.map(|v| v.to_string()),
                })
            })
            .collect(),
    )
}

fn policies_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    Value::Array(
        cfg.policies
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "vdom": p.vdom,
                    "src_zone": p.src_zones.join(","),
                    "dst_zone": p.dst_zones.join(","),
                    "src": crate::model::addr_list_text(&p.src, p.negate_src),
                    "dst": crate::model::addr_list_text(&p.dst, p.negate_dst),
                    "proto": p.proto.to_string(),
                    "dst_port": p.dst_port,
                    "service": if p.services.is_empty() { None } else { Some(p.services.join(",")) },
                    "action": p.action.as_str(),
                            "enabled": p.enabled,
                            "name": p.name,
                    "nat": p.nat,
                    "app": if p.apps.is_empty() { None } else { Some(p.apps.join(",")) },
                "group": p.group,
                "users": p.users,
                    "url": p.url,
                    "ips": p.ips,
                    "av": p.av,
                    "shaper": p.shaper,
                    "logging": p.log,
                })
            })
            .collect(),
    )
}

fn nat_value(engine: &Engine) -> Value {
    let cfg = engine.cfg.read().unwrap();
    let rules: Vec<Value> = cfg
        .dnat
        .iter()
        .map(|d| {
            json!({
                "id": d.id,
                "vdom": d.vdom,
                "proto": d.proto.to_string(),
                "dst": d.dst.to_string(),
                "dst_port": d.dst_port,
                "to_ip": d.to_ip.to_string(),
                "to_port": d.to_port,
            })
        })
        .collect();
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
        "services": cfg.services.iter().map(|s| json!({"name": s.name, "proto": s.proto.to_string(), "port": s.ports_text()})).collect::<Vec<_>>(),
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
        "zones": cfg.zones.iter().map(|z| json!({"name": z.name, "syn_flood": z.syn_flood, "icmp_flood": z.icmp_flood, "udp_flood": z.udp_flood})).collect::<Vec<_>>(),
        "tls_inspection": {"state": "not_implemented"},
        "vpn": {"state": "not_implemented"},
    })
}

/// Everything the GUI's configuration pages need, from the candidate when
/// one is staged (unless `source=running`), else from the running config.
fn config_model(engine: &Engine, source: &str) -> Value {
    let staged = engine.candidate_text();
    let use_candidate = source != "running" && staged.is_some();
    let text = if use_candidate { staged.clone().unwrap_or_default() } else { engine.running_text() };
    let cfg = crate::model::Config::parse(&text).unwrap_or_default();
    let mut zones: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = Default::default();
    for v in &cfg.vdoms {
        zones.entry(v.clone()).or_default();
    }
    for i in &cfg.interfaces {
        zones.entry(i.vdom.clone()).or_default().insert(i.zone.clone());
    }
    let hits: Vec<Value> = engine
        .policy_hits()
        .into_iter()
        .map(|((vdom, id), (packets, bytes, last))| json!({"vdom": vdom, "id": id, "packets": packets, "bytes": bytes, "last": last}))
        .collect();
    json!({
        "source": if use_candidate { "candidate" } else { "running" },
        "revision": engine.config_revision(),
        "base": engine.candidate_base(),
        "staged": staged.is_some(),
        "changes": engine.pending_changes(),
        "dataplane": if engine.kernel.is_some() { "kernel" } else { "userspace" },
        "vdoms": cfg.vdoms,
        "zones": zones,
        "interfaces": cfg.interfaces.iter().map(|i| json!({
            "name": i.name, "vdom": i.vdom, "zone": i.zone, "tunnel": i.tunnel,
            "address": i.address.map(|a| a.to_string()), "address6": i.address6.map(|a| a.to_string()), "mtu": i.mtu,
        })).collect::<Vec<_>>(),
        "sections": crate::editor::model(&text),
        "hits": hits,
    })
}

/// Which rule would decide a flow: the PAN-OS `test security-policy-match`.
fn policy_match(engine: &Engine, q: &HashMap<String, String>) -> Response {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    let cfg = engine.cfg.read().unwrap();
    let (Ok(src), Ok(dst)) = (get("src").parse::<IpAddr>(), get("dst").parse::<IpAddr>()) else {
        return Response::error(400, "src and dst must be IP addresses");
    };
    if src.is_ipv4() != dst.is_ipv4() {
        return Response::error(400, "src and dst must be the same address family");
    }
    let proto: u8 = match get("proto") {
        "tcp" | "" => 6,
        "udp" => 17,
        "icmp" => 1,
        other => match other.parse() {
            Ok(n) => n,
            Err(_) => return Response::error(400, "proto must be tcp, udp, icmp or a number"),
        },
    };
    let port: u16 = get("port").parse().unwrap_or(0);
    let vdom = if get("vdom").is_empty() { "root" } else { get("vdom") };
    let app = Some(get("app")).filter(|a| !a.is_empty());
    let user = Some(get("user")).filter(|u| !u.is_empty());
    let user = match (user, src) {
        (Some(u), _) => Some(u.to_string()),
        (None, IpAddr::V4(v4)) => engine.user_for(&cfg, v4),
        _ => None,
    };
    let hit = cfg.match_or_default_ip(vdom, get("from"), get("to"), src, dst, proto, port, app, user.as_deref());
    Response::json(
        200,
        json!({
            "matched": hit.map(|p| json!({
                "id": p.id,
                "name": p.name,
                "action": p.action.as_str(),
                "default_rule": crate::model::is_default_rule_id(p.id),
                "profiles": {"url": p.url, "ips": p.ips, "av": p.av, "group": p.group},
            })),
            "user": user,
            "note": if app.is_none() { "no application given: rules that name applications match provisionally, as before App-ID decides" } else { "" },
        }),
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// The web UI: plain HTML, CSS and JavaScript compiled into the binary and
// served from this origin, so the CSP can forbid inline code entirely.
const UI_HTML: &str = include_str!("ui/index.html");
const UI_JS: &str = include_str!("ui/app.js");
const UI_MODEL_JS: &str = include_str!("ui/model.js");
const UI_CSS: &str = include_str!("ui/app.css");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_enforces_burst_and_can_be_disabled() {
        let limiter = Limiter::default();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(limiter.allow(ip, 60, 1));
        assert!(!limiter.allow(ip, 60, 1));
        assert!(limiter.allow(ip, 0, 0));
        assert!(limiter.allow(ip, 0, 0));
    }
}
