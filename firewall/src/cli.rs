//! An authenticated CLI, reachable on stdin or over TCP.
//!
//! The transport carries credentials, so the listener binds loopback by
//! default. Remote use should go through an authenticated tunnel.

use crate::auth::{Auth, Session};
use crate::dataplane::Engine;
use crate::model::{Config, Policy};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub const END_MARKER: &str = "__END__";

#[derive(Deserialize)]
struct LoginLine {
    action: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    token: String,
}

pub fn serve(engine: Arc<Engine>, auth: Arc<Auth>) {
    let (bind, port) = {
        let cfg = engine.cfg.read().unwrap();
        (cfg.settings.cli_bind, cfg.settings.cli_port)
    };
    let listener = match TcpListener::bind((bind, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cli: cannot listen on {bind}:{port}: {e}");
            return;
        }
    };
    if !bind.is_loopback() {
        eprintln!(
            "cli: listening on {bind}:{port} (authenticated plaintext; use an encrypted tunnel)"
        );
    } else {
        println!("cli: listening on {bind}:{port}");
    }
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let engine = engine.clone();
                let auth = auth.clone();
                std::thread::spawn(move || handle_client(&engine, &auth, stream));
            }
            Err(e) => eprintln!("cli: accept: {e}"),
        }
    }
}

fn handle_client(engine: &Engine, auth: &Auth, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    let mut line = String::new();
    let mut session: Option<Session> = None;
    // Vendor-style front end for this connection; None is the native CLI.
    let mut style: Option<Box<dyn crate::style::Style>> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let line = line.trim();
        let response = match session.as_ref() {
            Some(session) => {
                let hostname = engine.cfg.read().unwrap().settings.hostname.clone();
                let mut words = line.split_whitespace();
                match (words.next(), words.next()) {
                    (Some("cli-style"), Some(name)) => match crate::style::by_name(name) {
                        Ok(next) => {
                            style = next;
                            auth.audit(&session.username, "cli.style", name);
                            format!("cli style: {name}")
                        }
                        Err(e) => format!("error: {e}"),
                    },
                    (Some("cli-style"), None) => {
                        format!("cli style: {}", style.as_ref().map(|s| s.name()).unwrap_or("native"))
                    }
                    (Some("prompt"), None) => match &style {
                        Some(s) => s.prompt(&hostname),
                        None => format!("{hostname}> "),
                    },
                    (Some("quit"), None) => "bye".to_string(),
                    _ => match style.as_mut() {
                        Some(s) => {
                            let ctx = crate::style::Ctx { store: engine, can_write: session.role.can_write() };
                            let response = s.exec(line, &ctx);
                            auth.audit(&session.username, "cli.command", audit_detail(line));
                            response
                        }
                        None if !authorized(session, line) => "error: permission denied for this role".to_string(),
                        None => {
                            let response = execute(engine, line);
                            auth.audit(&session.username, "cli.command", audit_detail(line));
                            response
                        }
                    },
                }
            }
            None => match authenticate_line(auth, line) {
                Ok(Some((token, new_session))) => {
                    let _ = token;
                    let response = format!(
                        "authenticated as {} ({})",
                        new_session.username,
                        new_session.role.as_str()
                    );
                    session = Some(new_session);
                    let default_style = engine.cfg.read().unwrap().settings.cli_style.clone();
                    style = crate::style::by_name(&default_style).unwrap_or(None);
                    response
                }
                Ok(None) if matches!(line, "help" | "?") => help(),
                Ok(None) if matches!(line, "quit" | "exit") => "bye".to_string(),
                Ok(None) => "authentication required: send {\"action\":\"login\",\"username\":\"...\",\"password\":\"...\"}".to_string(),
                Err(e) => format!("error: {e}"),
            },
        };
        if writer
            .write_all(format!("{response}\n{END_MARKER}\n").as_bytes())
            .is_err()
        {
            break;
        }
        if response == "bye" {
            break;
        }
    }
}

fn authenticate_line(auth: &Auth, line: &str) -> Result<Option<(String, Session)>, String> {
    if !line.starts_with('{') {
        return Ok(None);
    }
    let request: LoginLine =
        serde_json::from_str(line).map_err(|_| "invalid login request".to_string())?;
    match request.action.as_str() {
        "login" => {
            let (token, session) = auth.login(&request.username, &request.password)?;
            Ok(Some((token, session)))
        }
        "token" => {
            let session = auth
                .authenticate_api_token(&request.token)
                .ok_or_else(|| "invalid or expired API token".to_string())?;
            Ok(Some((request.token, session)))
        }
        _ => Err("login request action must be login or token".to_string()),
    }
}

fn authorized(session: &Session, line: &str) -> bool {
    let mut words = line.split_whitespace();
    let word = words.next().unwrap_or("");
    match word {
        "" | "help" | "?" | "quit" | "exit" | "show" => true,
        "save" | "write" => session.role.can_write(),
        "policy" => {
            let action = words.next().unwrap_or("");
            matches!(action, "add" | "delete" | "del") && session.role.can_write()
        }
        _ => session.role.can_write(),
    }
}

fn audit_detail(line: &str) -> &str {
    line
}

pub fn execute(engine: &Engine, line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.is_empty() {
        return String::new();
    }
    match (words[0], words.get(1).copied()) {
        ("help" | "?", _) => help(),
        ("quit" | "exit", _) => "bye".to_string(),
        ("show", Some("version")) => {
            let cfg = engine.cfg.read().unwrap();
            format!(
                "firewall 0.2.0\nhostname {}\nuptime {}s\nsessions {}",
                cfg.settings.hostname,
                engine.uptime_secs(),
                engine.sessions.lock().unwrap().len()
            )
        }
        ("show", Some("config")) => engine.cfg.read().unwrap().to_text(),
        ("show", Some("interfaces")) => show_interfaces(engine),
        ("show", Some("policies" | "policy")) => show_policies(engine),
        ("show", Some("sessions" | "conntrack")) => show_sessions(engine),
        ("show", Some("stats")) => show_stats(engine),
        ("show", Some("applications")) => crate::appid::catalog_text(words.get(2).copied()),
        ("show", Some("ha")) => engine.ha.lock().unwrap().text(),
        ("show", Some("vpn")) => engine.vpn_status(),
        ("ha", Some("suspend")) => {
            engine.ha_suspended.store(true, std::sync::atomic::Ordering::SeqCst);
            "ha: this unit is suspended and will not be active until 'ha resume'".to_string()
        }
        ("ha", Some("resume")) => {
            engine.ha_suspended.store(false, std::sync::atomic::Ordering::SeqCst);
            "ha: this unit is eligible again".to_string()
        }
        ("show", Some("users")) => {
            let cfg = engine.cfg.read().unwrap().clone();
            let mut out = format!("{:<20} {:<24} {:<8} {}\n", "address", "user", "source", "expires");
            for (ip, user, source, left) in engine.user_mappings(&cfg) {
                let left = left.map(|s| format!("{s}s")).unwrap_or_else(|| "never".into());
                out.push_str(&format!("{ip:<20} {user:<24} {source:<8} {left}\n"));
            }
            out
        }
        ("user-id", Some("login")) => {
            // user-id login <ip> <user> [timeout <seconds>]
            let (Some(ip), Some(user)) = (words.get(2), words.get(3)) else {
                return "usage: user-id login <ip> <user> [timeout <seconds>]".to_string();
            };
            let Ok(ip) = ip.parse() else { return format!("error: invalid address {ip}") };
            let timeout = match (words.get(4), words.get(5)) {
                (Some(&"timeout"), Some(secs)) => match secs.parse::<u64>() {
                    Ok(s) => Some(Duration::from_secs(s)),
                    Err(_) => return "error: invalid timeout".to_string(),
                },
                (None, _) => None,
                _ => return "usage: user-id login <ip> <user> [timeout <seconds>]".to_string(),
            };
            match engine.user_login(ip, user, timeout) {
                Ok(()) => format!("mapped {ip} to {user}"),
                Err(e) => format!("error: {e}"),
            }
        }
        ("user-id", Some("logout")) => match words.get(2).and_then(|ip| ip.parse().ok()) {
            Some(ip) if engine.user_logout(ip) => format!("removed mapping for {ip}"),
            Some(ip) => format!("no dynamic mapping for {ip}"),
            None => "usage: user-id logout <ip>".to_string(),
        },
        ("policy", Some("add")) => policy_add(engine, &words[2..]),
        ("policy", Some("delete" | "del")) => policy_delete(engine, &words[2..]),
        ("save" | "write", _) => match engine.save() {
            Ok(()) => "saved".to_string(),
            Err(e) => format!("error: {e}"),
        },
        _ => format!("unknown command: {line}\n{}", help()),
    }
}

fn help() -> String {
    [
        "commands:",
        "  show version | config | interfaces | policies | sessions | stats | applications [filter]",
        "  policy add [vdom NAME] <id> <src-zone> <dst-zone> <src-cidr|@object|any> <dst-cidr|@object|any> <proto|any> <port|@service|any> <permit|deny> [nat] [app X] [url X] [ips X] [av X] [shaper X] [nolog]",
        "  policy delete <id>",
        "  save",
        "  show ha | ha suspend | ha resume | show vpn",
        "  show users | user-id login <ip> <user> [timeout <s>] | user-id logout <ip>",
        "  cli-style native|fortios|panos   switch this session to a FortiOS- or PAN-OS-style CLI",
        "  quit",
    ]
    .join("\n")
}

fn show_interfaces(engine: &Engine) -> String {
    let cfg = engine.cfg.read().unwrap();
    let stats = engine.stats.lock().unwrap();
    let mut out = String::from(
        "name       vdom       zone       address              mac                rx       tx       drop\n",
    );
    for iface in &cfg.interfaces {
        let s = stats.ifaces.get(&iface.name);
        let (rx, tx, drop) = s
            .map(|s| (s.rx_packets, s.tx_packets, s.dropped))
            .unwrap_or((0, 0, 0));
        out.push_str(&format!(
            "{:<10} {:<10} {:<10} {:<20} {:<18} {:<8} {:<8} {}\n",
            iface.name,
            iface.vdom,
            iface.zone,
            iface
                .address
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".to_string()),
            iface
                .mac
                .map(|m| crate::model::format_mac(&m))
                .unwrap_or_else(|| "auto".to_string()),
            rx,
            tx,
            drop
        ));
    }
    out
}

fn show_policies(engine: &Engine) -> String {
    let cfg = engine.cfg.read().unwrap();
    let hits = engine.policy_hits();
    let mut out = String::from(
        "vdom       id   source        destination   src            dst            proto  port       action  nat  profiles\n",
    );
    let mut policies: Vec<&Policy> = cfg.policies.iter().collect();
    policies.sort_by_key(|p| p.id);
    for p in policies {
        let mut profiles = Vec::new();
        if !p.enabled {
            profiles.push("disabled".to_string());
        }
        if let Some(name) = &p.name {
            profiles.push(format!("name={name}"));
        }
        let (hit_packets, hit_bytes, _) = hits
            .get(&(p.vdom.clone(), p.id))
            .copied()
            .unwrap_or((0, 0, 0));
        profiles.push(format!("hits={hit_packets}/{hit_bytes}B"));
        if !p.apps.is_empty() {
            profiles.push(format!("app={}", p.apps.join(",")));
        }
        if let Some(group) = &p.group {
            profiles.push(format!("group={group}"));
        }
        if let Some(url) = &p.url {
            profiles.push(format!("url={url}"));
        }
        if let Some(ips) = &p.ips {
            profiles.push(format!("ips={ips}"));
        }
        if let Some(av) = &p.av {
            profiles.push(format!("av={av}"));
        }
        if let Some(shaper) = &p.shaper {
            profiles.push(format!("shaper={shaper}"));
        }
        out.push_str(&format!(
            "{:<10} {:<4} {:<13} {:<13} {:<14} {:<14} {:<6} {:<10} {:<7} {:<4} {}\n",
            p.vdom,
            p.id,
            p.src_zones.join(","),
            p.dst_zones.join(","),
            crate::model::addr_list_text(&p.src, p.negate_src),
            crate::model::addr_list_text(&p.dst, p.negate_dst),
            p.proto.to_string(),
            if p.services.is_empty() {
                p.dst_port.map(|v| v.to_string()).unwrap_or_else(|| "any".to_string())
            } else {
                p.services.join(",")
            },
            p.action.as_str(),
            if p.nat { "yes" } else { "no" },
            profiles.join(",")
        ));
    }
    for d in &cfg.default_policies {
        out.push_str(&format!(
            "{:<10} {:<4} {:<13} {:<13} {:<14} {:<14} {:<6} {:<10} {:<7} {:<4} {}\n",
            d.vdom,
            "-",
            d.src_zones.join(","),
            d.dst_zones.join(","),
            "any",
            "any",
            "any",
            "any",
            d.action.as_str(),
            "no",
            format!("default={}", d.name.clone().unwrap_or_default())
        ));
    }
    out
}

fn show_sessions(engine: &Engine) -> String {
    let sessions = engine.sessions.lock().unwrap().snapshot();
    let mut out = String::from(
        "vdom       proto  source                     destination                nat                 app              ttl   state\n",
    );
    for s in sessions {
        let nat = match (s.nat_src, s.nat_dst) {
            (Some((ip, port)), None) => format!("snat {ip}:{port}"),
            (None, Some((ip, port))) => format!("dnat {ip}:{port}"),
            (Some((sip, sport)), Some((dip, dport))) => {
                format!("snat {sip}:{sport} dnat {dip}:{dport}")
            }
            (None, None) => "-".to_string(),
        };
        let app = s.app.as_deref().unwrap_or("pending");
        out.push_str(&format!(
            "{:<10} {:<6} {:<26} {:<26} {:<19} {:<16} {}s {}\n",
            s.key.vdom,
            s.key.proto,
            format!("{}:{}", s.key.src, s.key.sport),
            format!("{}:{}", s.key.dst, s.key.dport),
            nat,
            app,
            s.expires
                .saturating_duration_since(std::time::Instant::now())
                .as_secs(),
            if s.key.proto == 6 {
                s.tcp.as_str()
            } else {
                "-"
            }
        ));
    }
    for s in engine.sessions6.lock().unwrap().snapshot() {
        out.push_str(&format!(
            "{:<10} {:<6} {:<26} {:<26} {:<19} {:<16} {}s {}\n",
            s.key.vdom,
            s.key.proto,
            format!("[{}]:{}", s.key.src, s.key.sport),
            format!("[{}]:{}", s.key.dst, s.key.dport),
            "-",
            s.app.as_deref().unwrap_or("pending"),
            s.expires.saturating_duration_since(std::time::Instant::now()).as_secs(),
            if s.key.proto == 6 { s.tcp.as_str() } else { "-" }
        ));
    }
    out
}

fn show_stats(engine: &Engine) -> String {
    let stats = engine.stats.lock().unwrap();
    format!(
        "accepted    {}\ndenied      {}\narp-misses  {}\nerrors      {}\nsessions    {}\nuptime      {}s",
        stats.accepted,
        stats.denied,
        stats.arp_misses,
        stats.errors,
        engine.sessions.lock().unwrap().len(),
        engine.uptime_secs()
    )
}

fn policy_add(engine: &Engine, words: &[&str]) -> String {
    let (vdom, body) = if words.first() == Some(&"vdom") {
        let Some(name) = words.get(1) else {
            return "usage: policy add [vdom NAME] ...".to_string();
        };
        (name.to_string(), &words[2..])
    } else {
        ("root".to_string(), words)
    };
    if body.is_empty() {
        return "usage: policy add [vdom NAME] ...".to_string();
    }
    let line = format!("policy {}", body.join(" "));
    // Revision before config: if a commit lands in between, the base check
    // in apply_config_from refuses this edit instead of overwriting it.
    let base = engine.config_revision();
    let cfg = engine.cfg.read().unwrap().clone();
    let mut text = cfg.to_text();
    text.push_str(&format!("\nvdom {vdom}\n{line}\n"));
    // Through the same path as every other commit: validation, history
    // (so `rollback` works), revision bump (so open sessions are re-checked)
    // and save before activation (so disk and running config never diverge).
    match Config::parse(&text).and_then(|parsed| engine.apply_config_from(base, &parsed)) {
        Ok(()) => format!("policy added\n{line}"),
        Err(e) => format!("error: {e}"),
    }
}

fn policy_delete(engine: &Engine, words: &[&str]) -> String {
    let Some(raw) = words.first() else {
        return "usage: policy delete <id>".to_string();
    };
    let Ok(id) = raw.parse::<u32>() else {
        return format!("error: invalid policy id '{raw}'");
    };
    // Policy ids are unique across all VDOMs (the parser rejects duplicates),
    // so the id alone names one policy.
    let base = engine.config_revision();
    let mut cfg = engine.cfg.read().unwrap().clone();
    let before = cfg.policies.len();
    cfg.policies.retain(|p| p.id != id);
    if cfg.policies.len() == before {
        return format!("error: policy {id} not found");
    }
    match engine.apply_config_from(base, &cfg) {
        Ok(()) => format!("policy {id} deleted"),
        Err(e) => format!("error: {e}"),
    }
}

pub fn run_client(host: &str, port: u16, command: Option<&str>) -> std::io::Result<()> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    login(&mut stream, &mut reader)?;
    match command {
        Some(cmd) => {
            stream.write_all(format!("{cmd}\n").as_bytes())?;
            let text = read_response(&mut reader)?;
            println!("{text}");
        }
        None => {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            loop {
                stream.write_all(b"prompt\n")?;
                print!("{}", read_response(&mut reader)?);
                std::io::stdout().flush()?;
                let mut line = String::new();
                if input.read_line(&mut line)? == 0 {
                    break;
                }
                if line.trim().is_empty() {
                    continue;
                }
                stream.write_all(line.as_bytes())?;
                let text = read_response(&mut reader)?;
                if !text.is_empty() {
                    println!("{text}");
                }
                if text == "bye" {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn login(stream: &mut TcpStream, reader: &mut BufReader<TcpStream>) -> std::io::Result<()> {
    let request = if let Ok(token) = std::env::var("VELA_API_TOKEN") {
        serde_json::json!({"action": "token", "token": token}).to_string()
    } else {
        let username = std::env::var("VELA_CLI_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let password = std::env::var("VELA_CLI_PASSWORD").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "set VELA_CLI_PASSWORD or VELA_API_TOKEN (or use an SSH tunnel to run the daemon-side CLI)",
            )
        })?;
        serde_json::json!({"action": "login", "username": username, "password": password})
            .to_string()
    };
    stream.write_all(format!("{request}\n").as_bytes())?;
    let response = read_response(reader)?;
    if response.starts_with("error:") || !response.starts_with("authenticated as ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            response,
        ));
    }
    Ok(())
}

fn read_response(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
    let mut out = String::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            break;
        }
        out.push(byte[0] as char);
        if out.ends_with(&format!("\n{END_MARKER}\n")) || out == format!("{END_MARKER}\n") {
            let cut = out.rfind(END_MARKER).unwrap_or(out.len());
            out.truncate(cut);
            while out.ends_with('\n') {
                out.pop();
            }
            break;
        }
    }
    Ok(out)
}
