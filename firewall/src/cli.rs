//! A small vendor-neutral CLI, reachable on stdin or over TCP.

use crate::dataplane::Engine;
use crate::model::{Config, Policy};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub const END_MARKER: &str = "__END__";

pub fn serve(engine: Arc<Engine>) {
    let port = engine.cfg.read().unwrap().settings.cli_port;
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cli: cannot listen on port {port}: {e}");
            return;
        }
    };
    println!("cli: listening on tcp/{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let engine = engine.clone();
                std::thread::spawn(move || handle_client(&engine, stream));
            }
            Err(e) => eprintln!("cli: accept: {e}"),
        }
    }
}

fn handle_client(engine: &Engine, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let response = execute(engine, line.trim());
        if writer
            .write_all(format!("{response}\n{END_MARKER}\n").as_bytes())
            .is_err()
        {
            break;
        }
    }
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
                "firewall 0.1.0\nhostname {}\nuptime {}s\nsessions {}",
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
        "  show version | config | interfaces | policies | sessions | stats",
        "  policy add [vdom NAME] <id> <src-zone> <dst-zone> <src-cidr|@object|any> <dst-cidr|@object|any> <proto|any> <port|@service|any> <permit|deny> [nat] [app X] [url X] [ips X] [av X] [shaper X] [nolog]",
        "  policy delete <id>",
        "  save",
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
    let mut out = String::from(
        "vdom       id   source        destination   src            dst            proto  port       action  nat  profiles\n",
    );
    let mut policies: Vec<&Policy> = cfg.policies.iter().collect();
    policies.sort_by_key(|p| p.id);
    for p in policies {
        let mut profiles = Vec::new();
        if let Some(app) = &p.app {
            profiles.push(format!("app={app}"));
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
            p.src_zone,
            p.dst_zone,
            p.src.to_string(),
            p.dst.to_string(),
            p.proto.to_string(),
            p.service
                .as_ref()
                .map(|s| format!("@{s}"))
                .or_else(|| p.dst_port.map(|v| v.to_string()))
                .unwrap_or_else(|| "any".to_string()),
            p.action.as_str(),
            if p.nat { "yes" } else { "no" },
            profiles.join(",")
        ));
    }
    out
}

fn show_sessions(engine: &Engine) -> String {
    let sessions = engine.sessions.lock().unwrap().snapshot();
    let cfg = engine.cfg.read().unwrap();
    let mut out = String::from(
        "vdom       proto  source                     destination                nat                 app        ttl\n",
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
        let app = cfg.detected_app(s.key.proto, s.key.dport).unwrap_or("-");
        out.push_str(&format!(
            "{:<10} {:<6} {:<26} {:<26} {:<19} {:<10} {}s\n",
            s.key.vdom,
            s.key.proto,
            format!("{}:{}", s.key.src, s.key.sport),
            format!("{}:{}", s.key.dst, s.key.dport),
            nat,
            app,
            s.expires
                .saturating_duration_since(std::time::Instant::now())
                .as_secs()
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
    let cfg = engine.cfg.read().unwrap().clone();
    let mut text = cfg.to_text();
    text.push_str(&format!("\nvdom {vdom}\n{line}\n"));
    match Config::parse(&text) {
        Ok(parsed) => {
            *engine.cfg.write().unwrap() = parsed;
            match engine.save() {
                Ok(()) => format!("policy added\n{line}"),
                Err(e) => format!("policy added in memory; save failed: {e}"),
            }
        }
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
    let mut cfg = engine.cfg.read().unwrap().clone();
    let before = cfg.policies.len();
    cfg.policies.retain(|p| p.id != id);
    if cfg.policies.len() == before {
        return format!("error: policy {id} not found");
    }
    *engine.cfg.write().unwrap() = cfg;
    match engine.save() {
        Ok(()) => format!("policy {id} deleted"),
        Err(e) => format!("policy {id} deleted in memory; save failed: {e}"),
    }
}

pub fn run_client(host: &str, port: u16, command: Option<&str>) -> std::io::Result<()> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    match command {
        Some(cmd) => {
            stream.write_all(format!("{cmd}\n").as_bytes())?;
            let text = read_response(&mut reader)?;
            println!("{text}");
        }
        None => {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                stream.write_all(format!("{line}\n").as_bytes())?;
                let text = read_response(&mut reader)?;
                println!("{text}");
                if matches!(line.trim(), "quit" | "exit") {
                    break;
                }
            }
        }
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
