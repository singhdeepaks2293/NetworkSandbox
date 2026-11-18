mod auth;
mod cli;
mod dataplane;
mod diff;
mod gui;
mod inspect;
mod model;
mod nft;
mod packet;
mod tls;

use dataplane::{Engine, Sessions, Stats};
use model::Config;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const DEFAULT_CONFIG_PATH: &str = "/etc/firewall/firewall.conf";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("daemon") => daemon(&args[1..]),
        Some("cli") => client(&args[1..]),
        Some("config-check" | "check") => config_check(&args[1..]),
        Some("nft-apply") => nft_apply(&args[1..]),
        Some("nft-remove") => nft_remove(&args[1..]),
        Some("password-reset-token") => password_reset_token(&args[1..]),
        Some("version" | "-V" | "--version") => {
            println!("firewall 0.1.0");
            Ok(())
        }
        Some("help" | "-h" | "--help") | None => {
            usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}' (try --help)")),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    println!(
        "firewall 0.1.0 - a tiny educational stateful IPv4 firewall\n\
\n\
usage:\n\
  firewall daemon [--config PATH] [--hostname NAME] [--cli-port N] [--gui-port N]\n\
                  [--no-dataplane] [--no-gui] [--no-cli] [--dry-run]\n\
  firewall cli [--host HOST] [--port N] [-c COMMAND]\n\
  firewall config-check --config PATH\n\
  firewall nft-apply --config PATH\n\
  firewall nft-remove\n\
  firewall password-reset-token --config PATH --username NAME\n\
\n\
The daemon opens AF_PACKET sockets on every configured interface, forwards\n\
IPv4 between zones according to the first matching policy, keeps a stateful\n\
connection table and can source-NAT outbound flows. The web GUI listens on\n\
the configured gui-port and the CLI on the configured cli-port."
    );
}

fn daemon(args: &[String]) -> Result<(), String> {
    let mut config_path: Option<PathBuf> = None;
    let mut hostname: Option<String> = None;
    let mut cli_port: Option<u16> = None;
    let mut gui_port: Option<u16> = None;
    let mut no_dataplane = false;
    let mut no_gui = false;
    let mut no_cli = false;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = Some(PathBuf::from(need(args, i, "--config")?));
            }
            "--hostname" => {
                i += 1;
                hostname = Some(need(args, i, "--hostname")?.to_string());
            }
            "--cli-port" => {
                i += 1;
                cli_port = Some(
                    need(args, i, "--cli-port")?
                        .parse()
                        .map_err(|_| "invalid --cli-port".to_string())?,
                );
            }
            "--gui-port" => {
                i += 1;
                gui_port = Some(
                    need(args, i, "--gui-port")?
                        .parse()
                        .map_err(|_| "invalid --gui-port".to_string())?,
                );
            }
            "--no-dataplane" => no_dataplane = true,
            "--no-gui" => no_gui = true,
            "--no-cli" => no_cli = true,
            "--dry-run" => dry_run = true,
            other => return Err(format!("unknown daemon option '{other}'")),
        }
        i += 1;
    }

    let path = config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let (auth, bootstrap) = auth::Auth::load(&path)?;
    if let Some(bootstrap) = bootstrap {
        println!(
            "auth: initialized administrator '{}'; password written to {} (mode 0600)",
            bootstrap.username,
            bootstrap.path.display()
        );
    }
    let auth = Arc::new(auth);
    let mut cfg = load_config(&path)?;
    if let Some(name) = hostname {
        cfg.settings.hostname = name;
    }
    if let Some(port) = cli_port {
        cfg.settings.cli_port = port;
    }
    if let Some(port) = gui_port {
        cfg.settings.gui_port = port;
    }

    println!("firewall 0.1.0");
    println!("hostname: {}", cfg.settings.hostname);
    if cfg.interfaces.is_empty() {
        println!("interfaces: none configured (control plane only)");
    } else {
        for iface in &cfg.interfaces {
            println!(
                "interface {}: zone {} address {}",
                iface.name,
                iface.zone,
                iface
                    .address
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unset".to_string())
            );
        }
    }
    println!(
        "cli: tcp/{} gui: {}/{} dataplane: {}",
        cfg.settings.cli_port,
        if cfg.settings.tls { "https" } else { "http" },
        cfg.settings.gui_port,
        if no_dataplane { "off" } else { "on" }
    );
    if cfg.settings.tls {
        tls::server_config(Some(&path), &cfg.settings, &cfg.settings.hostname)?;
    }

    let cfg = Arc::new(RwLock::new(cfg));
    let stats = Arc::new(Mutex::new(Stats::default()));
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let arp = Arc::new(Mutex::new(
        HashMap::<(String, Ipv4Addr), ([u8; 6], Instant)>::new(),
    ));

    let engine = Arc::new(Engine::open(
        cfg,
        stats,
        sessions,
        arp,
        dry_run || no_dataplane,
        Some(path.clone()),
    ));

    if !no_gui {
        let engine = engine.clone();
        let auth = auth.clone();
        std::thread::spawn(move || gui::serve(engine, auth));
    }
    if !no_cli {
        let engine = engine.clone();
        let auth = auth.clone();
        std::thread::spawn(move || cli::serve(engine, auth));
    }
    let _auth = auth;
    if !no_dataplane && !dry_run {
        let engine = engine.clone();
        std::thread::spawn(move || engine.run());
    }

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn client(args: &[String]) -> Result<(), String> {
    let mut host = "127.0.0.1".to_string();
    let mut port = 2200u16;
    let mut command: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = need(args, i, "--host")?.to_string();
            }
            "--port" => {
                i += 1;
                port = need(args, i, "--port")?
                    .parse()
                    .map_err(|_| "invalid --port".to_string())?;
            }
            "-c" => {
                i += 1;
                command = Some(need(args, i, "-c")?.to_string());
            }
            other => return Err(format!("unknown cli option '{other}'")),
        }
        i += 1;
    }
    cli::run_client(&host, port, command.as_deref()).map_err(|e| format!("{host}:{port}: {e}"))
}

fn password_reset_token(args: &[String]) -> Result<(), String> {
    let mut config: Option<String> = None;
    let mut username: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config = Some(need(args, i, "--config")?.to_string());
            }
            "--username" => {
                i += 1;
                username = Some(need(args, i, "--username")?.to_string());
            }
            other => return Err(format!("unknown password-reset-token option '{other}'")),
        }
        i += 1;
    }
    let config = config.ok_or_else(|| {
        "usage: firewall password-reset-token --config PATH --username NAME".to_string()
    })?;
    let username =
        username.ok_or_else(|| "password-reset-token requires --username".to_string())?;
    let (token, path) = auth::Auth::issue_reset_token(Path::new(&config), &username)?;
    println!("reset token for {username}: {token}");
    println!("valid for 15 minutes; stored in {}", path.display());
    println!("POST /api/v1/auth/password-reset with {{\"token\":\"...\",\"password\":\"...\"}}");
    Ok(())
}

fn config_check(args: &[String]) -> Result<(), String> {
    let Some(path) = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
    else {
        return Err("usage: firewall config-check --config PATH".to_string());
    };
    let path = Path::new(path);
    let cfg = load_config(path)?;
    println!(
        "ok: {} vdom(s), {} interface(s), {} policy(ies), {} default route(s)",
        cfg.vdoms.len(),
        cfg.interfaces.len(),
        cfg.policies.len(),
        cfg.routes.len()
    );
    for route in &cfg.routes {
        println!(
            "  {:<12} default {}{}",
            route.vdom,
            route.interface,
            route.via.map(|v| format!(" via {v}")).unwrap_or_default()
        );
    }
    Ok(())
}

fn nft_apply(args: &[String]) -> Result<(), String> {
    let path = match args {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => return Err("usage: firewall nft-apply --config PATH".to_string()),
    };
    let cfg = load_config(&path)?;
    let summary = nft::install(&cfg)?;
    println!(
        "ok: installed inet {} with {} chain(s) and {} rule(s)",
        nft::TABLE,
        summary.chains,
        summary.rules
    );
    Ok(())
}

fn nft_remove(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: firewall nft-remove".to_string());
    }
    nft::uninstall()?;
    println!("ok: removed inet {}", nft::TABLE);
    Ok(())
}

fn need<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn load_config(path: &Path) -> Result<Config, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Config::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "config: {} does not exist; starting with an empty configuration",
                path.display()
            );
            Ok(Config::default())
        }
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}
