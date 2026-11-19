mod appid;
mod auth;
mod cli;
mod dataplane;
mod diff;
mod editor;
mod gui;
mod ha;
mod wg;
mod inspect;
mod model;
mod nft;
mod packet;
mod style;
mod tls;
mod tls_inspect;

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
        Some("ssl-ca-generate") => ssl_ca_generate(&args[1..]),
        Some("wg-genkey") => {
            println!("{}", wg::genkey());
            Ok(())
        }
        Some("wg-pubkey") => {
            let mut key = String::new();
            std::io::stdin()
                .read_line(&mut key)
                .map_err(|e| e.to_string())
                .and_then(|_| wg::pubkey(&key))
                .map(|k| println!("{k}"))
        }
        Some("version" | "-V" | "--version") => {
            println!("firewall 0.2.0");
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
        "firewall 0.2.0 - a lightweight educational next-generation IPv4 firewall\n\
\n\
usage:\n\
  firewall daemon [--config PATH] [--hostname NAME] [--cli-port N] [--gui-port N]\n\
                  [--no-dataplane] [--no-gui] [--no-cli] [--dry-run]\n\
  firewall cli [--host HOST] [--port N] [-c COMMAND]\n\
  firewall config-check --config PATH\n\
  firewall nft-apply --config PATH\n\
  firewall nft-remove\n\
  firewall password-reset-token --config PATH --username NAME\n\
  firewall wg-genkey | firewall wg-pubkey      (WireGuard keys, like wg genkey / wg pubkey)\n\
  firewall ssl-ca-generate --out DIR [--name CN]  (TLS inspection CA: ca.crt, ca.key)\n\
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

    println!("firewall 0.2.0");
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
    if !no_cli && !cfg.settings.cli_bind.is_loopback() && !cfg.settings.cli_remote_plaintext {
        return Err(format!(
            "cli: refusing to listen on {}: the CLI transport is plaintext and carries credentials. \
             Bind it to loopback, or set `system cli-remote-plaintext on` to accept the risk",
            cfg.settings.cli_bind
        ));
    }
    // Fail closed: the userspace engine only sees copies of frames, so if the
    // kernel forwards between our interfaces it routes traffic around us.
    let enforcing = !no_dataplane && !dry_run;
    // Mode B: the kernel forwards and enforces; the AF_PACKET engine stays
    // closed so there is exactly one enforcement path.
    let kernel_mode = enforcing && cfg.settings.dataplane_kernel;
    if kernel_mode {
        let problems = nft::kernel_problems(&cfg);
        if !problems.is_empty() {
            return Err(format!(
                "`system dataplane kernel` cannot enforce this configuration exactly:\n  {}\n\
                 Remove these features or use the userspace dataplane",
                problems.join("\n  ")
            ));
        }
    }
    let iface_names: Vec<String> = cfg.interfaces.iter().filter(|i| !i.tunnel).map(|i| i.name.clone()).collect();
    let mut _daemon_lock = None;
    if enforcing {
        let problems = dataplane::kernel_forwarding_problems(Path::new(SYSCTL_NET), &iface_names);
        if !kernel_mode && !problems.is_empty() {
            if cfg.settings.kernel_forwarding_refuse {
                return Err(format!(
                    "refusing to start the dataplane: the kernel would route traffic around the firewall\n  {}\n\
                     Disable it (sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0), \
                     or set `system kernel-forwarding warn` to start degraded",
                    problems.join("\n  ")
                ));
            }
            for p in &problems {
                eprintln!("warning: {p}; the firewall will report itself degraded");
            }
        }
        // Held for the life of the process; `nft-apply` refuses to add a
        // second enforcement path while it is held.
        _daemon_lock = Some(daemon_lock(&path, true)?.ok_or_else(|| {
            format!("another firewall daemon already holds {}", lock_path(&path).display())
        })?);
    }

    let cfg = Arc::new(RwLock::new(cfg));
    let stats = Arc::new(Mutex::new(Stats::default()));
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let arp = Arc::new(Mutex::new(
        HashMap::<(String, Ipv4Addr), ([u8; 6], Instant)>::new(),
    ));

    let mut engine = Engine::open(
        cfg,
        stats,
        sessions,
        arp,
        dry_run || no_dataplane || kernel_mode,
        Some(path.clone()),
    );
    if kernel_mode {
        engine.kernel = Some(Box::new(nft::Netlink::default()));
        engine.kernel_start()?;
        println!("dataplane: kernel (nftables table inet {}), installed and verified", nft::TABLE);
    }
    let engine = Arc::new(engine);

    if kernel_mode {
        let engine = engine.clone();
        std::thread::spawn(move || loop {
            // The kernel forwards in this mode; with forwarding off nothing
            // passes (fail closed), which is still worth reporting.
            let off = std::fs::read_to_string(Path::new(SYSCTL_NET).join("ipv4/ip_forward"))
                .map(|v| v.trim() == "0")
                .unwrap_or(false);
            *engine.kernel_problems.lock().unwrap() = if off {
                vec!["kernel forwarding is off (net.ipv4.ip_forward = 0): the kernel dataplane forwards nothing".to_string()]
            } else {
                Vec::new()
            };
            if let Some(event) = engine.kernel_reconcile() {
                eprintln!("{event}");
            }
            std::thread::sleep(Duration::from_secs(5));
        });
    }
    if enforcing && !kernel_mode {
        let engine = engine.clone();
        std::thread::spawn(move || {
            let mut last: Vec<String> = Vec::new();
            loop {
                let names: Vec<String> =
                    engine.cfg.read().unwrap().interfaces.iter().filter(|i| !i.tunnel).map(|i| i.name.clone()).collect();
                let now = dataplane::kernel_forwarding_problems(Path::new(SYSCTL_NET), &names);
                if now != last {
                    for p in now.iter().filter(|p| !last.contains(p)) {
                        eprintln!("degraded: {p}");
                    }
                    if now.is_empty() && !last.is_empty() {
                        eprintln!("kernel forwarding is off again");
                    }
                    last = now.clone();
                }
                *engine.kernel_problems.lock().unwrap() = now;
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }
    if !engine.cfg.read().unwrap().tunnels.is_empty() {
        let engine = engine.clone();
        std::thread::spawn(move || loop {
            engine.vpn_tick();
            std::thread::sleep(Duration::from_millis(250));
        });
    }
    let ha_settings = engine.cfg.read().unwrap().ha.clone();
    if ha_settings.enabled {
        let agent = ha::Agent::new(engine.clone(), ha_settings.clone())
            .map_err(|e| format!("ha: cannot bind {:?}: {e}", ha_settings.bind))?;
        println!(
            "ha: active-passive, priority {}, heartbeat {} -> {}",
            ha_settings.priority,
            ha_settings.bind.map(|b| b.to_string()).unwrap_or_default(),
            ha_settings.peer.map(|p| p.to_string()).unwrap_or_default()
        );
        std::thread::spawn(move || agent.run());
    }
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
    if enforcing && !kernel_mode {
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
        "ok: {} vdom(s), {} interface(s), {} policy(ies), {} route(s), {} IPv6 route(s), {} snat rule(s)",
        cfg.vdoms.len(),
        cfg.interfaces.len(),
        cfg.policies.len(),
        cfg.routes.len(),
        cfg.routes6.len(),
        cfg.snat.len()
    );
    for route in &cfg.routes {
        let dst = if route.dst == model::Cidr::ANY { "default".to_string() } else { route.dst.to_string() };
        println!(
            "  {:<12} {dst} {}{} distance {}",
            route.vdom,
            route.interface,
            route.via.map(|v| format!(" via {v}")).unwrap_or_default(),
            route.distance
        );
    }
    Ok(())
}

/// Create the TLS inspection CA. Clients must trust ca.crt; ca.key stays 0600.
fn ssl_ca_generate(args: &[String]) -> Result<(), String> {
    let (mut out, mut name) = (None, "NetworkSandbox NGFW Inspection CA".to_string());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => out = Some(PathBuf::from(need(args, i + 1, "--out")?)),
            "--name" => name = need(args, i + 1, "--name")?.to_string(),
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 2;
    }
    let dir = out.ok_or("usage: firewall ssl-ca-generate --out DIR [--name CN]")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (key_path, cert_path) = (dir.join("ca.key"), dir.join("ca.crt"));
    if key_path.exists() {
        return Err(format!("{} exists; refusing to overwrite a CA key", key_path.display()));
    }
    let (ca, key_pem) = tls_inspect::Ca::generate(&name)?;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_path).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut f, key_pem.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::write(&cert_path, &ca.cert_pem).map_err(|e| e.to_string())?;
    println!("wrote {} (install on clients) and {} (mode 0600)", cert_path.display(), key_path.display());
    Ok(())
}

fn nft_apply(args: &[String]) -> Result<(), String> {
    let path = match args {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => return Err("usage: firewall nft-apply --config PATH".to_string()),
    };
    let cfg = load_config(&path)?;
    // One authoritative enforcement path: while a daemon is forwarding in
    // userspace with this configuration, a kernel ruleset would be a second,
    // diverging one.
    if daemon_lock(&path, false)?.is_none() {
        return Err(format!(
            "a firewall daemon is running with {} and enforcing in userspace; \
             stop it before installing the kernel ruleset",
            path.display()
        ));
    }
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

const SYSCTL_NET: &str = "/proc/sys/net";

fn lock_path(config: &Path) -> PathBuf {
    config.with_extension("lock")
}

/// Take an exclusive, non-blocking lock next to the configuration file.
/// `Ok(None)` means another process holds it. With `create == false` a
/// missing lock file means no daemon has ever run: the lock is free.
fn daemon_lock(config: &Path, create: bool) -> Result<Option<std::fs::File>, String> {
    use std::os::unix::io::AsRawFd;
    let path = lock_path(config);
    let file = match std::fs::OpenOptions::new().read(true).write(true).create(create).open(&path) {
        Ok(f) => f,
        Err(e) if !create && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(std::fs::File::open("/dev/null").map_err(|e| e.to_string())?))
        }
        Err(e) => return Err(format!("lock {}: {e}", path.display())),
    };
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(Some(file))
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(format!("lock {}: {}", path.display(), std::io::Error::last_os_error()))
    }
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
