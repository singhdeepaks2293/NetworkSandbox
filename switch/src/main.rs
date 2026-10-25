//! `switch` — a tiny educational Ethernet switch.
//!
//! One binary runs either the daemon (dataplane + CLI server) or a CLI client:
//!
//! ```text
//! switch daemon --ports eth1,eth2 [--no-dataplane] [--tcp 2200]
//! switch cli [-c "show vlan"]
//! switch cli --host 172.20.20.3 --port 2200
//! ```

mod cli;
mod dataplane;
mod lldp;
mod md5;
mod model;
mod packet;
mod stp;

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use model::Switch;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const PROMPT_MARKER: &str = "@@PROMPT@@ ";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("daemon");

    match cmd {
        "daemon" | "start" | "run" => run_daemon(&args[1..]),
        "cli" | "console" | "attach" => run_cli(&args[1..]),
        "version" | "-V" | "--version" => println!(
            "{}",
            concat!("switch ", env!("CARGO_PKG_VERSION"), " (educational L2 switch)")
        ),
        "help" | "-h" | "--help" => print_help(),
        other if other.starts_with('-') => run_daemon(&args),
        other => {
            eprintln!("switch: unknown command '{}'", other);
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "switch - educational Ethernet switch with a vendor-neutral CLI

Usage:
  switch daemon [options]        run the switch (default)
  switch cli [options]           attach to a running switch
  switch version

Daemon options:
  --ports LIST        comma separated interfaces (default: all eth*/en*)
  --hostname NAME     system hostname
  --mac MAC           system MAC (aabb.ccdd.eeff), default from first port
  --config PATH       startup-config path
  --socket PATH       Unix control socket (default /run/switch/console.sock)
  --tcp PORT          also listen for CLI clients on TCP (telnet-style)
  --no-dataplane      simulation mode: CLI and STP timers, no raw sockets
  --no-startup        ignore the startup configuration

CLI options:
  --socket PATH       Unix socket to connect to
  --host HOST --port PORT   connect over TCP instead
  -c \"COMMAND\"        run a command (repeatable) and exit

Examples:
  switch daemon --ports eth1,eth2,eth3
  switch daemon --ports eth1,eth2 --tcp 2200 --no-dataplane
  switch cli -c \"show spanning-tree\"
  switch cli --host 172.20.20.11 --port 2200
"
    );
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

struct DaemonOpts {
    hostname: Option<String>,
    ports: Option<Vec<String>>,
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
    tcp: Option<u16>,
    dataplane: bool,
    startup: bool,
    mac: Option<[u8; 6]>,
}

fn parse_daemon_opts(args: &[String]) -> Result<DaemonOpts, String> {
    let mut o = DaemonOpts {
        hostname: None,
        ports: None,
        config: None,
        socket: None,
        tcp: None,
        dataplane: true,
        startup: true,
        mac: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let need = |n: usize| -> Result<&str, String> {
            args.get(i + n)
                .map(|s| s.as_str())
                .ok_or_else(|| format!("option '{}' needs a value", a))
        };
        match a {
            "--ports" | "-p" => {
                let v = need(1)?;
                o.ports = Some(
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                i += 2;
            }
            "--hostname" | "-n" => {
                o.hostname = Some(need(1)?.to_string());
                i += 2;
            }
            "--config" => {
                o.config = Some(PathBuf::from(need(1)?));
                i += 2;
            }
            "--socket" => {
                o.socket = Some(PathBuf::from(need(1)?));
                i += 2;
            }
            "--tcp" => {
                o.tcp = Some(
                    need(1)?
                        .parse()
                        .map_err(|_| "invalid TCP port".to_string())?,
                );
                i += 2;
            }
            "--mac" => {
                o.mac = Some(
                    packet::parse_mac(need(1)?)
                        .ok_or_else(|| "invalid MAC address".to_string())?,
                );
                i += 2;
            }
            "--no-dataplane" | "--simulate" => {
                o.dataplane = false;
                i += 1;
            }
            "--no-startup" => {
                o.startup = false;
                i += 1;
            }
            "--autosave" | "-v" | "--verbose" => i += 1,
            other => return Err(format!("unknown option '{}'", other)),
        }
    }
    Ok(o)
}

fn default_hostname() -> String {
    env::var("SWITCH_HOSTNAME")
        .ok()
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "switch".to_string())
}

fn default_config_path() -> PathBuf {
    let etc = PathBuf::from("/etc/switch/startup-config");
    if let Some(parent) = etc.parent() {
        if fs::create_dir_all(parent).is_ok() {
            return etc;
        }
    }
    PathBuf::from("/tmp/switch/startup-config")
}

fn default_socket_path() -> PathBuf {
    let run = PathBuf::from("/run/switch/console.sock");
    if let Some(parent) = run.parent() {
        if fs::create_dir_all(parent).is_ok() {
            return run;
        }
    }
    PathBuf::from("/tmp/switch/console.sock")
}

fn read_iface_mac(ifname: &str) -> Option<[u8; 6]> {
    fs::read_to_string(format!("/sys/class/net/{}/address", ifname))
        .ok()
        .and_then(|s| packet::parse_mac(s.trim()))
}

fn fallback_mac(seed: &str) -> [u8; 6] {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    [
        0x02,
        (h >> 40) as u8,
        (h >> 32) as u8,
        (h >> 24) as u8,
        (h >> 16) as u8,
        (h >> 8) as u8,
    ]
}

fn run_daemon(args: &[String]) {
    let opts = match parse_daemon_opts(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("switch: {}", e);
            std::process::exit(2);
        }
    };

    unsafe {
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let hostname = opts.hostname.clone().unwrap_or_else(default_hostname);
    let config_path = opts.config.clone().unwrap_or_else(default_config_path);
    let socket_path = opts.socket.clone().unwrap_or_else(default_socket_path);

    let interfaces: Vec<String> = match &opts.ports {
        Some(p) => p.clone(),
        None => dataplane::list_interfaces(),
    };

    let system_mac = opts.mac.unwrap_or_else(|| {
        interfaces
            .iter()
            .find_map(|i| read_iface_mac(i))
            .unwrap_or_else(|| fallback_mac(&hostname))
    });

    let mut sw = Switch::new(&hostname, system_mac, config_path.clone());
    if opts.tcp.is_some() {
        // The TCP listener is an opt-in transport; the feature flag lets a
        // startup-config disable logins again.
        sw.features.telnet = true;
    }
    for ifname in &interfaces {
        sw.add_port(ifname);
    }
    // Non-existent interfaces are kept so configuration can refer to them.
    if opts.dataplane {
        dataplane::poll_links(&mut sw);
    } else {
        for p in sw.ports.iter_mut() {
            p.link_up = true;
        }
    }

    if opts.startup {
        if let Ok(text) = fs::read_to_string(&config_path) {
            cli::load_config(&mut sw, &text);
            eprintln!("switchd: loaded {}", config_path.display());
        }
    }
    stp::sync(&mut sw);

    let sw = Arc::new(Mutex::new(sw));
    let io = dataplane::Io::new(opts.dataplane);

    let ports_explicit = opts.ports.is_some();
    if opts.dataplane {
        // Interfaces may not exist yet (containerlab creates veths after the
        // container starts); the periodic thread keeps retrying.
        dataplane::attach_missing(&sw, &io);
    }

    {
        let mut guard = sw.lock().unwrap();
        let p = guard.ports.len();
        eprintln!(
            "switchd: {} ({} port{}) starting, dataplane={}",
            guard.hostname,
            p,
            if p == 1 { "" } else { "s" },
            if opts.dataplane { "on" } else { "simulation" }
        );
        for port in &guard.ports {
            eprintln!(
                "switchd:   {} -> {} ({})",
                port.ifname,
                port.name,
                port.status_str()
            );
        }
        let out = stp::tick(&mut guard, Instant::now());
        dataplane::run_outcome(&mut guard, &io, out);
    }

    // ---- control sockets ---------------------------------------------------
    if UnixStream::connect(&socket_path).is_ok() {
        eprintln!(
            "switchd: another instance is already listening on {}",
            socket_path.display()
        );
        std::process::exit(1);
    }
    let _ = fs::remove_file(&socket_path);
    if let Some(parent) = socket_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let unix_listener = match UnixListener::bind(&socket_path) {
        Ok(l) => {
            eprintln!("switchd: console on unix:{}", socket_path.display());
            Some(l)
        }
        Err(e) => {
            eprintln!(
                "switchd: cannot bind unix:{} ({}); use TCP or --socket",
                socket_path.display(),
                e
            );
            None
        }
    };

    if let Some(l) = unix_listener {
        let sw2 = Arc::clone(&sw);
        thread::spawn(move || {
            for conn in l.incoming() {
                match conn {
                    Ok(stream) => {
                        let sw3 = Arc::clone(&sw2);
                        thread::spawn(move || serve(stream, sw3));
                    }
                    Err(_) => {
                        if STOP.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                }
            }
        });
    }

    if let Some(port) = opts.tcp {
        match TcpListener::bind(("0.0.0.0", port)) {
            Ok(l) => {
                eprintln!("switchd: console on tcp:0.0.0.0:{}", port);
                let sw2 = Arc::clone(&sw);
                thread::spawn(move || {
                    for conn in l.incoming() {
                        match conn {
                            Ok(mut stream) => {
                                let _ = stream.set_nodelay(true);
                                let allowed = sw2
                                    .lock()
                                    .map(|s| s.features.telnet)
                                    .unwrap_or(false);
                                if !allowed {
                                    let _ = stream.write_all(
                                        b"% TCP console disabled (enable with 'feature telnet')\n",
                                    );
                                    continue;
                                }
                                let sw3 = Arc::clone(&sw2);
                                thread::spawn(move || serve(stream, sw3));
                            }
                            Err(_) => {
                                if STOP.load(Ordering::SeqCst) {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("switchd: cannot listen on tcp:{}: {}", port, e),
        }
    }

    // ---- periodic engine ---------------------------------------------------
    {
        let sw2 = Arc::clone(&sw);
        let io2 = Arc::clone(&io);
        let dataplane_on = opts.dataplane;
        thread::spawn(move || {
            let mut last_link = Instant::now();
            let mut last_save = Instant::now();
            let mut last_attach = Instant::now()
                .checked_sub(Duration::from_secs(5))
                .unwrap_or_else(Instant::now);
            while !STOP.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(200));
                let now = Instant::now();

                // Late interface creation / hot-plug (must run without holding
                // the switch lock: attach_missing takes it itself).
                if dataplane_on && now.duration_since(last_attach) >= Duration::from_secs(1) {
                    last_attach = now;
                    if !ports_explicit {
                        let names = dataplane::list_interfaces();
                        if let Ok(mut g) = sw2.lock() {
                            for n in names {
                                g.add_port(&n);
                            }
                        }
                    }
                    dataplane::attach_missing(&sw2, &io2);
                }

                let mut guard = match sw2.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                if dataplane_on && now.duration_since(last_link) >= Duration::from_secs(2) {
                    last_link = now;
                    if dataplane::poll_links(&mut guard) {
                        guard.log_line("link state changed, re-running STP");
                    }
                }
                dataplane::tick(&mut guard, &io2, now);
                let aging = Duration::from_secs(guard.mac_aging as u64);
                guard.mac_table.age(now, aging);
                if guard.dirty && now.duration_since(last_save) >= Duration::from_secs(2) {
                    last_save = now;
                    let _ = cli::save_config(&mut guard);
                }
            }
        });
    }

    // ---- wait for shutdown -------------------------------------------------
    while !STOP.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    {
        let mut guard = match sw.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if guard.dirty {
            let _ = cli::save_config(&mut guard);
        }
        guard.log_line("shutting down");
    }
    io.close_all();
    let _ = fs::remove_file(&socket_path);
    eprintln!("switchd: stopped");
}

// ---------------------------------------------------------------------------
// CLI server
// ---------------------------------------------------------------------------

fn serve<S: Read + Write>(stream: S, sw: Arc<Mutex<Switch>>) {
    let mut reader = BufReader::new(stream);
    let mut session = cli::Session::new();

    let (banner, prompt) = {
        let guard = match sw.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        (cli::banner(&guard), session.prompt(&guard))
    };
    let mut out = String::new();
    out.push_str(&banner);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(PROMPT_MARKER);
    out.push_str(&prompt);
    out.push('\n');
    if reader.get_mut().write_all(out.as_bytes()).is_err() {
        return;
    }
    let _ = reader.get_mut().flush();

    loop {
        let mut raw = Vec::new();
        match read_telnet_line(&mut reader, &mut raw) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let line = String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if line.len() > 512 {
            let _ = reader.get_mut().write_all(b"% line too long\n");
        }
        if line == "quit" || line == "logout" && session.mode == cli::Mode::Exec {
            break;
        }

        let (output, prompt) = {
            let mut guard = match sw.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            let output = if line.trim().is_empty() {
                String::new()
            } else {
                cli::execute(&mut guard, &mut session, &line)
            };
            let prompt = session.prompt(&guard);
            (output, prompt)
        };

        let mut response = String::new();
        if !output.is_empty() {
            response.push_str(&output);
            if !response.ends_with('\n') {
                response.push('\n');
            }
        }
        response.push_str(PROMPT_MARKER);
        response.push_str(&prompt);
        response.push('\n');
        if reader.get_mut().write_all(response.as_bytes()).is_err() {
            break;
        }
        let _ = reader.get_mut().flush();
    }
}

/// Read one line, dropping telnet IAC negotiation bytes (0xFF + 2 bytes).
fn read_telnet_line<R: BufRead>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf)?;
    out.clear();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0xff {
            i += 3;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// CLI client
// ---------------------------------------------------------------------------

enum Target {
    Unix(PathBuf),
    Tcp(String, u16),
}

fn run_cli(args: &[String]) {
    let mut socket: Option<PathBuf> = None;
    let mut host: Option<String> = None;
    let mut port: u16 = 2200;
    let mut commands: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" | "-s" => {
                if i + 1 >= args.len() {
                    eprintln!("switch: --socket needs a path");
                    std::process::exit(2);
                }
                socket = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--host" | "-H" => {
                if i + 1 >= args.len() {
                    eprintln!("switch: --host needs a value");
                    std::process::exit(2);
                }
                host = Some(args[i + 1].clone());
                i += 2;
            }
            "--port" | "-p" => {
                if i + 1 >= args.len() {
                    eprintln!("switch: --port needs a value");
                    std::process::exit(2);
                }
                port = args[i + 1].parse().unwrap_or(2200);
                i += 2;
            }
            "-c" | "--command" => {
                if i + 1 >= args.len() {
                    eprintln!("switch: -c needs a command");
                    std::process::exit(2);
                }
                commands.push(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _other => {
                // Bare words are treated as one command (switch cli show vlan).
                commands.push(args[i..].join(" "));
                i = args.len();
            }
        }
    }

    let target = if let Some(h) = host {
        Target::Tcp(h, port)
    } else {
        Target::Unix(socket.unwrap_or_else(default_socket_path))
    };

    let stream: Box<dyn ReadWrite> = match &target {
        Target::Unix(path) => match UnixStream::connect(path) {
            Ok(s) => Box::new(s),
            Err(e) => {
                eprintln!(
                    "switch: cannot connect to {}: {} (is 'switch daemon' running?)",
                    path.display(),
                    e
                );
                std::process::exit(1);
            }
        },
        Target::Tcp(host, port) => match TcpStream::connect((host.as_str(), *port)) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            Err(e) => {
                eprintln!("switch: cannot connect to {}:{}: {}", host, port, e);
                std::process::exit(1);
            }
        },
    };

    if run_client(stream, commands).is_err() {
        std::process::exit(1);
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn run_client(stream: Box<dyn ReadWrite>, commands: Vec<String>) -> io::Result<()> {
    let write_half = stream;
    let mut reader = BufReader::new(write_half);
    let one_shot = !commands.is_empty();
    let mut prompt = String::new();
    read_response(&mut reader, &mut prompt, !one_shot)?;

    if one_shot {
        for cmd in commands {
            reader.get_mut().write_all(cmd.as_bytes())?;
            reader.get_mut().write_all(b"\n")?;
            reader.get_mut().flush()?;
            let mut p = String::new();
            read_response(&mut reader, &mut p, true)?;
            prompt = p;
            if prompt.is_empty() {
                break;
            }
        }
        return Ok(());
    }

    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        print!("{}", prompt);
        io::stdout().flush()?;
        line.clear();
        let n = stdin.lock().read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "quit" {
            break;
        }
        reader.get_mut().write_all(trimmed.as_bytes())?;
        reader.get_mut().write_all(b"\n")?;
        reader.get_mut().flush()?;
        let mut p = String::new();
        read_response(&mut reader, &mut p, true)?;
        prompt = p;
        if prompt.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Print all server output until the prompt marker; returns the prompt text.
fn read_response<R: BufRead>(
    reader: &mut R,
    prompt: &mut String,
    print_output: bool,
) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            prompt.clear();
            return Ok(());
        }
        if let Some(rest) = line.strip_prefix(PROMPT_MARKER) {
            *prompt = rest.trim_end_matches(['\r', '\n']).to_string();
            return Ok(());
        }
        if print_output || line.starts_with('%') {
            print!("{}", line);
            io::stdout().flush()?;
        }
    }
}
