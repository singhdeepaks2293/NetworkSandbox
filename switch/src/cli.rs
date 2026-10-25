//! Vendor-neutral command line interface.
//!
//! IOS spellings are accepted as aliases, but the documented vocabulary is the
//! switch's own.  Modes: user (`>`), admin (`#`), global configuration
//! (`(config)#`), port configuration (`(config-port)#`) and VLAN
//! configuration (`(config-vlan)#`).  The CLI is transport agnostic: the
//! daemon serves the same engine over Unix socket, TCP and the local console.

use std::fmt::Write as _;
use std::fs;
use std::time::Instant;

use crate::lldp;
use crate::model::*;
use crate::packet;
use crate::stp;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    Exec,
    Priv,
    Config,
    Interface(usize),
    Vlan(u16),
}

pub struct Session {
    pub mode: Mode,
    pub debug_stp: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Session {
            mode: Mode::Priv,
            debug_stp: false,
        }
    }

    pub fn prompt(&self, sw: &Switch) -> String {
        match &self.mode {
            Mode::Exec => format!("{}>", sw.hostname),
            Mode::Priv => format!("{}#", sw.hostname),
            Mode::Config => format!("{}(config)#", sw.hostname),
            Mode::Interface(_) => format!("{}(config-port)#", sw.hostname),
            Mode::Vlan(_) => format!("{}(config-vlan)#", sw.hostname),
        }
    }
}

pub fn banner(sw: &Switch) -> String {
    format!(
        "{}\nEducational Ethernet switch, {} built-in.\nType '?' or 'help' for commands.\n",
        sw.version, sw.hostname
    )
}

fn error(msg: &str) -> String {
    format!("% {}\n", msg)
}

fn incomplete() -> String {
    "% Incomplete command.\n".to_string()
}

fn parse_u16(tok: &str) -> Result<u16, String> {
    tok.parse::<u16>().map_err(|_| format!("invalid number '{}'", tok))
}

fn feature_off(name: &str) -> String {
    format!(
        "% Feature '{}' is disabled. Enable it with 'feature enable {}'.\n",
        name, name
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Translate the switch's own command vocabulary into the internal handler
/// names.  The old IOS/Cisco spellings are kept as aliases: anything this
/// function does not recognise is passed through unchanged.
fn translate(sess: &Session, line: &str) -> String {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.is_empty() {
        return String::new();
    }
    let lower = |i: usize| t.get(i).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let c0 = lower(0);

    // `do ...` is re-entered by execute(), which translates the inner line in
    // privileged mode; help passes through untouched.
    if c0 == "do" || c0 == "help" || c0 == "?" {
        return line.to_string();
    }
    if c0 == "quit" {
        return "exit".to_string();
    }

    match &sess.mode {
        Mode::Exec | Mode::Priv => match c0.as_str() {
            "config" => "configure terminal".to_string(),
            "admin" => "enable".to_string(),
            "user" => "disable".to_string(),
            "save" => "write memory".to_string(),
            "clear" if lower(1) == "fdb" => {
                if t.len() == 2 {
                    "clear mac address-table".to_string()
                } else {
                    format!("clear mac address-table {}", t[2..].join(" "))
                }
            }
            "show" => match lower(1).as_str() {
                "ports" if t.len() == 2 => "show interfaces status".to_string(),
                "port" if t.len() >= 3 => format!("show interfaces {}", t[2]),
                "vlans" => "show vlan brief".to_string(),
                "bridge" => {
                    if t.len() == 2 {
                        "show spanning-tree".to_string()
                    } else {
                        format!("show spanning-tree {}", t[2..].join(" "))
                    }
                }
                "fdb" => {
                    if t.len() == 2 {
                        "show mac address-table".to_string()
                    } else {
                        format!("show mac address-table {}", t[2..].join(" "))
                    }
                }
                "trunk" => "show interfaces trunk".to_string(),
                "counters" if t.len() >= 3 => format!("show interfaces counters {}", t[2]),
                "counters" => "show interfaces counters".to_string(),
                "config" => "show running-config".to_string(),
                "log" => "show logging".to_string(),
                _ => line.to_string(),
            },
            "debug" => match lower(1).as_str() {
                "stp" | "bridge" => match lower(2).as_str() {
                    "off" | "disable" => "undebug spanning-tree".to_string(),
                    _ => "debug spanning-tree".to_string(),
                },
                _ => line.to_string(),
            },
            _ => line.to_string(),
        },
        Mode::Config => match c0.as_str() {
            "device" if lower(1) == "name" && t.len() >= 3 => {
                format!("hostname {}", t[2..].join(" "))
            }
            "no" if lower(1) == "bridge" && t.len() >= 3 => {
                format!("no spanning-tree {}", t[2..].join(" "))
            }
            "port" if t.len() >= 2 => format!("interface {}", t[1..].join(" ")),
            "bridge" => match lower(1).as_str() {
                "mode" if t.len() >= 3 => format!("spanning-tree mode {}", t[2]),
                "priority" if t.len() >= 3 => {
                    format!("spanning-tree priority {}", t[2])
                }
                "hello" | "hello-time" if t.len() >= 3 => {
                    format!("spanning-tree hello-time {}", t[2])
                }
                "max-age" | "maxage" if t.len() >= 3 => {
                    format!("spanning-tree max-age {}", t[2])
                }
                "forward-delay" | "forward" if t.len() >= 3 => {
                    format!("spanning-tree forward-time {}", t[2])
                }
                "mst" if t.len() >= 3 => {
                    format!("spanning-tree mst {}", t[2..].join(" "))
                }
                // Compatibility with the old per-VLAN syntax.  Since the
                // CIST/MSTI allocation is shared, the value applies to the
                // whole bridge.
                "vlan" if t.len() >= 5 => {
                    let canon = match lower(3).as_str() {
                        "priority" => "priority",
                        "hello" | "hello-time" => "hello-time",
                        "max-age" | "maxage" => "max-age",
                        "forward-delay" | "forward" => "forward-time",
                        _ => return line.to_string(),
                    };
                    format!("spanning-tree vlan {} {} {}", t[2], canon, t[4..].join(" "))
                }
                _ => line.to_string(),
            },
            "feature" => match lower(1).as_str() {
                "enable" if t.len() >= 3 => format!("feature {}", t[2]),
                "disable" if t.len() >= 3 => format!("no feature {}", t[2]),
                _ => line.to_string(),
            },
            "mac" if lower(1) == "aging" && t.len() >= 3 => {
                format!("mac address-table aging-time {}", t[2])
            }
            _ => line.to_string(),
        },
        Mode::Interface(_) => match c0.as_str() {
            "mode" if t.len() >= 2 => format!("switchport mode {}", t[1]),
            "access" if lower(1) == "vlan" && t.len() >= 3 => {
                format!("switchport access vlan {}", t[2])
            }
            "native" if lower(1) == "vlan" && t.len() >= 3 => {
                format!("switchport trunk native vlan {}", t[2])
            }
            "allow" if lower(1) == "vlans" && t.len() >= 3 => {
                format!("switchport trunk allowed vlan {}", t[2..].join(" "))
            }
            "edge" => match lower(1).as_str() {
                "on" | "enable" => "spanning-tree portfast".to_string(),
                "off" | "disable" => "no spanning-tree portfast".to_string(),
                _ => line.to_string(),
            },
            "guard" => match lower(1).as_str() {
                "on" | "enable" => "spanning-tree bpduguard enable".to_string(),
                "off" | "disable" => "spanning-tree bpduguard disable".to_string(),
                _ => line.to_string(),
            },
            "cost" if t.len() >= 2 => format!("spanning-tree cost {}", t[1]),
            "priority" if t.len() >= 2 => format!("spanning-tree priority {}", t[1]),
            "mst" if t.len() >= 2 => format!("spanning-tree mst {}", t[1..].join(" ")),
            "link" => match lower(1).as_str() {
                "up" => "no shutdown".to_string(),
                "down" => "shutdown".to_string(),
                _ => line.to_string(),
            },
            _ => line.to_string(),
        },
        Mode::Vlan(_) => line.to_string(),
    }
}

pub fn execute(sw: &mut Switch, sess: &mut Session, line: &str) -> String {
    let translated = translate(sess, line.trim());
    let line = translated.trim();
    if line.is_empty() {
        return String::new();
    }
    let toks: Vec<&str> = line.split_whitespace().collect();
    let raw_cmd = toks[0].to_ascii_lowercase();
    let cmd = match raw_cmd.as_str() {
        "sh" => "show".to_string(),
        "conf" => "configure".to_string(),
        "int" => "interface".to_string(),
        "wr" => "write".to_string(),
        "en" => "enable".to_string(),
        "e" => "exit".to_string(),
        other => other.to_string(),
    };

    // Universal commands first.
    match raw_cmd.as_str() {
        "end" => {
            if matches!(sess.mode, Mode::Config | Mode::Interface(_) | Mode::Vlan(_)) {
                sess.mode = Mode::Priv;
            }
            return String::new();
        }
        "exit" => {
            sess.mode = match sess.mode {
                Mode::Exec => Mode::Exec,
                Mode::Priv => Mode::Exec,
                Mode::Config => Mode::Priv,
                Mode::Interface(_) | Mode::Vlan(_) => Mode::Config,
            };
            return String::new();
        }
        "?" => return help(sess),
        "help" => return help(sess),
        _ => {}
    }

    if cmd == "do" {
        if matches!(sess.mode, Mode::Config | Mode::Interface(_) | Mode::Vlan(_)) {
            let rest = line[2..].trim();
            let saved = sess.mode.clone();
            sess.mode = Mode::Priv;
            let out = execute(sw, sess, rest);
            sess.mode = saved;
            return out;
        }
        return error("'do' is only valid in configuration mode");
    }

    if toks.len() > 1 && toks[toks.len() - 1] == "?" {
        return help_for(sess, &toks[..toks.len() - 1]);
    }

    let mutating = matches!(
        sess.mode,
        Mode::Config | Mode::Interface(_) | Mode::Vlan(_)
    ) && !matches!(cmd.as_str(), "show" | "exit" | "end" | "help");

    let out = match sess.mode.clone() {
        Mode::Exec => exec_cmd(sw, sess, &cmd, &toks, line),
        Mode::Priv => priv_cmd(sw, sess, &cmd, &toks, line),
        Mode::Config => config_cmd(sw, sess, &cmd, &toks, line),
        Mode::Interface(_) => interface_cmd(sw, sess, &cmd, &toks, line),
        Mode::Vlan(vlan) => vlan_cmd(sw, sess, &cmd, &toks, line, vlan),
    };

    if mutating && !out.starts_with('%') {
        sw.dirty = true;
    }
    out
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn help(sess: &Session) -> String {
    match sess.mode {
        Mode::Exec => "  show          Inspect the switch\n  admin         Enter admin mode\n  quit          Exit the shell\n".to_string(),
        Mode::Priv => "  config        Enter configuration mode\n  show          Inspect the switch\n  save          Save the running configuration\n  clear         Clear tables/counters\n  debug stp     Trace spanning-tree events\n  user          Return to user mode\n  quit          Exit the shell\n".to_string(),
        Mode::Config => "  device name NAME\n  vlan create ID [name NAME]\n  vlan delete ID\n  vlan ID\n  port IFNAME\n  bridge priority N\n  bridge hello N\n  bridge max-age N\n  bridge forward-delay N\n  feature enable|disable NAME\n  mac aging SEC\n  end / exit\n".to_string(),
        Mode::Interface(_) => "  mode access|trunk\n  access vlan N\n  native vlan N\n  allow vlans LIST|add|remove|except|none|all\n  edge on|off\n  guard on|off\n  link up|down\n  description TEXT\n  speed N | duplex full|half|auto\n  end / exit\n".to_string(),
        Mode::Vlan(_) => "  name NAME\n  state active|suspend\n  end / exit\n".to_string(),
    }
}

fn help_for(sess: &Session, _prefix: &[&str]) -> String {
    help(sess)
}

// ---------------------------------------------------------------------------
// User / privileged EXEC
// ---------------------------------------------------------------------------

fn exec_cmd(sw: &mut Switch, sess: &mut Session, cmd: &str, toks: &[&str], _line: &str) -> String {
    match cmd {
        "enable" => {
            sess.mode = Mode::Priv;
            String::new()
        }
        "show" => show_cmd(sw, toks),
        "disable" => {
            sess.mode = Mode::Exec;
            String::new()
        }
        _ => error(&format!("invalid command '{}'", toks[0])),
    }
}

fn priv_cmd(sw: &mut Switch, sess: &mut Session, cmd: &str, toks: &[&str], line: &str) -> String {
    match cmd {
        "configure" => {
            if toks.len() < 2 {
                return incomplete();
            }
            match toks[1] {
                "terminal" | "t" | "term" => {
                    sess.mode = Mode::Config;
                    String::new()
                }
                other => error(&format!("unknown configure target '{}'", other)),
            }
        }
        "disable" => {
            sess.mode = Mode::Exec;
            String::new()
        }
        "show" => show_cmd(sw, toks),
        "write" => {
            if toks.len() < 2 || matches!(toks[1], "memory" | "mem" | "m") {
                save_config(sw)
            } else {
                error("usage: write memory")
            }
        }
        "copy" => {
            // copy running-config startup-config
            if toks.len() >= 3 && toks[1].starts_with("run") && toks[2].starts_with("start") {
                save_config(sw)
            } else {
                error("usage: copy running-config startup-config")
            }
        }
        "erase" => {
            if toks.len() >= 3 && toks[1] == "startup-config" || (toks.len() >= 2 && toks[1] == "startup-config") {
                match fs::remove_file(&sw.startup_path) {
                    Ok(_) => "Startup configuration erased.\n".to_string(),
                    Err(_) => "% Startup configuration not present.\n".to_string(),
                }
            } else {
                error("usage: erase startup-config")
            }
        }
        "clear" => clear_cmd(sw, toks),
        "debug" => debug_cmd(sw, sess, &toks[1..], true),
        "no" => {
            if toks.len() >= 2 && toks[1] == "debug" {
                debug_cmd(sw, sess, &toks[2..], false)
            } else if toks.len() >= 2 && toks[1] == "logging" {
                sw.logging_enabled = true;
                String::new()
            } else {
                error("invalid 'no' command")
            }
        }
        "undebug" => debug_cmd(sw, sess, &toks[1..], false),
        "reload" => "% reload is not supported; stop the container instead.\n".to_string(),
        "logout" => {
            sess.mode = Mode::Exec;
            "% Logged out.\n".to_string()
        }
        "hostname" => {
            // Tolerate hostname from privileged mode (handy for scripts).
            if toks.len() >= 2 {
                let mut s = toks[1..].join(" ");
                let out = set_hostname(sw, &mut s);
                out
            } else {
                incomplete()
            }
        }
        "monitor" => error("not supported"),
        _ => {
            let _ = line;
            error(&format!("invalid command '{}'", toks[0]))
        }
    }
}

fn set_hostname(sw: &mut Switch, name: &mut String) -> String {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 63 {
        return error("hostname must be 1..63 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return error("hostname may contain letters, digits, '-', '_' and '.'");
    }
    sw.hostname = name;
    String::new()
}

fn clear_cmd(sw: &mut Switch, toks: &[&str]) -> String {
    if toks.len() >= 2 && toks[1] == "mac" {
        sw.mac_table.clear_dynamic();
        sw.dirty = true;
        "MAC address table cleared.\n".to_string()
    } else if toks.len() >= 2 && toks[1] == "counters" {
        if let Some(name) = toks.get(2) {
            match sw.port_by_name(name) {
                Some(idx) => {
                    if let Some(p) = sw.port_mut(idx) {
                        p.counters = Default::default();
                    }
                    String::new()
                }
                None => error("no such interface"),
            }
        } else {
            for p in sw.ports.iter_mut() {
                p.counters = Default::default();
            }
            String::new()
        }
    } else if toks.len() >= 2 && toks[1] == "spanning-tree" {
        stp::refresh(sw);
        "Spanning tree counters cleared.\n".to_string()
    } else {
        error("usage: clear mac address-table | clear counters [IF] | clear spanning-tree")
    }
}

fn debug_cmd(sw: &mut Switch, sess: &mut Session, toks: &[&str], enable: bool) -> String {
    if toks.len() >= 1 && toks[0] == "spanning-tree" {
        sess.debug_stp = enable;
        sw.stp.debug = enable;
        sw.dirty = true;
        format!(
            "STP debugging is {}\n",
            if enable { "on" } else { "off" }
        )
    } else {
        error("usage: debug spanning-tree events")
    }
}

// ---------------------------------------------------------------------------
// Global configuration
// ---------------------------------------------------------------------------

fn config_cmd(sw: &mut Switch, sess: &mut Session, cmd: &str, toks: &[&str], line: &str) -> String {
    match cmd {
        "hostname" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let mut name = toks[1..].join(" ");
            set_hostname(sw, &mut name)
        }
        "vlan" => {
            if !sw.features.vlan {
                return feature_off("vlan");
            }
            if toks.len() < 2 {
                return incomplete();
            }
            let verb = toks[1].to_ascii_lowercase();
            if verb == "delete" {
                if toks.len() < 3 {
                    return incomplete();
                }
                let id = match parse_u16(toks[2]) {
                    Ok(v) => v,
                    Err(e) => return error(&e),
                };
                if id == 1 {
                    return error("VLAN 1 cannot be deleted");
                }
                remove_vlan(sw, id);
                return String::new();
            }
            let (id_tok, name) = if verb == "create" {
                if toks.len() < 3 {
                    return incomplete();
                }
                let name = if toks.len() >= 5 && toks[3].eq_ignore_ascii_case("name") {
                    Some(toks[4..].join(" "))
                } else if toks.len() > 3 {
                    return error("usage: vlan create ID [name NAME]");
                } else {
                    None
                };
                (toks[2], name)
            } else {
                (toks[1], None)
            };
            match parse_u16(id_tok) {
                Ok(id) if (1..=MAX_VLAN_ID).contains(&id) => {
                    sw.vlans.entry(id).or_insert_with(|| Vlan::new(id));
                    if let Some(n) = name {
                        if let Some(v) = sw.vlans.get_mut(&id) {
                            v.name = n;
                        }
                    }
                    stp::refresh(sw);
                    if verb == "create" {
                        String::new()
                    } else {
                        sess.mode = Mode::Vlan(id);
                        String::new()
                    }
                }
                Ok(_) => error("VLAN id must be 1..4094"),
                Err(e) => error(&e),
            }
        }
        "no" => {
            if toks.len() >= 2 && toks[1] == "vlan" {
                if toks.len() < 3 {
                    return incomplete();
                }
                let id = match parse_u16(toks[2]) {
                    Ok(v) => v,
                    Err(e) => return error(&e),
                };
                if id == 1 {
                    return error("VLAN 1 cannot be deleted");
                }
                remove_vlan(sw, id);
                String::new()
            } else if toks.len() >= 2 && toks[1] == "feature" {
                if toks.len() < 3 {
                    return incomplete();
                }
                set_feature(sw, toks[2], false)
            } else if toks.len() >= 2 && toks[1] == "spanning-tree" {
                if toks.len() >= 3 && toks[2] == "priority" {
                    sw.stp_config.priority = DEFAULT_PRIORITY;
                    stp::refresh(sw);
                    String::new()
                } else if toks.len() >= 3 && toks[2] == "vlan" {
                    // Old per-VLAN spelling: reset the shared CIST priority.
                    sw.stp_config.priority = DEFAULT_PRIORITY;
                    stp::refresh(sw);
                    String::new()
                } else if toks.len() >= 3 && toks[2] == "max-hops" {
                    sw.stp_config.max_hops = DEFAULT_MAX_HOPS;
                    stp::reset(sw);
                    stp::refresh(sw);
                    String::new()
                } else if toks.len() >= 4 && toks[2] == "mst" {
                    match toks[3] {
                        "name" => {
                            sw.mst.name = packet::format_mac(sw.system_mac);
                            mst_changed(sw)
                        }
                        "revision" => {
                            sw.mst.revision = 0;
                            mst_changed(sw)
                        }
                        "instance" if toks.len() >= 5 => {
                            match toks[4].parse::<u16>() {
                                Ok(id) if (1..=MAX_MSTID).contains(&id) => {
                                    sw.mst.remove_instance(id);
                                    mst_changed(sw)
                                }
                                _ => error(&format!(
                                    "MST instance id must be 1..{}",
                                    MAX_MSTID
                                )),
                            }
                        }
                        other => error(&format!("unknown 'no spanning-tree mst {}'", other)),
                    }
                } else {
                    error("usage: no spanning-tree priority|max-hops|mst ...")
                }
            } else if toks.len() >= 2 && toks[1] == "logging" {
                sw.logging_enabled = true;
                String::new()
            } else {
                error("invalid 'no' command")
            }
        }
        "interface" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let name = toks[1];
            match sw.port_by_name(name) {
                Some(idx) => {
                    sess.mode = Mode::Interface(idx);
                    String::new()
                }
                None => error(&format!(
                    "interface '{}' is not present (known: {})",
                    name,
                    sw.ports
                        .iter()
                        .map(|p| p.ifname.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            }
        }
        "spanning-tree" => span_global(sw, toks),
        "feature" => {
            if toks.len() < 2 {
                return incomplete();
            }
            set_feature(sw, toks[1], true)
        }
        "mac" => {
            // mac address-table aging-time SEC
            if toks.len() >= 4 && toks[1] == "address-table" && toks[2] == "aging-time" {
                match parse_u16(toks[3]) {
                    Ok(v) if v >= 10 => {
                        sw.mac_aging = v;
                        String::new()
                    }
                    Ok(_) => error("aging time must be at least 10 seconds"),
                    Err(e) => error(&e),
                }
            } else {
                error("usage: mac address-table aging-time SECONDS")
            }
        }
        "logging" => {
            if toks.len() >= 2 && toks[1] == "off" {
                sw.logging_enabled = false;
            } else {
                sw.logging_enabled = true;
            }
            String::new()
        }
        "end" => {
            sess.mode = Mode::Priv;
            String::new()
        }
        "banner" => error("banners are not configurable in this build"),
        "username" | "enable" | "line" | "ip" | "snmp-server" | "vtp" => {
            error(&format!("'{}' is not supported by this educational switch", cmd))
        }
        _ => {
            let _ = line;
            error(&format!("invalid command '{}'", toks[0]))
        }
    }
}

fn remove_vlan(sw: &mut Switch, id: u16) {
    sw.vlans.remove(&id);
    for p in sw.ports.iter_mut() {
        if p.mode == PortMode::Access && p.access_vlan == id {
            p.access_vlan = 1;
        }
        if p.trunk.native_vlan == id {
            p.trunk.native_vlan = 1;
        }
        p.trunk.allowed.remove(id);
    }
    sw.mac_table.entries.retain(|(vlan, _), _| *vlan != id);
    stp::refresh(sw);
}

fn set_feature(sw: &mut Switch, name: &str, enable: bool) -> String {
    let name = name.to_ascii_lowercase();
    let name = if name == "bpduguard" { "bpdu-guard" } else { &name };
    if name == "pvst" || name == "pvst+" || name == "rapid-pvst" {
        return error(
            "PVST+ has been removed; use IEEE 802.1Q-2005 MSTP (spanning-tree mode mstp)",
        );
    }
    if Features::names().iter().all(|n| *n != name) {
        return error(&format!(
            "unknown feature '{}' (known: {})",
            name,
            Features::names().join(", ")
        ));
    }
    if let Err(e) = sw.features.set(name, enable) {
        return error(&e);
    }

    match (name, enable) {
        ("trunking", false) => {
            for p in sw.ports.iter_mut() {
                if p.mode == PortMode::Trunk {
                    p.mode = PortMode::Access;
                    p.access_vlan = p.trunk.native_vlan;
                }
            }
        }
        ("portfast", false) => {
            // Keep the per-port setting but STP stops treating ports as edge.
        }
        ("vlan", false) => {
            // Collapse to VLAN 1 so the dataplane stays consistent.
            for p in sw.ports.iter_mut() {
                p.access_vlan = 1;
                p.trunk.native_vlan = 1;
                p.trunk.allowed = VlanSet::none();
            }
            sw.vlans.retain(|id, _| *id == 1);
        }
        ("stp", false) => {
            sw.stp.instance = None;
        }
        ("mstp", true) => {
            // Enabling the feature selects MSTP; the MST configuration is kept.
            sw.stp_config.mode = StpMode::Mstp;
            stp::reset(sw);
        }
        ("mstp", false) => {
            // Without MSTP the bridge falls back to classic IEEE 802.1D STP
            // with a single tree for every VLAN.
            sw.stp_config.mode = StpMode::Stp;
            stp::reset(sw);
        }
        ("lldp", false) => {
            sw.lldp.clear();
        }
        _ => {}
    }
    stp::refresh(sw);
    format!(
        "Feature '{}' {}.\n",
        name,
        if enable { "enabled" } else { "disabled" }
    )
}

fn set_stp_priority(sw: &mut Switch, value: &str) -> String {
    let prio = match parse_u16(value) {
        Ok(v) => v,
        Err(e) => return error(&e),
    };
    if prio > 61440 || prio % 4096 != 0 {
        return error("priority must be a multiple of 4096 between 0 and 61440");
    }
    sw.stp_config.priority = prio;
    stp::refresh(sw);
    String::new()
}

fn set_stp_timer(sw: &mut Switch, which: &str, value: &str) -> String {
    let val = match parse_u16(value) {
        Ok(v) => v,
        Err(e) => return error(&e),
    };
    let (lo, hi) = match which {
        "hello-time" => (1, 10),
        "forward-time" => (4, 30),
        _ => (6, 40),
    };
    if val < lo || val > hi {
        return error(&format!("value must be {}-{}", lo, hi));
    }
    match which {
        "hello-time" => sw.stp_config.hello = val,
        "forward-time" => sw.stp_config.forward_delay = val,
        _ => sw.stp_config.max_age = val,
    }
    stp::refresh(sw);
    String::new()
}

fn span_global(sw: &mut Switch, toks: &[&str]) -> String {
    if toks.len() < 2 {
        return incomplete();
    }
    match toks[1] {
        "mode" => {
            if toks.len() < 3 {
                return incomplete();
            }
            set_stp_mode(sw, toks[2])
        }
        "priority" => {
            if toks.len() < 3 {
                return incomplete();
            }
            set_stp_priority(sw, toks[2])
        }
        "hello-time" | "forward-time" | "max-age" => {
            if toks.len() < 3 {
                return incomplete();
            }
            set_stp_timer(sw, toks[1], toks[2])
        }
        "max-hops" => {
            if toks.len() < 3 {
                return incomplete();
            }
            set_max_hops(sw, toks[2])
        }
        "mst" => span_mst(sw, &toks[2..]),
        "vlan" => {
            // Compatibility alias for configs written when this switch ran
            // PVST+.  There is now a single VLAN-to-MSTID allocation, so the
            // requested value applies to the CIST (or the whole bridge).
            if toks.len() < 5 {
                return incomplete();
            }
            if let Err(e) = VlanSet::parse(toks[2]) {
                return error(&e);
            }
            let out = match toks[3] {
                "priority" => set_stp_priority(sw, toks[4]),
                "hello-time" | "forward-time" | "max-age" => set_stp_timer(sw, toks[3], toks[4]),
                other => return error(&format!("unknown spanning-tree option '{}'", other)),
            };
            if out.starts_with('%') {
                out
            } else {
                "Note: per-VLAN STP is gone; the value applies to the IEEE 802.1Q CIST.\n"
                    .to_string()
            }
        }
        "portfast" => error("configure portfast under 'interface'"),
        other => error(&format!("unknown spanning-tree option '{}'", other)),
    }
}

fn set_stp_mode(sw: &mut Switch, value: &str) -> String {
    let mode = match value.to_ascii_lowercase().as_str() {
        "mstp" | "mst" => StpMode::Mstp,
        "stp" | "802.1d" | "8021d" => StpMode::Stp,
        "cst" | "ieee" | "802.1q" | "8021q" => StpMode::Cst,
        "pvst" | "pvst+" => {
            return error(
                "PVST+ has been removed; use MSTP (IEEE 802.1Q-2005) or the CIST compatibility mode",
            )
        }
        "rapid-pvst" | "rapid-pvst+" | "rstp" => {
            return error("RSTP is not selectable on its own; use 'spanning-tree mode mstp'")
        }
        other => return error(&format!("unknown STP mode '{}'", other)),
    };
    if mode.is_mstp() && !sw.features.mstp {
        return error("MSTP is disabled; enable it with 'feature enable mstp'");
    }
    sw.stp_config.mode = mode;
    // Keep the feature state consistent with the selected protocol: running
    // STP/CST means MSTP is not active.
    sw.features.mstp = mode.is_mstp();
    stp::reset(sw);
    stp::refresh(sw);
    match mode {
        StpMode::Mstp => {
            "Spanning tree mode is IEEE 802.1Q-2005 Multiple Spanning Tree (MSTP).\n".to_string()
        }
        StpMode::Cst => {
            "Spanning tree mode is IEEE 802.1Q common spanning tree (CST).\n".to_string()
        }
        StpMode::Stp => "Spanning tree mode is IEEE 802.1D STP.\n".to_string(),
    }
}

fn set_max_hops(sw: &mut Switch, value: &str) -> String {
    let hops = match value.parse::<u8>() {
        Ok(v) => v,
        Err(_) => return error("max-hops must be an integer"),
    };
    if !(1..=40).contains(&hops) {
        return error("max-hops must be between 1 and 40");
    }
    sw.stp_config.max_hops = hops;
    stp::reset(sw);
    stp::refresh(sw);
    String::new()
}

/// Handle `spanning-tree mst ...` (the `mst` token is already consumed).
fn span_mst(sw: &mut Switch, toks: &[&str]) -> String {
    if toks.is_empty() {
        return incomplete();
    }
    match toks[0] {
        "name" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let name = toks[1..].join(" ");
            if name.len() > 32 {
                return error("MST configuration name is limited to 32 octets");
            }
            if name.is_empty() {
                return error("MST configuration name must not be empty");
            }
            sw.mst.name = name;
            mst_changed(sw)
        }
        "revision" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let rev = match parse_u16(toks[1]) {
                Ok(v) => v,
                Err(e) => return error(&e),
            };
            sw.mst.revision = rev;
            mst_changed(sw)
        }
        "max-hops" => {
            if toks.len() < 2 {
                return incomplete();
            }
            set_max_hops(sw, toks[1])
        }
        "instance" => {
            if toks.len() < 3 {
                return incomplete();
            }
            let id = match toks[1].parse::<u16>() {
                Ok(v) if (1..=MAX_MSTID).contains(&v) => v,
                _ => {
                    return error(&format!(
                        "MST instance id must be 1..{}",
                        MAX_MSTID
                    ))
                }
            };
            match toks[2] {
                "vlan" => {
                    if toks.len() < 4 {
                        return incomplete();
                    }
                    let list = toks[3..].join(" ");
                    let vlans = match VlanSet::parse(&list) {
                        Ok(v) => v,
                        Err(e) => return error(&e),
                    };
                    if vlans.is_empty() {
                        return error("VLAN list must not be empty");
                    }
                    sw.mst.set_instance_vlans(id, vlans);
                    mst_changed(sw)
                }
                "priority" => {
                    if toks.len() < 4 {
                        return incomplete();
                    }
                    let prio = match parse_u16(toks[3]) {
                        Ok(v) => v,
                        Err(e) => return error(&e),
                    };
                    if prio > 61440 || prio % 4096 != 0 {
                        return error("priority must be a multiple of 4096 between 0 and 61440");
                    }
                    sw.mst.ensure_instance(id).priority = prio;
                    mst_changed(sw)
                }
                "remove" | "delete" => {
                    sw.mst.remove_instance(id);
                    mst_changed(sw)
                }
                other => error(&format!(
                    "unknown MST instance option '{}' (use vlan|priority|remove)",
                    other
                )),
            }
        }
        other => error(&format!(
            "unknown MST option '{}' (use name|revision|instance)",
            other
        )),
    }
}

fn mst_changed(sw: &mut Switch) -> String {
    // Changing the MST Configuration Identifier or the VID allocation resets
    // the spanning-tree state (IEEE 802.1Q-2005, 13.7 and 13.26).
    stp::reset(sw);
    stp::refresh(sw);
    String::new()
}

// ---------------------------------------------------------------------------
// Interface configuration
// ---------------------------------------------------------------------------

fn current_port(sw: &Switch, sess: &Session) -> Option<Port> {
    match sess.mode {
        Mode::Interface(idx) => sw.port(idx).cloned(),
        _ => None,
    }
}

fn interface_cmd(sw: &mut Switch, sess: &mut Session, cmd: &str, toks: &[&str], line: &str) -> String {
    let Some(port) = current_port(sw, sess) else {
        return error("interface context lost");
    };
    let idx = port.index;

    match cmd {
        "switchport" => switchport_cmd(sw, sess, idx, toks),
        "spanning-tree" => {
            if toks.len() < 2 {
                return incomplete();
            }
            match toks[1] {
                "portfast" => {
                    if !sw.features.portfast {
                        return feature_off("portfast");
                    }
                    let value = !matches!(toks.get(2), Some(&"disable"));
                    if let Some(p) = sw.port_mut(idx) {
                        p.portfast = value;
                    }
                    stp::refresh(sw);
                    if value {
                        "Portfast enabled on this port.\n".to_string()
                    } else {
                        "Portfast disabled on this port.\n".to_string()
                    }
                }
                "bpduguard" | "bpdu-guard" => {
                    if !sw.features.bpdu_guard {
                        return feature_off("bpdu-guard");
                    }
                    if toks.len() < 3 {
                        return incomplete();
                    }
                    let value = match toks[2] {
                        "enable" => true,
                        "disable" => false,
                        other => return error(&format!("expected enable|disable, got '{}'", other)),
                    };
                    if let Some(p) = sw.port_mut(idx) {
                        p.bpduguard = value;
                    }
                    stp::refresh(sw);
                    format!(
                        "BPDU guard {}.\n",
                        if value { "enabled" } else { "disabled" }
                    )
                }
                "enable" | "disable" => {
                    let value = toks[1] == "enable";
                    if let Some(p) = sw.port_mut(idx) {
                        p.stp_enabled = value;
                    }
                    stp::refresh(sw);
                    String::new()
                }
                "cost" => {
                    if toks.len() < 3 {
                        return incomplete();
                    }
                    let cost = match toks[2].parse::<u32>() {
                        Ok(v) if (1..=200_000_000).contains(&v) => v,
                        _ => return error("cost must be 1..200000000"),
                    };
                    sw.port_mut(idx).unwrap().stp_cost = Some(cost);
                    stp::refresh(sw);
                    String::new()
                }
                "priority" => {
                    if toks.len() < 3 {
                        return incomplete();
                    }
                    let prio = match toks[2].parse::<u8>() {
                        Ok(v) => v,
                        Err(_) => return error("port priority must be 0..255"),
                    };
                    sw.port_mut(idx).unwrap().stp_priority = prio;
                    stp::refresh(sw);
                    String::new()
                }
                "mst" => {
                    if toks.len() < 4 {
                        return incomplete();
                    }
                    let id = match toks[2].parse::<u16>() {
                        Ok(v) if (1..=MAX_MSTID).contains(&v) => v,
                        _ => return error(&format!("MST instance id must be 1..{}", MAX_MSTID)),
                    };
                    match toks[3] {
                        "cost" => {
                            if toks.len() < 5 {
                                return incomplete();
                            }
                            let cost = match toks[4].parse::<u32>() {
                                Ok(v) if (1..=200_000_000).contains(&v) => v,
                                _ => return error("cost must be 1..200000000"),
                            };
                            sw.port_mut(idx)
                                .unwrap()
                                .msti
                                .entry(id)
                                .or_default()
                                .cost = Some(cost);
                            stp::refresh(sw);
                            String::new()
                        }
                        "priority" => {
                            if toks.len() < 5 {
                                return incomplete();
                            }
                            let prio = match toks[4].parse::<u8>() {
                                Ok(v) => v,
                                Err(_) => return error("port priority must be 0..255"),
                            };
                            sw.port_mut(idx)
                                .unwrap()
                                .msti
                                .entry(id)
                                .or_default()
                                .priority = prio;
                            stp::refresh(sw);
                            String::new()
                        }
                        other => error(&format!(
                            "unknown MST port option '{}' (use cost|priority)",
                            other
                        )),
                    }
                }
                other => error(&format!("unknown spanning-tree option '{}'", other)),
            }
        }
        "shutdown" => {
            if let Some(p) = sw.port_mut(idx) {
                p.admin_up = false;
                p.last_change = Instant::now();
            }
            stp::refresh(sw);
            String::new()
        }
        "no" => {
            if toks.len() < 2 {
                return incomplete();
            }
            match toks[1] {
                "shutdown" => {
                    if let Some(p) = sw.port_mut(idx) {
                        p.admin_up = true;
                        p.counters.err_disabled = false;
                        p.last_change = Instant::now();
                    }
                    stp::refresh(sw);
                    String::new()
                }
                "description" => {
                    if let Some(p) = sw.port_mut(idx) {
                        p.description.clear();
                    }
                    String::new()
                }
                "switchport" => {
                    sw.port_mut(idx).unwrap().mode = PortMode::Access;
                    stp::refresh(sw);
                    String::new()
                }
                "spanning-tree" => {
                    if toks.len() >= 3 {
                        match toks[2] {
                            "portfast" => {
                                sw.port_mut(idx).unwrap().portfast = false;
                                stp::refresh(sw);
                            }
                            "cost" => {
                                sw.port_mut(idx).unwrap().stp_cost = None;
                                stp::refresh(sw);
                            }
                            "priority" => {
                                sw.port_mut(idx).unwrap().stp_priority =
                                    DEFAULT_PORT_PRIORITY;
                                stp::refresh(sw);
                            }
                            "mst" if toks.len() >= 5 => {
                                if let Ok(id) = toks[3].parse::<u16>() {
                                    if let Some(cfg) =
                                        sw.port_mut(idx).unwrap().msti.get_mut(&id)
                                    {
                                        match toks[4] {
                                            "cost" => cfg.cost = None,
                                            "priority" => {
                                                cfg.priority = DEFAULT_PORT_PRIORITY
                                            }
                                            _ => {}
                                        }
                                    }
                                    stp::refresh(sw);
                                }
                            }
                            _ => {}
                        }
                    }
                    String::new()
                }
                "channel-group" | "ip" => error("not supported"),
                other => error(&format!("invalid 'no {}'", other)),
            }
        }
        "description" => {
            let text = line
                .splitn(2, char::is_whitespace)
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string();
            sw.port_mut(idx).unwrap().description = text;
            String::new()
        }
        "speed" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let speed = match toks[1] {
                "auto" => 1000,
                "10" => 10,
                "100" => 100,
                "1000" => 1000,
                "10000" => 10000,
                other => return error(&format!("unsupported speed '{}'", other)),
            };
            sw.port_mut(idx).unwrap().speed = speed;
            stp::refresh(sw);
            String::new()
        }
        "duplex" => {
            if toks.len() < 2 || !matches!(toks[1], "auto" | "full" | "half") {
                return error("usage: duplex auto|full|half");
            }
            String::new()
        }
        "mtu" => error("MTU configuration is not supported"),
        "channel-group" | "ip" => error("not supported on this switch"),
        "end" => {
            sess.mode = Mode::Priv;
            String::new()
        }
        "banner" | "username" | "line" => error("not valid in interface mode"),
        _ => error(&format!("invalid command '{}'", toks[0])),
    }
}

fn switchport_cmd(sw: &mut Switch, sess: &mut Session, idx: usize, toks: &[&str]) -> String {
    let _ = sess;
    if toks.len() < 2 {
        return incomplete();
    }
    match toks[1] {
        "mode" => {
            if toks.len() < 3 {
                return incomplete();
            }
            match toks[2] {
                "access" => {
                    let p = sw.port(idx).unwrap();
                    if !sw.has_vlan(p.access_vlan) && sw.features.vlan {
                        return error("access VLAN is not configured");
                    }
                    sw.port_mut(idx).unwrap().mode = PortMode::Access;
                    stp::refresh(sw);
                    String::new()
                }
                "trunk" => {
                    if !sw.features.trunking {
                        return feature_off("trunking");
                    }
                    sw.port_mut(idx).unwrap().mode = PortMode::Trunk;
                    stp::refresh(sw);
                    String::new()
                }
                other => error(&format!("unknown switchport mode '{}'", other)),
            }
        }
        "access" => {
            if toks.len() >= 3 && toks[2] == "vlan" {
                if toks.len() < 4 {
                    return incomplete();
                }
                let id = match parse_u16(toks[3]) {
                    Ok(v) => v,
                    Err(e) => return error(&e),
                };
                if !sw.features.vlan {
                    return feature_off("vlan");
                }
                if !sw.has_vlan(id) {
                    return error(&format!("VLAN {} does not exist (create it with 'vlan {}')", id, id));
                }
                sw.port_mut(idx).unwrap().access_vlan = id;
                stp::refresh(sw);
                String::new()
            } else {
                error("usage: switchport access vlan ID")
            }
        }
        "trunk" => {
            if !sw.features.trunking {
                return feature_off("trunking");
            }
            if toks.len() < 3 {
                return incomplete();
            }
            match toks[2] {
                "native" => {
                    if toks.len() < 5 || toks[3] != "vlan" {
                        return error("usage: switchport trunk native vlan ID");
                    }
                    let id = match parse_u16(toks[4]) {
                        Ok(v) => v,
                        Err(e) => return error(&e),
                    };
                    if !sw.has_vlan(id) {
                        return error(&format!("VLAN {} does not exist", id));
                    }
                    sw.port_mut(idx).unwrap().trunk.native_vlan = id;
                    stp::refresh(sw);
                    String::new()
                }
                "allowed" => {
                    if toks.len() < 5 || toks[3] != "vlan" {
                        return error("usage: switchport trunk allowed vlan LIST|add|remove|except|all|none");
                    }
                    let arg = toks[4];
                    let p = sw.port(idx).unwrap();
                    let mut allowed = p.trunk.allowed.clone();
                    let mut add = false;
                    let mut remove = false;
                    let mut except = false;
                    let list_tok = if matches!(arg, "add" | "remove" | "except") {
                        if toks.len() < 6 {
                            return incomplete();
                        }
                        add = arg == "add";
                        remove = arg == "remove";
                        except = arg == "except";
                        toks[5]
                    } else {
                        arg
                    };
                    match list_tok {
                        "all" => {
                            allowed = VlanSet::all();
                        }
                        "none" => {
                            allowed = VlanSet::none();
                        }
                        list => {
                            let set = match VlanSet::parse(list) {
                                Ok(s) => s,
                                Err(e) => return error(&e),
                            };
                            if add {
                                for v in set.iter() {
                                    allowed.insert(v);
                                }
                            } else if remove || except {
                                for v in set.iter() {
                                    allowed.remove(v);
                                }
                            } else {
                                allowed = set;
                            }
                        }
                    }
                    sw.port_mut(idx).unwrap().trunk.allowed = allowed;
                    stp::refresh(sw);
                    String::new()
                }
                other => error(&format!("unknown trunk option '{}'", other)),
            }
        }
        "nonegotiate" => String::new(),
        other => error(&format!("unknown switchport option '{}'", other)),
    }
}

// ---------------------------------------------------------------------------
// VLAN configuration
// ---------------------------------------------------------------------------

fn vlan_cmd(
    sw: &mut Switch,
    sess: &mut Session,
    cmd: &str,
    toks: &[&str],
    line: &str,
    vlan: u16,
) -> String {
    match cmd {
        "name" => {
            if toks.len() < 2 {
                return incomplete();
            }
            let name: String = line
                .splitn(2, char::is_whitespace)
                .nth(1)
                .unwrap_or("")
                .trim()
                .chars()
                .take(32)
                .collect();
            if name.is_empty() {
                return incomplete();
            }
            if let Some(v) = sw.vlans.get_mut(&vlan) {
                v.name = name;
            }
            String::new()
        }
        "state" => {
            if toks.len() < 2 {
                return incomplete();
            }
            match toks[1] {
                "active" => {
                    if let Some(v) = sw.vlans.get_mut(&vlan) {
                        v.state = VlanState::Active;
                    }
                    stp::refresh(sw);
                    String::new()
                }
                "suspend" | "suspended" => {
                    if let Some(v) = sw.vlans.get_mut(&vlan) {
                        v.state = VlanState::Suspended;
                    }
                    stp::refresh(sw);
                    String::new()
                }
                other => error(&format!("expected active|suspend, got '{}'", other)),
            }
        }
        "no" => {
            if toks.len() >= 2 && toks[1] == "name" {
                if let Some(v) = sw.vlans.get_mut(&vlan) {
                    v.name = if vlan == 1 {
                        "default".to_string()
                    } else {
                        format!("VLAN{:04}", vlan)
                    };
                }
                String::new()
            } else {
                error("invalid 'no' command")
            }
        }
        "end" => {
            sess.mode = Mode::Priv;
            String::new()
        }
        "exit" => {
            sess.mode = Mode::Config;
            String::new()
        }
        _ => error(&format!("invalid command '{}'", toks[0])),
    }
}

// ---------------------------------------------------------------------------
// show commands
// ---------------------------------------------------------------------------

fn show_cmd(sw: &mut Switch, toks: &[&str]) -> String {
    if toks.len() < 2 {
        return error("incomplete command: show <feature>");
    }
    match toks[1] {
        "version" => show_version(sw),
        "vlan" => show_vlan(sw, toks),
        "interfaces" | "interface" => show_interfaces(sw, toks),
        "spanning-tree" => show_stp(sw, toks),
        "mac" => show_mac(sw, toks),
        "running-config" | "run" => show_running(sw),
        "startup-config" | "start" => match fs::read_to_string(&sw.startup_path) {
            Ok(s) => format!("Startup configuration:\n{}\n", s),
            Err(_) => "% Startup configuration not present.\n".to_string(),
        },
        "features" => show_features(sw),
        "lldp" => show_lldp(sw, toks),
        "logging" | "log" => show_logging(sw),
        "clock" => format!(
            "Uptime: {}\n",
            sw.short_uptime()
        ),
        other => error(&format!("unknown show command '{}'", other)),
    }
}

fn show_version(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", sw.version);
    let _ = writeln!(out, "  Educational layer-2 switch (Rust)");
    let _ = writeln!(out, "  Hostname: {}", sw.hostname);
    let _ = writeln!(out, "  System MAC: {}", packet::format_mac(sw.system_mac));
    let _ = writeln!(out, "  Serial: {}", sw.serial());
    let _ = writeln!(out, "  Uptime: {}", sw.short_uptime());
    let stp = match sw.stp_config.mode {
        StpMode::Mstp => format!(
            "IEEE 802.1Q-2005 MSTP (CIST + {} MSTI{})",
            sw.stp.mstis.len(),
            if sw.stp.mstis.len() == 1 { "" } else { "s" }
        ),
        StpMode::Cst => "IEEE 802.1Q CST".to_string(),
        StpMode::Stp => "IEEE 802.1D STP".to_string(),
    };
    let _ = writeln!(
        out,
        "  Spanning tree: {}   VLANs: {}   Ports: {}",
        stp,
        sw.vlans.len(),
        sw.ports.len()
    );
    let _ = writeln!(
        out,
        "  Features: {}",
        Features::names()
            .iter()
            .filter(|n| sw.features.get(n).unwrap_or(false))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    out
}

fn show_vlan(sw: &Switch, toks: &[&str]) -> String {
    if toks.len() >= 3 {
        match toks[2] {
            "brief" => {}
            "id" => {
                if toks.len() < 4 {
                    return incomplete();
                }
                let id = match parse_u16(toks[3]) {
                    Ok(v) => v,
                    Err(e) => return error(&e),
                };
                let Some(v) = sw.vlans.get(&id) else {
                    return error(&format!("VLAN {} does not exist", id));
                };
                return format!(
                    "VLAN {} Name {} Status {}\n",
                    v.id,
                    v.name,
                    v.state.as_str()
                );
            }
            "name" => {
                if toks.len() < 4 {
                    return incomplete();
                }
                let name = toks[3].to_ascii_lowercase();
                let found: Vec<&Vlan> = sw
                    .vlans
                    .values()
                    .filter(|v| v.name.to_ascii_lowercase() == name)
                    .collect();
                if found.is_empty() {
                    return error(&format!("VLAN name '{}' not found", toks[3]));
                }
                return found
                    .iter()
                    .map(|v| format!("VLAN {} Name {} Status {}\n", v.id, v.name, v.state.as_str()))
                    .collect();
            }
            other => return error(&format!("unknown vlan option '{}'", other)),
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "VLAN Name                             Status    Ports");
    let _ = writeln!(out, "---- -------------------------------- --------- -------------------------------");
    for v in sw.vlans.values() {
        let ports: Vec<String> = sw
            .ports
            .iter()
            .filter(|p| p.mode == PortMode::Access && p.access_vlan == v.id)
            .map(|p| p.name.clone())
            .collect();
        let ports = if ports.is_empty() {
            String::new()
        } else {
            let mut s = ports.join(", ");
            if s.len() > 60 {
                s.truncate(57);
                s.push_str("...");
            }
            s
        };
        let _ = writeln!(
            out,
            "{:<4} {:<32} {:<9} {}",
            v.id,
            v.name,
            v.state.as_str(),
            ports
        );
    }
    out
}

fn show_interfaces(sw: &Switch, toks: &[&str]) -> String {
    let mut mode = "summary";
    let mut name: Option<&str> = None;
    let mut i = 2;
    while i < toks.len() {
        match toks[i] {
            "status" => mode = "status",
            "switchport" => mode = "switchport",
            "trunk" => mode = "trunk",
            "counters" => mode = "counters",
            other => {
                if name.is_none() {
                    name = Some(other);
                } else if other == "switchport" {
                    mode = "switchport";
                }
            }
        }
        i += 1;
    }

    if mode == "trunk" {
        return show_trunks(sw);
    }

    if let Some(name) = name {
        let Some(idx) = sw.port_by_name(name) else {
            return error(&format!("no such interface '{}'", name));
        };
        let p = sw.port(idx).unwrap();
        return if mode == "switchport" {
            show_switchport(sw, p)
        } else {
            show_one_interface(sw, p)
        };
    }

    if mode == "switchport" {
        let mut out = String::new();
        for p in &sw.ports {
            out.push_str(&show_switchport(sw, p));
        }
        return out;
    }

    if mode == "counters" {
        let mut out = String::new();
        let _ = writeln!(out, "{:<10} {:>10} {:>10} {:>8} {:>8}", "Port", "RX", "TX", "Drops", "BPDUs");
        for p in &sw.ports {
            let _ = writeln!(
                out,
                "{:<10} {:>10} {:>10} {:>8} {:>8}",
                p.name,
                p.counters.rx_packets,
                p.counters.tx_packets,
                p.counters.drops,
                p.counters.bpdu_rx + p.counters.bpdu_tx
            );
        }
        return out;
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<10} {:<18} {:<12} {:<9} {:<7} {:<6} {}",
        "Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"
    );
    for p in &sw.ports {
        let vlan = match p.mode {
            PortMode::Access => format!("{}", p.access_vlan),
            PortMode::Trunk => "trunk".to_string(),
        };
        let _ = writeln!(
            out,
            "{:<10} {:<18} {:<12} {:<9} {:<7} {:<6} {}",
            p.name,
            p.description,
            p.status_str(),
            vlan,
            "full",
            p.speed,
            "P2p"
        );
    }
    out
}

fn show_one_interface(sw: &Switch, p: &Port) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} is {}, line protocol is {}",
        p.name,
        if p.admin_up { "up" } else { "administratively down" },
        if p.oper_up() { "up" } else { "down" }
    );
    let _ = writeln!(
        out,
        "  Hardware is Ethernet, address is {}",
        packet::format_mac(sw.system_mac)
    );
    if !p.description.is_empty() {
        let _ = writeln!(out, "  Description: {}", p.description);
    }
    let _ = writeln!(
        out,
        "  MTU 1500 bytes, BW {} Kbit/sec, DLY 10 usec",
        p.speed * 1000
    );
    let _ = writeln!(
        out,
        "  {} mode, native/access vlan {}, BPDUs rx/tx {}/{}",
        p.mode.as_str(),
        p.pvid(),
        p.counters.bpdu_rx,
        p.counters.bpdu_tx
    );
    let _ = writeln!(out, "  {} packets input, {} bytes", p.counters.rx_packets, p.counters.rx_bytes);
    let _ = writeln!(out, "  {} packets output, {} bytes", p.counters.tx_packets, p.counters.tx_bytes);
    let _ = writeln!(
        out,
        "  {} input errors, {} dropped",
        p.counters.rx_errors, p.counters.drops
    );
    if p.counters.err_disabled {
        let _ = writeln!(out, "  err-disabled (bpduguard). Use 'shutdown' + 'no shutdown' to recover.");
    }
    if sw.features.stp {
        let state = stp::port_state(sw, p.index);
        let role = stp::port_role(sw, p.index)
            .map(|r| r.short())
            .unwrap_or("Dis");
        let _ = writeln!(
            out,
            "  IEEE 802.1Q CST: role {} state {}",
            role,
            state.long()
        );
    }
    out
}

fn show_switchport(sw: &Switch, p: &Port) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Name: {}", p.name);
    let _ = writeln!(out, "Switchport: Enabled");
    let _ = writeln!(out, "Administrative Mode: {}", p.mode.as_str());
    let _ = writeln!(out, "Operational Mode: {}", p.mode.as_str());
    let _ = writeln!(
        out,
        "Access Mode VLAN: {} ({})",
        p.access_vlan,
        sw.vlan_name(p.access_vlan)
    );
    let _ = writeln!(
        out,
        "Trunking Native Mode VLAN: {} ({})",
        p.trunk.native_vlan,
        sw.vlan_name(p.trunk.native_vlan)
    );
    let _ = writeln!(out, "Trunking VLANs Allowed: {}", p.trunk.allowed);
    let _ = writeln!(out, "Portfast: {}", if p.portfast { "enabled" } else { "disabled" });
    let _ = writeln!(out, "BPDU guard: {}", if p.bpduguard { "enabled" } else { "disabled" });
    let _ = writeln!(out);
    out
}

fn show_trunks(sw: &Switch) -> String {
    let trunks: Vec<&Port> = sw.ports.iter().filter(|p| p.mode == PortMode::Trunk).collect();
    if trunks.is_empty() {
        return "No trunking ports.\n".to_string();
    }
    let mut out = String::new();
    let _ = writeln!(out, "Port        Mode         Encapsulation  Status        Native vlan");
    for p in &trunks {
        let _ = writeln!(
            out,
            "{:<11} on           802.1q         trunking      {}",
            p.name, p.trunk.native_vlan
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Port        Vlans allowed on trunk");
    for p in &trunks {
        let _ = writeln!(out, "{:<11} {}", p.name, p.trunk.allowed);
    }
    out
}

fn show_stp(sw: &Switch, toks: &[&str]) -> String {
    let mut filter_vlan: Option<u16> = None;
    let mut filter_mst: Option<u16> = None;
    let mut summary = false;
    let mut mst_config = false;
    let mut i = 2;
    while i < toks.len() {
        match toks[i] {
            "vlan" => {
                if i + 1 < toks.len() {
                    if let Ok(v) = toks[i + 1].parse::<u16>() {
                        filter_vlan = Some(v);
                    }
                    i += 1;
                }
            }
            "mst" => {
                if toks.get(i + 1) == Some(&"configuration") {
                    mst_config = true;
                    i += 1;
                } else if let Some(v) = toks.get(i + 1).and_then(|s| s.parse::<u16>().ok()) {
                    filter_mst = Some(v);
                    i += 1;
                }
            }
            "instance" => {
                if let Some(v) = toks.get(i + 1).and_then(|s| s.parse::<u16>().ok()) {
                    filter_mst = Some(v);
                    i += 1;
                }
            }
            "summary" | "total" => summary = true,
            "detail" => {}
            other => {
                if let Ok(v) = other.parse::<u16>() {
                    filter_vlan = Some(v);
                }
            }
        }
        i += 1;
    }

    if mst_config {
        return show_mst_configuration(sw);
    }

    let Some(cist) = sw.stp.instance() else {
        return error("spanning tree is disabled (enable it with 'feature enable stp')");
    };

    if summary {
        let mode = match sw.stp_config.mode {
            StpMode::Mstp => "IEEE 802.1Q-2005 Multiple Spanning Tree (MSTP)",
            StpMode::Cst => "IEEE 802.1Q common spanning tree (CST)",
            StpMode::Stp => "IEEE 802.1D Spanning Tree Protocol (STP)",
        };
        let mut out = String::new();
        let _ = writeln!(out, "Switch is in {} mode", mode);
        let mut roots: Vec<String> = Vec::new();
        if cist.is_root {
            roots.push("CIST".to_string());
        }
        for (id, inst) in &sw.stp.mstis {
            if inst.is_root {
                roots.push(format!("MSTI {}", id));
            }
        }
        if roots.is_empty() {
            let _ = writeln!(out, "Root bridge for: none");
        } else {
            let _ = writeln!(out, "Root bridge for: {}", roots.join(", "));
        }
        if sw.stp_config.mode.is_mstp() {
            let _ = writeln!(
                out,
                "MST configuration: name '{}' revision {}",
                sw.mst.name, sw.mst.revision
            );
            let _ = writeln!(out, "MST digest: {}", format_digest(&sw.mst.digest()));
            let _ = writeln!(
                out,
                "Extended system ID is enabled (CIST + {} MSTI{})",
                sw.stp.mstis.len(),
                if sw.stp.mstis.len() == 1 { "" } else { "s" }
            );
        } else {
            let _ = writeln!(
                out,
                "MSTP feature is disabled; running one {} tree for all VLANs",
                sw.stp_config.mode.as_str().to_ascii_uppercase()
            );
        }
        let _ = writeln!(out, "EtherChannel misconfig guard is disabled");
        let _ = writeln!(
            out,
            "Portfast Default is {}",
            if sw.features.portfast { "enabled" } else { "disabled" }
        );
        let _ = writeln!(
            out,
            "BPDU Guard is {}",
            if sw.features.bpdu_guard { "enabled" } else { "disabled" }
        );
        let _ = writeln!(
            out,
            "{} spanning tree instance{} (1 CIST + {} MSTI{})",
            1 + sw.stp.mstis.len(),
            if sw.stp.mstis.is_empty() { "" } else { "s" },
            sw.stp.mstis.len(),
            if sw.stp.mstis.len() == 1 { "" } else { "s" }
        );
        return out;
    }

    if let Some(v) = filter_vlan {
        if !sw.vlans.contains_key(&v) {
            return error(&format!("VLAN {} does not exist", v));
        }
        let mstid = if sw.stp_config.mode.is_mstp() {
            sw.mst.mstid_for_vlan(v)
        } else {
            0
        };
        let Some(inst) = sw.stp.msti(mstid) else {
            return error(&format!("no spanning-tree instance for VLAN {}", v));
        };
        return show_stp_instance(sw, inst, Some(v));
    }

    if let Some(id) = filter_mst {
        let Some(inst) = sw.stp.msti(id) else {
            return error(&format!("MST instance {} is not configured", id));
        };
        return show_stp_instance(sw, inst, None);
    }

    let mut out = show_stp_instance(sw, cist, None);
    for inst in sw.stp.mstis.values() {
        out.push_str(&show_stp_instance(sw, inst, None));
    }
    out
}

fn show_stp_instance(sw: &Switch, inst: &stp::Instance, vlan: Option<u16>) -> String {
    let now = Instant::now();
    let mut out = String::new();
    if inst.is_cist() {
        match sw.stp_config.mode {
            StpMode::Mstp => {
                let _ = writeln!(out, "IEEE 802.1Q-2005 CIST (MSTID 0)");
            }
            StpMode::Cst => {
                let _ = writeln!(out, "IEEE 802.1Q Common Spanning Tree (CST)");
            }
            StpMode::Stp => {
                let _ = writeln!(out, "IEEE 802.1D Spanning Tree Protocol (STP)");
            }
        }
    } else {
        let _ = writeln!(out, "IEEE 802.1Q-2005 MSTI {}", inst.mstid);
    }
    if let Some(v) = vlan {
        let _ = writeln!(out, "  VLAN {} maps to this instance", v);
    }
    let _ = writeln!(out, "  Spanning tree enabled protocol {}", sw.stp_config.mode.as_str());
    let _ = writeln!(out, "  Root ID    Priority    {}", inst.root_id.priority());
    let _ = writeln!(
        out,
        "             Address     {}",
        packet::format_mac(inst.root_id.mac())
    );
    if let Some(rp) = inst.root_port {
        let name = sw
            .port(rp)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| rp.to_string());
        let _ = writeln!(out, "             Cost        {}", inst.root_cost);
        let _ = writeln!(out, "             Port        {} ({})", rp, name);
    } else {
        let _ = writeln!(out, "             This bridge is the root");
    }
    let _ = writeln!(
        out,
        "             Hello Time   {} sec  Max Age {} sec  Forward Delay {} sec",
        inst.hello, inst.max_age, inst.forward_delay
    );
    if inst.is_cist() && sw.stp_config.mode.is_mstp() {
        let _ = writeln!(out, "             Remaining Hops {}", inst.remaining_hops);
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  Bridge ID  Priority    {}",
        inst.bridge_id.priority()
    );
    let _ = writeln!(
        out,
        "             Address     {}",
        packet::format_mac(inst.bridge_id.mac())
    );
    let _ = writeln!(
        out,
        "             Hello Time   {} sec  Max Age {} sec  Forward Delay {} sec",
        inst.hello, inst.max_age, inst.forward_delay
    );
    if inst.tc_active(now) {
        let _ = writeln!(out, "             Topology change flag set");
    }
    let _ = writeln!(out, "             Aging Time  {} sec", sw.mac_aging);
    let _ = writeln!(out);
    let _ = writeln!(out, "Interface           Role Sts Cost      Prio.Nbr Type");
    let _ = writeln!(out, "------------------- ---- --- --------- -------- ----");
    for p in &sw.ports {
        let Some(pi) = inst.port(p.index) else { continue };
        let (cost, prio) = if inst.is_cist() {
            (p.cist_external_cost(), p.stp_priority)
        } else {
            (p.msti_cost(inst.mstid), p.msti_priority(inst.mstid))
        };
        let _ = writeln!(
            out,
            "{:<19} {:<4} {:<3} {:<9} {:<8} {}",
            p.name,
            pi.role.short(),
            pi.state.short(),
            cost,
            format_args!("{}.{}", prio, p.index),
            if p.portfast && sw.features.portfast { "P2p Edge" } else { "P2p" }
        );
    }
    let _ = writeln!(out);
    out
}

fn show_mst_configuration(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "MST configuration");
    let config_id = sw.mst.config_id();
    let _ = writeln!(out, "  Name:     {}", config_id.name_str());
    let _ = writeln!(out, "  Revision: {}", config_id.revision);
    let _ = writeln!(out, "  Digest:   {}", format_digest(&config_id.digest));
    let _ = writeln!(out, "  Max hops: {}", sw.stp_config.max_hops);
    let _ = writeln!(out);
    let _ = writeln!(out, "Instance  Vlans mapped");
    let _ = writeln!(out, "--------  -------------------------------------");
    let mut cist = VlanSet::all();
    for inst in sw.mst.instances.values() {
        for v in inst.vlans.iter() {
            cist.remove(v);
        }
    }
    let _ = writeln!(out, "{:<9} {}", "0 (CIST)", cist);
    for inst in sw.mst.instances.values() {
        let _ = writeln!(
            out,
            "{:<9} {}  (priority {})",
            inst.id, inst.vlans, inst.priority
        );
    }
    out
}

fn format_digest(digest: &[u8; 16]) -> String {
    digest.iter().map(|b| format!("{:02X}", b)).collect()
}

fn show_mac(sw: &Switch, toks: &[&str]) -> String {
    let mut vlan_filter: Option<u16> = None;
    let mut port_filter: Option<usize> = None;
    let mut only_static = false;
    let mut count_only = false;
    let mut i = 2;
    while i < toks.len() {
        match toks[i] {
            "address-table" | "address" => {}
            "vlan" => {
                if i + 1 < toks.len() {
                    vlan_filter = toks[i + 1].parse::<u16>().ok();
                    i += 1;
                }
            }
            "interface" => {
                if i + 1 < toks.len() {
                    port_filter = sw.port_by_name(toks[i + 1]);
                    i += 1;
                }
            }
            "static" => only_static = true,
            "dynamic" => {}
            "count" => count_only = true,
            other => {
                if let Ok(v) = other.parse::<u16>() {
                    vlan_filter = Some(v);
                }
            }
        }
        i += 1;
    }

    let mut entries: Vec<(u16, [u8; 6], usize, bool)> = sw
        .mac_table
        .entries
        .iter()
        .filter(|((v, _), _)| vlan_filter.map(|f| f == *v).unwrap_or(true))
        .filter(|((_, _), e)| port_filter.map(|f| f == e.port).unwrap_or(true))
        .filter(|((_, _), e)| !only_static || e.static_entry)
        .map(|((v, m), e)| (*v, *m, e.port, e.static_entry))
        .collect();
    entries.sort_by_key(|(v, m, _, _)| (*v, *m));

    if count_only {
        return format!("Total MAC addresses: {}\n", entries.len());
    }

    let mut out = String::new();
    let _ = writeln!(out, "          Mac Address Table");
    let _ = writeln!(out, "-------------------------------------------");
    let _ = writeln!(out, "Vlan    Mac Address       Type        Ports");
    let _ = writeln!(out, "----    -----------       --------    -----");
    for (vlan, mac, port, stat) in entries {
        let name = sw
            .port(port)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| port.to_string());
        let _ = writeln!(
            out,
            "{:<7} {:<17} {:<11} {}",
            vlan,
            packet::format_mac(mac),
            if stat { "STATIC" } else { "DYNAMIC" },
            name
        );
    }
    out
}

fn fit(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

fn show_lldp(sw: &Switch, toks: &[&str]) -> String {
    if !sw.features.lldp {
        return "LLDP is disabled.\nEnable it with 'feature enable lldp'.\n".to_string();
    }
    match toks.get(2).copied().unwrap_or("") {
        "" => show_lldp_status(sw),
        "neighbors" | "neighbours" => {
            if toks.get(3).map(|s| *s == "detail").unwrap_or(false) {
                show_lldp_neighbors_detail(sw)
            } else {
                show_lldp_neighbors(sw)
            }
        }
        "interface" | "interfaces" => show_lldp_interfaces(sw, toks.get(3).copied()),
        "traffic" | "counters" | "statistics" => show_lldp_traffic(sw),
        other => error(&format!("unknown show lldp command '{}'", other)),
    }
}

fn show_lldp_status(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "LLDP is enabled");
    let _ = writeln!(out, "  Standard: IEEE 802.1AB-2026 (single-frame PDU)");
    let _ = writeln!(out, "  Transmit interval: {} seconds", sw.lldp.tx_interval);
    let _ = writeln!(out, "  Hold multiplier: {}", sw.lldp.hold);
    let _ = writeln!(out, "  Transmit TTL: {} seconds", sw.lldp.ttl());
    let _ = writeln!(out, "  Neighbors: {}", sw.lldp.neighbor_count());
    out
}

fn show_lldp_neighbors(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<13} {:<20} {:<20} {:<5} {:<15} {}",
        "Local Port", "Chassis ID", "Port ID", "Hold", "Capabilities", "System Name"
    );
    let _ = writeln!(
        out,
        "{:<13} {:<20} {:<20} {:<5} {:<15} {}",
        "----------", "----------", "-------", "----", "------------", "-----------"
    );
    let mut any = false;
    for port in &sw.ports {
        let Some(neighbor) = sw.lldp.port(port.index).and_then(|s| s.neighbor.as_ref()) else {
            continue;
        };
        any = true;
        let _ = writeln!(
            out,
            "{:<13} {:<20} {:<20} {:<5} {:<15} {}",
            port.name,
            fit(&neighbor.chassis.chassis_text(), 20),
            fit(&neighbor.port.port_text(), 20),
            neighbor.ttl,
            fit(&lldp::capabilities_text(neighbor.enabled_capabilities), 15),
            neighbor.system_label()
        );
    }
    if !any {
        return "No LLDP neighbors.\n".to_string();
    }
    out
}

fn show_lldp_neighbors_detail(sw: &Switch) -> String {
    let now = Instant::now();
    let mut out = String::new();
    let mut any = false;
    for port in &sw.ports {
        let Some(neighbor) = sw.lldp.port(port.index).and_then(|s| s.neighbor.as_ref()) else {
            continue;
        };
        any = true;
        let _ = writeln!(out, "Local port: {}", port.name);
        let _ = writeln!(
            out,
            "  Chassis ID: {} ({})",
            neighbor.chassis.chassis_text(),
            neighbor.chassis.chassis_subtype_name()
        );
        let _ = writeln!(
            out,
            "  Port ID: {} ({})",
            neighbor.port.port_text(),
            neighbor.port.port_subtype_name()
        );
        let _ = writeln!(out, "  TTL: {} seconds", neighbor.ttl);
        if let Some(name) = &neighbor.system_name {
            let _ = writeln!(out, "  System name: {}", name);
        }
        if let Some(desc) = &neighbor.system_description {
            let _ = writeln!(out, "  System description: {}", desc);
        }
        if let Some(desc) = &neighbor.port_description {
            let _ = writeln!(out, "  Port description: {}", desc);
        }
        let _ = writeln!(
            out,
            "  Capabilities: {}",
            lldp::capabilities_text(neighbor.capabilities)
        );
        let _ = writeln!(
            out,
            "  Enabled capabilities: {}",
            lldp::capabilities_text(neighbor.enabled_capabilities)
        );
        let _ = writeln!(
            out,
            "  Management address: {}",
            if neighbor.management_addresses.is_empty() {
                "none".to_string()
            } else {
                neighbor.management_addresses.join(", ")
            }
        );
        let _ = writeln!(
            out,
            "  Last update: {}s ago",
            now.saturating_duration_since(neighbor.last_seen).as_secs()
        );
        out.push('\n');
    }
    if !any {
        return "No LLDP neighbors.\n".to_string();
    }
    out
}

fn show_lldp_interfaces(sw: &Switch, only: Option<&str>) -> String {
    let filter = match only {
        Some(name) => match sw.port_by_name(name) {
            Some(index) => Some(index),
            None => return error("no such interface"),
        },
        None => None,
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<13} {:>10} {:>10} {:>8} {:>8}  {}",
        "Port", "Tx", "Rx", "Errors", "Ageouts", "Neighbor"
    );
    let _ = writeln!(
        out,
        "{:<13} {:>10} {:>10} {:>8} {:>8}  {}",
        "----------", "--------", "--------", "------", "-------", "--------"
    );
    for port in &sw.ports {
        if filter.map(|i| i != port.index).unwrap_or(false) {
            continue;
        }
        let state = sw.lldp.port(port.index);
        let neighbor = state
            .and_then(|s| s.neighbor.as_ref())
            .map(|n| format!("{} ({})", n.system_label(), n.port.port_text()))
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "{:<13} {:>10} {:>10} {:>8} {:>8}  {}",
            port.name,
            state.map(|s| s.tx_frames).unwrap_or(0),
            state.map(|s| s.rx_frames).unwrap_or(0),
            state.map(|s| s.rx_errors).unwrap_or(0),
            state.map(|s| s.ageouts).unwrap_or(0),
            neighbor
        );
    }
    out
}

fn show_lldp_traffic(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "LLDP traffic:");
    let _ = writeln!(out, "  Transmit frames: {}", sw.lldp.total_tx());
    let _ = writeln!(out, "  Receive frames: {}", sw.lldp.total_rx());
    let _ = writeln!(out, "  Receive errors: {}", sw.lldp.total_errors());
    let _ = writeln!(out, "  Ageouts: {}", sw.lldp.total_ageouts());
    let _ = writeln!(out, "  Neighbors: {}", sw.lldp.neighbor_count());
    out
}

fn show_features(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Feature                     State");
    let _ = writeln!(out, "--------------------------- -------");
    for name in Features::names() {
        let state = if sw.features.get(name).unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        };
        let _ = writeln!(out, "{:<27} {}", name, state);
    }
    out
}

fn show_logging(sw: &Switch) -> String {
    if sw.log.is_empty() {
        return "% Log buffer is empty.\n".to_string();
    }
    let mut out = String::new();
    for line in &sw.log {
        let _ = writeln!(out, "{}", line);
    }
    out
}

fn show_running(sw: &Switch) -> String {
    let cfg = running_config(sw);
    let mut out = String::new();
    let _ = writeln!(out, "Building configuration...");
    let _ = writeln!(out);
    let _ = writeln!(out, "Current configuration : {} bytes", cfg.len());
    out.push_str(&cfg);
    out
}

// ---------------------------------------------------------------------------
// Configuration persistence
// ---------------------------------------------------------------------------

pub fn running_config(sw: &Switch) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "!");
    let _ = writeln!(out, "version 1.0");
    let _ = writeln!(out, "device name {}", sw.hostname);
    let _ = writeln!(out, "!");
    for name in Features::names() {
        let on = sw.features.get(name).unwrap_or(false);
        let _ = writeln!(
            out,
            "feature {} {}",
            if on { "enable" } else { "disable" },
            name
        );
    }
    let _ = writeln!(out, "!");
    let _ = writeln!(out, "mac aging {}", sw.mac_aging);
    let _ = writeln!(out, "!");
    for v in sw.vlans.values() {
        let _ = writeln!(out, "vlan {}", v.id);
        let _ = writeln!(out, " name {}", v.name);
        if v.state == VlanState::Suspended {
            let _ = writeln!(out, " state suspend");
        }
        let _ = writeln!(out, "!");
    }
    for p in &sw.ports {
        let _ = writeln!(out, "port {}", p.ifname);
        if !p.description.is_empty() {
            let _ = writeln!(out, " description {}", p.description);
        }
        if !p.admin_up {
            let _ = writeln!(out, " link down");
        }
        if p.mode == PortMode::Trunk {
            let _ = writeln!(out, " mode trunk");
            if p.trunk.native_vlan != 1 {
                let _ = writeln!(out, " native vlan {}", p.trunk.native_vlan);
            }
            if p.trunk.allowed != VlanSet::all() {
                let _ = writeln!(out, " allow vlans {}", p.trunk.allowed);
            }
        } else if p.access_vlan != 1 {
            let _ = writeln!(out, " access vlan {}", p.access_vlan);
        }
        if p.portfast {
            let _ = writeln!(out, " edge on");
        }
        if p.bpduguard {
            let _ = writeln!(out, " guard on");
        }
        if p.stp_priority != DEFAULT_PORT_PRIORITY {
            let _ = writeln!(out, " priority {}", p.stp_priority);
        }
        if let Some(cost) = p.stp_cost {
            let _ = writeln!(out, " cost {}", cost);
        }
        for (id, cfg) in &p.msti {
            if cfg.priority != DEFAULT_PORT_PRIORITY {
                let _ = writeln!(out, " mst {} priority {}", id, cfg.priority);
            }
            if let Some(cost) = cfg.cost {
                let _ = writeln!(out, " mst {} cost {}", id, cost);
            }
        }
        if p.speed != 1000 {
            let _ = writeln!(out, " speed {}", p.speed);
        }
        let _ = writeln!(out, "!");
    }
    if sw.stp_config.mode != StpMode::Mstp {
        let _ = writeln!(out, "bridge mode {}", sw.stp_config.mode.as_str());
    }
    let _ = writeln!(
        out,
        "bridge priority {}",
        sw.stp_config.priority
    );
    let _ = writeln!(out, "bridge mst name {}", sw.mst.name);
    if sw.mst.revision != 0 {
        let _ = writeln!(out, "bridge mst revision {}", sw.mst.revision);
    }
    if sw.stp_config.max_hops != DEFAULT_MAX_HOPS {
        let _ = writeln!(out, "bridge mst max-hops {}", sw.stp_config.max_hops);
    }
    for inst in sw.mst.instances.values() {
        let _ = writeln!(out, "bridge mst instance {} vlan {}", inst.id, inst.vlans);
        if inst.priority != MST_DEFAULT_PRIORITY {
            let _ = writeln!(
                out,
                "bridge mst instance {} priority {}",
                inst.id, inst.priority
            );
        }
    }
    if sw.stp_config.hello != DEFAULT_HELLO_TIME {
        let _ = writeln!(out, "bridge hello {}", sw.stp_config.hello);
    }
    if sw.stp_config.max_age != DEFAULT_MAX_AGE {
        let _ = writeln!(out, "bridge max-age {}", sw.stp_config.max_age);
    }
    if sw.stp_config.forward_delay != DEFAULT_FORWARD_DELAY {
        let _ = writeln!(
            out,
            "bridge forward-delay {}",
            sw.stp_config.forward_delay
        );
    }
    let _ = writeln!(out, "!");
    let _ = writeln!(out, "end");
    out
}

pub fn save_config(sw: &mut Switch) -> String {
    let cfg = running_config(sw);
    if let Some(parent) = sw.startup_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(&sw.startup_path, cfg) {
        Ok(_) => {
            sw.dirty = false;
            "Building configuration...\n[OK]\n".to_string()
        }
        Err(e) => error(&format!(
            "cannot write {}: {}",
            sw.startup_path.display(),
            e
        )),
    }
}

pub fn load_config(sw: &mut Switch, text: &str) {
    let mut sess = Session::new();
    let _ = execute(sw, &mut sess, "configure terminal");
    for raw in text.lines() {
        let indented = raw.starts_with(' ') || raw.starts_with('\t');
        let l = raw.trim();
        if l.is_empty()
            || l.starts_with('!')
            || l == "end"
            || l.starts_with("version ")
            || l.starts_with("Current configuration")
            || l.starts_with("Building configuration")
        {
            continue;
        }
        // A non-indented line ends any interface/VLAN sub-mode.
        if !indented && matches!(sess.mode, Mode::Interface(_) | Mode::Vlan(_)) {
            let _ = execute(sw, &mut sess, "exit");
        }
        let mut out = execute(sw, &mut sess, l);
        // Tolerate older configs that emitted global commands inside a
        // VLAN/interface block: leave the sub-mode and retry.
        if out.starts_with('%')
            && indented
            && matches!(sess.mode, Mode::Interface(_) | Mode::Vlan(_))
            && (l.starts_with("spanning-tree vlan ") || l.starts_with("mac address-table"))
        {
            let _ = execute(sw, &mut sess, "exit");
            let retry = execute(sw, &mut sess, l);
            if !retry.starts_with('%') {
                out.clear();
            }
        }
        if out.starts_with('%') {
            sw.log_line(&format!("startup-config: {} -> {}", l, out.trim()));
        }
    }
    let _ = execute(sw, &mut sess, "end");
    sw.dirty = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_switch() -> Switch {
        let mut sw = Switch::new(
            "sw1",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            PathBuf::from("/tmp/opencode/switch-test/startup-config"),
        );
        sw.add_port("eth1");
        sw.add_port("eth2");
        sw.features.portfast = true;
        sw.features.bpdu_guard = true;
        sw
    }

    fn cmd(sw: &mut Switch, sess: &mut Session, line: &str) -> String {
        execute(sw, sess, line)
    }

    #[test]
    fn vlan_and_interface_config() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        assert_eq!(s.mode, Mode::Config);
        assert!(cmd(&mut sw, &mut s, "vlan 10").is_empty());
        assert_eq!(s.mode, Mode::Vlan(10));
        cmd(&mut sw, &mut s, "name sales");
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "interface eth1");
        assert_eq!(s.mode, Mode::Interface(1));
        cmd(&mut sw, &mut s, "switchport access vlan 10");
        cmd(&mut sw, &mut s, "spanning-tree portfast");
        cmd(&mut sw, &mut s, "end");
        assert_eq!(sw.port(1).unwrap().access_vlan, 10);
        assert!(sw.port(1).unwrap().portfast);
        assert_eq!(sw.vlan_name(10), "sales");
    }

    #[test]
    fn trunk_allowed_lists() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        for v in [10u16, 20, 30] {
            cmd(&mut sw, &mut s, &format!("vlan {}", v));
            cmd(&mut sw, &mut s, "exit");
        }
        cmd(&mut sw, &mut s, "interface eth2");
        cmd(&mut sw, &mut s, "switchport mode trunk");
        cmd(&mut sw, &mut s, "switchport trunk allowed vlan 10,20");
        assert_eq!(sw.port(2).unwrap().trunk.allowed.to_string(), "10,20");
        cmd(&mut sw, &mut s, "switchport trunk allowed vlan add 30");
        assert_eq!(sw.port(2).unwrap().trunk.allowed.to_string(), "10,20,30");
        cmd(&mut sw, &mut s, "switchport trunk allowed vlan remove 20");
        assert_eq!(sw.port(2).unwrap().trunk.allowed.to_string(), "10,30");
        cmd(&mut sw, &mut s, "switchport trunk native vlan 10");
        assert_eq!(sw.port(2).unwrap().pvid(), 10);
    }

    #[test]
    fn feature_gating() {
        let mut sw = test_switch();
        sw.features.trunking = false;
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        cmd(&mut sw, &mut s, "interface eth1");
        let out = cmd(&mut sw, &mut s, "switchport mode trunk");
        assert!(out.starts_with('%'));
        assert!(out.contains("trunking"));
    }

    #[test]
    fn config_roundtrip() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        cmd(&mut sw, &mut s, "hostname lab-sw");
        cmd(&mut sw, &mut s, "vlan 100");
        cmd(&mut sw, &mut s, "name users");
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "interface eth1");
        cmd(&mut sw, &mut s, "switchport access vlan 100");
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "interface eth2");
        cmd(&mut sw, &mut s, "switchport mode trunk");
        cmd(&mut sw, &mut s, "switchport trunk native vlan 100");
        cmd(&mut sw, &mut s, "end");
        let text = running_config(&sw);

        let mut restored = Switch::new(
            "other",
            [0, 1, 2, 3, 4, 5],
            PathBuf::from("/tmp/opencode/switch-test/x"),
        );
        restored.add_port("eth1");
        restored.add_port("eth2");
        restored.features.portfast = true;
        restored.features.bpdu_guard = true;
        load_config(&mut restored, &text);
        assert_eq!(restored.hostname, "lab-sw");
        assert_eq!(restored.vlan_name(100), "users");
        assert_eq!(restored.port(1).unwrap().access_vlan, 100);
        assert_eq!(restored.port(2).unwrap().mode, PortMode::Trunk);
        assert_eq!(restored.port(2).unwrap().trunk.native_vlan, 100);
    }

    #[test]
    fn vlan_deletion_cleans_ports() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        cmd(&mut sw, &mut s, "vlan 10");
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "interface eth1");
        cmd(&mut sw, &mut s, "switchport access vlan 10");
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "no vlan 10");
        assert!(!sw.vlans.contains_key(&10));
        assert_eq!(sw.port(1).unwrap().access_vlan, 1);
    }

    #[test]
    fn show_outputs_do_not_panic() {
        let mut sw = test_switch();
        let mut s = Session::new();
        for c in [
            "show version",
            "show vlan",
            "show vlan brief",
            "show interfaces",
            "show interfaces status",
            "show interfaces eth1",
            "show interfaces eth1 switchport",
            "show interfaces trunk",
            "show spanning-tree",
            "show spanning-tree summary",
            "show mac address-table",
            "show running-config",
            "show features",
            "show logging",
        ] {
            let out = execute(&mut sw, &mut s, c);
            assert!(!out.is_empty(), "{} produced no output", c);
        }
    }

    #[test]
    fn lldp_commands_and_feature_gate() {
        let mut sw = test_switch();
        let mut s = Session::new();

        assert!(cmd(&mut sw, &mut s, "show lldp").contains("disabled"));
        cmd(&mut sw, &mut s, "config");
        assert!(cmd(&mut sw, &mut s, "feature enable lldp").contains("enabled"));
        assert!(sw.features.lldp);
        cmd(&mut sw, &mut s, "end");

        let status = cmd(&mut sw, &mut s, "show lldp");
        assert!(status.contains("IEEE 802.1AB-2026"));
        assert!(status.contains("Transmit interval: 30"));
        assert!(cmd(&mut sw, &mut s, "show lldp traffic").contains("Transmit frames"));
        assert!(cmd(&mut sw, &mut s, "show lldp interface eth1").contains("Gi0/1"));
        assert!(cmd(&mut sw, &mut s, "show lldp neighbors").contains("No LLDP neighbors"));

        // Inject an advertisement from a peer switch.
        let mut peer = Switch::new(
            "peer",
            [0x02, 0, 0, 0, 0, 0xbb],
            PathBuf::from("/tmp/opencode/switch-test/peer"),
        );
        peer.add_port("eth9");
        let wire = lldp::frame(&peer, peer.port(1).unwrap());
        let parsed = packet::parse(&wire).unwrap();
        lldp::on_frame(&mut sw, 1, &parsed, Instant::now());

        let table = cmd(&mut sw, &mut s, "show lldp neighbors");
        assert!(table.contains("peer"));
        assert!(table.contains("eth9"));
        assert!(table.contains("Gi0/1"));
        let detail = cmd(&mut sw, &mut s, "show lldp neighbors detail");
        assert!(detail.contains("System name: peer"));
        assert!(detail.contains("Capabilities: bridge"));

        // Disabling the feature clears learned neighbours.
        cmd(&mut sw, &mut s, "config");
        cmd(&mut sw, &mut s, "feature disable lldp");
        assert_eq!(sw.lldp.neighbor_count(), 0);
        cmd(&mut sw, &mut s, "end");
        assert!(cmd(&mut sw, &mut s, "show lldp").contains("disabled"));
    }

    #[test]
    fn mstp_feature_toggles_protocol_mode() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "config");
        cmd(&mut sw, &mut s, "vlan create 10");
        cmd(&mut sw, &mut s, "bridge mst instance 1 vlan 10");
        assert!(!sw.features.mstp, "MSTP is disabled by default");
        assert_eq!(sw.stp_config.mode, StpMode::Stp);
        assert!(sw.stp.mstis.is_empty(), "no MSTI runs under STP");

        // MSTP cannot be selected while the feature is off.
        let err = cmd(&mut sw, &mut s, "spanning-tree mode mstp");
        assert!(err.starts_with('%'));
        assert!(err.contains("MSTP is disabled"));
        assert_eq!(sw.stp_config.mode, StpMode::Stp);

        // Enabling the feature restores the configured MSTI.
        let out = cmd(&mut sw, &mut s, "feature enable mstp");
        assert!(out.contains("enabled"));
        assert!(sw.features.mstp);
        assert_eq!(sw.stp_config.mode, StpMode::Mstp);
        assert!(sw.stp.mstis.contains_key(&1));

        // Disabling it returns to one STP tree.
        let out = cmd(&mut sw, &mut s, "feature disable mstp");
        assert!(out.contains("disabled"));
        assert!(!sw.features.mstp);
        assert_eq!(sw.stp_config.mode, StpMode::Stp);
        assert!(sw.stp.mstis.is_empty());

        // Selecting STP explicitly also disables the MSTP feature.
        cmd(&mut sw, &mut s, "feature enable mstp");
        cmd(&mut sw, &mut s, "spanning-tree mode stp");
        assert!(!sw.features.mstp);
        assert_eq!(sw.stp_config.mode, StpMode::Stp);
        assert!(sw.stp.mstis.is_empty());
        let text = running_config(&sw);
        assert!(text.contains("feature disable mstp"));
        assert!(text.contains("bridge mode stp"));
        cmd(&mut sw, &mut s, "end");
        assert!(cmd(&mut sw, &mut s, "show version").contains("IEEE 802.1D STP"));
    }

    #[test]
    fn native_vocabulary() {
        let mut sw = test_switch();
        let mut s = Session::new();
        assert!(cmd(&mut sw, &mut s, "config").is_empty());
        assert_eq!(s.mode, Mode::Config);
        cmd(&mut sw, &mut s, "device name core-1");
        assert_eq!(sw.hostname, "core-1");

        assert!(cmd(&mut sw, &mut s, "vlan create 10 name sales").is_empty());
        assert_eq!(sw.vlan_name(10), "sales");
        assert_eq!(s.mode, Mode::Config, "vlan create must not enter a sub-mode");

        let out = cmd(&mut sw, &mut s, "bridge priority 4096");
        assert!(out.is_empty());
        assert_eq!(sw.stp_config.priority, 4096);
        // The old per-VLAN form is accepted as a compatibility alias and
        // applies to the single common spanning tree.
        let out = cmd(&mut sw, &mut s, "bridge vlan 10 priority 8192");
        assert!(out.contains("CIST"));
        assert_eq!(sw.stp_config.priority, 8192);

        assert!(cmd(&mut sw, &mut s, "feature enable pvst").starts_with('%'));

        assert!(cmd(&mut sw, &mut s, "port eth1").is_empty());
        assert_eq!(s.mode, Mode::Interface(1));
        cmd(&mut sw, &mut s, "mode trunk");
        cmd(&mut sw, &mut s, "allow vlans 10,20");
        cmd(&mut sw, &mut s, "native vlan 1");
        cmd(&mut sw, &mut s, "edge on");
        cmd(&mut sw, &mut s, "link down");
        assert_eq!(sw.port(1).unwrap().trunk.allowed.to_string(), "10,20");
        assert!(sw.port(1).unwrap().portfast);
        assert!(!sw.port(1).unwrap().admin_up);

        cmd(&mut sw, &mut s, "end");
        cmd(&mut sw, &mut s, "show fdb");
        cmd(&mut sw, &mut s, "show bridge vlan 10");
        cmd(&mut sw, &mut s, "show ports");
        cmd(&mut sw, &mut s, "show vlans");
        cmd(&mut sw, &mut s, "debug stp on");
        assert!(sw.stp.debug);
        cmd(&mut sw, &mut s, "debug stp off");
        assert!(!sw.stp.debug);

        // The IOS aliases still work unchanged.
        cmd(&mut sw, &mut s, "configure terminal");
        cmd(&mut sw, &mut s, "vlan 20");
        assert_eq!(s.mode, Mode::Vlan(20));
        cmd(&mut sw, &mut s, "exit");
        cmd(&mut sw, &mut s, "interface eth2");
        cmd(&mut sw, &mut s, "switchport mode trunk");
        assert_eq!(sw.port(2).unwrap().mode, PortMode::Trunk);
    }

    #[test]
    fn mstp_configuration_show_and_persistence() {
        let mut sw = test_switch();
        let mut s = Session::new();
        cmd(&mut sw, &mut s, "configure terminal");
        for v in [10u16, 20] {
            cmd(&mut sw, &mut s, &format!("vlan {}", v));
            cmd(&mut sw, &mut s, "exit");
        }

        let out = cmd(&mut sw, &mut s, "feature enable mstp");
        assert!(out.contains("enabled"));
        let out = cmd(&mut sw, &mut s, "spanning-tree mode mstp");
        assert!(out.contains("MSTP"));
        assert_eq!(sw.stp_config.mode, StpMode::Mstp);

        assert!(cmd(&mut sw, &mut s, "bridge mst name REGION-A").is_empty());
        assert!(cmd(&mut sw, &mut s, "bridge mst revision 7").is_empty());
        assert!(cmd(&mut sw, &mut s, "bridge mst max-hops 17").is_empty());
        assert!(cmd(&mut sw, &mut s, "bridge mst instance 1 vlan 10,20").is_empty());
        assert!(cmd(&mut sw, &mut s, "bridge mst instance 1 priority 4096").is_empty());
        assert_eq!(sw.mst.name, "REGION-A");
        assert_eq!(sw.mst.revision, 7);
        assert_eq!(sw.stp_config.max_hops, 17);
        assert_eq!(sw.mst.mstid_for_vlan(10), 1);
        assert_eq!(sw.mst.mstid_for_vlan(20), 1);
        assert_eq!(sw.mst.instances[&1].priority, 4096);
        assert!(sw.stp.mstis.contains_key(&1), "runtime MSTI exists");

        // A VID belongs to exactly one MSTI.
        cmd(&mut sw, &mut s, "bridge mst instance 2 vlan 20,30");
        assert_eq!(sw.mst.mstid_for_vlan(10), 1);
        assert_eq!(sw.mst.mstid_for_vlan(20), 2);
        assert_eq!(sw.mst.mstid_for_vlan(30), 2);
        cmd(&mut sw, &mut s, "no bridge mst instance 2");
        assert_eq!(sw.mst.mstid_for_vlan(20), 0);
        cmd(&mut sw, &mut s, "bridge mst instance 1 vlan 10,20");
        cmd(&mut sw, &mut s, "end");

        let cfg = cmd(&mut sw, &mut s, "show spanning-tree mst configuration");
        assert!(cfg.contains("REGION-A"));
        assert!(cfg.contains("Revision: 7"));
        assert!(cfg.contains("0 (CIST)"));
        assert!(cfg.contains("10,20"));
        assert!(cfg.contains("priority 4096"));
        assert!(cfg.contains("Digest:"));

        let msti = cmd(&mut sw, &mut s, "show spanning-tree mst 1");
        assert!(msti.contains("MSTI 1"));
        let vlan = cmd(&mut sw, &mut s, "show spanning-tree vlan 10");
        assert!(vlan.contains("MSTI 1"));
        let summary = cmd(&mut sw, &mut s, "show spanning-tree summary");
        assert!(summary.contains("Multiple Spanning Tree"));
        assert!(summary.contains("1 CIST + 1 MSTI"));
        assert!(
            summary.contains("Root bridge for: CIST, MSTI 1"),
            "summary should list the instances this bridge roots: {summary}"
        );

        cmd(&mut sw, &mut s, "configure terminal");
        cmd(&mut sw, &mut s, "interface eth1");
        assert!(cmd(&mut sw, &mut s, "spanning-tree cost 123").is_empty());
        assert!(cmd(&mut sw, &mut s, "spanning-tree priority 64").is_empty());
        assert!(cmd(&mut sw, &mut s, "spanning-tree mst 1 cost 456").is_empty());
        assert!(cmd(&mut sw, &mut s, "spanning-tree mst 1 priority 96").is_empty());
        assert_eq!(sw.port(1).unwrap().stp_cost, Some(123));
        assert_eq!(sw.port(1).unwrap().stp_priority, 64);
        assert_eq!(sw.port(1).unwrap().msti[&1].cost, Some(456));
        assert_eq!(sw.port(1).unwrap().msti[&1].priority, 96);

        let text = running_config(&sw);
        assert!(text.contains("bridge mst name REGION-A"));
        assert!(text.contains("bridge mst revision 7"));
        assert!(text.contains("bridge mst max-hops 17"));
        assert!(text.contains("bridge mst instance 1 vlan 10,20"));
        assert!(text.contains("bridge mst instance 1 priority 4096"));
        assert!(text.contains("mst 1 cost 456"));
        assert!(text.contains("priority 64"));

        let mut restored = Switch::new(
            "other",
            [0, 1, 2, 3, 4, 5],
            PathBuf::from("/tmp/opencode/switch-test/mst"),
        );
        restored.add_port("eth1");
        restored.add_port("eth2");
        restored.features.portfast = true;
        restored.features.bpdu_guard = true;
        load_config(&mut restored, &text);
        assert_eq!(restored.stp_config.mode, StpMode::Mstp);
        assert_eq!(restored.mst.name, "REGION-A");
        assert_eq!(restored.mst.revision, 7);
        assert_eq!(restored.stp_config.max_hops, 17);
        assert_eq!(restored.mst.mstid_for_vlan(10), 1);
        assert_eq!(restored.mst.instances[&1].priority, 4096);
        assert_eq!(restored.port(1).unwrap().stp_cost, Some(123));
        assert_eq!(restored.port(1).unwrap().stp_priority, 64);
        assert_eq!(restored.port(1).unwrap().msti[&1].cost, Some(456));
        assert_eq!(restored.port(1).unwrap().msti[&1].priority, 96);
        assert_eq!(restored.mst.digest(), sw.mst.digest());

        // Invalid values are rejected rather than silently ignored.
        cmd(&mut sw, &mut s, "end");
        cmd(&mut sw, &mut s, "configure terminal");
        assert!(cmd(&mut sw, &mut s, "bridge mst instance 0 vlan 10").starts_with('%'));
        assert!(cmd(&mut sw, &mut s, "bridge mst instance 1 priority 1234").starts_with('%'));
        assert!(cmd(&mut sw, &mut s, "spanning-tree mode pvst").starts_with('%'));
    }
}
