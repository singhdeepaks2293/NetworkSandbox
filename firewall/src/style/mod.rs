//! Vendor-style command line front ends.
//!
//! The firewall has one configuration model and one packet engine. A *style*
//! is a front end that reads and edits that model the way an administrator of
//! a given product would:
//!
//! | Style | Modelled on | Changes take effect |
//! |---|---|---|
//! | `native` | this firewall's own line language | on `save` |
//! | `fortios` | FortiGate CLI: `config` / `edit` / `set` / `next` / `end` | on `next` and `end` |
//! | `panos` | PAN-OS CLI: `configure`, `set` / `delete`, `commit` | on `commit` |
//!
//! These are original implementations of each product's command *style* for
//! teaching. They cover a subset of commands, and they are not affiliated with
//! or endorsed by Fortinet or Palo Alto Networks.

pub mod fortios;
pub mod panos;

use crate::dataplane::Session;
use crate::model::Config;
use std::collections::HashMap;

/// Where a style reads and commits configuration. The engine implements it;
/// tests use an in-memory store.
pub trait Store {
    fn running(&self) -> Config;
    fn commit(&self, next: &Config) -> Result<(), String>;
    fn sessions(&self) -> Vec<Session>;
    fn hits(&self) -> HashMap<(String, u32), (u64, u64, u64)>;
    fn user_login(&self, ip: std::net::Ipv4Addr, user: &str, timeout_secs: Option<u64>) -> Result<(), String>;
    fn user_logout(&self, ip: std::net::Ipv4Addr) -> bool;
    /// (address or network, user, "dynamic"/"static", seconds left).
    fn user_mappings(&self) -> Vec<(String, String, &'static str, Option<u64>)>;
    fn ha_status(&self) -> String;
    /// Suspend (`true`) or resume this unit; an error when HA is off.
    fn ha_suspend(&self, suspend: bool) -> Result<(), String>;
}

impl Store for crate::dataplane::Engine {
    fn running(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }
    fn commit(&self, next: &Config) -> Result<(), String> {
        self.apply_config(next)
    }
    fn sessions(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().snapshot()
    }
    fn hits(&self) -> HashMap<(String, u32), (u64, u64, u64)> {
        self.policy_hits()
    }
    fn user_login(&self, ip: std::net::Ipv4Addr, user: &str, timeout_secs: Option<u64>) -> Result<(), String> {
        crate::dataplane::Engine::user_login(self, ip, user, timeout_secs.map(std::time::Duration::from_secs))
    }
    fn user_logout(&self, ip: std::net::Ipv4Addr) -> bool {
        crate::dataplane::Engine::user_logout(self, ip)
    }
    fn user_mappings(&self) -> Vec<(String, String, &'static str, Option<u64>)> {
        let cfg = self.cfg.read().unwrap().clone();
        crate::dataplane::Engine::user_mappings(self, &cfg)
    }
    fn ha_status(&self) -> String {
        self.ha.lock().unwrap().text()
    }
    fn ha_suspend(&self, suspend: bool) -> Result<(), String> {
        if !self.ha.lock().unwrap().enabled {
            return Err("HA is not enabled on this unit".into());
        }
        self.ha_suspended.store(suspend, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

pub struct Ctx<'a> {
    pub store: &'a dyn Store,
    /// Whether the logged-in role may change configuration.
    pub can_write: bool,
}

pub trait Style: Send {
    fn name(&self) -> &'static str;
    fn prompt(&self, hostname: &str) -> String;
    fn exec(&mut self, line: &str, ctx: &Ctx<'_>) -> String;
}

/// Create a style by name. `native` returns `None`: the caller keeps using
/// the built-in command set.
pub fn by_name(name: &str) -> Result<Option<Box<dyn Style>>, String> {
    match name {
        "native" => Ok(None),
        "fortios" => Ok(Some(Box::new(fortios::FortiOs::new()))),
        "panos" => Ok(Some(Box::new(panos::PanOs::new()))),
        other => Err(format!("unknown cli style '{other}' (native, fortios or panos)")),
    }
}

// ------------------------------------------------------------------ helpers

/// Split a command line into words, honouring double quotes; `[` and `]`
/// are words of their own.
pub fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                quoted = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() || quoted {
                    out.push(std::mem::take(&mut cur));
                }
                quoted = false;
            }
            '[' | ']' if !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(ch.to_string());
            }
            c => cur.push(c),
        }
    }
    if in_quotes {
        return Err("unterminated quote".into());
    }
    if !cur.is_empty() || quoted {
        out.push(cur);
    }
    Ok(out)
}

/// `255.255.255.0` → 24; rejects non-contiguous masks.
pub fn mask_len(mask: &str) -> Option<u8> {
    let bits = u32::from(mask.parse::<std::net::Ipv4Addr>().ok()?);
    let len = bits.leading_ones();
    (bits.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

pub fn len_mask(len: u8) -> String {
    let bits: u32 = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
    std::net::Ipv4Addr::from(bits).to_string()
}

/// Quote a value for display if it needs it.
pub fn q(s: &str) -> String {
    format!("\"{s}\"")
}

pub fn quote_all(v: &[String]) -> String {
    v.iter().map(|s| q(s)).collect::<Vec<_>>().join(" ")
}

/// Next free policy id, global across VDOMs as the model requires.
pub fn next_policy_id(cfg: &Config, step: u32) -> u32 {
    let max = cfg.policies.iter().map(|p| p.id).max().unwrap_or(0);
    (max / step + 1) * step
}

/// A text table with left-aligned columns.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(c.len());
            }
        }
    }
    let fmt = |cells: Vec<String>| {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:<w$}", c, w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = fmt(header.iter().map(|h| h.to_string()).collect());
    out.push('\n');
    for r in rows {
        out.push_str(&fmt(r.clone()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    /// In-memory store: commit validates by round-tripping through the
    /// config language, exactly like the engine.
    pub struct Mem(pub Mutex<Config>, pub Mutex<Vec<(std::net::Ipv4Addr, String)>>);

    impl Mem {
        pub fn new(text: &str) -> Mem {
            Mem(Mutex::new(Config::parse(text).expect("test config")), Mutex::new(Vec::new()))
        }
    }

    impl Store for Mem {
        fn running(&self) -> Config {
            self.0.lock().unwrap().clone()
        }
        fn commit(&self, next: &Config) -> Result<(), String> {
            let parsed = Config::parse(&next.to_text())?;
            *self.0.lock().unwrap() = parsed;
            Ok(())
        }
        fn sessions(&self) -> Vec<Session> {
            Vec::new()
        }
        fn hits(&self) -> HashMap<(String, u32), (u64, u64, u64)> {
            HashMap::new()
        }
        fn user_login(&self, ip: std::net::Ipv4Addr, user: &str, _: Option<u64>) -> Result<(), String> {
            crate::model::valid_user_name(user)?;
            let mut v = self.1.lock().unwrap();
            v.retain(|(i, _)| *i != ip);
            v.push((ip, user.to_string()));
            Ok(())
        }
        fn user_logout(&self, ip: std::net::Ipv4Addr) -> bool {
            let mut v = self.1.lock().unwrap();
            let n = v.len();
            v.retain(|(i, _)| *i != ip);
            n != v.len()
        }
        fn user_mappings(&self) -> Vec<(String, String, &'static str, Option<u64>)> {
            self.1.lock().unwrap().iter().map(|(ip, u)| (ip.to_string(), u.clone(), "dynamic", None)).collect()
        }
        fn ha_status(&self) -> String {
            "HA: standalone\n".into()
        }
        fn ha_suspend(&self, _: bool) -> Result<(), String> {
            Err("HA is not enabled on this unit".into())
        }
    }

    pub fn run(style: &mut dyn Style, store: &Mem, script: &str) -> Vec<String> {
        let ctx = Ctx { store, can_write: true };
        script.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| style.exec(l, &ctx)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(tokenize(r#"set name "web out" [ a b ]"#).unwrap(), vec!["set", "name", "web out", "[", "a", "b", "]"]);
        assert_eq!(mask_len("255.255.255.0"), Some(24));
        assert_eq!(mask_len("255.0.255.0"), None);
        assert_eq!(len_mask(20), "255.255.240.0");
    }
}
