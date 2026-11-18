//! FortiOS-style CLI.
//!
//! ```text
//! config vdom
//!     edit root
//!         config firewall policy
//!             edit 0
//!                 set name "lan-out"
//!                 set srcintf "lan"
//!                 set dstintf "wan"
//!                 set srcaddr "all"
//!                 set dstaddr "all"
//!                 set service "HTTPS" "DNS"
//!                 set action accept
//!                 set nat enable
//!             next
//!         end
//!     next
//! end
//! ```
//!
//! As on a FortiGate, an entry takes effect when it is closed with `next` or
//! `end`; `abort` throws it away. `edit 0` on a policy takes the next free id.
//! FortiOS names interfaces and zones in policies; an interface that is in no
//! zone acts as its own zone (its zone name is its interface name).
//!
//! Lightweight differences from FortiOS: applications and categories use this
//! firewall's App-ID names rather than numeric ids; web filter, IPS and
//! antivirus profiles take domains, categories and literal signatures
//! directly; VIPs create an address object of the same name for policies.

use super::{len_mask, mask_len, next_policy_id, q, quote_all, table, tokenize, Ctx, Style};
use crate::model::{
    addr_list_text, parse_port_ranges, Action, DefaultKind, DefaultRule, AddrRef, AddressGroup, AddressObject, AppGroup, Cidr, Config, DnatRule,
    Policy, Proto, Route, ServiceGroup, ServiceObject, Shaper, SignatureProfile, SnatRule, SnatTarget, UrlFilter,
};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Table {
    Global,
    Vdom,
    Interface,
    Zone,
    Address,
    Addrgrp,
    ServiceCustom,
    ServiceGroup,
    AppGroup,
    UserGroup,
    Policy,
    Vip,
    CentralSnat,
    RouterStatic,
    Webfilter,
    IpsSensor,
    Antivirus,
    Shaper,
}

const TABLES: &[(&str, Table)] = &[
    ("system global", Table::Global),
    ("vdom", Table::Vdom),
    ("system interface", Table::Interface),
    ("system zone", Table::Zone),
    ("firewall address", Table::Address),
    ("firewall addrgrp", Table::Addrgrp),
    ("firewall service custom", Table::ServiceCustom),
    ("firewall service group", Table::ServiceGroup),
    ("application group", Table::AppGroup),
    ("user group", Table::UserGroup),
    ("firewall policy", Table::Policy),
    ("firewall vip", Table::Vip),
    ("firewall central-snat-map", Table::CentralSnat),
    ("router static", Table::RouterStatic),
    ("webfilter profile", Table::Webfilter),
    ("ips sensor", Table::IpsSensor),
    ("antivirus profile", Table::Antivirus),
    ("firewall shaper traffic-shaper", Table::Shaper),
];

/// Tables shown by a plain `show`, in FortiOS order.
const SHOW_ORDER: &[Table] = &[
    Table::Global,
    Table::Interface,
    Table::Zone,
    Table::Address,
    Table::Addrgrp,
    Table::ServiceCustom,
    Table::ServiceGroup,
    Table::AppGroup,
    Table::UserGroup,
    Table::Webfilter,
    Table::IpsSensor,
    Table::Antivirus,
    Table::Shaper,
    Table::Vip,
    Table::Policy,
    Table::CentralSnat,
    Table::RouterStatic,
];

impl Table {
    fn path(self) -> &'static str {
        TABLES.iter().find(|t| t.1 == self).map(|t| t.0).expect("listed")
    }
    fn short(self) -> &'static str {
        self.path().rsplit(' ').next().expect("non-empty")
    }
}

/// FortiOS predefined services, created on first use.
const PREDEFINED: &[(&str, Proto, &str)] = &[
    ("HTTP", Proto::Tcp, "80"),
    ("HTTPS", Proto::Tcp, "443"),
    ("DNS", Proto::Any, "53"),
    ("SSH", Proto::Tcp, "22"),
    ("TELNET", Proto::Tcp, "23"),
    ("FTP", Proto::Tcp, "21"),
    ("SMTP", Proto::Tcp, "25"),
    ("SMTPS", Proto::Tcp, "465"),
    ("POP3", Proto::Tcp, "110"),
    ("POP3S", Proto::Tcp, "995"),
    ("IMAP", Proto::Tcp, "143"),
    ("IMAPS", Proto::Tcp, "993"),
    ("NTP", Proto::Udp, "123"),
    ("SNMP", Proto::Udp, "161-162"),
    ("RDP", Proto::Tcp, "3389"),
    ("SAMBA", Proto::Tcp, "139,445"),
    ("MYSQL", Proto::Tcp, "3306"),
    ("PING", Proto::Icmp, "any"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Frame {
    Table(Table),
    Edit(Table, String),
}

pub struct FortiOs {
    vdom: String,
    frames: Vec<Frame>,
    /// Edits not yet applied; created on the first change, applied on next/end.
    draft: Option<Config>,
}

impl FortiOs {
    pub fn new() -> FortiOs {
        FortiOs { vdom: "root".into(), frames: Vec::new(), draft: None }
    }
}

type R = Result<String, String>;

fn fail<T>(msg: impl Into<String>) -> Result<T, String> {
    Err(msg.into())
}

fn arg(w: &[String], i: usize) -> Result<&str, String> {
    w.get(i).map(String::as_str).ok_or_else(|| "command parse error before 'eol'".to_string())
}

fn cidr_from(w: &[String], i: usize) -> Result<Cidr, String> {
    let a = arg(w, i)?;
    if a.contains('/') {
        return Cidr::parse(a);
    }
    let mask = arg(w, i + 1)?;
    let len = mask_len(mask).ok_or_else(|| format!("invalid netmask {mask}"))?;
    Cidr::parse(&format!("{a}/{len}"))
}

fn network(c: Cidr) -> Cidr {
    let mask: u32 = if c.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(c.prefix)) };
    Cidr { addr: Ipv4Addr::from(u32::from(c.addr) & mask), prefix: c.prefix }
}

fn subnet_text(c: &Cidr) -> String {
    format!("{} {}", c.addr, len_mask(c.prefix))
}

fn enable(w: &[String], i: usize) -> Result<bool, String> {
    match arg(w, i)? {
        "enable" => Ok(true),
        "disable" => Ok(false),
        other => fail(format!("invalid value {other} (enable or disable)")),
    }
}

impl Style for FortiOs {
    fn name(&self) -> &'static str {
        "fortios"
    }

    fn prompt(&self, hostname: &str) -> String {
        match self.frames.last() {
            None => format!("{hostname} # "),
            Some(Frame::Table(t)) => format!("{hostname} ({}) # ", t.short()),
            Some(Frame::Edit(_, k)) => format!("{hostname} ({k}) # "),
        }
    }

    fn exec(&mut self, line: &str, ctx: &Ctx<'_>) -> String {
        let words = match tokenize(line.trim()) {
            Ok(w) => w,
            Err(e) => return format!("Command fail. {e}"),
        };
        if words.is_empty() || words[0].starts_with('#') {
            return String::new();
        }
        let writes = matches!(words[0].as_str(), "set" | "unset" | "edit" | "delete" | "purge" | "append");
        if writes && !ctx.can_write {
            return "Command fail. Permission denied (read-only administrator)".into();
        }
        match self.dispatch(&words, ctx) {
            Ok(out) => out,
            Err(e) => format!("Command fail. {e}"),
        }
    }
}

impl FortiOs {
    fn view(&self, ctx: &Ctx<'_>) -> Config {
        self.draft.clone().unwrap_or_else(|| ctx.store.running())
    }

    fn draft<'s>(&'s mut self, ctx: &Ctx<'_>) -> &'s mut Config {
        if self.draft.is_none() {
            self.draft = Some(ctx.store.running());
        }
        self.draft.as_mut().expect("just set")
    }

    fn apply(&mut self, ctx: &Ctx<'_>) -> R {
        let Some(draft) = self.draft.take() else { return Ok(String::new()) };
        ctx.store.commit(&draft).map(|()| String::new())
    }

    fn dispatch(&mut self, w: &[String], ctx: &Ctx<'_>) -> R {
        match w[0].as_str() {
            "config" => self.config(&w[1..]),
            "edit" => self.edit(arg(w, 1)?, ctx),
            "set" | "unset" | "append" => self.set(w, ctx),
            "delete" => self.delete(arg(w, 1)?, ctx),
            "next" => self.next(ctx),
            "end" => self.end(ctx),
            "abort" => {
                self.draft = None;
                if let Some(Frame::Edit(..)) = self.frames.last() {
                    self.frames.pop();
                }
                Ok(String::new())
            }
            "show" => self.show(&w[1..], ctx),
            "get" => self.get(&w[1..], ctx),
            "execute" => match w.iter().skip(1).map(String::as_str).collect::<Vec<_>>().as_slice() {
                ["ha", "failover", "set", "1"] if ctx.can_write => ctx.store.ha_suspend(true).map(|()| "This unit is now held passive (failover set).".into()),
                ["ha", "failover", "unset", "1"] if ctx.can_write => ctx.store.ha_suspend(false).map(|()| "Failover hold removed.".into()),
                ["ha", ..] => fail("Permission denied or usage: execute ha failover set 1 | execute ha failover unset 1"),
                _ => fail("supported: execute ha failover set 1 | unset 1"),
            },
            "diagnose" => self.diagnose(&w[1..], ctx),
            other => fail(format!("Unknown action 0: {other}")),
        }
    }

    fn config(&mut self, w: &[String]) -> R {
        let path = w.join(" ");
        let t = TABLES.iter().find(|t| t.0 == path).map(|t| t.1).ok_or_else(|| format!("Unknown table '{path}'"))?;
        let at_top = self.frames.is_empty();
        let in_vdom = matches!(self.frames.last(), Some(Frame::Edit(Table::Vdom, _)));
        let in_edit = matches!(self.frames.last(), Some(Frame::Edit(..)));
        if !(at_top || in_vdom || (in_edit && t != Table::Vdom)) {
            return fail("finish the current table with 'end' first");
        }
        if t == Table::Vdom && !at_top {
            return fail("'config vdom' is only available at the top level");
        }
        self.frames.push(Frame::Table(t));
        Ok(String::new())
    }

    fn edit(&mut self, key: &str, ctx: &Ctx<'_>) -> R {
        let t = match self.frames.last() {
            Some(Frame::Table(t)) => *t,
            _ => return fail("'edit' needs a config table"),
        };
        let vdom = self.vdom.clone();
        if t == Table::Global {
            return fail("system global has no entries; use set");
        }
        if t == Table::Vdom {
            let cfg = self.draft(ctx);
            if !cfg.vdoms.iter().any(|v| v == key) {
                cfg.vdoms.push(key.to_string());
            }
            self.vdom = key.to_string();
            self.frames.push(Frame::Edit(t, key.to_string()));
            return Ok(String::new());
        }
        let exists = entry_exists(&self.view(ctx), t, key, &vdom);
        let mut key = key.to_string();
        if !exists {
            let cfg = self.draft(ctx);
            key = create_entry(cfg, t, &key, &vdom)?;
        }
        self.frames.push(Frame::Edit(t, key));
        Ok(String::new())
    }

    fn next(&mut self, ctx: &Ctx<'_>) -> R {
        match self.frames.last().cloned() {
            Some(Frame::Edit(Table::Vdom, _)) => {
                self.frames.pop();
                self.vdom = "root".into();
                self.apply(ctx)
            }
            Some(Frame::Edit(t, key)) => {
                if let Some(draft) = &self.draft {
                    complete(draft, t, &key, &self.vdom)?;
                }
                self.frames.pop();
                let r = self.apply(ctx);
                if r.is_err() {
                    self.draft = None;
                }
                r
            }
            _ => fail("'next' closes an entry opened with 'edit'"),
        }
    }

    fn end(&mut self, ctx: &Ctx<'_>) -> R {
        let mut out = String::new();
        if let Some(Frame::Edit(t, key)) = self.frames.last().cloned() {
            if t == Table::Vdom {
                return self.next(ctx);
            }
            if let Some(draft) = &self.draft {
                if let Err(e) = complete(draft, t, &key, &self.vdom) {
                    self.draft = None;
                    self.frames.pop();
                    self.frames.pop();
                    return Err(e);
                }
            }
            self.frames.pop();
        }
        match self.frames.pop() {
            Some(Frame::Table(Table::Vdom)) => self.vdom = "root".into(),
            Some(_) => {}
            None => return fail("nothing to end"),
        }
        match self.apply(ctx) {
            Ok(s) => out.push_str(&s),
            Err(e) => {
                self.draft = None;
                return Err(e);
            }
        }
        Ok(out)
    }

    fn delete(&mut self, key: &str, ctx: &Ctx<'_>) -> R {
        let t = match self.frames.last() {
            Some(Frame::Table(t)) => *t,
            _ => return fail("'delete' needs a config table"),
        };
        let vdom = self.vdom.clone();
        let cfg = self.draft(ctx);
        delete_entry(cfg, t, key, &vdom)?;
        Ok(String::new())
    }

    fn set(&mut self, w: &[String], ctx: &Ctx<'_>) -> R {
        let unset = w[0] == "unset";
        let append = w[0] == "append";
        let field = arg(w, 1)?.to_string();
        let vals: Vec<String> = w[2..].to_vec();
        let vdom = self.vdom.clone();
        match self.frames.last().cloned() {
            Some(Frame::Table(Table::Global)) => {
                let cfg = self.draft(ctx);
                match field.as_str() {
                    "hostname" if !unset => cfg.settings.hostname = arg(w, 2)?.to_string(),
                    other => return fail(format!("field '{other}' is not supported in system global")),
                }
                Ok(String::new())
            }
            Some(Frame::Edit(t, key)) => {
                let cfg = self.draft(ctx);
                set_field(cfg, t, &key, &vdom, &field, &vals, unset, append)?;
                Ok(String::new())
            }
            _ => fail("'set' needs an entry opened with 'edit'"),
        }
    }

    fn show(&self, w: &[String], ctx: &Ctx<'_>) -> R {
        let cfg = self.view(ctx);
        if w.is_empty() || w[0] == "full-configuration" {
            return Ok(match self.frames.last() {
                Some(Frame::Edit(t, key)) if *t != Table::Vdom => render_table(&cfg, *t, &self.vdom, Some(key)),
                Some(Frame::Table(t)) | Some(Frame::Edit(t, _)) if *t != Table::Vdom => render_table(&cfg, *t, &self.vdom, None),
                _ => SHOW_ORDER.iter().map(|t| render_table(&cfg, *t, &self.vdom, None)).collect(),
            });
        }
        // `show firewall policy [id]`
        for (path, t) in TABLES {
            let n = path.split(' ').count();
            if w.len() >= n && w[..n].join(" ") == *path {
                return Ok(render_table(&cfg, *t, &self.vdom, w.get(n).map(String::as_str)));
            }
        }
        fail(format!("Unknown table '{}'", w.join(" ")))
    }

    fn get(&self, w: &[String], ctx: &Ctx<'_>) -> R {
        match w.join(" ").as_str() {
            "system status" => {
                let cfg = ctx.store.running();
                Ok(format!(
                    "Version: NetworkSandbox NGFW (FortiOS-style CLI)\nHostname: {}\nOperation Mode: NAT\nCurrent virtual domain: {}\nVirtual domains: {}\nFirewall policies: {}\nSessions: {}\n",
                    cfg.settings.hostname,
                    self.vdom,
                    cfg.vdoms.join(", "),
                    cfg.policies.len(),
                    ctx.store.sessions().len()
                ))
            }
            "router info routing-table all" => {
                let cfg = ctx.store.running();
                let mut out = String::from("Codes: S - static, C - connected\n\n");
                for i in cfg.interfaces.iter().filter(|i| i.vdom == self.vdom) {
                    if let Some(a) = i.address {
                        out.push_str(&format!("C       {} is directly connected, {}\n", network(a), i.name));
                    }
                }
                for r in cfg.routes.iter().filter(|r| r.vdom == self.vdom) {
                    let via = r.via.map(|v| format!("via {v}, ")).unwrap_or_default();
                    out.push_str(&format!("S       {} [{}/0] {via}{}\n", r.dst, r.distance, r.interface));
                }
                Ok(out)
            }
            "application list" => Ok(crate::appid::catalog_text(None)),
            "system ha status" => Ok(ctx.store.ha_status()),
            other if other.starts_with("application list ") => Ok(crate::appid::catalog_text(other.split(' ').nth(2))),
            other => fail(format!("unknown get command '{other}'")),
        }
    }

    fn diagnose(&self, w: &[String], ctx: &Ctx<'_>) -> R {
        let joined = w.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
        match joined.as_str() {
            "sys session list" => {
                let rows: Vec<Vec<String>> = ctx
                    .store
                    .sessions()
                    .into_iter()
                    .filter(|s| s.key.vdom == self.vdom)
                    .map(|s| {
                        vec![
                            proto_name(s.key.proto),
                            format!("{}:{}", s.key.src, s.key.sport),
                            format!("{}:{}", s.key.dst, s.key.dport),
                            s.policy_id.to_string(),
                            s.app.unwrap_or_else(|| "pending".into()),
                            s.nat_src.map(|(ip, p)| format!("{ip}:{p}")).unwrap_or_else(|| "-".into()),
                        ]
                    })
                    .collect();
                Ok(table(&["proto", "src", "dst", "policy_id", "app", "snat"], &rows))
            }
            "firewall iprope lookup" => {
                // diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <srcintf> [app]
                let a = &w[3..];
                if a.len() < 6 {
                    return fail("usage: diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <srcintf> [application]");
                }
                let cfg = ctx.store.running();
                let src: Ipv4Addr = a[0].parse().map_err(|_| "invalid source".to_string())?;
                let dst: Ipv4Addr = a[2].parse().map_err(|_| "invalid destination".to_string())?;
                let dport: u16 = a[3].parse().map_err(|_| "invalid port".to_string())?;
                let proto = proto_number(&a[4])?;
                let iface = cfg.interfaces.iter().find(|i| i.name == a[5] && i.vdom == self.vdom).ok_or("unknown interface")?;
                let (egress, _) = cfg.egress(&self.vdom, dst).ok_or("no route to destination")?;
                let app = a.get(6).map(String::as_str);
                let hit = cfg.match_or_default(&self.vdom, &iface.zone, &egress.zone, src, dst, proto, dport, app);
                Ok(match hit {
                    Some(p) if crate::model::is_default_rule_id(p.id) && p.action == Action::Permit => {
                        format!("matches {} (allow)\n", p.name.clone().unwrap_or_default())
                    }
                    Some(p) if crate::model::is_default_rule_id(p.id) => "matches policy id: 0 (implicit deny)\n".to_string(),
                    Some(p) => format!(
                        "<src [{src}-{}] dst [{dst}-{dport}] proto {proto} dev {} -> {}>\nmatches policy id: {}{} action: {}\n",
                        a[1],
                        iface.name,
                        egress.name,
                        p.id,
                        p.name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
                        if p.action == Action::Permit { "accept" } else { "deny" }
                    ),
                    None => "matches policy id: 0 (implicit deny)\n".to_string(),
                })
            }
            "firewall auth list" => {
                let rows: Vec<Vec<String>> = ctx
                    .store
                    .user_mappings()
                    .into_iter()
                    .map(|(ip, user, source, left)| vec![ip, user, source.to_string(), left.map(|s| format!("{s}s")).unwrap_or_else(|| "-".into())])
                    .collect();
                Ok(table(&["ip", "user", "source", "expires"], &rows))
            }
            _ => fail("supported: diagnose sys session list | diagnose firewall auth list | diagnose firewall iprope lookup ..."),
        }
    }
}

fn proto_name(p: u8) -> String {
    match p {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        n => n.to_string(),
    }
}

fn proto_number(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        n => n.parse().map_err(|_| format!("invalid protocol {s}")),
    }
}

// ---------------------------------------------------------------- entries

fn entry_exists(cfg: &Config, t: Table, key: &str, vdom: &str) -> bool {
    match t {
        Table::Interface => cfg.interfaces.iter().any(|i| i.name == key),
        Table::Zone => cfg.interfaces.iter().any(|i| i.vdom == vdom && i.zone == key && i.name != key),
        Table::Address => cfg.addresses.iter().any(|a| a.name == key),
        Table::Addrgrp => cfg.address_groups.iter().any(|g| g.name == key),
        Table::ServiceCustom => cfg.services.iter().any(|s| s.name == key),
        Table::ServiceGroup => cfg.service_groups.iter().any(|g| g.name == key),
        Table::AppGroup => cfg.app_groups.iter().any(|g| g.name == key),
        Table::UserGroup => cfg.user_groups.iter().any(|g| g.name == key),
        Table::Policy => key.parse::<u32>().map_or(false, |id| id != 0 && cfg.policies.iter().any(|p| p.id == id && p.vdom == vdom)),
        Table::Vip => cfg.dnat.iter().any(|d| d.vdom == vdom && d.name.as_deref() == Some(key)),
        Table::CentralSnat => key.parse::<u32>().map_or(false, |id| cfg.snat.iter().any(|r| r.id == id && r.vdom == vdom)),
        Table::RouterStatic => cfg.routes.iter().any(|r| r.vdom == vdom && r.name.as_deref() == Some(key)),
        Table::Webfilter => cfg.url_filters.iter().any(|f| f.name == key),
        Table::IpsSensor => cfg.ips_profiles.iter().any(|p| p.name == key),
        Table::Antivirus => cfg.av_profiles.iter().any(|p| p.name == key),
        Table::Shaper => cfg.shapers.iter().any(|s| s.name == key),
        Table::Global | Table::Vdom => true,
    }
}

/// Create an entry with FortiOS defaults. Returns the key actually used
/// (`edit 0` on a policy picks an id).
fn create_entry(cfg: &mut Config, t: Table, key: &str, vdom: &str) -> Result<String, String> {
    match t {
        Table::Interface => return fail(format!("entry not found in datasource: interface {key} (interfaces are created by the platform)")),
        Table::Zone => {
            if cfg.interfaces.iter().any(|i| i.name == key) {
                return fail(format!("{key} is an interface name"));
            }
        }
        Table::Address => cfg.addresses.push(AddressObject { name: key.into(), entries: vec![Cidr::ANY], entries6: Vec::new() }),
        Table::Addrgrp => cfg.address_groups.push(AddressGroup { name: key.into(), members: Vec::new() }),
        Table::ServiceCustom => cfg.services.push(ServiceObject { name: key.into(), proto: Proto::Tcp, ports: Vec::new() }),
        Table::ServiceGroup => cfg.service_groups.push(ServiceGroup { name: key.into(), members: Vec::new() }),
        Table::AppGroup => cfg.app_groups.push(AppGroup { name: key.into(), members: Vec::new() }),
        Table::UserGroup => cfg.user_groups.push(crate::model::UserGroup { name: key.into(), members: Vec::new() }),
        Table::Policy => {
            let mut id: u32 = key.parse().map_err(|_| "policy id must be a number".to_string())?;
            if id == 0 {
                id = next_policy_id(cfg, 1);
            }
            if let Some(other) = cfg.policies.iter().find(|p| p.id == id) {
                return fail(format!("policy id {id} is already used in vdom {}", other.vdom));
            }
            let mut p = Policy::new(id, vdom);
            p.src_zones.clear();
            p.dst_zones.clear();
            p.src.clear();
            p.dst.clear();
            cfg.policies.push(p);
            cfg.policies.sort_by_key(|p| p.id);
            return Ok(id.to_string());
        }
        Table::Vip => {
            if cfg.addresses.iter().any(|a| a.name == key) {
                return fail(format!("an address named {key} already exists"));
            }
            let id = cfg.dnat.iter().map(|d| d.id).max().unwrap_or(0) + 1;
            cfg.dnat.push(DnatRule {
                id,
                vdom: vdom.into(),
                proto: Proto::Any,
                dst: Cidr::ANY,
                dst_port: None,
                to_ip: Ipv4Addr::UNSPECIFIED,
                to_port: None,
                name: Some(key.into()),
            });
        }
        Table::CentralSnat => {
            let id: u32 = key.parse().map_err(|_| "id must be a number".to_string())?;
            if cfg.snat.iter().any(|r| r.id == id) {
                return fail(format!("snat id {id} is used in another vdom"));
            }
            cfg.snat.push(SnatRule {
                id,
                vdom: vdom.into(),
                src_zones: Vec::new(),
                dst_zones: Vec::new(),
                src: Vec::new(),
                dst: Vec::new(),
                to: SnatTarget::Masquerade,
                enabled: true,
                name: None,
            });
        }
        Table::RouterStatic => {
            key.parse::<u32>().map_err(|_| "sequence number must be a number".to_string())?;
            cfg.routes.push(Route { dst: Cidr::ANY, interface: String::new(), via: None, distance: 10, vdom: vdom.into(), name: Some(key.into()) });
        }
        Table::Webfilter => cfg.url_filters.push(UrlFilter { name: key.into(), block: Vec::new(), allow: Vec::new() }),
        Table::IpsSensor => cfg.ips_profiles.push(SignatureProfile { name: key.into(), patterns: Vec::new() }),
        Table::Antivirus => cfg.av_profiles.push(SignatureProfile { name: key.into(), patterns: Vec::new() }),
        Table::Shaper => cfg.shapers.push(Shaper { name: key.into(), kbps: 0 }),
        Table::Global | Table::Vdom => {}
    }
    Ok(key.to_string())
}

/// FortiOS refuses to save an entry missing required fields.
fn complete(cfg: &Config, t: Table, key: &str, vdom: &str) -> Result<(), String> {
    let missing = |field: &str| Err(format!("{field} must be set"));
    match t {
        Table::Policy => {
            let id: u32 = key.parse().unwrap_or(0);
            if let Some(p) = cfg.policies.iter().find(|p| p.id == id && p.vdom == vdom) {
                if p.src_zones.is_empty() {
                    return missing("srcintf");
                }
                if p.dst_zones.is_empty() {
                    return missing("dstintf");
                }
                if p.src.is_empty() {
                    return missing("srcaddr");
                }
                if p.dst.is_empty() {
                    return missing("dstaddr");
                }
            }
        }
        Table::Addrgrp if cfg.address_groups.iter().any(|g| g.name == key && g.members.is_empty()) => return missing("member"),
        Table::ServiceGroup if cfg.service_groups.iter().any(|g| g.name == key && g.members.is_empty()) => return missing("member"),
        Table::AppGroup if cfg.app_groups.iter().any(|g| g.name == key && g.members.is_empty()) => return missing("application"),
        Table::UserGroup if cfg.user_groups.iter().any(|g| g.name == key && g.members.is_empty()) => return missing("member"),
        Table::Vip => {
            if let Some(d) = cfg.dnat.iter().find(|d| d.vdom == vdom && d.name.as_deref() == Some(key)) {
                if d.dst == Cidr::ANY {
                    return missing("extip");
                }
                if d.to_ip.is_unspecified() {
                    return missing("mappedip");
                }
            }
        }
        Table::CentralSnat => {
            let id: u32 = key.parse().unwrap_or(0);
            if let Some(r) = cfg.snat.iter().find(|r| r.id == id) {
                if r.src_zones.is_empty() || r.dst_zones.is_empty() {
                    return missing("srcintf and dstintf");
                }
                if r.src.is_empty() || r.dst.is_empty() {
                    return missing("orig-addr and dst-addr");
                }
            }
        }
        Table::RouterStatic if cfg.routes.iter().any(|r| r.vdom == vdom && r.name.as_deref() == Some(key) && r.interface.is_empty()) => {
            return missing("device")
        }
        Table::Shaper if cfg.shapers.iter().any(|s| s.name == key && s.kbps == 0) => return missing("maximum-bandwidth"),
        _ => {}
    }
    Ok(())
}

fn delete_entry(cfg: &mut Config, t: Table, key: &str, vdom: &str) -> Result<(), String> {
    let before = count(cfg);
    match t {
        Table::Zone => {
            for i in cfg.interfaces.iter_mut().filter(|i| i.vdom == vdom && i.zone == key) {
                i.zone = i.name.clone();
            }
        }
        Table::Address => cfg.addresses.retain(|a| a.name != key),
        Table::Addrgrp => cfg.address_groups.retain(|g| g.name != key),
        Table::ServiceCustom => cfg.services.retain(|s| s.name != key),
        Table::ServiceGroup => cfg.service_groups.retain(|g| g.name != key),
        Table::AppGroup => cfg.app_groups.retain(|g| g.name != key),
        Table::UserGroup => cfg.user_groups.retain(|g| g.name != key),
        Table::Policy => cfg.policies.retain(|p| !(p.vdom == vdom && p.id.to_string() == key)),
        Table::Vip => {
            cfg.dnat.retain(|d| !(d.vdom == vdom && d.name.as_deref() == Some(key)));
            cfg.addresses.retain(|a| a.name != key);
        }
        Table::CentralSnat => cfg.snat.retain(|r| !(r.vdom == vdom && r.id.to_string() == key)),
        Table::RouterStatic => cfg.routes.retain(|r| !(r.vdom == vdom && r.name.as_deref() == Some(key))),
        Table::Webfilter => cfg.url_filters.retain(|f| f.name != key),
        Table::IpsSensor => cfg.ips_profiles.retain(|p| p.name != key),
        Table::Antivirus => cfg.av_profiles.retain(|p| p.name != key),
        Table::Shaper => cfg.shapers.retain(|s| s.name != key),
        Table::Interface => return fail("interfaces cannot be deleted"),
        Table::Global | Table::Vdom => return fail("cannot delete here"),
    }
    let zone_reverted = t == Table::Zone;
    if before == count(cfg) && !zone_reverted {
        return fail(format!("entry not found: {key}"));
    }
    Ok(())
}

fn count(cfg: &Config) -> usize {
    cfg.addresses.len()
        + cfg.address_groups.len()
        + cfg.services.len()
        + cfg.service_groups.len()
        + cfg.app_groups.len()
        + cfg.user_groups.len()
        + cfg.policies.len()
        + cfg.dnat.len()
        + cfg.snat.len()
        + cfg.routes.len()
        + cfg.url_filters.len()
        + cfg.ips_profiles.len()
        + cfg.av_profiles.len()
        + cfg.shapers.len()
}

/// A FortiOS interface-or-zone name → this firewall's zone name.
fn zone_of(cfg: &Config, vdom: &str, name: &str) -> Result<String, String> {
    if name == "any" {
        return Ok("any".into());
    }
    if cfg.interfaces.iter().any(|i| i.vdom == vdom && i.zone == name && i.name != name) {
        return Ok(name.into());
    }
    match cfg.interfaces.iter().find(|i| i.vdom == vdom && i.name == name) {
        Some(i) if i.zone == i.name => Ok(name.into()),
        Some(i) => fail(format!("{name} is a member of zone {}; use the zone", i.zone)),
        None => fail(format!("entry not found in datasource: {name}")),
    }
}

/// FortiOS address names: `all` is any; a name must be an address or group.
fn addr_ref(cfg: &Config, name: &str) -> Result<AddrRef, String> {
    if name == "all" {
        return Ok(AddrRef::Cidr(Cidr::ANY));
    }
    if cfg.addresses.iter().any(|a| a.name == name) || cfg.address_groups.iter().any(|g| g.name == name) {
        return Ok(AddrRef::Named(name.into()));
    }
    fail(format!("entry not found in datasource: {name}"))
}

/// Resolve a FortiOS service name, creating predefined services on first use.
fn service_name(cfg: &mut Config, name: &str) -> Result<String, String> {
    if name == "ALL" {
        return Ok("any".into());
    }
    if cfg.services.iter().any(|s| s.name == name) || cfg.service_groups.iter().any(|g| g.name == name) {
        return Ok(name.into());
    }
    if let Some((_, proto, ports)) = PREDEFINED.iter().find(|(n, _, _)| *n == name) {
        cfg.services.push(ServiceObject { name: name.into(), proto: *proto, ports: parse_port_ranges(ports)? });
        return Ok(name.into());
    }
    fail(format!("entry not found in datasource: {name}"))
}

#[allow(clippy::too_many_arguments)]
fn set_field(cfg: &mut Config, t: Table, key: &str, vdom: &str, field: &str, vals: &[String], unset: bool, append: bool) -> Result<(), String> {
    let first = || vals.first().map(String::as_str).ok_or_else(|| "value parse error before 'eol'".to_string());
    match t {
        Table::Vdom => fail("configure objects inside the vdom with 'config <table>'"),
        Table::Global => unreachable!("handled by caller"),
        Table::Interface => {
            let iface = cfg.interfaces.iter_mut().find(|i| i.name == key).expect("checked on edit");
            match field {
                // FortiOS nests this under "config ipv6"; set directly here.
                "ip6-address" if unset => iface.address6 = None,
                "ip6-address" => iface.address6 = Some(crate::model::Cidr6::parse(first()?)?),
                "ip" if unset => iface.address = None,
                "ip" => iface.address = Some(cidr_from(vals, 0)?),
                "vdom" => iface.vdom = first()?.to_string(),
                "mtu-override" => {}
                "mtu" if unset => iface.mtu = 1500,
                "mtu" => iface.mtu = first()?.parse().map_err(|_| "invalid mtu".to_string())?,
                other => return fail(format!("field '{other}' is not supported on interfaces in this build")),
            }
            Ok(())
        }
        Table::Zone => {
            if field == "intrazone" {
                let action = if unset || first()? == "deny" { Action::Deny } else if first()? == "allow" { Action::Permit } else {
                    return fail("intrazone must be allow or deny");
                };
                return cfg.set_default_rule(DefaultRule { vdom: vdom.into(), kind: DefaultKind::Intrazone, zone: Some(key.into()), action, log: false });
            }
            if field != "interface" {
                return fail(format!("field '{field}' is not supported on zones in this build"));
            }
            for name in vals {
                match cfg.interfaces.iter().find(|i| i.name == *name && i.vdom == vdom) {
                    None => return fail(format!("entry not found in datasource: {name}")),
                    Some(i) if i.zone != i.name && i.zone != key => {
                        return fail(format!("{name} is already a member of zone {}", i.zone))
                    }
                    Some(_) => {}
                }
            }
            for i in cfg.interfaces.iter_mut().filter(|i| i.vdom == vdom) {
                let listed = vals.contains(&i.name);
                if listed && !unset {
                    i.zone = key.to_string();
                } else if i.zone == key && !append {
                    i.zone = i.name.clone();
                }
            }
            Ok(())
        }
        Table::Address => {
            let a = cfg.addresses.iter_mut().find(|a| a.name == key).expect("created");
            match field {
                "subnet" if unset => a.entries = vec![Cidr::ANY],
                "subnet" => a.entries = vec![network(cidr_from(vals, 0)?)],
                // FortiOS keeps IPv6 in "firewall address6"; here one object holds both.
                "ip6" if unset => a.entries6.clear(),
                "ip6" => {
                    a.entries6 = vec![crate::model::Cidr6::parse(first()?)?.network()];
                    if a.entries == vec![Cidr::ANY] {
                        a.entries.clear();
                    }
                }
                "type" if first()? == "ipmask" => {}
                "type" => return fail("only type ipmask is supported"),
                other => return fail(format!("field '{other}' is not supported on addresses in this build")),
            }
            Ok(())
        }
        Table::Addrgrp => {
            if field != "member" {
                return fail(format!("field '{field}' is not supported on address groups"));
            }
            for m in vals {
                addr_ref(cfg, m)?;
            }
            let g = cfg.address_groups.iter_mut().find(|g| g.name == key).expect("created");
            list_update(&mut g.members, vals, unset, append);
            Ok(())
        }
        Table::ServiceCustom => {
            let s = cfg.services.iter_mut().find(|s| s.name == key).expect("created");
            match field {
                "tcp-portrange" | "udp-portrange" => {
                    let proto = if field.starts_with("tcp") { Proto::Tcp } else { Proto::Udp };
                    let mut ports = Vec::new();
                    for v in vals {
                        if v.contains(':') {
                            return fail("source port ranges are not supported");
                        }
                        ports.extend(parse_port_ranges(v)?);
                    }
                    if unset {
                        s.ports.clear();
                    } else if s.ports.is_empty() || s.proto == proto {
                        s.proto = proto;
                        s.ports = ports;
                    } else if s.ports == ports {
                        s.proto = Proto::Any;
                    } else {
                        return fail("this build keeps one port list per service; use equal TCP and UDP ranges or two services");
                    }
                }
                "protocol" => match first()?.to_ascii_uppercase().as_str() {
                    "ICMP" => {
                        s.proto = Proto::Icmp;
                        s.ports.clear();
                    }
                    "TCP/UDP/SCTP" => {}
                    other => return fail(format!("protocol {other} is not supported")),
                },
                other => return fail(format!("field '{other}' is not supported on services in this build")),
            }
            Ok(())
        }
        Table::ServiceGroup => {
            if field != "member" {
                return fail(format!("field '{field}' is not supported on service groups"));
            }
            let mut names = Vec::new();
            for m in vals {
                names.push(service_name(cfg, m)?);
            }
            let g = cfg.service_groups.iter_mut().find(|g| g.name == key).expect("created");
            list_update(&mut g.members, &names, unset, append);
            Ok(())
        }
        Table::UserGroup => {
            if field != "member" {
                return fail(format!("field '{field}' is not supported on user groups"));
            }
            for m in vals {
                crate::model::valid_user_name(m)?;
            }
            let g = cfg.user_groups.iter_mut().find(|g| g.name == key).expect("created");
            list_update(&mut g.members, vals, unset, append);
            Ok(())
        }
        Table::AppGroup => {
            let entries: Vec<String> = match field {
                "application" => vals.to_vec(),
                "category" => vals.iter().map(|c| format!("category:{c}")).collect(),
                other => return fail(format!("field '{other}' is not supported on application groups")),
            };
            for e in &entries {
                if !cfg.app_name_valid(e) {
                    return fail(format!("unknown application or category {e}"));
                }
            }
            let g = cfg.app_groups.iter_mut().find(|g| g.name == key).expect("created");
            let keep_other: Vec<String> = g
                .members
                .iter()
                .filter(|m| (field == "category") != m.starts_with("category:"))
                .cloned()
                .collect();
            if unset {
                g.members = keep_other;
            } else if append {
                list_update(&mut g.members, &entries, false, true);
            } else {
                g.members = keep_other.into_iter().chain(entries).collect();
            }
            Ok(())
        }
        Table::Policy => set_policy(cfg, key, vdom, field, vals, unset, append),
        Table::Vip => {
            let pos = cfg.dnat.iter().position(|d| d.vdom == vdom && d.name.as_deref() == Some(key)).expect("created");
            match field {
                "extip" => cfg.dnat[pos].dst = Cidr::parse(first()?)?,
                "mappedip" => {
                    let ip: Ipv4Addr = first()?.split('-').next().unwrap_or("").parse().map_err(|_| "invalid mappedip".to_string())?;
                    cfg.dnat[pos].to_ip = ip;
                    // Policies name the VIP; they match the translated address.
                    cfg.addresses.retain(|a| a.name != key);
                    cfg.addresses.push(AddressObject { name: key.into(), entries: vec![Cidr { addr: ip, prefix: 32 }], entries6: Vec::new() });
                }
                "extintf" | "portforward" => {}
                "protocol" => cfg.dnat[pos].proto = Proto::parse(&first()?.to_ascii_lowercase())?,
                "extport" => {
                    cfg.dnat[pos].dst_port = if unset { None } else { Some(first()?.parse().map_err(|_| "invalid extport".to_string())?) }
                }
                "mappedport" => {
                    cfg.dnat[pos].to_port = if unset { None } else { Some(first()?.parse().map_err(|_| "invalid mappedport".to_string())?) }
                }
                other => return fail(format!("field '{other}' is not supported on VIPs in this build")),
            }
            Ok(())
        }
        Table::CentralSnat => {
            let id: u32 = key.parse().expect("numeric");
            let zones: Vec<String> = match field {
                "srcintf" | "dstintf" => vals.iter().map(|v| zone_of(cfg, vdom, v)).collect::<Result<_, _>>()?,
                _ => Vec::new(),
            };
            let addrs: Vec<AddrRef> = match field {
                "orig-addr" | "dst-addr" => vals.iter().map(|v| addr_ref(cfg, v)).collect::<Result<_, _>>()?,
                _ => Vec::new(),
            };
            let r = cfg.snat.iter_mut().find(|r| r.id == id).expect("created");
            match field {
                "srcintf" => r.src_zones = zones,
                "dstintf" => r.dst_zones = zones,
                "orig-addr" => r.src = addrs,
                "dst-addr" => r.dst = addrs,
                "nat" if enable(vals, 0)? => r.to = SnatTarget::Masquerade,
                "nat" => return fail("NAT exemption rules are not supported in this build"),
                "status" => r.enabled = enable(vals, 0)?,
                other => return fail(format!("field '{other}' is not supported on central SNAT in this build")),
            }
            Ok(())
        }
        Table::RouterStatic => {
            let r = cfg.routes.iter_mut().find(|r| r.vdom == vdom && r.name.as_deref() == Some(key)).expect("created");
            match field {
                "dst" => r.dst = if unset { Cidr::ANY } else { network(cidr_from(vals, 0)?) },
                "gateway" => r.via = if unset { None } else { Some(first()?.parse().map_err(|_| "invalid gateway".to_string())?) },
                "device" => r.interface = first()?.to_string(),
                "distance" => r.distance = first()?.parse().map_err(|_| "invalid distance".to_string())?,
                other => return fail(format!("field '{other}' is not supported on static routes in this build")),
            }
            Ok(())
        }
        Table::Webfilter => {
            let f = cfg.url_filters.iter_mut().find(|f| f.name == key).expect("created");
            match field {
                "block-category" => {
                    let cats: Vec<String> = vals.iter().map(|c| format!("category:{c}")).collect();
                    f.block.retain(|b| !b.starts_with("category:"));
                    if !unset {
                        f.block.extend(cats);
                    }
                }
                "block-domain" => {
                    f.block.retain(|b| b.starts_with("category:"));
                    if !unset {
                        f.block.extend(vals.iter().cloned());
                    }
                }
                "allow-domain" => list_update(&mut f.allow, vals, unset, append),
                other => return fail(format!("field '{other}' is not supported on web filter profiles in this build")),
            }
            Ok(())
        }
        Table::IpsSensor | Table::Antivirus => {
            let list = if t == Table::IpsSensor { &mut cfg.ips_profiles } else { &mut cfg.av_profiles };
            let p = list.iter_mut().find(|p| p.name == key).expect("created");
            match field {
                "signature" => list_update(&mut p.patterns, vals, unset, append),
                other => return fail(format!("field '{other}' is not supported (use set signature \"<pattern>\")")),
            }
            Ok(())
        }
        Table::Shaper => {
            let s = cfg.shapers.iter_mut().find(|s| s.name == key).expect("created");
            match field {
                "maximum-bandwidth" => s.kbps = first()?.parse().map_err(|_| "invalid bandwidth".to_string())?,
                "bandwidth-unit" if first()? == "kbps" => {}
                other => return fail(format!("field '{other}' is not supported on shapers in this build")),
            }
            Ok(())
        }
    }
}

fn list_update(list: &mut Vec<String>, vals: &[String], unset: bool, append: bool) {
    if unset {
        list.clear();
    } else if append {
        for v in vals {
            if !list.contains(v) {
                list.push(v.clone());
            }
        }
    } else {
        *list = vals.to_vec();
    }
}

fn set_policy(cfg: &mut Config, key: &str, vdom: &str, field: &str, vals: &[String], unset: bool, append: bool) -> Result<(), String> {
    let id: u32 = key.parse().expect("numeric");
    let pos = cfg.policies.iter().position(|p| p.id == id && p.vdom == vdom).expect("created");
    let first = || vals.first().map(String::as_str).ok_or_else(|| "value parse error before 'eol'".to_string());
    match field {
        "srcintf" | "dstintf" => {
            let zones: Vec<String> = vals.iter().map(|v| zone_of(cfg, vdom, v)).collect::<Result<_, _>>()?;
            let p = &mut cfg.policies[pos];
            let list = if field == "srcintf" { &mut p.src_zones } else { &mut p.dst_zones };
            list_update(list, &zones, unset, append);
        }
        "srcaddr" | "dstaddr" => {
            let addrs: Vec<AddrRef> = vals.iter().map(|v| addr_ref(cfg, v)).collect::<Result<_, _>>()?;
            let p = &mut cfg.policies[pos];
            let list = if field == "srcaddr" { &mut p.src } else { &mut p.dst };
            if unset {
                list.clear();
            } else if append {
                list.extend(addrs);
            } else {
                *list = addrs;
            }
        }
        "srcaddr-negate" => cfg.policies[pos].negate_src = !unset && enable(vals, 0)?,
        "dstaddr-negate" => cfg.policies[pos].negate_dst = !unset && enable(vals, 0)?,
        "service" => {
            let names: Vec<String> = vals.iter().map(|v| service_name(cfg, v)).collect::<Result<_, _>>()?;
            let p = &mut cfg.policies[pos];
            p.proto = Proto::Any;
            p.dst_port = None;
            list_update(&mut p.services, &names, unset, append);
            if p.services.iter().any(|s| s == "any") {
                p.services.clear();
            }
        }
        "application" | "app-category" => {
            let entries: Vec<String> = if field == "application" {
                vals.to_vec()
            } else {
                vals.iter().map(|c| format!("category:{c}")).collect()
            };
            for e in &entries {
                if !cfg.app_name_valid(e) {
                    return fail(format!("unknown application or category {e}"));
                }
            }
            let p = &mut cfg.policies[pos];
            let is_cat = field == "app-category";
            let others: Vec<String> = p.apps.iter().filter(|a| a.starts_with("category:") != is_cat).cloned().collect();
            if unset {
                p.apps = others;
            } else if append {
                list_update(&mut p.apps, &entries, false, true);
            } else {
                p.apps = others.into_iter().chain(entries).collect();
            }
        }
        "users" | "groups" => {
            let is_group = |n: &str| cfg.user_groups.iter().any(|g| g.name == n);
            for v in vals {
                crate::model::valid_user_name(v)?;
                if field == "groups" && !is_group(v) {
                    return fail(format!("entry not found in datasource: user group {v}"));
                }
            }
            let keep: Vec<String> = cfg.policies[pos].users.iter().filter(|u| is_group(u) != (field == "groups")).cloned().collect();
            let p = &mut cfg.policies[pos];
            if unset {
                p.users = keep;
            } else if append {
                list_update(&mut p.users, vals, false, true);
            } else {
                p.users = keep.into_iter().chain(vals.iter().cloned()).collect();
            }
        }
        "av-profile" | "ips-sensor" | "webfilter-profile" | "traffic-shaper" => {
            let value = if unset { None } else { Some(first()?.to_string()) };
            let p = &mut cfg.policies[pos];
            match field {
                "av-profile" => p.av = value,
                "ips-sensor" => p.ips = value,
                "webfilter-profile" => p.url = value,
                _ => p.shaper = value,
            }
        }
        _ => {
            let p = &mut cfg.policies[pos];
            match field {
                "name" => p.name = if unset { None } else { Some(first()?.replace(' ', "-")) },
                "action" => {
                    p.action = match first()? {
                        "accept" => Action::Permit,
                        "deny" if p.action == Action::Reject => Action::Reject,
                        "deny" => Action::Deny,
                        other => return fail(format!("invalid action {other} (accept or deny)")),
                    }
                }
                "send-deny-packet" => {
                    if enable(vals, 0)? {
                        p.action = Action::Reject;
                    } else if p.action == Action::Reject {
                        p.action = Action::Deny;
                    }
                }
                "nat" => p.nat = !unset && enable(vals, 0)?,
                "status" => p.enabled = unset || enable(vals, 0)?,
                "logtraffic" => p.log = !unset && first()? != "disable",
                "schedule" if unset || first()? == "always" => {}
                "schedule" => return fail("only the 'always' schedule is supported"),
                "utm-status" | "inspection-mode" | "profile-type" | "ssl-ssh-profile" => {}
                "groups" | "users" => unreachable!("handled above"),
                other => return fail(format!("field '{other}' is not supported on policies in this build")),
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------------- rendering

fn render_table(cfg: &Config, t: Table, vdom: &str, only: Option<&str>) -> String {
    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    let quoted_key = !matches!(t, Table::Policy | Table::CentralSnat | Table::RouterStatic);
    match t {
        Table::Global => {
            return format!("config system global\n    set hostname {}\nend\n", q(&cfg.settings.hostname));
        }
        Table::Vdom => return String::new(),
        Table::Interface => {
            for i in &cfg.interfaces {
                let mut f = vec![format!("vdom {}", q(&i.vdom))];
                if let Some(a) = i.address {
                    f.push(format!("ip {}", subnet_text(&a)));
                }
                if let Some(a) = i.address6 {
                    f.push(format!("ip6-address {a}"));
                }
                if i.mtu != 1500 {
                    f.push("mtu-override enable".into());
                    f.push(format!("mtu {}", i.mtu));
                }
                entries.push((i.name.clone(), f));
            }
        }
        Table::Zone => {
            let mut zones: Vec<String> = cfg
                .interfaces
                .iter()
                .filter(|i| i.vdom == vdom && i.zone != i.name)
                .map(|i| i.zone.clone())
                .collect();
            zones.sort();
            zones.dedup();
            for z in zones {
                let members: Vec<String> = cfg.interfaces.iter().filter(|i| i.vdom == vdom && i.zone == z).map(|i| i.name.clone()).collect();
                let intrazone = cfg
                    .default_rules
                    .iter()
                    .find(|r| r.vdom == vdom && r.zone.as_deref() == Some(z.as_str()))
                    .map(|r| r.action == Action::Permit)
                    .unwrap_or(false);
                entries.push((z, vec![format!("intrazone {}", if intrazone { "allow" } else { "deny" }), format!("interface {}", quote_all(&members))]));
            }
        }
        Table::Address => {
            for a in &cfg.addresses {
                if cfg.dnat.iter().any(|d| d.name.as_deref() == Some(a.name.as_str())) {
                    continue; // shown as a VIP
                }
                let mut f: Vec<String> = a.entries.first().map(|c| vec![format!("subnet {}", subnet_text(c))]).unwrap_or_default();
                if let Some(c) = a.entries6.first() {
                    f.push(format!("ip6 {c}"));
                }
                entries.push((a.name.clone(), f));
            }
        }
        Table::Addrgrp => {
            for g in &cfg.address_groups {
                entries.push((g.name.clone(), vec![format!("member {}", quote_all(&g.members))]));
            }
        }
        Table::ServiceCustom => {
            for s in &cfg.services {
                let f = match s.proto {
                    Proto::Icmp => vec!["protocol ICMP".to_string()],
                    Proto::Udp => vec![format!("udp-portrange {}", s.ports_text().replace(',', " "))],
                    Proto::Any => vec![
                        format!("tcp-portrange {}", s.ports_text().replace(',', " ")),
                        format!("udp-portrange {}", s.ports_text().replace(',', " ")),
                    ],
                    _ => vec![format!("tcp-portrange {}", s.ports_text().replace(',', " "))],
                };
                entries.push((s.name.clone(), f));
            }
        }
        Table::ServiceGroup => {
            for g in &cfg.service_groups {
                entries.push((g.name.clone(), vec![format!("member {}", quote_all(&g.members))]));
            }
        }
        Table::AppGroup => {
            for g in &cfg.app_groups {
                entries.push((g.name.clone(), app_fields(&g.members, "application", "category")));
            }
        }
        Table::UserGroup => {
            for g in &cfg.user_groups {
                entries.push((g.name.clone(), vec![format!("member {}", quote_all(&g.members))]));
            }
        }
        Table::Policy => {
            for p in cfg.policies.iter().filter(|p| p.vdom == vdom) {
                entries.push((p.id.to_string(), policy_fields(cfg, p)));
            }
        }
        Table::Vip => {
            for d in cfg.dnat.iter().filter(|d| d.vdom == vdom) {
                let mut f = vec![format!("extip {}", d.dst.addr), format!("mappedip {}", q(&d.to_ip.to_string()))];
                if let (Some(ext), Some(mapped)) = (d.dst_port, d.to_port) {
                    f.push("portforward enable".into());
                    if d.proto != Proto::Any {
                        f.push(format!("protocol {}", d.proto));
                    }
                    f.push(format!("extport {ext}"));
                    f.push(format!("mappedport {mapped}"));
                }
                let name = d.name.clone().unwrap_or_else(|| format!("dnat-{}", d.id));
                entries.push((name, f));
            }
        }
        Table::CentralSnat => {
            for r in cfg.snat.iter().filter(|r| r.vdom == vdom) {
                let mut f = vec![
                    format!("srcintf {}", quote_all(&r.src_zones)),
                    format!("dstintf {}", quote_all(&r.dst_zones)),
                    format!("orig-addr {}", addr_names(&r.src)),
                    format!("dst-addr {}", addr_names(&r.dst)),
                    "nat enable".into(),
                ];
                if !r.enabled {
                    f.push("status disable".into());
                }
                entries.push((r.id.to_string(), f));
            }
        }
        Table::RouterStatic => {
            for (n, r) in cfg.routes.iter().filter(|r| r.vdom == vdom).enumerate() {
                let mut f = Vec::new();
                if r.dst != Cidr::ANY {
                    f.push(format!("dst {}", subnet_text(&r.dst)));
                }
                if let Some(v) = r.via {
                    f.push(format!("gateway {v}"));
                }
                f.push(format!("device {}", q(&r.interface)));
                if r.distance != 10 {
                    f.push(format!("distance {}", r.distance));
                }
                entries.push((r.name.clone().unwrap_or_else(|| (n + 1).to_string()), f));
            }
        }
        Table::Webfilter => {
            for w in &cfg.url_filters {
                let cats: Vec<String> = w.block.iter().filter_map(|b| b.strip_prefix("category:").map(str::to_string)).collect();
                let doms: Vec<String> = w.block.iter().filter(|b| !b.starts_with("category:")).cloned().collect();
                let mut f = Vec::new();
                if !cats.is_empty() {
                    f.push(format!("block-category {}", quote_all(&cats)));
                }
                if !doms.is_empty() {
                    f.push(format!("block-domain {}", quote_all(&doms)));
                }
                if !w.allow.is_empty() {
                    f.push(format!("allow-domain {}", quote_all(&w.allow)));
                }
                entries.push((w.name.clone(), f));
            }
        }
        Table::IpsSensor | Table::Antivirus => {
            let list = if t == Table::IpsSensor { &cfg.ips_profiles } else { &cfg.av_profiles };
            for p in list {
                let f = if p.patterns.is_empty() { Vec::new() } else { vec![format!("signature {}", quote_all(&p.patterns))] };
                entries.push((p.name.clone(), f));
            }
        }
        Table::Shaper => {
            for s in &cfg.shapers {
                entries.push((s.name.clone(), vec![format!("maximum-bandwidth {}", s.kbps), "bandwidth-unit kbps".into()]));
            }
        }
    }
    if let Some(key) = only {
        entries.retain(|(k, _)| k == key);
    }
    let mut out = format!("config {}\n", t.path());
    for (key, fields) in entries {
        if quoted_key {
            out.push_str(&format!("    edit {}\n", q(&key)));
        } else {
            out.push_str(&format!("    edit {key}\n"));
        }
        for f in fields {
            out.push_str(&format!("        set {f}\n"));
        }
        out.push_str("    next\n");
    }
    out.push_str("end\n");
    out
}

fn addr_names(list: &[AddrRef]) -> String {
    list.iter()
        .map(|a| match a {
            AddrRef::Cidr(c) if *c == Cidr::ANY => q("all"),
            AddrRef::Cidr(c) => q(&c.to_string()),
            AddrRef::Cidr6(c) => q(&c.to_string()),
            AddrRef::Named(n) => q(n),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn app_fields(entries: &[String], app_field: &str, cat_field: &str) -> Vec<String> {
    let apps: Vec<String> = entries.iter().filter(|a| !a.starts_with("category:")).cloned().collect();
    let cats: Vec<String> = entries.iter().filter_map(|a| a.strip_prefix("category:").map(str::to_string)).collect();
    let mut f = Vec::new();
    if !apps.is_empty() {
        f.push(format!("{app_field} {}", quote_all(&apps)));
    }
    if !cats.is_empty() {
        f.push(format!("{cat_field} {}", quote_all(&cats)));
    }
    f
}

fn policy_fields(cfg: &Config, p: &Policy) -> Vec<String> {
    let mut f = Vec::new();
    if let Some(n) = &p.name {
        f.push(format!("name {}", q(n)));
    }
    f.push(format!("srcintf {}", quote_all(&p.src_zones)));
    f.push(format!("dstintf {}", quote_all(&p.dst_zones)));
    f.push(format!("srcaddr {}", addr_names(&p.src)));
    if p.negate_src {
        f.push("srcaddr-negate enable".into());
    }
    f.push(format!("dstaddr {}", addr_names(&p.dst)));
    if p.negate_dst {
        f.push("dstaddr-negate enable".into());
    }
    f.push(format!("action {}", if p.action == Action::Permit { "accept" } else { "deny" }));
    if p.action == Action::Reject {
        f.push("send-deny-packet enable".into());
    }
    f.push(format!("schedule {}", q("always")));
    let service = if !p.services.is_empty() {
        quote_all(&p.services)
    } else if p.proto == Proto::Any && p.dst_port.is_none() {
        q("ALL")
    } else {
        // An inline protocol/port from the native language.
        q(&format!("{}/{}", p.proto, p.dst_port.map(|x| x.to_string()).unwrap_or_else(|| "any".into())))
    };
    f.push(format!("service {service}"));
    f.extend(app_fields(&p.apps, "application", "app-category"));
    let (groups, users): (Vec<String>, Vec<String>) = p.users.iter().cloned().partition(|u| cfg.user_groups.iter().any(|g| &g.name == u));
    if !users.is_empty() {
        f.push(format!("users {}", quote_all(&users)));
    }
    if !groups.is_empty() {
        f.push(format!("groups {}", quote_all(&groups)));
    }
    let utm = p.url.is_some() || p.ips.is_some() || p.av.is_some() || p.group.is_some();
    if utm {
        f.push("utm-status enable".into());
    }
    if let Some(v) = &p.av {
        f.push(format!("av-profile {}", q(v)));
    }
    if let Some(v) = &p.ips {
        f.push(format!("ips-sensor {}", q(v)));
    }
    if let Some(v) = &p.url {
        f.push(format!("webfilter-profile {}", q(v)));
    }
    if let Some(v) = &p.shaper {
        f.push(format!("traffic-shaper {}", q(v)));
    }
    if p.log {
        f.push("logtraffic all".into());
    } else {
        f.push("logtraffic disable".into());
    }
    if p.nat {
        f.push("nat enable".into());
    }
    if !p.enabled {
        f.push("status disable".into());
    }
    let _ = addr_list_text;
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::testing::{run, Mem};
    use crate::style::Store;

    const BASE: &str = "\
system hostname FGT-LAB
interface port1 zone port1 address 10.0.0.1/24
interface port2 zone port2 address 203.0.113.2/24
interface port3 zone port3 address 10.1.0.1/24
";

    #[test]
    fn policy_with_predefined_services_and_nat() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        assert_eq!(s.prompt("FGT-LAB"), "FGT-LAB # ");
        let out = run(&mut s, &store, r#"
            config firewall policy
                edit 0
                    set name "lan out"
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "HTTPS" "DNS"
                    set action accept
                    set nat enable
                next
            end
        "#);
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        let cfg = store.running();
        let p = &cfg.policies[0];
        assert_eq!((p.id, p.name.as_deref(), p.nat), (1, Some("lan-out"), true));
        assert_eq!(p.services, vec!["HTTPS", "DNS"]);
        assert!(cfg.match_policy("root", "port1", "port2", "10.0.0.5".parse().unwrap(), "8.8.8.8".parse().unwrap(), 17, 53, None).is_some());
        assert!(cfg.match_policy("root", "port1", "port2", "10.0.0.5".parse().unwrap(), "8.8.8.8".parse().unwrap(), 6, 22, None).is_none());

        let shown = s.exec("show firewall policy 1", &crate::style::Ctx { store: &store, can_write: true });
        assert!(shown.contains("    edit 1\n        set name \"lan-out\"\n        set srcintf \"port1\""), "{shown}");
        assert!(shown.contains("set service \"HTTPS\" \"DNS\""), "{shown}");
    }

    #[test]
    fn zones_change_membership_and_policies_use_them() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        run(&mut s, &store, r#"
            config system zone
                edit "inside"
                    set interface "port1" "port3"
                next
            end
        "#);
        let cfg = store.running();
        assert_eq!(cfg.interfaces.iter().filter(|i| i.zone == "inside").count(), 2);
        let out = run(&mut s, &store, "config firewall policy\nedit 7\nset srcintf port1");
        assert!(out[2].contains("member of zone inside"), "{out:?}");
        let out = run(&mut s, &store, "set srcintf inside\nset dstintf port2\nset srcaddr all\nset dstaddr all\nset action accept\nnext\nend");
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        assert_eq!(store.running().policies[0].src_zones, vec!["inside"]);
    }

    #[test]
    fn missing_required_fields_reject_the_entry() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, "config firewall policy\nedit 3\nset srcintf port1\nnext");
        assert!(out[3].contains("dstintf must be set"), "{out:?}");
        assert!(store.running().policies.is_empty());
        // As on FortiOS, the entry stays open so it can be fixed.
        assert_eq!(s.prompt("FGT"), "FGT (3) # ");
        let out = run(&mut s, &store, "set dstintf port2\nset srcaddr all\nset dstaddr all\nnext\nend");
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        assert_eq!(store.running().policies[0].id, 3);
    }

    #[test]
    fn application_control_and_utm_profiles() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, r#"
            config webfilter profile
                edit "corp"
                    set block-category "gambling"
                    set block-domain "evil.test"
                next
            end
            config firewall policy
                edit 10
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "ALL"
                    set action deny
                    set app-category "social-networking"
                    set application "bittorrent"
                next
                edit 20
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "ALL"
                    set action accept
                    set utm-status enable
                    set webfilter-profile "corp"
                next
            end
        "#);
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        let cfg = store.running();
        assert_eq!(cfg.policies[0].apps, vec!["category:social-networking", "bittorrent"]);
        assert!(cfg.url_filter("corp").unwrap().blocked("bet365.com"));
        let hit = |app| cfg.match_policy("root", "port1", "port2", "10.0.0.5".parse().unwrap(), "8.8.8.8".parse().unwrap(), 6, 443, Some(app)).map(|p| p.id);
        assert_eq!(hit("facebook"), Some(10));
        assert_eq!(hit("github"), Some(20));
    }

    #[test]
    fn vip_and_central_snat() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, r#"
            config firewall vip
                edit "web-vip"
                    set extip 203.0.113.2
                    set mappedip "10.1.0.10"
                    set portforward enable
                    set protocol tcp
                    set extport 8080
                    set mappedport 80
                next
            end
            config firewall central-snat-map
                edit 1
                    set srcintf "port1"
                    set dstintf "port2"
                    set orig-addr "all"
                    set dst-addr "all"
                    set nat enable
                next
            end
            config firewall policy
                edit 30
                    set srcintf "port2"
                    set dstintf "port3"
                    set srcaddr "all"
                    set dstaddr "web-vip"
                    set service "HTTP"
                    set action accept
                next
            end
        "#);
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        let cfg = store.running();
        let d = cfg.dnat_match("root", 6, "203.0.113.2".parse().unwrap(), 8080).unwrap();
        assert_eq!((d.to_ip.to_string(), d.to_port), ("10.1.0.10".to_string(), Some(80)));
        assert!(cfg.snat_match("root", "port1", "port2", "10.0.0.9".parse().unwrap(), "1.1.1.1".parse().unwrap()).is_some());
        let p = cfg.match_policy("root", "port2", "port3", "198.51.100.7".parse().unwrap(), "10.1.0.10".parse().unwrap(), 6, 80, None);
        assert_eq!(p.map(|p| p.id), Some(30));
    }

    #[test]
    fn static_routes_vdoms_and_lookup() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        run(&mut s, &store, r#"
            config router static
                edit 1
                    set gateway 203.0.113.1
                    set device "port2"
                next
                edit 2
                    set dst 172.16.0.0 255.240.0.0
                    set gateway 10.1.0.254
                    set device "port3"
                next
            end
            config firewall policy
                edit 5
                    set srcintf "port1"
                    set dstintf "port3"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "SSH"
                    set action accept
                next
            end
        "#);
        let ctx = crate::style::Ctx { store: &store, can_write: true };
        let rt = s.exec("get router info routing-table all", &ctx);
        assert!(rt.contains("S       172.16.0.0/12 [10/0] via 10.1.0.254, port3"), "{rt}");
        let hit = s.exec("diagnose firewall iprope lookup 10.0.0.5 5555 172.16.1.1 22 tcp port1", &ctx);
        assert!(hit.contains("matches policy id: 5"), "{hit}");
        let miss = s.exec("diagnose firewall iprope lookup 10.0.0.5 5555 172.16.1.1 80 tcp port1", &ctx);
        assert!(miss.contains("implicit deny"), "{miss}");
    }

    #[test]
    fn user_groups_in_policies() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, r#"
            config user group
                edit "admins"
                    set member "alice" "bob"
                next
            end
            config firewall policy
                edit 9
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "SSH"
                    set action accept
                    set groups "admins"
                    set users "carol"
                next
            end
        "#);
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        let cfg = store.running();
        assert_eq!(cfg.policies[0].users, vec!["admins", "carol"]);
        let m = |u| cfg.match_policy_user("root", "port1", "port2", "10.0.0.5".parse().unwrap(), "1.1.1.1".parse().unwrap(), 6, 22, None, u).map(|p| p.id);
        assert_eq!(m(Some("bob")), Some(9));
        assert_eq!(m(Some("carol")), Some(9));
        assert_eq!(m(Some("eve")), None);
        let ctx = crate::style::Ctx { store: &store, can_write: true };
        let shown = s.exec("show firewall policy 9", &ctx);
        assert!(shown.contains("set users \"carol\"") && shown.contains("set groups \"admins\""), "{shown}");
        assert!(run(&mut s, &store, "config firewall policy\nedit 9\nset groups nope")[2].contains("entry not found"));
    }

    #[test]
    fn zone_intrazone_allow() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, "config system zone\nedit inside\nset interface port1 port3\nset intrazone allow\nnext\nend");
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        let ctx = crate::style::Ctx { store: &store, can_write: true };
        let hit = s.exec("diagnose firewall iprope lookup 10.0.0.5 5555 10.1.0.9 22 tcp port1", &ctx);
        assert!(hit.contains("intrazone-default:inside (allow)"), "{hit}");
        assert!(s.exec("show system zone", &ctx).contains("set intrazone allow"));
    }

    #[test]
    fn interface_ipv6_address() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let out = run(&mut s, &store, "config system interface\nedit port1\nset ip6-address 2001:db8:1::1/64\nnext\nend");
        assert!(out.iter().all(|o| o.is_empty()), "{out:?}");
        assert_eq!(store.running().interfaces[0].address6.unwrap().to_string(), "2001:db8:1::1/64");
    }

    #[test]
    fn read_only_admin_cannot_change_config() {
        let store = Mem::new(BASE);
        let mut s = FortiOs::new();
        let ctx = crate::style::Ctx { store: &store, can_write: false };
        assert!(s.exec("config firewall policy", &ctx).is_empty());
        assert!(s.exec("edit 0", &ctx).contains("Permission denied"));
        assert!(s.exec("show", &ctx).contains("config firewall policy"));
    }
}
