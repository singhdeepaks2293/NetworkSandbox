//! PAN-OS-style CLI.
//!
//! ```text
//! admin@PA-LAB> configure
//! admin@PA-LAB# set zone trust network layer3 ethernet1/1
//! admin@PA-LAB# set rulebase security rules allow-web from trust to untrust source any destination any application [ ssl web-browsing ] service application-default action allow
//! admin@PA-LAB# set rulebase nat rules outbound from trust to untrust source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/2
//! admin@PA-LAB# commit
//! Configuration committed successfully
//! admin@PA-LAB# run test security-policy-match from trust to untrust source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 443 application ssl
//! ```
//!
//! Operational mode (`>`) and configuration mode (`#`). `set`, `delete`,
//! `move` and `rename` edit a candidate configuration that only takes effect
//! on `commit`; a failed commit keeps the candidate. `vsys1` is this
//! firewall's `root` VDOM; `set vsys <name> ...` works in another VDOM.
//!
//! Lightweight differences from PAN-OS: there are no default intrazone/
//! interzone rules (traffic no rule allows is denied); vulnerability and virus
//! profiles take literal signatures; a NAT rule's service may be written as
//! `tcp/8080`; the `ping` and `icmp` applications stand in for ICMP services.

use super::{next_policy_id, table, tokenize, Ctx, Style};
use crate::model::{
    parse_port_ranges, Action, DefaultKind, DefaultRule, AddrRef, AddressGroup, AddressObject, AppGroup, Cidr, Config, DnatRule, Policy, ProfileGroup,
    Proto, Route, ServiceGroup, ServiceObject, SignatureProfile, SnatRule, SnatTarget, UrlFilter, APPLICATION_DEFAULT,
};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Operational,
    Configure,
}

pub struct PanOs {
    mode: Mode,
    candidate: Option<Config>,
    /// Running revision the candidate was copied from.
    base: u64,
}

impl PanOs {
    pub fn new() -> PanOs {
        PanOs { mode: Mode::Operational, candidate: None, base: 0 }
    }
}

type R = Result<String, String>;

fn fail<T>(msg: impl Into<String>) -> Result<T, String> {
    Err(msg.into())
}

fn at(w: &[String], i: usize) -> Result<&str, String> {
    w.get(i).map(String::as_str).ok_or_else(|| "Invalid syntax.".to_string())
}

fn expect(w: &[String], i: usize, word: &str) -> Result<(), String> {
    match w.get(i) {
        Some(x) if x == word => Ok(()),
        Some(x) => fail(format!("Invalid syntax: expected '{word}', got '{x}'")),
        None => fail(format!("Invalid syntax: expected '{word}'")),
    }
}

/// `[ a b ]` or a single word at `w[i]`; returns the values and the next index.
fn list(w: &[String], i: usize) -> Result<(Vec<String>, usize), String> {
    match w.get(i).map(String::as_str) {
        Some("[") => {
            let end = w[i..].iter().position(|x| x == "]").ok_or("Invalid syntax: missing ']'")? + i;
            Ok((w[i + 1..end].to_vec(), end + 1))
        }
        Some(x) => Ok((vec![x.to_string()], i + 1)),
        None => fail("Invalid syntax: missing value"),
    }
}

fn yes(v: &str) -> Result<bool, String> {
    match v {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => fail(format!("Invalid value '{other}' (yes or no)")),
    }
}

fn vsys_to_vdom(vsys: &str) -> String {
    if vsys == "vsys1" { "root".into() } else { vsys.into() }
}

fn vdom_to_vsys(vdom: &str) -> String {
    if vdom == "root" { "vsys1".into() } else { vdom.into() }
}

/// PAN-OS URL category names → this firewall's built-in URL categories.
fn url_category(name: &str) -> Option<&'static str> {
    match name {
        "gambling" => Some("gambling"),
        "social-networking" => Some("social"),
        "adult" => Some("adult"),
        "malware" => Some("malware"),
        "phishing" => Some("phishing"),
        "streaming-media" => Some("streaming"),
        _ => None,
    }
}

fn url_category_back(native: &str) -> String {
    match native {
        "social" => "social-networking".into(),
        "streaming" => "streaming-media".into(),
        other => other.into(),
    }
}

fn addr(name: &str) -> Result<AddrRef, String> {
    if name == "any" {
        Ok(AddrRef::Cidr(Cidr::ANY))
    } else if name.contains(':') || name.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        AddrRef::parse(name)
    } else {
        Ok(AddrRef::Named(name.into()))
    }
}

fn rule_pos(cfg: &Config, vdom: &str, name: &str) -> Option<usize> {
    cfg.policies.iter().position(|p| p.vdom == vdom && p.name.as_deref().map_or(p.id.to_string() == name, |n| n == name))
}

fn rule_name(p: &Policy) -> String {
    p.name.clone().unwrap_or_else(|| p.id.to_string())
}

impl Style for PanOs {
    fn name(&self) -> &'static str {
        "panos"
    }

    fn prompt(&self, hostname: &str) -> String {
        match self.mode {
            Mode::Operational => format!("admin@{hostname}> "),
            Mode::Configure => format!("admin@{hostname}# "),
        }
    }

    fn exec(&mut self, line: &str, ctx: &Ctx<'_>) -> String {
        let w = match tokenize(line.trim()) {
            Ok(w) => w,
            Err(e) => return format!("Invalid syntax: {e}"),
        };
        if w.is_empty() {
            return String::new();
        }
        let result = match self.mode {
            Mode::Operational => self.operational(&w, ctx),
            Mode::Configure => self.configure(&w, ctx),
        };
        result.unwrap_or_else(|e| e)
    }
}

impl PanOs {
    fn operational(&mut self, w: &[String], ctx: &Ctx<'_>) -> R {
        match w[0].as_str() {
            "configure" => {
                if !ctx.can_write {
                    return fail("Server error: permission denied (read-only administrator)");
                }
                self.mode = Mode::Configure;
                if self.candidate.is_none() {
                    let fresh = self.begin(ctx);
                    self.candidate = Some(fresh);
                }
                Ok("Entering configuration mode".into())
            }
            "show" => self.op_show(&w[1..], ctx),
            "test" => self.test_match(&w[1..], ctx),
            "request" => {
                if !ctx.can_write {
                    return fail("Server error: permission denied (read-only administrator)");
                }
                match w.iter().skip(1).map(String::as_str).collect::<Vec<_>>().as_slice() {
                    ["high-availability", "state", "suspend"] => ctx.store.ha_suspend(true).map(|()| "Successfully changed HA state to suspended".into()),
                    ["high-availability", "state", "functional"] => ctx.store.ha_suspend(false).map(|()| "Successfully changed HA state to functional".into()),
                    ["user-id", "login", "user", user, "ip", ip, rest @ ..] => {
                        let ip = ip.parse().map_err(|_| "invalid ip".to_string())?;
                        let timeout = match rest {
                            [] => None,
                            ["timeout", secs] => Some(secs.parse().map_err(|_| "invalid timeout".to_string())?),
                            _ => return fail("Invalid syntax."),
                        };
                        ctx.store.user_login(ip, user, timeout)?;
                        Ok(format!("ip-user-mapping {ip} -> {user} added"))
                    }
                    ["user-id", "logout", "ip", ip] => {
                        let ip = ip.parse().map_err(|_| "invalid ip".to_string())?;
                        Ok(if ctx.store.user_logout(ip) { format!("ip-user-mapping for {ip} removed") } else { format!("no mapping for {ip}") })
                    }
                    _ => fail("Unknown command: request user-id login user <u> ip <ip> [timeout <s>] | request user-id logout ip <ip>"),
                }
            }
            "exit" | "quit" => Ok(String::new()),
            other => fail(format!("Unknown command: {other}")),
        }
    }

    fn op_show(&self, w: &[String], ctx: &Ctx<'_>) -> R {
        let running = ctx.store.running();
        match w.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            ["config", "running", rest @ ..] => Ok(filter(&render(&running), rest)),
            ["config", "candidate", rest @ ..] => Ok(filter(&render(self.candidate.as_ref().unwrap_or(&running)), rest)),
            ["applications"] => Ok(crate::appid::catalog_text(None)),
            ["applications", filter] => Ok(crate::appid::catalog_text(Some(filter))),
            ["system", "info"] => Ok(format!(
                "hostname: {}\nmodel: NetworkSandbox NGFW (PAN-OS-style CLI)\nmulti-vsys: {}\nvsys: {}\nsecurity rules: {}\nsessions: {}\n",
                running.settings.hostname,
                if running.vdoms.len() > 1 { "on" } else { "off" },
                running.vdoms.iter().map(|v| vdom_to_vsys(v)).collect::<Vec<_>>().join(", "),
                running.policies.len(),
                ctx.store.sessions().len()
            )),
            ["high-availability", "state"] | ["high-availability", "all"] => Ok(ctx.store.ha_status()),
            ["user", "ip-user-mapping", "all"] => {
                let rows: Vec<Vec<String>> = ctx
                    .store
                    .user_mappings()
                    .into_iter()
                    .map(|(ip, user, source, left)| vec![ip, user, source.to_string(), left.map(|s| s.to_string()).unwrap_or_else(|| "Never".into())])
                    .collect();
                Ok(table(&["IP", "User", "From", "Timeout(s)"], &rows))
            }
            ["interface", "all"] => {
                let rows: Vec<Vec<String>> = running
                    .interfaces
                    .iter()
                    .map(|i| vec![i.name.clone(), vdom_to_vsys(&i.vdom), i.zone.clone(), i.address.map(|a| a.to_string()).unwrap_or_else(|| "N/A".into())])
                    .collect();
                Ok(table(&["name", "vsys", "zone", "address"], &rows))
            }
            ["running", "security-policy"] => {
                let hits = ctx.store.hits();
                let mut out = String::new();
                let mut rules: Vec<&Policy> = running.policies.iter().collect();
                rules.sort_by_key(|p| (p.vdom.clone(), p.id));
                rules.extend(running.default_policies.iter().filter(|d| d.src_zones == ["any"]));
                for (n, p) in rules.iter().enumerate() {
                    let (packets, bytes, _) = hits.get(&(p.vdom.clone(), p.id)).copied().unwrap_or((0, 0, 0));
                    out.push_str(&format!(
                        "\"{}; index: {}\" {{\n        from {};\n        source {};\n        source-user {};\n        to {};\n        destination {};\n        application {};\n        service {};\n        action {};\n        hits {} packets / {} bytes;\n}}\n",
                        rule_name(p),
                        n + 1,
                        p.src_zones.join(" "),
                        addr_names(&p.src, p.negate_src),
                        if p.users.is_empty() { "any".to_string() } else { p.users.join(" ") },
                        p.dst_zones.join(" "),
                        addr_names(&p.dst, p.negate_dst),
                        if p.apps.is_empty() { "any".to_string() } else { p.apps.join(" ") },
                        service_names(p).join(" "),
                        action_name(p.action),
                        packets,
                        bytes
                    ));
                }
                Ok(out)
            }
            ["session", "all"] => {
                let rows: Vec<Vec<String>> = ctx
                    .store
                    .sessions()
                    .into_iter()
                    .map(|s| {
                        let rule = running
                            .policy_by_id(&s.key.vdom, s.policy_id)
                            .map(rule_name)
                            .unwrap_or_else(|| s.policy_id.to_string());
                        vec![
                            s.app.unwrap_or_else(|| "incomplete".into()),
                            s.key.proto.to_string(),
                            format!("{}[{}]", s.key.src, s.key.sport),
                            format!("{}[{}]", s.key.dst, s.key.dport),
                            s.src_zone.clone(),
                            s.dst_zone.clone(),
                            s.user.clone().unwrap_or_else(|| "unknown".into()),
                            rule,
                            s.nat_src.map(|(ip, p)| format!("{ip}[{p}]")).unwrap_or_else(|| "-".into()),
                        ]
                    })
                    .collect();
                Ok(table(&["application", "proto", "source", "destination", "from", "to", "user", "rule", "snat"], &rows))
            }
            _ => fail("Unknown command: show config running|candidate, show system info, show interface all, show running security-policy, show session all"),
        }
    }

    fn test_match(&self, w: &[String], ctx: &Ctx<'_>) -> R {
        if w.first().map(String::as_str) != Some("security-policy-match") {
            return fail("Unknown command: test security-policy-match ...");
        }
        let cfg = ctx.store.running();
        let (mut from, mut to, mut src, mut dst, mut proto, mut port, mut app, mut vdom) =
            (None, None, None, None, 6u8, 0u16, None, "root".to_string());
        let mut user: Option<String> = None;
        let mut i = 1;
        while i < w.len() {
            let v = at(w, i + 1)?;
            match w[i].as_str() {
                "from" => from = Some(v.to_string()),
                "to" => to = Some(v.to_string()),
                "source" => src = Some(v.parse::<Ipv4Addr>().map_err(|_| "invalid source")?),
                "destination" => dst = Some(v.parse::<Ipv4Addr>().map_err(|_| "invalid destination")?),
                "protocol" => proto = v.parse().map_err(|_| "invalid protocol")?,
                "destination-port" => port = v.parse().map_err(|_| "invalid port")?,
                "application" => app = Some(v.to_string()),
                "vsys" => vdom = vsys_to_vdom(v),
                "source-user" => user = Some(v.to_string()),
                other => return fail(format!("Invalid syntax: {other}")),
            }
            i += 2;
        }
        let (from, to) = (from.ok_or("from is required")?, to.ok_or("to is required")?);
        let (src, dst) = (src.ok_or("source is required")?, dst.ok_or("destination is required")?);
        let user = user.or_else(|| cfg.static_user_for(src).map(str::to_string));
        match cfg.match_or_default_user(&vdom, &from, &to, src, dst, proto, port, app.as_deref(), user.as_deref()) {
            Some(p) => {
                let index = cfg.policies.iter().filter(|x| x.vdom == vdom && x.id <= p.id).count()
                    + usize::from(crate::model::is_default_rule_id(p.id));
                Ok(format!(
                    "\"{}; index: {index}\" {{\n        from {};\n        source {};\n        source-user {};\n        to {};\n        destination {};\n        application {};\n        service {};\n        action {};\n}}\n",
                    rule_name(p),
                    p.src_zones.join(" "),
                    addr_names(&p.src, p.negate_src),
                    if p.users.is_empty() { "any".to_string() } else { p.users.join(" ") },
                    p.dst_zones.join(" "),
                    addr_names(&p.dst, p.negate_dst),
                    if p.apps.is_empty() { "any".to_string() } else { p.apps.join(" ") },
                    service_names(p).join(" "),
                    action_name(p.action)
                ))
            }
            None => Ok("No matching rule: traffic is denied by default\n".into()),
        }
    }

    fn configure(&mut self, w: &[String], ctx: &Ctx<'_>) -> R {
        let cmd = w[0].as_str();
        match cmd {
            "exit" | "quit" => {
                self.mode = Mode::Operational;
                let dirty = self.candidate.as_ref().map_or(false, |c| c.to_text() != ctx.store.running().to_text());
                Ok(if dirty {
                    "Exiting configuration mode\nWarning: uncommitted changes remain in the candidate configuration".into()
                } else {
                    "Exiting configuration mode".into()
                })
            }
            "run" => self.operational(&w[1..], ctx),
            "show" => {
                if self.candidate.is_none() {
                    let fresh = self.begin(ctx);
                    self.candidate = Some(fresh);
                }
                let cand = self.candidate.as_ref().expect("just set");
                let rest: Vec<&str> = w[1..].iter().map(String::as_str).collect();
                Ok(filter(&render(cand), &rest))
            }
            "commit" => self.commit(ctx),
            "revert" => {
                let fresh = self.begin(ctx);
                self.candidate = Some(fresh);
                Ok("Candidate configuration reverted to the running configuration".into())
            }
            "set" | "delete" | "move" | "rename" => {
                let mut cand = match self.candidate.take() {
                    Some(cand) => cand,
                    None => self.begin(ctx),
                };
                let (vdom, body) = match (w.get(1).map(String::as_str), w.get(2)) {
                    (Some("vsys"), Some(vsys)) => (vsys_to_vdom(vsys), &w[3..]),
                    _ => ("root".to_string(), &w[1..]),
                };
                if vdom != "root" && !cand.vdoms.contains(&vdom) {
                    if cmd == "set" {
                        cand.vdoms.push(vdom.clone());
                    } else {
                        self.candidate = Some(cand);
                        return fail(format!("vsys {} does not exist", vdom_to_vsys(&vdom)));
                    }
                }
                let result = match cmd {
                    "set" => set(&mut cand, &vdom, body),
                    "delete" => delete(&mut cand, &vdom, body),
                    "move" => move_rule(&mut cand, &vdom, body),
                    _ => rename(&mut cand, &vdom, body),
                };
                self.candidate = Some(cand);
                result.map(|()| String::new())
            }
            other => fail(format!("Unknown command: {other}")),
        }
    }

    /// Copy the running configuration for a new candidate, remembering the
    /// revision it came from (read first, so a racing commit is caught).
    fn begin(&mut self, ctx: &Ctx<'_>) -> Config {
        self.base = ctx.store.revision();
        ctx.store.running()
    }

    fn commit(&mut self, ctx: &Ctx<'_>) -> R {
        if self.candidate.is_none() {
            let fresh = self.begin(ctx);
            self.candidate = Some(fresh);
        }
        let base = self.base;
        let cand = self.candidate.as_mut().expect("just set");
        let mut problems = Vec::new();
        for p in &cand.policies {
            for (field, empty) in [("from", p.src_zones.is_empty()), ("to", p.dst_zones.is_empty()), ("source", p.src.is_empty()), ("destination", p.dst.is_empty())] {
                if empty {
                    problems.push(format!("rulebase -> security -> rules -> {} is missing '{field}'", rule_name(p)));
                }
            }
        }
        let zone_known = |vdom: &str, z: &str| z == "any" || cand.interfaces.iter().any(|i| i.vdom == vdom && i.zone == z);
        for p in &cand.policies {
            for z in p.src_zones.iter().chain(p.dst_zones.iter()) {
                if !zone_known(&p.vdom, z) {
                    problems.push(format!("rulebase -> security -> rules -> {}: zone '{z}' is not a valid reference", rule_name(p)));
                }
            }
        }
        for r in &cand.snat {
            for z in r.src_zones.iter().chain(r.dst_zones.iter()) {
                if !zone_known(&r.vdom, z) {
                    problems.push(format!("rulebase -> nat -> rules -> {}: zone '{z}' is not a valid reference", r.name.clone().unwrap_or_default()));
                }
            }
            if r.src_zones.is_empty() || r.dst_zones.is_empty() || r.src.is_empty() || r.dst.is_empty() {
                problems.push(format!("rulebase -> nat -> rules -> {} is missing from/to/source/destination", r.name.clone().unwrap_or_default()));
            }
        }
        if !problems.is_empty() {
            return fail(format!("Commit failed\n{}", problems.join("\n")));
        }
        if cand.to_text() == ctx.store.running().to_text() {
            return Ok("There are no changes to commit.".into());
        }
        match ctx.store.commit_from(base, cand) {
            Ok(()) => {
                let fresh = self.begin(ctx);
                self.candidate = Some(fresh);
                Ok("Configuration committed successfully".into())
            }
            Err(e) => fail(format!("Commit failed\n{e}")),
        }
    }
}

/// Keep only `set` lines under a path, as `show <path>` does.
fn filter(text: &str, path: &[&str]) -> String {
    if path.is_empty() {
        return text.to_string();
    }
    let prefix = format!("set {}", path.join(" "));
    text.lines().filter(|l| l.starts_with(&prefix)).map(|l| format!("{l}\n")).collect()
}

// ------------------------------------------------------------------- set

fn set(cfg: &mut Config, vdom: &str, w: &[String]) -> Result<(), String> {
    match at(w, 0)? {
        "deviceconfig" => {
            expect(w, 1, "system")?;
            expect(w, 2, "hostname")?;
            cfg.settings.hostname = at(w, 3)?.into();
        }
        "network" => match at(w, 1)? {
            "interface" => {
                expect(w, 2, "ethernet")?;
                let name = at(w, 3)?;
                let iface = cfg.interfaces.iter_mut().find(|i| i.name == name).ok_or_else(|| format!("{name} is not a valid interface"))?;
                expect(w, 4, "layer3")?;
                match at(w, 5)? {
                    "ip" => {
                        let (ips, _) = list(w, 6)?;
                        iface.address = Some(Cidr::parse(ips.first().ok_or("missing address")?)?);
                    }
                    "mtu" => iface.mtu = at(w, 6)?.parse().map_err(|_| "invalid mtu".to_string())?,
                    "ipv6" => {
                        expect(w, 6, "address")?;
                        iface.address6 = Some(crate::model::Cidr6::parse(at(w, 7)?)?);
                    }
                    other => return fail(format!("Unsupported layer3 option {other}")),
                }
            }
            "virtual-router" => {
                expect(w, 3, "routing-table")?;
                expect(w, 4, "ip")?;
                expect(w, 5, "static-route")?;
                let name = at(w, 6)?.to_string();
                let pos = match cfg.routes.iter().position(|r| r.vdom == vdom && r.name.as_deref() == Some(&name)) {
                    Some(p) => p,
                    None => {
                        cfg.routes.push(Route { dst: Cidr::ANY, interface: String::new(), via: None, distance: 10, vdom: vdom.into(), name: Some(name) });
                        cfg.routes.len() - 1
                    }
                };
                let mut i = 7;
                while i < w.len() {
                    let r = &mut cfg.routes[pos];
                    match w[i].as_str() {
                        "destination" => r.dst = Cidr::parse(at(w, i + 1)?)?,
                        "nexthop" => {
                            expect(w, i + 1, "ip-address")?;
                            r.via = Some(at(w, i + 2)?.parse().map_err(|_| "invalid nexthop".to_string())?);
                            i += 1;
                        }
                        "interface" => r.interface = at(w, i + 1)?.into(),
                        "metric" | "admin-dist" => r.distance = at(w, i + 1)?.parse().map_err(|_| "invalid metric".to_string())?,
                        other => return fail(format!("Unsupported static-route option {other}")),
                    }
                    i += 2;
                }
            }
            other => return fail(format!("Unsupported network object {other}")),
        },
        "zone" => {
            let zone = at(w, 1)?.to_string();
            expect(w, 2, "network")?;
            expect(w, 3, "layer3")?;
            let (ifaces, _) = list(w, 4)?;
            for name in &ifaces {
                let iface = cfg.interfaces.iter_mut().find(|i| &i.name == name && i.vdom == vdom).ok_or_else(|| format!("{name} is not an interface of {}", vdom_to_vsys(vdom)))?;
                iface.zone = zone.clone();
            }
        }
        "address" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "ip-netmask")?;
            let value = at(w, 3)?;
            cfg.addresses.retain(|a| a.name != name);
            if value.contains(':') {
                cfg.addresses.push(AddressObject { name, entries: Vec::new(), entries6: vec![crate::model::Cidr6::parse(value)?] });
            } else {
                cfg.addresses.push(AddressObject { name, entries: vec![Cidr::parse(value)?], entries6: Vec::new() });
            }
        }
        "address-group" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "static")?;
            let (members, _) = list(w, 3)?;
            cfg.address_groups.retain(|g| g.name != name);
            cfg.address_groups.push(AddressGroup { name, members });
        }
        "service" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "protocol")?;
            let proto = match at(w, 3)? {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                "tcp-udp" => Proto::Any,
                other => return fail(format!("Invalid protocol {other} (tcp or udp)")),
            };
            expect(w, 4, "port")?;
            let ports = parse_port_ranges(at(w, 5)?)?;
            if w.len() > 6 {
                return fail("source-port is not supported");
            }
            cfg.services.retain(|s| s.name != name);
            cfg.services.push(ServiceObject { name, proto, ports });
        }
        "service-group" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "members")?;
            let (members, _) = list(w, 3)?;
            cfg.service_groups.retain(|g| g.name != name);
            cfg.service_groups.push(ServiceGroup { name, members });
        }
        "user-group" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "members")?;
            let (members, _) = list(w, 3)?;
            for m in &members {
                crate::model::valid_user_name(m)?;
            }
            cfg.user_groups.retain(|g| g.name != name);
            cfg.user_groups.push(crate::model::UserGroup { name, members });
        }
        "user-id" => {
            // Static mapping (lightweight; PAN-OS learns these from agents).
            expect(w, 1, "ip-user-mapping")?;
            let cidr = Cidr::parse(at(w, 2)?)?;
            expect(w, 3, "user")?;
            let user = at(w, 4)?.to_string();
            crate::model::valid_user_name(&user)?;
            cfg.user_maps.retain(|m| m.cidr != cidr);
            cfg.user_maps.push(crate::model::UserMap { cidr, user });
        }
        "application-group" => {
            let name = at(w, 1)?.to_string();
            expect(w, 2, "members")?;
            let (members, _) = list(w, 3)?;
            for m in &members {
                if !cfg.app_name_valid(m) {
                    return fail(format!("{m} is not a valid application"));
                }
            }
            cfg.app_groups.retain(|g| g.name != name);
            cfg.app_groups.push(AppGroup { name, members });
        }
        "profiles" => set_profile(cfg, w)?,
        "profile-group" => {
            let name = at(w, 1)?.to_string();
            if !cfg.profile_groups.iter().any(|g| g.name == name) {
                cfg.profile_groups.push(ProfileGroup { name: name.clone(), ..ProfileGroup::default() });
            }
            let g = cfg.profile_groups.iter_mut().find(|g| g.name == name).expect("just ensured");
            let mut i = 2;
            while i < w.len() {
                let v = Some(at(w, i + 1)?.to_string());
                match w[i].as_str() {
                    "url-filtering" => g.url = v,
                    "vulnerability" => g.ips = v,
                    "virus" => g.av = v,
                    other => return fail(format!("Unsupported profile type {other}")),
                }
                i += 2;
            }
        }
        "rulebase" => match at(w, 1)? {
            "default-security-rules" => {
                expect(w, 2, "rules")?;
                let kind = match at(w, 3)? {
                    "intrazone-default" => DefaultKind::Intrazone,
                    "interzone-default" => DefaultKind::Interzone,
                    other => return fail(format!("{other} is not a default rule (intrazone-default or interzone-default)")),
                };
                let mut rule = cfg
                    .default_rules
                    .iter()
                    .find(|r| r.vdom == vdom && r.kind == kind && r.zone.is_none())
                    .cloned()
                    .unwrap_or(DefaultRule { vdom: vdom.into(), kind, zone: None, action: Action::Deny, log: false });
                let mut i = 4;
                while i < w.len() {
                    match w[i].as_str() {
                        "action" => {
                            rule.action = match at(w, i + 1)? {
                                "allow" => Action::Permit,
                                "deny" | "drop" => Action::Deny,
                                other => return fail(format!("Invalid action {other} (allow or deny)")),
                            }
                        }
                        "log-end" => rule.log = yes(at(w, i + 1)?)?,
                        other => return fail(format!("Unsupported default rule attribute {other}")),
                    }
                    i += 2;
                }
                cfg.set_default_rule(rule)?;
            }
            "security" => {
                expect(w, 2, "rules")?;
                set_security_rule(cfg, vdom, at(w, 3)?, &w[4..])?;
            }
            "nat" => {
                expect(w, 2, "rules")?;
                set_nat_rule(cfg, vdom, at(w, 3)?, &w[4..])?;
            }
            other => return fail(format!("Unsupported rulebase {other}")),
        },
        other => return fail(format!("Unsupported object {other}")),
    }
    Ok(())
}

fn set_profile(cfg: &mut Config, w: &[String]) -> Result<(), String> {
    let kind = at(w, 1)?;
    let name = at(w, 2)?.to_string();
    match kind {
        "url-filtering" => {
            if !cfg.url_filters.iter().any(|f| f.name == name) {
                cfg.url_filters.push(UrlFilter { name: name.clone(), block: Vec::new(), allow: Vec::new() });
            }
            let f = cfg.url_filters.iter_mut().find(|f| f.name == name).expect("ensured");
            let mut i = 3;
            while i < w.len() {
                let which = w[i].clone();
                let (items, next) = list(w, i + 1)?;
                let mapped: Vec<String> = items
                    .iter()
                    .map(|x| url_category(x).map(|c| format!("category:{c}")).unwrap_or_else(|| x.clone()))
                    .collect();
                match which.as_str() {
                    "block" => f.block = mapped,
                    "allow" => f.allow = mapped,
                    other => return fail(format!("Unsupported url-filtering option {other}")),
                }
                i = next;
            }
        }
        "vulnerability" | "virus" => {
            expect(w, 3, "signature")?;
            let (patterns, _) = list(w, 4)?;
            let profiles = if kind == "vulnerability" { &mut cfg.ips_profiles } else { &mut cfg.av_profiles };
            profiles.retain(|p| p.name != name);
            profiles.push(SignatureProfile { name, patterns });
        }
        other => return fail(format!("Unsupported profile type {other}")),
    }
    Ok(())
}

fn set_security_rule(cfg: &mut Config, vdom: &str, name: &str, w: &[String]) -> Result<(), String> {
    let pos = match rule_pos(cfg, vdom, name) {
        Some(p) => p,
        None => {
            let mut p = Policy::new(next_policy_id(cfg, 10), vdom);
            p.name = Some(name.into());
            p.src_zones.clear();
            p.dst_zones.clear();
            p.src.clear();
            p.dst.clear();
            p.services = vec![APPLICATION_DEFAULT.into()];
            cfg.policies.push(p);
            cfg.policies.len() - 1
        }
    };
    let mut i = 0;
    while i < w.len() {
        let key = w[i].clone();
        let p = &mut cfg.policies[pos];
        match key.as_str() {
            "from" | "to" | "source" | "destination" | "application" | "service" | "source-user" | "category" => {
                let (vals, next) = list(w, i + 1)?;
                match key.as_str() {
                    "from" => p.src_zones = vals,
                    "to" => p.dst_zones = vals,
                    "source" => p.src = vals.iter().map(|v| addr(v)).collect::<Result<_, _>>()?,
                    "destination" => p.dst = vals.iter().map(|v| addr(v)).collect::<Result<_, _>>()?,
                    "application" => p.apps = if vals == ["any"] { Vec::new() } else { vals },
                    "service" => {
                        p.proto = Proto::Any;
                        p.dst_port = None;
                        p.services.clear();
                        if vals.len() == 1 && vals[0].contains('/') {
                            let (proto, port) = vals[0].split_once('/').expect("checked");
                            p.proto = Proto::parse(proto)?;
                            p.dst_port = if port == "any" { None } else { Some(port.parse().map_err(|_| "invalid port".to_string())?) };
                        } else if vals != ["any"] {
                            p.services = vals;
                        }
                    }
                    "source-user" => {
                        for v in &vals {
                            crate::model::valid_user_name(v)?;
                        }
                        p.users = if vals == ["any"] { Vec::new() } else { vals };
                    }
                    "category" if vals == ["any"] => {}
                    _ => return fail("URL category match in a security rule is not supported; use a url-filtering profile"),
                }
                i = next;
                continue;
            }
            "action" => {
                p.action = match at(w, i + 1)? {
                    "allow" => Action::Permit,
                    "deny" | "drop" => Action::Deny,
                    "reset-client" | "reset-server" | "reset-both" => Action::Reject,
                    other => return fail(format!("Invalid action {other}")),
                }
            }
            "log-end" => p.log = yes(at(w, i + 1)?)?,
            "log-start" => {
                yes(at(w, i + 1)?)?;
            }
            "disabled" => p.enabled = !yes(at(w, i + 1)?)?,
            "negate-source" => p.negate_src = yes(at(w, i + 1)?)?,
            "negate-destination" => p.negate_dst = yes(at(w, i + 1)?)?,
            "profile-setting" => match at(w, i + 1)? {
                "group" => {
                    p.group = Some(at(w, i + 2)?.into());
                    p.url = None;
                    p.ips = None;
                    p.av = None;
                    i += 3;
                    continue;
                }
                "profiles" => {
                    p.group = None;
                    let mut j = i + 2;
                    while j < w.len() && matches!(w[j].as_str(), "url-filtering" | "vulnerability" | "virus") {
                        let v = Some(at(w, j + 1)?.to_string());
                        match w[j].as_str() {
                            "url-filtering" => p.url = v,
                            "vulnerability" => p.ips = v,
                            _ => p.av = v,
                        }
                        j += 2;
                    }
                    i = j;
                    continue;
                }
                other => return fail(format!("Invalid profile-setting {other}")),
            },
            "description" | "tag" => return fail(format!("'{key}' is not stored by this build")),
            other => return fail(format!("Unsupported rule attribute {other}")),
        }
        i += 2;
    }
    Ok(())
}

fn set_nat_rule(cfg: &mut Config, vdom: &str, name: &str, w: &[String]) -> Result<(), String> {
    let (mut from, mut to, mut src, mut dst) = (None, None, None, None);
    let mut service: Option<String> = None;
    let mut snat: Option<SnatTarget> = None;
    let mut dnat: Option<(Ipv4Addr, Option<u16>)> = None;
    let mut disabled = false;
    // Start from the existing rule's values so attributes can be set one at a time.
    if let Some(r) = cfg.snat.iter().find(|r| r.vdom == vdom && r.name.as_deref() == Some(name)) {
        from = Some(r.src_zones.clone());
        to = Some(r.dst_zones.clone());
        src = Some(r.src.clone());
        dst = Some(r.dst.clone());
        snat = Some(r.to);
        disabled = !r.enabled;
    }
    let mut i = 0;
    while i < w.len() {
        match w[i].as_str() {
            k @ ("from" | "to" | "source" | "destination" | "service" | "to-interface") => {
                let (vals, next) = list(w, i + 1)?;
                match k {
                    "from" => from = Some(vals),
                    "to" => to = Some(vals),
                    "source" => src = Some(vals.iter().map(|v| addr(v)).collect::<Result<_, _>>()?),
                    "destination" => dst = Some(vals.iter().map(|v| addr(v)).collect::<Result<_, _>>()?),
                    "service" => service = vals.into_iter().next(),
                    _ => {}
                }
                i = next;
            }
            "source-translation" => {
                let kind = at(w, i + 1)?;
                if kind != "dynamic-ip-and-port" && kind != "static-ip" {
                    return fail(format!("Unsupported source-translation {kind}"));
                }
                match at(w, i + 2)? {
                    "interface-address" => {
                        snat = Some(SnatTarget::Masquerade);
                        i += 3;
                        if w.get(i).map(String::as_str) == Some("interface") {
                            i += 2;
                        }
                        if w.get(i).map(String::as_str) == Some("ip") {
                            i += 2;
                        }
                    }
                    "translated-address" => {
                        let (vals, next) = list(w, i + 3)?;
                        let ip = vals.first().ok_or("missing translated-address")?.split('/').next().unwrap_or("").parse().map_err(|_| "invalid translated-address".to_string())?;
                        snat = Some(SnatTarget::Address(ip));
                        i = next;
                    }
                    other => return fail(format!("Unsupported source-translation option {other}")),
                }
            }
            "destination-translation" => {
                expect(w, i + 1, "translated-address")?;
                let ip: Ipv4Addr = at(w, i + 2)?.split('/').next().unwrap_or("").parse().map_err(|_| "invalid translated-address".to_string())?;
                let mut port = None;
                i += 3;
                if w.get(i).map(String::as_str) == Some("translated-port") {
                    port = Some(at(w, i + 1)?.parse().map_err(|_| "invalid translated-port".to_string())?);
                    i += 2;
                }
                dnat = Some((ip, port));
            }
            "disabled" => {
                disabled = yes(at(w, i + 1)?)?;
                i += 2;
            }
            other => return fail(format!("Unsupported NAT rule attribute {other}")),
        }
    }
    if let Some(target) = snat {
        cfg.snat.retain(|r| !(r.vdom == vdom && r.name.as_deref() == Some(name)));
        let id = cfg.snat.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        cfg.snat.push(SnatRule {
            id,
            vdom: vdom.into(),
            src_zones: from.clone().unwrap_or_default(),
            dst_zones: to.clone().unwrap_or_default(),
            src: src.clone().unwrap_or_default(),
            dst: dst.clone().unwrap_or_default(),
            to: target,
            enabled: !disabled,
            name: Some(name.into()),
        });
    }
    if let Some((to_ip, to_port)) = dnat {
        let dst_list = dst.unwrap_or_default();
        let public = match dst_list.as_slice() {
            [AddrRef::Cidr(c)] => *c,
            [AddrRef::Named(n)] => {
                let obj = cfg.addresses.iter().find(|a| &a.name == n).ok_or_else(|| format!("address {n} does not exist"))?;
                *obj.entries.first().ok_or("empty address")?
            }
            _ => return fail("destination translation needs exactly one destination address"),
        };
        let (proto, dst_port) = match service.as_deref() {
            None | Some("any") => (Proto::Any, None),
            Some(s) if s.contains('/') => {
                let (p, port) = s.split_once('/').expect("checked");
                (Proto::parse(p)?, Some(port.parse().map_err(|_| "invalid port".to_string())?))
            }
            Some(s) => {
                let svc = cfg.services.iter().find(|x| x.name == s).ok_or_else(|| format!("service {s} does not exist"))?;
                match svc.ports.as_slice() {
                    [(lo, hi)] if lo == hi => (svc.proto, Some(*lo)),
                    [] => (svc.proto, None),
                    _ => return fail("destination translation needs a service with one port"),
                }
            }
        };
        if to_port.is_some() && dst_port.is_none() {
            return fail("translated-port needs a service with a destination port");
        }
        cfg.dnat.retain(|d| !(d.vdom == vdom && d.name.as_deref() == Some(name)));
        let id = cfg.dnat.iter().map(|d| d.id).max().unwrap_or(0) + 1;
        cfg.dnat.push(DnatRule { id, vdom: vdom.into(), proto, dst: public, dst_port, to_ip, to_port: to_port.or(dst_port), name: Some(name.into()) });
    }
    if snat.is_none() && dnat.is_none() && !cfg.dnat.iter().any(|d| d.vdom == vdom && d.name.as_deref() == Some(name)) {
        return fail("a NAT rule needs source-translation or destination-translation");
    }
    Ok(())
}

// ---------------------------------------------------------------- delete

fn delete(cfg: &mut Config, vdom: &str, w: &[String]) -> Result<(), String> {
    let before = cfg.to_text();
    match (at(w, 0)?, w.get(1).map(String::as_str)) {
        ("rulebase", Some("default-security-rules")) => {
            expect(w, 2, "rules")?;
            let kind = if at(w, 3)? == "intrazone-default" { DefaultKind::Intrazone } else { DefaultKind::Interzone };
            cfg.default_rules.retain(|r| !(r.vdom == vdom && r.kind == kind && r.zone.is_none()));
            cfg.rebuild_defaults();
        }
        ("rulebase", Some("security")) => {
            expect(w, 2, "rules")?;
            let name = at(w, 3)?;
            let pos = rule_pos(cfg, vdom, name).ok_or_else(|| format!("rule {name} does not exist"))?;
            cfg.policies.remove(pos);
        }
        ("rulebase", Some("nat")) => {
            expect(w, 2, "rules")?;
            let name = at(w, 3)?;
            cfg.snat.retain(|r| !(r.vdom == vdom && r.name.as_deref() == Some(name)));
            cfg.dnat.retain(|d| !(d.vdom == vdom && d.name.as_deref() == Some(name)));
        }
        ("address", Some(n)) => cfg.addresses.retain(|a| a.name != n),
        ("address-group", Some(n)) => cfg.address_groups.retain(|g| g.name != n),
        ("service", Some(n)) => cfg.services.retain(|s| s.name != n),
        ("service-group", Some(n)) => cfg.service_groups.retain(|g| g.name != n),
        ("application-group", Some(n)) => cfg.app_groups.retain(|g| g.name != n),
        ("user-group", Some(n)) => cfg.user_groups.retain(|g| g.name != n),
        ("user-id", Some("ip-user-mapping")) => {
            let cidr = Cidr::parse(at(w, 2)?)?;
            cfg.user_maps.retain(|m| m.cidr != cidr);
        }
        ("profile-group", Some(n)) => cfg.profile_groups.retain(|g| g.name != n),
        ("profiles", Some(kind)) => {
            let name = at(w, 2)?;
            match kind {
                "url-filtering" => cfg.url_filters.retain(|f| f.name != name),
                "vulnerability" => cfg.ips_profiles.retain(|p| p.name != name),
                "virus" => cfg.av_profiles.retain(|p| p.name != name),
                other => return fail(format!("Unsupported profile type {other}")),
            }
        }
        ("zone", Some(z)) => {
            for i in cfg.interfaces.iter_mut().filter(|i| i.vdom == vdom && i.zone == z) {
                i.zone = i.name.clone();
            }
        }
        ("network", Some("virtual-router")) => {
            let name = at(w, 6)?;
            cfg.routes.retain(|r| !(r.vdom == vdom && r.name.as_deref() == Some(name)));
        }
        _ => return fail("Unsupported delete path"),
    }
    if cfg.to_text() == before {
        return fail("Object does not exist");
    }
    Ok(())
}

fn move_rule(cfg: &mut Config, vdom: &str, w: &[String]) -> Result<(), String> {
    expect(w, 0, "rulebase")?;
    expect(w, 1, "security")?;
    expect(w, 2, "rules")?;
    let name = at(w, 3)?;
    let mut order: Vec<usize> = (0..cfg.policies.len()).filter(|i| cfg.policies[*i].vdom == vdom).collect();
    order.sort_by_key(|i| cfg.policies[*i].id);
    let ids: Vec<u32> = order.iter().map(|i| cfg.policies[*i].id).collect();
    let me = rule_pos(cfg, vdom, name).ok_or_else(|| format!("rule {name} does not exist"))?;
    order.retain(|i| *i != me);
    let target = |n: &str| rule_pos(cfg, vdom, n).and_then(|p| order.iter().position(|i| *i == p)).ok_or_else(|| format!("rule {n} does not exist"));
    let at_index = match at(w, 4)? {
        "top" => 0,
        "bottom" => order.len(),
        "before" => target(at(w, 5)?)?,
        "after" => target(at(w, 5)?)? + 1,
        other => return fail(format!("Invalid move '{other}' (top, bottom, before or after)")),
    };
    order.insert(at_index, me);
    // Reuse this VDOM's ids in the new order, so ids stay unique overall.
    for (i, id) in order.into_iter().zip(ids) {
        cfg.policies[i].id = id;
    }
    cfg.policies.sort_by_key(|p| p.id);
    Ok(())
}

fn rename(cfg: &mut Config, vdom: &str, w: &[String]) -> Result<(), String> {
    expect(w, 0, "rulebase")?;
    expect(w, 1, "security")?;
    expect(w, 2, "rules")?;
    let (old, new) = (at(w, 3)?, at(w, 5)?);
    expect(w, 4, "to")?;
    if rule_pos(cfg, vdom, new).is_some() {
        return fail(format!("rule {new} already exists"));
    }
    let pos = rule_pos(cfg, vdom, old).ok_or_else(|| format!("rule {old} does not exist"))?;
    cfg.policies[pos].name = Some(new.into());
    Ok(())
}

// ------------------------------------------------------------- rendering

fn one_or_list(v: &[String]) -> String {
    if v.len() == 1 { v[0].clone() } else { format!("[ {} ]", v.join(" ")) }
}

fn addr_names(list: &[AddrRef], negate: bool) -> String {
    let names: Vec<String> = list
        .iter()
        .map(|a| match a {
            AddrRef::Cidr(c) if *c == Cidr::ANY => "any".to_string(),
            AddrRef::Cidr(c) => c.to_string(),
            AddrRef::Cidr6(c) => c.to_string(),
            AddrRef::Named(n) => n.clone(),
        })
        .collect();
    let body = one_or_list(&names);
    if negate { format!("{body} (negated)") } else { body }
}

fn addr_list(list: &[AddrRef]) -> String {
    addr_names(list, false)
}

fn service_names(p: &Policy) -> Vec<String> {
    if !p.services.is_empty() {
        p.services.clone()
    } else if p.proto == Proto::Any && p.dst_port.is_none() {
        vec!["any".into()]
    } else {
        vec![format!("{}/{}", p.proto, p.dst_port.map(|x| x.to_string()).unwrap_or_else(|| "any".into()))]
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Permit => "allow",
        Action::Deny => "deny",
        Action::Reject => "reset-both",
    }
}

fn vsys_prefix(vdom: &str) -> String {
    if vdom == "root" { "set ".into() } else { format!("set vsys {vdom} ") }
}

/// The whole configuration as PAN-OS-style `set` commands.
pub fn render(cfg: &Config) -> String {
    let mut out = format!("set deviceconfig system hostname {}\n", cfg.settings.hostname);
    for i in &cfg.interfaces {
        if let Some(a) = i.address {
            out.push_str(&format!("set network interface ethernet {} layer3 ip {a}\n", i.name));
        }
        if let Some(a) = i.address6 {
            out.push_str(&format!("set network interface ethernet {} layer3 ipv6 address {a}\n", i.name));
        }
    }
    for vdom in &cfg.vdoms {
        let mut zones: Vec<&str> = cfg.interfaces.iter().filter(|i| &i.vdom == vdom).map(|i| i.zone.as_str()).collect();
        zones.sort();
        zones.dedup();
        for z in zones {
            let members: Vec<String> = cfg.interfaces.iter().filter(|i| &i.vdom == vdom && i.zone == z).map(|i| i.name.clone()).collect();
            out.push_str(&format!("{}zone {z} network layer3 {}\n", vsys_prefix(vdom), one_or_list(&members)));
        }
    }
    for a in &cfg.addresses {
        if let Some(c) = a.entries.first() {
            out.push_str(&format!("set address {} ip-netmask {c}\n", a.name));
        } else if let Some(c) = a.entries6.first() {
            out.push_str(&format!("set address {} ip-netmask {c}\n", a.name));
        }
    }
    for g in &cfg.address_groups {
        out.push_str(&format!("set address-group {} static {}\n", g.name, one_or_list(&g.members)));
    }
    for s in &cfg.services {
        let proto = match s.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Any => "tcp-udp",
            _ => {
                out.push_str(&format!("# service {} is not TCP/UDP; use the ping or icmp application\n", s.name));
                continue;
            }
        };
        out.push_str(&format!("set service {} protocol {proto} port {}\n", s.name, s.ports_text()));
    }
    for g in &cfg.service_groups {
        out.push_str(&format!("set service-group {} members {}\n", g.name, one_or_list(&g.members)));
    }
    for g in &cfg.app_groups {
        out.push_str(&format!("set application-group {} members {}\n", g.name, one_or_list(&g.members)));
    }
    for g in &cfg.user_groups {
        out.push_str(&format!("set user-group {} members {}\n", g.name, one_or_list(&g.members)));
    }
    for m in &cfg.user_maps {
        out.push_str(&format!("set user-id ip-user-mapping {} user {}\n", m.cidr, m.user));
    }
    for f in &cfg.url_filters {
        let map = |v: &[String]| -> Vec<String> {
            v.iter().map(|x| x.strip_prefix("category:").map(url_category_back).unwrap_or_else(|| x.clone())).collect()
        };
        let mut line = format!("set profiles url-filtering {}", f.name);
        if !f.block.is_empty() {
            line.push_str(&format!(" block {}", one_or_list(&map(&f.block))));
        }
        if !f.allow.is_empty() {
            line.push_str(&format!(" allow {}", one_or_list(&map(&f.allow))));
        }
        out.push_str(&line);
        out.push('\n');
    }
    for (kind, list) in [("vulnerability", &cfg.ips_profiles), ("virus", &cfg.av_profiles)] {
        for p in list {
            let quoted: Vec<String> = p.patterns.iter().map(|x| format!("\"{x}\"")).collect();
            out.push_str(&format!("set profiles {kind} {} signature [ {} ]\n", p.name, quoted.join(" ")));
        }
    }
    for g in &cfg.profile_groups {
        let mut line = format!("set profile-group {}", g.name);
        for (k, v) in [("url-filtering", &g.url), ("vulnerability", &g.ips), ("virus", &g.av)] {
            if let Some(v) = v {
                line.push_str(&format!(" {k} {v}"));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    let mut rules: Vec<&Policy> = cfg.policies.iter().collect();
    rules.sort_by_key(|p| p.id);
    for p in rules {
        let apps = if p.apps.is_empty() { vec!["any".to_string()] } else { p.apps.clone() };
        let mut line = format!(
            "{}rulebase security rules {} from {} to {} source {} destination {}{} application {} service {} action {}",
            vsys_prefix(&p.vdom),
            rule_name(p),
            one_or_list(&p.src_zones),
            one_or_list(&p.dst_zones),
            addr_list(&p.src),
            addr_list(&p.dst),
            if p.users.is_empty() { String::new() } else { format!(" source-user {}", one_or_list(&p.users)) },
            one_or_list(&apps),
            one_or_list(&service_names(p)),
            action_name(p.action)
        );
        if p.negate_src {
            line.push_str(" negate-source yes");
        }
        if p.negate_dst {
            line.push_str(" negate-destination yes");
        }
        if !p.log {
            line.push_str(" log-end no");
        }
        if !p.enabled {
            line.push_str(" disabled yes");
        }
        if let Some(g) = &p.group {
            line.push_str(&format!(" profile-setting group {g}"));
        } else if p.url.is_some() || p.ips.is_some() || p.av.is_some() {
            line.push_str(" profile-setting profiles");
            for (k, v) in [("url-filtering", &p.url), ("vulnerability", &p.ips), ("virus", &p.av)] {
                if let Some(v) = v {
                    line.push_str(&format!(" {k} {v}"));
                }
            }
        }
        out.push_str(&line);
        out.push('\n');
        if p.nat {
            out.push_str(&format!("# rule {} also source-NATs to the egress interface (policy NAT)\n", rule_name(p)));
        }
    }
    for d in cfg.default_rules.iter().filter(|d| d.zone.is_none()) {
        out.push_str(&format!(
            "{}rulebase default-security-rules rules {} action {}{}\n",
            vsys_prefix(&d.vdom),
            if d.kind == DefaultKind::Intrazone { "intrazone-default" } else { "interzone-default" },
            if d.action == Action::Permit { "allow" } else { "deny" },
            if d.log { " log-end yes" } else { "" }
        ));
    }
    for d in cfg.default_rules.iter().filter(|d| d.zone.is_some()) {
        out.push_str(&format!("# zone {} overrides intrazone-default: {}\n", d.zone.clone().unwrap_or_default(), action_name(d.action)));
    }
    for r in &cfg.snat {
        let to = match r.to {
            SnatTarget::Masquerade => "interface-address".to_string(),
            SnatTarget::Address(ip) => format!("translated-address {ip}"),
        };
        out.push_str(&format!(
            "{}rulebase nat rules {} from {} to {} source {} destination {} service any source-translation dynamic-ip-and-port {to}{}\n",
            vsys_prefix(&r.vdom),
            r.name.clone().unwrap_or_else(|| format!("snat-{}", r.id)),
            one_or_list(&r.src_zones),
            one_or_list(&r.dst_zones),
            addr_list(&r.src),
            addr_list(&r.dst),
            if r.enabled { "" } else { " disabled yes" }
        ));
    }
    for d in &cfg.dnat {
        let service = match (d.proto, d.dst_port) {
            (_, None) => "any".to_string(),
            (p, Some(port)) => format!("{p}/{port}"),
        };
        let port = d.to_port.map(|p| format!(" translated-port {p}")).unwrap_or_default();
        out.push_str(&format!(
            "{}rulebase nat rules {} from any to any source any destination {} service {service} destination-translation translated-address {}{port}\n",
            vsys_prefix(&d.vdom),
            d.name.clone().unwrap_or_else(|| format!("dnat-{}", d.id)),
            d.dst,
            d.to_ip
        ));
    }
    for r in &cfg.routes {
        let mut line = format!(
            "set network virtual-router default routing-table ip static-route {} destination {}",
            r.name.clone().unwrap_or_else(|| r.dst.to_string().replace('/', "-")),
            r.dst
        );
        if let Some(v) = r.via {
            line.push_str(&format!(" nexthop ip-address {v}"));
        }
        line.push_str(&format!(" interface {} metric {}", r.interface, r.distance));
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::testing::{run, Mem};
    use crate::style::Store;
    use crate::style::Ctx;

    const BASE: &str = "\
system hostname PA-LAB
interface ethernet1/1 zone ethernet1/1 address 10.0.0.1/24
interface ethernet1/2 zone ethernet1/2 address 203.0.113.2/24
interface ethernet1/3 zone ethernet1/3 address 10.1.0.1/24
";

    fn setup(store: &Mem) -> PanOs {
        let mut s = PanOs::new();
        let out = run(&mut s, store, "
            configure
            set zone trust network layer3 ethernet1/1
            set zone untrust network layer3 ethernet1/2
            set zone dmz network layer3 ethernet1/3
            set rulebase security rules block-social from trust to untrust source any destination any application social-networking-apps service application-default action deny
            set application-group social-networking-apps members [ facebook instagram category:social-networking ]
            set rulebase security rules allow-web from trust to untrust source any destination any application [ ssl web-browsing github ] service application-default action allow
            set rulebase nat rules outbound from trust to untrust source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/2
        ");
        assert!(out.iter().skip(1).all(|o| o.is_empty()), "{out:?}");
        s
    }

    #[test]
    fn candidate_then_commit() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        assert!(store.running().policies.is_empty(), "nothing applies before commit");
        let ctx = Ctx { store: &store, can_write: true };
        assert_eq!(s.exec("commit", &ctx), "Configuration committed successfully");
        assert_eq!(s.exec("commit", &ctx), "There are no changes to commit.");
        let cfg = store.running();
        assert_eq!(cfg.policies.len(), 2);
        assert_eq!(cfg.snat.len(), 1);
        let m = |app: &str, port| cfg.match_policy("root", "trust", "untrust", "10.0.0.5".parse().unwrap(), "8.8.8.8".parse().unwrap(), 6, port, Some(app)).and_then(|p| p.name.clone());
        assert_eq!(m("facebook", 443).as_deref(), Some("block-social"));
        assert_eq!(m("github", 443).as_deref(), Some("allow-web"));
        assert_eq!(m("ssl", 8443), None, "application-default");
    }

    #[test]
    fn test_security_policy_match() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let ctx = Ctx { store: &store, can_write: true };
        s.exec("commit", &ctx);
        let hit = s.exec("run test security-policy-match from trust to untrust source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 443 application tiktok", &ctx);
        assert!(hit.contains("\"block-social; index: 1\"") && hit.contains("action deny;"), "{hit}");
        let hit = s.exec("run test security-policy-match from trust to untrust source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 443 application ssl", &ctx);
        assert!(hit.contains("\"allow-web; index: 2\"") && hit.contains("action allow;"), "{hit}");
        let miss = s.exec("run test security-policy-match from dmz to untrust source 10.1.0.5 destination 8.8.8.8 protocol 6 destination-port 22", &ctx);
        assert!(miss.contains("interzone-default") && miss.contains("action deny"), "{miss}");
    }

    #[test]
    fn failed_commit_keeps_candidate() {
        let store = Mem::new(BASE);
        let mut s = PanOs::new();
        let out = run(&mut s, &store, "
            configure
            set rulebase security rules r1 from trust to untrust source any action allow
            commit
        ");
        assert!(out[2].contains("is missing 'destination'"), "{out:?}");
        let out = run(&mut s, &store, "set rulebase security rules r1 destination any application any\ncommit");
        assert!(out[1].starts_with("Commit failed"), "zones trust/untrust do not exist yet: {out:?}");
        let out = run(&mut s, &store, "set zone trust network layer3 ethernet1/1\nset zone untrust network layer3 ethernet1/2\ncommit");
        assert_eq!(out[2], "Configuration committed successfully", "{out:?}");
    }

    #[test]
    fn move_rename_delete_and_show() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let out = run(&mut s, &store, "
            move rulebase security rules allow-web top
            rename rulebase security rules allow-web to web-out
            commit
        ");
        assert_eq!(out[2], "Configuration committed successfully", "{out:?}");
        let names: Vec<String> = store.running().policies.iter().map(rule_name).collect();
        assert_eq!(names, vec!["web-out", "block-social"]);
        let ctx = Ctx { store: &store, can_write: true };
        let shown = s.exec("show rulebase security", &ctx);
        assert!(shown.starts_with("set rulebase security rules web-out from trust to untrust"), "{shown}");
        assert!(s.exec("delete rulebase security rules nope", &ctx).contains("does not exist"));
        assert_eq!(s.exec("delete rulebase security rules block-social", &ctx), "");
        s.exec("commit", &ctx);
        assert_eq!(store.running().policies.len(), 1);
    }

    #[test]
    fn destination_nat_profiles_and_routes() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let out = run(&mut s, &store, r#"
            set address web-public ip-netmask 203.0.113.2/32
            set service web-8080 protocol tcp port 8080
            set rulebase nat rules web-in from untrust to untrust source any destination web-public service web-8080 destination-translation translated-address 10.1.0.10 translated-port 80
            set profiles url-filtering corp block [ gambling evil.test ]
            set profiles vulnerability edge signature [ "/etc/passwd" ]
            set profile-group default url-filtering corp vulnerability edge
            set rulebase security rules allow-web profile-setting group default
            set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0 nexthop ip-address 203.0.113.1 interface ethernet1/2 metric 10
            commit
        "#);
        assert_eq!(out.last().unwrap(), "Configuration committed successfully", "{out:?}");
        let cfg = store.running();
        let d = cfg.dnat_match("root", 6, "203.0.113.2".parse().unwrap(), 8080).unwrap();
        assert_eq!((d.to_ip.to_string(), d.to_port), ("10.1.0.10".into(), Some(80)));
        let p = cfg.policies.iter().find(|p| p.name.as_deref() == Some("allow-web")).unwrap();
        assert_eq!(cfg.profiles(p), (Some("corp"), Some("edge"), None));
        assert!(cfg.url_filter("corp").unwrap().blocked("www.bet365.com"));
        assert_eq!(cfg.egress("root", "1.1.1.1".parse().unwrap()).unwrap().1.to_string(), "203.0.113.1");
        // The running config renders back as set commands that re-apply cleanly.
        let text = render(&cfg);
        let store2 = Mem::new(BASE);
        let mut s2 = PanOs::new();
        let script = format!("configure\n{}commit", text.lines().filter(|l| !l.starts_with('#')).map(|l| format!("{l}\n")).collect::<String>());
        let out2 = run(&mut s2, &store2, &script);
        assert_eq!(out2.last().unwrap(), "Configuration committed successfully", "{out2:?}");
        assert_eq!(store2.running().to_text(), cfg.to_text());
    }

    #[test]
    fn vsys_maps_to_vdoms() {
        let text = "interface ethernet1/1 zone ethernet1/1 address 10.0.0.1/24\nvdom tenant2\ninterface ethernet1/4 zone ethernet1/4 address 10.9.0.1/24\n";
        let store = Mem::new(text);
        let mut s = PanOs::new();
        let out = run(&mut s, &store, "
            configure
            set vsys tenant2 zone t2 network layer3 ethernet1/4
            set vsys tenant2 rulebase security rules t2-out from t2 to t2 source any destination any application any service any action allow
            commit
        ");
        assert_eq!(out.last().unwrap(), "Configuration committed successfully", "{out:?}");
        let cfg = store.running();
        assert_eq!(cfg.policies[0].vdom, "tenant2");
        assert!(s.exec("show", &Ctx { store: &store, can_write: true }).contains("set vsys tenant2 rulebase security rules t2-out"));
    }

    #[test]
    fn default_security_rules_like_pan_os() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let ctx = Ctx { store: &store, can_write: true };
        let before = s.exec("run test security-policy-match from trust to trust source 10.0.0.5 destination 10.0.0.6 protocol 6 destination-port 22", &ctx);
        assert!(before.contains("intrazone-default") && before.contains("action deny"), "{before}");
        let out = run(&mut s, &store, "set rulebase default-security-rules rules intrazone-default action allow log-end yes\ncommit");
        assert_eq!(out[1], "Configuration committed successfully", "{out:?}");
        let after = s.exec("run test security-policy-match from trust to trust source 10.0.0.5 destination 10.0.0.6 protocol 6 destination-port 22", &ctx);
        assert!(after.contains("action allow"), "{after}");
        let listing = s.exec("run show running security-policy", &ctx);
        assert!(listing.contains("\"intrazone-default; index: 3\"") && listing.contains("\"interzone-default; index: 4\""), "{listing}");
        assert!(s.exec("show rulebase default-security-rules", &ctx).contains("intrazone-default action allow log-end yes"));
    }

    #[test]
    fn source_user_rules_and_user_id_requests() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let out = run(&mut s, &store, "
            set user-group netops members [ alice corp\\bob ]
            set rulebase security rules ssh-admins from trust to untrust source any source-user netops destination any application ssh service application-default action allow
            move rulebase security rules ssh-admins top
            commit
        ");
        assert_eq!(out.last().unwrap(), "Configuration committed successfully", "{out:?}");
        let ctx = Ctx { store: &store, can_write: true };
        let probe = "run test security-policy-match from trust to untrust source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 22 application ssh";
        assert!(s.exec(probe, &ctx).contains("interzone-default"), "unknown user");
        assert!(s.exec(&format!("{probe} source-user alice"), &ctx).contains("ssh-admins"));
        assert_eq!(s.exec("run request user-id login user corp\\bob ip 10.0.0.5 timeout 600", &ctx), "ip-user-mapping 10.0.0.5 -> corp\\bob added");
        assert!(s.exec("run show user ip-user-mapping all", &ctx).contains("corp\\bob"));
        assert!(s.exec("show rulebase security rules ssh-admins", &ctx).contains("source-user netops"));
    }

    #[test]
    fn ipv6_interfaces_and_rules() {
        let store = Mem::new(BASE);
        let mut s = setup(&store);
        let out = run(&mut s, &store, "
            set network interface ethernet ethernet1/1 layer3 ipv6 address 2001:db8:1::1/64
            set address v6-servers ip-netmask 2001:db8:5::/64
            set rulebase security rules v6-web from trust to untrust source any destination v6-servers application ssh service application-default action allow
            commit
        ");
        assert_eq!(out.last().unwrap(), "Configuration committed successfully", "{out:?}");
        let cfg = store.running();
        let hit = cfg.match_policy_ip("root", "trust", "untrust", "2001:db8:1::5".parse().unwrap(), "2001:db8:5::9".parse().unwrap(), 6, 22, Some("ssh"), None);
        assert_eq!(hit.and_then(|p| p.name.clone()).as_deref(), Some("v6-web"));
        assert!(render(&cfg).contains("layer3 ipv6 address 2001:db8:1::1/64"));
    }

    #[test]
    fn read_only_admin_cannot_configure() {
        let store = Mem::new(BASE);
        let mut s = PanOs::new();
        let ctx = Ctx { store: &store, can_write: false };
        assert!(s.exec("configure", &ctx).contains("permission denied"));
        assert!(s.exec("show system info", &ctx).contains("hostname: PA-LAB"));
    }

    #[test]
    fn c9_candidate_older_than_running_is_refused_at_commit() {
        let engine = crate::dataplane::Engine::for_test_with_file(
            Config::parse(
                "interface ethernet1/1 zone trust address 10.0.0.1/24\n\
                 interface ethernet1/2 zone untrust address 203.0.113.1/24\n",
            )
            .unwrap(),
        );
        let ctx = crate::style::Ctx { store: &engine, can_write: true };
        let mut s = PanOs::new();
        s.exec("configure", &ctx);
        // Another administrator commits while this candidate is open.
        let mut other = engine.cfg.read().unwrap().clone();
        other.settings.hostname = "changed-elsewhere".into();
        engine.apply_config(&other).unwrap();
        let out = s.exec("commit", &ctx);
        assert!(out.contains("changed since"), "{out}");
        assert_eq!(engine.cfg.read().unwrap().settings.hostname, "changed-elsewhere");
        // After `revert` the candidate is current again and commits.
        s.exec("revert", &ctx);
        let out = s.exec("commit", &ctx);
        assert!(!out.contains("changed since"), "{out}");
    }
}
