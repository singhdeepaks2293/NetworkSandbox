//! Structured configuration edits for the GUI.
//!
//! The browser never writes a whole configuration. It asks to create,
//! replace or delete one *object* — all the lines that define it, such as
//! `policy 10 …`, or `ips-profile edge` with its `ips-signature edge …`
//! lines — in the canonical text produced by [`Config::to_text`]. The result
//! is then parsed by the real parser, so every grammar and validation rule
//! is enforced once, in Rust, exactly as for the CLI.
//!
//! Objects live either in the global section (addresses, services,
//! profiles, …, shared by every VDOM) or in a `vdom <name>` section
//! (interfaces, routes, policies, NAT, default rules, zone protection).

use serde_json::{json, Value};

/// Statements that belong to a VDOM section; everything else is global.
const VDOM_KINDS: &[&str] = &[
    "interface", "route", "route6", "policy", "snat", "dnat", "default-rule", "zone", "vpn",
];

/// Statements the GUI may edit. `vdom` is structural; `vpn` and `ha` hold
/// keys and stay with the CLI and raw editor.
const EDITABLE: &[&str] = &[
    "system", "interface", "route", "route6", "policy", "snat", "dnat", "default-rule", "zone",
    "address", "address-group", "service", "service-group", "app-def", "app-group",
    "profile-group", "url-filter", "ips-profile", "ips-signature", "av-profile", "av-signature",
    "shaper", "user-group", "user-map",
];

/// What an edit does to its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The object must not exist yet.
    Create,
    /// The object named by `key` must exist; it is replaced in place.
    Replace,
    /// The object named by `key` must exist; it is removed.
    Delete,
}

#[derive(Clone, Debug)]
pub struct Edit {
    pub mode: Mode,
    /// VDOM for VDOM-scoped objects; ignored for global ones.
    pub vdom: String,
    /// Existing object (`Replace`, `Delete`); for `Create`, derived from `lines`.
    pub key: String,
    /// New definition (`Create`, `Replace`); empty for `Delete`.
    pub lines: Vec<String>,
}

impl Edit {
    /// Parse one edit from the API's JSON form:
    /// `{"mode": "create|replace|delete", "vdom": "root", "key": "policy 10", "lines": ["…"]}`.
    pub fn from_json(value: &Value) -> Result<Edit, String> {
        let mode = match value["mode"].as_str() {
            Some("create") => Mode::Create,
            Some("replace") => Mode::Replace,
            Some("delete") => Mode::Delete,
            other => return Err(format!("edit mode must be create, replace or delete, not {other:?}")),
        };
        let lines: Vec<String> = match &value["lines"] {
            Value::Null => Vec::new(),
            Value::Array(items) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(|| "lines must be strings".to_string()))
                .collect::<Result<_, _>>()?,
            _ => return Err("lines must be an array of strings".into()),
        };
        Ok(Edit {
            mode,
            vdom: value["vdom"].as_str().unwrap_or("root").to_string(),
            key: value["key"].as_str().unwrap_or("").to_string(),
            lines,
        })
    }
}

fn tokens(line: &str) -> Vec<&str> {
    line.split('#').next().unwrap_or("").split_whitespace().collect()
}

/// The object a canonical line belongs to. Lines of one object share a key.
pub fn object_key(line: &str) -> Option<String> {
    let t = tokens(line);
    let first = *t.first()?;
    Some(match (first, t.get(1)) {
        ("ips-signature", Some(name)) => format!("ips-profile {name}"),
        ("av-signature", Some(name)) => format!("av-profile {name}"),
        // Routes have no id; the whole line is the identity.
        ("route" | "route6", _) => t.join(" "),
        // default-rule <intrazone|interzone> <allow|deny> [zone Z] [log]
        ("default-rule", Some(kind)) => match t.iter().position(|w| *w == "zone").and_then(|i| t.get(i + 1)) {
            Some(zone) => format!("default-rule {kind} zone {zone}"),
            None => format!("default-rule {kind}"),
        },
        (_, Some(second)) => format!("{first} {second}"),
        (_, None) => first.to_string(),
    })
}

fn is_vdom_kind(key: &str) -> bool {
    VDOM_KINDS.contains(&key.split_whitespace().next().unwrap_or(""))
}

fn valid_vdom(name: &str) -> bool {
    !name.is_empty() && name.len() <= 31 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

struct Section {
    vdom: Option<String>,
    lines: Vec<String>,
}

fn sections(text: &str) -> Vec<Section> {
    let mut out = vec![Section { vdom: None, lines: Vec::new() }];
    let mut current = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let t = tokens(line);
        if t.first() == Some(&"vdom") {
            let name = t.get(1).unwrap_or(&"root").to_string();
            current = match out.iter().position(|s| s.vdom.as_deref() == Some(name.as_str())) {
                Some(i) => i,
                None => {
                    out.push(Section { vdom: Some(name), lines: Vec::new() });
                    out.len() - 1
                }
            };
            continue;
        }
        out[current].lines.push(t.join(" "));
    }
    out
}

fn assemble(sections: &[Section]) -> String {
    let mut out = String::new();
    for s in sections {
        if let Some(vdom) = &s.vdom {
            out.push_str(&format!("\nvdom {vdom}\n"));
        }
        for line in &s.lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Apply `edits` in order to canonical configuration `text`. The result
/// still has to be parsed and validated by the caller.
pub fn apply(text: &str, edits: &[Edit]) -> Result<String, String> {
    let mut secs = sections(text);
    for (n, edit) in edits.iter().enumerate() {
        let at = |msg: String| format!("edit {}: {msg}", n + 1);
        let mut lines = Vec::new();
        for raw in &edit.lines {
            if raw.contains('\n') || raw.contains('\r') {
                return Err(at("a line must not contain line breaks".into()));
            }
            let t = tokens(raw);
            if t.is_empty() {
                continue;
            }
            if !EDITABLE.contains(&t[0]) {
                return Err(at(format!("'{}' cannot be edited here", t[0])));
            }
            lines.push(t.join(" "));
        }
        let new_key = match lines.first() {
            Some(first) => {
                let key = object_key(first).ok_or_else(|| at("empty line".into()))?;
                if let Some(other) = lines.iter().find(|l| object_key(l).as_deref() != Some(key.as_str())) {
                    return Err(at(format!("'{other}' does not belong to {key}")));
                }
                Some(key)
            }
            None => None,
        };
        let key = match edit.mode {
            Mode::Create => new_key.clone().ok_or_else(|| at("nothing to create".into()))?,
            Mode::Replace | Mode::Delete => {
                let key = tokens(&edit.key).join(" ");
                if key.is_empty() {
                    return Err(at("key is required".into()));
                }
                key
            }
        };
        if edit.mode != Mode::Delete && new_key.is_none() {
            return Err(at("lines are required".into()));
        }
        if let Some(nk) = &new_key {
            if is_vdom_kind(nk) != is_vdom_kind(&key) {
                return Err(at(format!("{nk} and {key} are different kinds of object")));
            }
        }
        let scoped = is_vdom_kind(&key);
        if scoped && !valid_vdom(&edit.vdom) {
            return Err(at(format!("invalid vdom '{}'", edit.vdom)));
        }
        let target = if scoped { Some(edit.vdom.clone()) } else { None };
        let index = match secs.iter().position(|s| s.vdom == target) {
            Some(i) => i,
            None if edit.mode == Mode::Create => {
                secs.push(Section { vdom: target.clone(), lines: Vec::new() });
                secs.len() - 1
            }
            None => return Err(at(format!("vdom '{}' does not exist", edit.vdom))),
        };
        let section = &mut secs[index];
        let owned = |l: &String, k: &str| object_key(l).as_deref() == Some(k);
        let exists = section.lines.iter().any(|l| owned(l, &key));
        match edit.mode {
            Mode::Create if exists => return Err(at(format!("{key} already exists"))),
            Mode::Replace | Mode::Delete if !exists => return Err(at(format!("{key} not found"))),
            _ => {}
        }
        if let (Mode::Replace, Some(nk)) = (edit.mode, &new_key) {
            if nk != &key && section.lines.iter().any(|l| owned(l, nk)) {
                return Err(at(format!("{nk} already exists")));
            }
        }
        let position = section.lines.iter().position(|l| owned(l, &key)).unwrap_or(section.lines.len());
        section.lines.retain(|l| !owned(l, &key));
        let position = position.min(section.lines.len());
        for (i, line) in lines.into_iter().enumerate() {
            section.lines.insert(position + i, line);
        }
    }
    Ok(assemble(&secs))
}

/// Every object in canonical `text`, grouped by section, for the GUI.
pub fn model(text: &str) -> Value {
    let secs = sections(text);
    let mut out = Vec::new();
    for s in &secs {
        let mut objects: Vec<(String, Vec<String>)> = Vec::new();
        for line in &s.lines {
            let Some(key) = object_key(line) else { continue };
            match objects.iter_mut().find(|(k, _)| k == &key) {
                Some((_, lines)) => lines.push(line.clone()),
                None => objects.push((key, vec![line.clone()])),
            }
        }
        out.push(json!({
            "vdom": s.vdom,
            "objects": objects
                .into_iter()
                .map(|(key, lines)| json!({"key": key, "kind": key.split_whitespace().next().unwrap_or(""), "lines": lines}))
                .collect::<Vec<_>>(),
        }));
    }
    Value::Array(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Config;

    fn canonical(extra: &str) -> String {
        Config::parse(&format!(
            "interface eth0 zone trust address 10.0.0.1/24\n\
             interface eth1 zone untrust address 203.0.113.1/24\n{extra}"
        ))
        .unwrap()
        .to_text()
    }

    fn edit(mode: Mode, key: &str, lines: &[&str]) -> Edit {
        Edit { mode, vdom: "root".into(), key: key.into(), lines: lines.iter().map(|s| s.to_string()).collect() }
    }

    fn reparse(text: &str) -> Config {
        Config::parse(text).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    #[test]
    fn keys_group_multi_line_objects() {
        assert_eq!(object_key("ips-signature edge 2 /etc/passwd").unwrap(), "ips-profile edge");
        assert_eq!(object_key("url-filter corp block a.example").unwrap(), "url-filter corp");
        assert_eq!(object_key("route default eth1 via 10.0.0.254").unwrap(), "route default eth1 via 10.0.0.254");
        assert_eq!(object_key("default-rule intrazone deny zone guest log").unwrap(), "default-rule intrazone zone guest");
        assert_eq!(object_key("default-rule interzone deny").unwrap(), "default-rule interzone");
        assert_eq!(object_key("policy 10 trust untrust any any tcp 443 permit").unwrap(), "policy 10");
    }

    #[test]
    fn create_replace_and_delete_a_policy() {
        let text = canonical("policy 10 trust untrust any any tcp 443 permit\n");
        let text = apply(&text, &[edit(Mode::Create, "", &["policy 20 trust untrust any any udp 53 permit name dns"])]).unwrap();
        let cfg = reparse(&text);
        assert_eq!(cfg.policies.len(), 2);
        assert_eq!(cfg.policies[1].name.as_deref(), Some("dns"));

        let text = apply(&text, &[edit(Mode::Replace, "policy 10", &["policy 10 trust untrust any any tcp 8443 permit"])]).unwrap();
        assert_eq!(reparse(&text).policies.iter().find(|p| p.id == 10).unwrap().dst_port, Some(8443));

        let text = apply(&text, &[edit(Mode::Delete, "policy 20", &[])]).unwrap();
        assert_eq!(reparse(&text).policies.len(), 1);
    }

    #[test]
    fn existence_rules_are_enforced() {
        let text = canonical("policy 10 trust untrust any any tcp 443 permit\npolicy 20 trust untrust any any udp 53 permit\n");
        assert!(apply(&text, &[edit(Mode::Create, "", &["policy 10 trust untrust any any any any deny"])]).unwrap_err().contains("already exists"));
        assert!(apply(&text, &[edit(Mode::Delete, "policy 99", &[])]).unwrap_err().contains("not found"));
        // Renumbering onto an existing id is refused...
        let renumber = edit(Mode::Replace, "policy 10", &["policy 20 trust untrust any any tcp 443 permit"]);
        assert!(apply(&text, &[renumber]).unwrap_err().contains("already exists"));
        // ...but swapping two policies works as delete + delete + create + create.
        let swapped = apply(
            &text,
            &[
                edit(Mode::Delete, "policy 10", &[]),
                edit(Mode::Delete, "policy 20", &[]),
                edit(Mode::Create, "", &["policy 10 trust untrust any any udp 53 permit"]),
                edit(Mode::Create, "", &["policy 20 trust untrust any any tcp 443 permit"]),
            ],
        )
        .unwrap();
        let cfg = reparse(&swapped);
        assert_eq!(cfg.policies.iter().find(|p| p.id == 10).unwrap().dst_port, Some(53));
    }

    #[test]
    fn multi_line_profiles_are_replaced_whole() {
        let text = canonical("ips-profile edge\nips-signature edge 1 /etc/passwd\nips-signature edge 2 cmd.exe\n");
        let text = apply(&text, &[edit(Mode::Replace, "ips-profile edge", &["ips-profile edge", "ips-signature edge 1 /bin/sh"])]).unwrap();
        let cfg = reparse(&text);
        assert_eq!(cfg.ips_profiles[0].patterns, vec!["/bin/sh".to_string()]);
    }

    #[test]
    fn vdom_objects_go_to_their_vdom_and_globals_stay_global() {
        let text = canonical("vdom tenant2\ninterface eth9 zone t2 address 10.9.0.1/24\n");
        let text = apply(
            &text,
            &[
                Edit { mode: Mode::Create, vdom: "tenant2".into(), key: String::new(), lines: vec!["policy 50 t2 t2 any any any any permit".into()] },
                Edit { mode: Mode::Create, vdom: "tenant2".into(), key: String::new(), lines: vec!["address web 10.9.0.10".into()] },
            ],
        )
        .unwrap();
        let cfg = reparse(&text);
        assert_eq!(cfg.policies.iter().find(|p| p.id == 50).unwrap().vdom, "tenant2");
        assert!(cfg.addresses.iter().any(|a| a.name == "web"), "address is global");
        let before_vdom = text.split("\nvdom ").next().unwrap();
        assert!(before_vdom.contains("address web"), "global objects are written before any vdom section");
    }

    #[test]
    fn malformed_and_out_of_scope_edits_are_refused() {
        let text = canonical("");
        assert!(apply(&text, &[edit(Mode::Create, "", &["policy 1 a b any any any any permit\nvdom evil"])]).is_err());
        assert!(apply(&text, &[edit(Mode::Create, "", &["vdom evil"])]).unwrap_err().contains("cannot be edited"));
        assert!(apply(&text, &[edit(Mode::Create, "", &["vpn wg0 listen 51820"])]).unwrap_err().contains("cannot be edited"));
        assert!(apply(&text, &[edit(Mode::Create, "", &["policy 1 trust untrust any any any any permit", "address x 10.0.0.1"])])
            .unwrap_err()
            .contains("does not belong"));
        let bad_vdom = Edit { mode: Mode::Create, vdom: "../x".into(), key: String::new(), lines: vec!["policy 1 a b any any any any permit".into()] };
        assert!(apply(&text, &[bad_vdom]).unwrap_err().contains("invalid vdom"));
        assert!(apply(&text, &[edit(Mode::Replace, "policy 1", &["address x 10.0.0.1"])]).unwrap_err().contains("different kinds"));
    }

    #[test]
    fn model_groups_objects_by_section() {
        let text = canonical("ips-profile edge\nips-signature edge 1 x\npolicy 10 trust untrust any any tcp 443 permit\n");
        let m = model(&text);
        let global = &m[0]["objects"];
        let ips = global.as_array().unwrap().iter().find(|o| o["key"] == "ips-profile edge").unwrap();
        assert_eq!(ips["lines"].as_array().unwrap().len(), 2);
        let root = m.as_array().unwrap().iter().find(|s| s["vdom"] == "root").unwrap();
        assert!(root["objects"].as_array().unwrap().iter().any(|o| o["key"] == "policy 10" && o["kind"] == "policy"));
    }
}
