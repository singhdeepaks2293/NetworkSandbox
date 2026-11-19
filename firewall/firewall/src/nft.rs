//! Kernel nftables backend.
//!
//! The backend owns exactly one table, `inet vela`, and never flushes or
//! rewrites tables it did not create. Each apply destroys and recreates that
//! table in a single nfnetlink batch so a rejected configuration cannot leave
//! a partially installed ruleset behind. The userspace dataplane remains the
//! default path; callers opt into kernel enforcement explicitly.
//!
//! Exactness: [`kernel_problems`] refuses any configuration the kernel cannot
//! enforce *exactly*. Nothing is translated into a looser rule: a permit that
//! needs inspection, a user-scoped rule, or a deny whose IPv6 part or service
//! cannot be represented makes the whole plan fail with the reasons.
//!
//! Verification: every rule carries the comment `vela:<generation>:<index>`
//! (nftables user data). After an apply, [`read_back`] dumps the table over netlink and
//! [`verify`] compares chains, hooks, policies and every rule tag in order, so
//! a missing, extra (foreign), reordered or replaced rule is detected.

use crate::model::{Action, AddrRef, Cidr, Config, DnatRule, Policy, Proto, SnatTarget, APPLICATION_DEFAULT};
use netlink_packet_core::{
    DefaultNla, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_APPEND,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_netfilter::nftables::{
    Bitwise, ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions,
    Hook, Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator,
    Payload, Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict,
    VerdictAttribute,
};
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};
use std::collections::BTreeSet;
use std::os::fd::AsRawFd;

pub const TABLE: &str = "vela";
const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;
const NFT_MSG_DESTROYTABLE: u8 = 26;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const CT_STATE: u32 = 0;
const CT_INVALID: u32 = 1;
const CT_ESTABLISHED: u32 = 2;
const CT_RELATED: u32 = 4;
const NFT_NAT_DNAT: u32 = 1;
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
const NFTA_LOG_PREFIX: u16 = 2;
const NFTA_REJECT_TYPE: u16 = 1;
const NFTA_REJECT_ICMP_CODE: u16 = 2;
const NFT_REJECT_ICMPX_UNREACH: u32 = 2;
const NFT_REJECT_ICMPX_PORT_UNREACH: u32 = 1;
const NFPROTO_IPV4: u32 = 2;
const PAYLOAD_NETWORK: u32 = 1;
const PAYLOAD_TRANSPORT: u32 = 2;
const MAX_RULES_PER_POLICY: usize = 4096;

type Expr = ListAttribute<ExpressionAttribute>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanSummary {
    pub chains: usize,
    pub rules: usize,
}

/// Build the complete replacement batch for the dedicated `vela` table.
pub fn plan(cfg: &Config) -> Result<Vec<NfTablesMessage>, String> {
    plan_tagged(cfg).map(|(messages, _)| messages)
}

/// What a verified install must look like in the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    /// Fingerprint of the planned ruleset; part of every rule tag.
    pub generation: u64,
    /// (name, hook number, policy) of each base chain.
    pub chains: Vec<(String, u32, u32)>,
    /// (chain, tag) of every rule, in installation order.
    pub rules: Vec<(String, Vec<u8>)>,
}

/// A chain as read back from the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualChain {
    pub table: String,
    pub name: String,
    pub hook: Option<u32>,
    pub policy: Option<u32>,
}

/// A rule as read back from the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualRule {
    pub table: String,
    pub chain: String,
    pub userdata: Option<Vec<u8>>,
}

/// Plan plus the state verification expects. Refuses configurations the
/// kernel cannot enforce exactly (see [`kernel_problems`]).
pub fn plan_tagged(cfg: &Config) -> Result<(Vec<NfTablesMessage>, Expected), String> {
    let problems = kernel_problems(cfg);
    if !problems.is_empty() {
        return Err(format!(
            "the kernel dataplane cannot enforce this configuration exactly:\n  {}",
            problems.join("\n  ")
        ));
    }
    let mut messages = plan_inner(cfg)?;
    let generation = fnv64(format!("{messages:?}").as_bytes());
    let mut expected = Expected { generation, chains: Vec::new(), rules: Vec::new() };
    let mut index = 0usize;
    for message in &mut messages {
        match message {
            NfTablesMessage::NewChain(ChainMessage { attributes }) => {
                let name = attributes.iter().find_map(|a| match a { ChainAttribute::Name(n) => Some(n.clone()), _ => None });
                let policy = attributes.iter().find_map(|a| match a { ChainAttribute::Policy(p) => Some(*p), _ => None });
                let hook = attributes.iter().find_map(|a| match a {
                    ChainAttribute::Hook(h) => h.iter().find_map(|x| match x { Hook::Number(n) => Some(*n), _ => None }),
                    _ => None,
                });
                if let (Some(name), Some(policy), Some(hook)) = (name, policy, hook) {
                    expected.chains.push((name, hook.into(), policy));
                }
            }
            NfTablesMessage::NewRule(RuleMessage { attributes }) => {
                let chain = attributes
                    .iter()
                    .find_map(|a| match a { RuleAttribute::Chain(c) => Some(c.clone()), _ => None })
                    .unwrap_or_default();
                // Encoded as an nftables comment (udata TLV type 0, NUL
                // terminated) so `nft list` shows it instead of choking on
                // unknown user data.
                let text = format!("vela:{generation:016x}:{index}");
                let mut tag = vec![0u8, (text.len() + 1) as u8];
                tag.extend_from_slice(text.as_bytes());
                tag.push(0);
                index += 1;
                attributes.push(RuleAttribute::UserData(tag.clone()));
                expected.rules.push((chain, tag));
            }
            _ => {}
        }
    }
    Ok((messages, expected))
}

/// Apply the configuration with one atomic nfnetlink batch.
pub fn install(cfg: &Config) -> Result<PlanSummary, String> {
    let messages = plan(cfg)?;
    let summary = summarize(&messages);
    send_batch(&messages)?;
    Ok(summary)
}

/// Apply, then read the table back and verify it matches exactly.
pub fn install_verified(cfg: &Config) -> Result<Expected, String> {
    let (messages, expected) = plan_tagged(cfg)?;
    send_batch(&messages)?;
    check_installed(&expected)?;
    Ok(expected)
}

/// Read the table back and compare it with `expected`.
pub fn check_installed(expected: &Expected) -> Result<(), String> {
    let (chains, rules) = read_back()?;
    verify(expected, &chains, &rules).map_err(|problems| problems.join("; "))
}

/// Fail-closed fallback when no verified ruleset can be installed: replace
/// the table with a forward chain that drops everything. Local input and
/// output stay open so the firewall remains manageable.
pub fn install_lockdown() -> Result<(), String> {
    send_batch(&[
        destroy_table(),
        new_table(),
        chain("forward", "filter", InetHookNumber::Forward, 0, NF_DROP),
    ])
}

/// The kernel enforcement path as the engine drives it. [`Netlink`] is the
/// real implementation; tests substitute a fake.
pub trait Backend: Send + Sync {
    /// Refuse a configuration before anything touches the kernel.
    fn validate(&self, cfg: &Config) -> Result<(), String> {
        plan_tagged(cfg).map(|_| ())
    }
    /// Install `cfg` atomically and verify it by read-back.
    fn apply(&self, cfg: &Config) -> Result<(), String>;
    /// Verify that the last verified install is still in place.
    fn check(&self) -> Result<(), String>;
    /// Fail-closed fallback: drop all forwarded traffic.
    fn lockdown(&self) -> Result<(), String>;
}

/// The real kernel backend: nfnetlink batches plus read-back verification.
#[derive(Default)]
pub struct Netlink {
    expected: std::sync::Mutex<Option<Expected>>,
}

impl Backend for Netlink {
    fn apply(&self, cfg: &Config) -> Result<(), String> {
        let expected = install_verified(cfg)?;
        *self.expected.lock().unwrap() = Some(expected);
        Ok(())
    }
    fn check(&self) -> Result<(), String> {
        match self.expected.lock().unwrap().as_ref() {
            Some(expected) => check_installed(expected),
            None => Err("no verified ruleset is installed".to_string()),
        }
    }
    fn lockdown(&self) -> Result<(), String> {
        *self.expected.lock().unwrap() = None;
        install_lockdown()
    }
}

/// Everything in `cfg` the kernel backend cannot enforce exactly. Each entry
/// names the object and why; an empty list means the plan is exact.
pub fn kernel_problems(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.ha.enabled {
        out.push("ha: session synchronisation needs the userspace dataplane".to_string());
    }
    if !cfg.tunnels.is_empty() {
        out.push("vpn: WireGuard tunnels need the userspace dataplane".to_string());
    }
    for zone in &cfg.zones {
        if zone.syn_flood.is_some() || zone.udp_flood.is_some() || zone.icmp_flood.is_some() {
            out.push(format!("zone {}: flood protection needs the userspace dataplane", zone.name));
        }
    }
    if cfg.settings.source_rate > 0 {
        out.push("system source-rate: per-source rate limiting needs the userspace dataplane".to_string());
    }
    let has_v6 = |list: &[AddrRef]| list.iter().any(|r| addr_has_v6(cfg, r, 0));
    for policy in cfg.policies.iter().filter(|p| p.enabled) {
        let id = policy.id;
        if let Err(e) = kernel_supported(cfg, policy) {
            out.push(e);
            continue;
        }
        let scoped_users = !(policy.users.is_empty() || policy.users.iter().any(|u| u == "any"));
        if scoped_users {
            out.push(format!("policy {id}: user-scoped rules need User-ID, which only the userspace engine enforces"));
        }
        if policy.action == Action::Permit {
            for (what, set) in [
                ("url", policy.url.is_some()),
                ("ips", policy.ips.is_some()),
                ("av", policy.av.is_some()),
                ("shaper", policy.shaper.is_some()),
                ("profile group", policy.group.is_some()),
            ] {
                if set {
                    out.push(format!("policy {id}: the {what} profile needs inspection, which only the userspace engine performs"));
                }
            }
        } else {
            // Dropping any part of a deny would widen access.
            if has_v6(&policy.src) || has_v6(&policy.dst) {
                out.push(format!("policy {id}: IPv6 addresses in a deny are not translated, so the deny would be incomplete"));
            }
            if selectors(cfg, policy).is_none() {
                out.push(format!("policy {id}: its services cannot be represented, so the deny would be skipped"));
            }
        }
    }
    out
}

fn addr_has_v6(cfg: &Config, reference: &AddrRef, depth: usize) -> bool {
    if depth > 16 {
        return true;
    }
    match reference {
        AddrRef::Cidr(_) => false,
        AddrRef::Cidr6(_) => true,
        AddrRef::Named(name) => {
            if let Some(object) = cfg.addresses.iter().find(|a| &a.name == name) {
                return !object.entries6.is_empty();
            }
            cfg.address_groups
                .iter()
                .find(|g| &g.name == name)
                .is_some_and(|g| g.members.iter().any(|m| addr_has_v6(cfg, &AddrRef::Named(m.clone()), depth + 1)))
        }
    }
}

fn fnv64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Compare the read-back table with what was installed. Every difference is
/// reported: missing or extra chains, a changed hook or policy, and per
/// chain any missing, foreign, reordered or replaced rule.
pub fn verify(expected: &Expected, chains: &[ActualChain], rules: &[ActualRule]) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let ours: Vec<&ActualChain> = chains.iter().filter(|c| c.table == TABLE).collect();
    if ours.is_empty() && !expected.chains.is_empty() {
        return Err(vec![format!("table inet {TABLE} is missing or empty")]);
    }
    for (name, hook, policy) in &expected.chains {
        match ours.iter().find(|c| &c.name == name) {
            None => problems.push(format!("chain {name}: missing")),
            Some(c) => {
                if c.hook != Some(*hook) {
                    problems.push(format!("chain {name}: hook changed ({:?}, expected {hook})", c.hook));
                }
                if c.policy != Some(*policy) {
                    problems.push(format!("chain {name}: policy changed ({:?}, expected {policy})", c.policy));
                }
            }
        }
    }
    for c in &ours {
        if !expected.chains.iter().any(|(n, _, _)| n == &c.name) {
            problems.push(format!("chain {}: not installed by the firewall", c.name));
        }
    }
    let mut names: Vec<&str> = expected.rules.iter().map(|(c, _)| c.as_str()).collect();
    names.extend(rules.iter().filter(|r| r.table == TABLE).map(|r| r.chain.as_str()));
    names.sort();
    names.dedup();
    for chain in names {
        let want: Vec<&[u8]> = expected.rules.iter().filter(|(c, _)| c == chain).map(|(_, t)| t.as_slice()).collect();
        let have: Vec<Option<&[u8]>> = rules
            .iter()
            .filter(|r| r.table == TABLE && r.chain == chain)
            .map(|r| r.userdata.as_deref())
            .collect();
        let foreign = have.iter().filter(|t| !t.is_some_and(|t| want.contains(&t))).count();
        if foreign > 0 {
            problems.push(format!("chain {chain}: {foreign} rule(s) not installed by the firewall"));
        }
        let missing = want.iter().filter(|t| !have.contains(&Some(**t))).count();
        if missing > 0 {
            problems.push(format!("chain {chain}: {missing} installed rule(s) missing or replaced"));
        }
        if foreign == 0 && missing == 0 && have.iter().map(|t| t.unwrap()).collect::<Vec<_>>() != want {
            problems.push(format!("chain {chain}: rules reordered"));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems) }
}

// ------------------------------------------------------------- read-back

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NFT_MSG_NEWCHAIN: u8 = 3;
const NFT_MSG_GETCHAIN: u8 = 4;
const NFT_MSG_NEWRULE: u8 = 6;
const NFT_MSG_GETRULE: u8 = 7;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_USERDATA: u16 = 7;
const NFPROTO_INET: u8 = 1;

/// Dump the chains and rules of the owned table.
pub fn read_back() -> Result<(Vec<ActualChain>, Vec<ActualRule>), String> {
    let chains = dump(NFT_MSG_GETCHAIN, NFTA_CHAIN_TABLE)?
        .iter()
        .filter_map(|(t, body)| (*t == NFT_MSG_NEWCHAIN).then(|| parse_chain(body)))
        .collect();
    let rules = dump(NFT_MSG_GETRULE, NFTA_RULE_TABLE)?
        .iter()
        .filter_map(|(t, body)| (*t == NFT_MSG_NEWRULE).then(|| parse_rule(body)))
        .collect();
    Ok((chains, rules))
}

/// Attributes of one netlink message body (after the 4-byte nfgenmsg).
fn nlas(body: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 4 <= body.len() {
        let len = u16::from_ne_bytes([body[at], body[at + 1]]) as usize;
        let kind = u16::from_ne_bytes([body[at + 2], body[at + 3]]) & 0x3fff;
        if len < 4 || at + len > body.len() {
            break;
        }
        out.push((kind, &body[at + 4..at + len]));
        at += (len + 3) & !3;
    }
    out
}

fn nla_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data.split(|b| *b == 0).next().unwrap_or(&[])).into_owned()
}

fn nla_be32(data: &[u8]) -> Option<u32> {
    data.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn parse_chain(body: &[u8]) -> ActualChain {
    let mut c = ActualChain { table: String::new(), name: String::new(), hook: None, policy: None };
    for (kind, data) in nlas(body.get(4..).unwrap_or(&[])) {
        match kind {
            NFTA_CHAIN_TABLE => c.table = nla_string(data),
            NFTA_CHAIN_NAME => c.name = nla_string(data),
            NFTA_CHAIN_POLICY => c.policy = nla_be32(data),
            NFTA_CHAIN_HOOK => {
                c.hook = nlas(data).into_iter().find(|(k, _)| *k == NFTA_HOOK_HOOKNUM).and_then(|(_, d)| nla_be32(d))
            }
            _ => {}
        }
    }
    c
}

fn parse_rule(body: &[u8]) -> ActualRule {
    let mut r = ActualRule { table: String::new(), chain: String::new(), userdata: None };
    for (kind, data) in nlas(body.get(4..).unwrap_or(&[])) {
        match kind {
            NFTA_RULE_TABLE => r.table = nla_string(data),
            NFTA_RULE_CHAIN => r.chain = nla_string(data),
            NFTA_RULE_USERDATA => r.userdata = Some(data.to_vec()),
            _ => {}
        }
    }
    r
}

/// Split a receive buffer into (nftables message type, body) pairs. Returns
/// `Ok(true)` once NLMSG_DONE is seen.
fn split_dump(buf: &[u8], out: &mut Vec<(u8, Vec<u8>)>) -> Result<bool, String> {
    let mut at = 0usize;
    while at + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes([buf[at + 4], buf[at + 5]]);
        if len < 16 || at + len > buf.len() {
            return Err(format!("malformed netlink message ({len} bytes at offset {at})"));
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = buf.get(at + 16..at + 20).map(|b| i32::from_ne_bytes(b.try_into().unwrap())).unwrap_or(0);
                if code != 0 {
                    return Err(format!("nftables dump: {}", std::io::Error::from_raw_os_error(-code)));
                }
            }
            _ if kind >> 8 == NFNL_SUBSYS_NFTABLES => out.push(((kind & 0xff) as u8, buf[at + 16..at + len].to_vec())),
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Ok(false)
}

fn dump(message_type: u8, table_attr: u16) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let socket = open_socket()?;
    let mut name = TABLE.as_bytes().to_vec();
    name.push(0);
    let attr_len = 4 + name.len();
    let total = 16 + 4 + ((attr_len + 3) & !3);
    let mut req = Vec::with_capacity(total);
    req.extend_from_slice(&(total as u32).to_ne_bytes());
    req.extend_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | u16::from(message_type)).to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req.extend_from_slice(&2u32.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&[NFPROTO_INET, 0, 0, 0]);
    req.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    req.extend_from_slice(&table_attr.to_ne_bytes());
    req.extend_from_slice(&name);
    req.resize(total, 0);
    socket.send(&req, 0).map_err(|e| format!("send nftables dump request: {e}"))?;
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 256 * 1024];
    for _ in 0..100_000 {
        let mut receive = &mut buffer[..];
        let size = socket.recv(&mut receive, 0).map_err(|e| format!("read nftables dump: {e}"))?;
        if split_dump(&buffer[..size], &mut out)? {
            return Ok(out);
        }
    }
    Err("nftables dump did not terminate".into())
}

fn open_socket() -> Result<Socket, String> {
    let mut socket = Socket::new(NETLINK_NETFILTER).map_err(|e| format!("open netfilter socket: {e}"))?;
    socket.bind_auto().map_err(|e| format!("bind netfilter socket: {e}"))?;
    socket.connect(&SocketAddr::new(0, 0)).map_err(|e| format!("connect netfilter socket: {e}"))?;
    set_receive_timeout(socket.as_raw_fd())?;
    Ok(socket)
}

/// Remove only the table owned by this backend.
pub fn uninstall() -> Result<(), String> {
    send_batch(&[destroy_table()])
}

fn summarize(messages: &[NfTablesMessage]) -> PlanSummary {
    let mut chains = 0;
    let mut rules = 0;
    for message in messages {
        match message {
            NfTablesMessage::NewChain(_) => chains += 1,
            NfTablesMessage::NewRule(_) => rules += 1,
            _ => {}
        }
    }
    PlanSummary { chains, rules }
}

fn plan_inner(cfg: &Config) -> Result<Vec<NfTablesMessage>, String> {
    let mut messages = vec![destroy_table(), new_table()];

    messages.push(chain(
        "input",
        "filter",
        InetHookNumber::LocalIn,
        0,
        NF_ACCEPT,
    ));
    messages.push(chain(
        "output",
        "filter",
        InetHookNumber::LocalOut,
        0,
        NF_ACCEPT,
    ));
    messages.push(chain(
        "forward",
        "filter",
        InetHookNumber::Forward,
        0,
        NF_DROP,
    ));
    messages.push(chain(
        "prerouting",
        "nat",
        InetHookNumber::PreRouting,
        (-100i32) as u32,
        NF_ACCEPT,
    ));
    messages.push(chain(
        "postrouting",
        "nat",
        InetHookNumber::PostRouting,
        100,
        NF_ACCEPT,
    ));

    for chain_name in ["input", "output", "forward"] {
        messages.push(rule(chain_name, state_rule(CT_ESTABLISHED, NF_ACCEPT)));
        messages.push(rule(chain_name, state_rule(CT_RELATED, NF_ACCEPT)));
        messages.push(rule(chain_name, state_rule(CT_INVALID, NF_DROP)));
    }

    let mut policies: Vec<&Policy> = cfg.policies.iter().collect();
    policies.sort_by_key(|policy| policy.id);
    for policy in policies {
        if policy.enabled {
            messages.extend(policy_rules(cfg, policy)?);
        }
    }

    // Default rules set to allow: intrazone pairs within each zone, and
    // interzone pairs across zones. Denies need nothing: the chain drops.
    for vdom in &cfg.vdoms {
        let mut zones: Vec<&str> = cfg.interfaces.iter().filter(|i| &i.vdom == vdom).map(|i| i.zone.as_str()).collect();
        zones.sort();
        zones.dedup();
        for from in &zones {
            for to in &zones {
                let Some(d) = cfg.default_rule_for(vdom, from, to) else { continue };
                if d.action != Action::Permit {
                    continue;
                }
                for src_iface in zone_ifaces(cfg, vdom, from) {
                    for dst_iface in zone_ifaces(cfg, vdom, to) {
                        let mut exprs = Vec::new();
                        exprs.extend(meta_matches(MetaKey::Iifname, cstring(&src_iface)));
                        exprs.extend(meta_matches(MetaKey::Oifname, cstring(&dst_iface)));
                        exprs.push(counter());
                        if d.log && cfg.settings.logging {
                            exprs.push(log_expr("vela "));
                        }
                        exprs.push(verdict_expr(NF_ACCEPT));
                        messages.push(rule("forward", exprs));
                    }
                }
            }
        }
    }

    let mut snat_rules: Vec<_> = cfg.snat.iter().filter(|r| r.enabled).collect();
    snat_rules.sort_by_key(|rule| rule.id);
    for snat in snat_rules {
        if snat.to != SnatTarget::Masquerade {
            return Err(format!("snat {}: the kernel backend supports masquerade only", snat.id));
        }
        let sources = resolve_list(cfg, &snat.src)?;
        let destinations = resolve_list(cfg, &snat.dst)?;
        for src_iface in zones_ifaces(cfg, &snat.vdom, &snat.src_zones) {
            for dst_iface in zones_ifaces(cfg, &snat.vdom, &snat.dst_zones) {
                for source in &sources {
                    for destination in &destinations {
                        let mut exprs = Vec::new();
                        exprs.extend(meta_matches(MetaKey::Iifname, cstring(&src_iface)));
                        exprs.extend(meta_matches(MetaKey::Oifname, cstring(&dst_iface)));
                        exprs.extend(cidr_matches(12, *source)?);
                        exprs.extend(cidr_matches(16, *destination)?);
                        exprs.push(counter());
                        exprs.push(masq());
                        exprs.push(verdict_expr(NF_ACCEPT));
                        messages.push(rule("postrouting", exprs));
                    }
                }
            }
        }
    }

    let mut dnat_rules: Vec<&DnatRule> = cfg.dnat.iter().collect();
    dnat_rules.sort_by_key(|rule| rule.id);
    for dnat in dnat_rules {
        messages.push(rule("prerouting", dnat_expressions(dnat)?));
    }

    Ok(messages)
}

fn new_table() -> NfTablesMessage {
    NfTablesMessage::NewTable(TableMessage {
        attributes: vec![TableAttribute::Name(TABLE.into())],
    })
}

fn destroy_table() -> NfTablesMessage {
    let mut name = TABLE.as_bytes().to_vec();
    name.push(0);
    NfTablesMessage::Other {
        message_type: NFT_MSG_DESTROYTABLE,
        attributes: vec![DefaultNla::new(NFTA_TABLE_NAME, name)],
    }
}

fn chain(
    name: &str,
    kind: &str,
    hook: InetHookNumber,
    priority: u32,
    policy: u32,
) -> NfTablesMessage {
    NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table(TABLE.into()),
            ChainAttribute::Name(name.into()),
            ChainAttribute::Type(kind.into()),
            ChainAttribute::Hook(vec![Hook::Number(hook.into()), Hook::Priority(priority)]),
            ChainAttribute::Policy(policy),
        ],
    })
}

fn rule(chain: &str, expressions: Vec<Expr>) -> NfTablesMessage {
    NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(TABLE.into()),
            RuleAttribute::Chain(chain.into()),
            RuleAttribute::Expressions(expressions),
        ],
    })
}

fn state_rule(state: u32, verdict: u32) -> Vec<Expr> {
    vec![
        raw_expr(
            "ct",
            vec![
                DefaultNla::new(NFTA_CT_DREG, be32(Register::Reg1.into())),
                DefaultNla::new(NFTA_CT_KEY, be32(CT_STATE)),
            ],
        ),
        cmp_native_u32(state),
        verdict_expr(verdict),
    ]
}

/// The kernel backend enforces addresses, zones, protocols and ports. App-ID,
/// address negation and the services that depend on them stay in the
/// userspace engine; a policy that needs them is refused rather than widened.
fn kernel_supported(cfg: &Config, policy: &Policy) -> Result<(), String> {
    if policy.negate_src || policy.negate_dst {
        return Err(format!("policy {}: address negation is enforced only by the userspace engine", policy.id));
    }
    for app in &policy.apps {
        if app != "any" && !cfg.apps.iter().any(|a| &a.name == app) {
            return Err(format!("policy {}: application '{app}' needs App-ID, which only the userspace engine enforces", policy.id));
        }
    }
    if policy.services.iter().any(|s| s == APPLICATION_DEFAULT) && !policy.names_app() {
        return Err(format!("policy {}: application-default without an application needs App-ID", policy.id));
    }
    Ok(())
}

fn resolve_list(cfg: &Config, list: &[AddrRef]) -> Result<Vec<Cidr>, String> {
    let mut out = Vec::new();
    for reference in list {
        out.extend(resolve_cidrs(cfg, reference, 0)?);
    }
    Ok(dedup(out))
}

fn zones_ifaces(cfg: &Config, vdom: &str, zones: &[String]) -> Vec<String> {
    let mut names: Vec<String> = if zones.iter().any(|z| z == "any") {
        cfg.interfaces.iter().filter(|i| i.vdom == vdom).map(|i| i.name.clone()).collect()
    } else {
        zones.iter().flat_map(|z| zone_ifaces(cfg, vdom, z)).collect()
    };
    names.sort();
    names.dedup();
    names
}

fn policy_rules(cfg: &Config, policy: &Policy) -> Result<Vec<NfTablesMessage>, String> {
    kernel_supported(cfg, policy)?;
    let sources = resolve_list(cfg, &policy.src)?;
    let destinations = resolve_list(cfg, &policy.dst)?;
    let src_ifaces = zones_ifaces(cfg, &policy.vdom, &policy.src_zones);
    let dst_ifaces = zones_ifaces(cfg, &policy.vdom, &policy.dst_zones);
    if sources.is_empty()
        || destinations.is_empty()
        || src_ifaces.is_empty()
        || dst_ifaces.is_empty()
    {
        return Ok(Vec::new());
    }
    let selectors = match selectors(cfg, policy) {
        Some(selectors) => selectors,
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    let mut count = 0usize;
    for src_iface in &src_ifaces {
        for dst_iface in &dst_ifaces {
            for source in &sources {
                for destination in &destinations {
                    for selector in &selectors {
                        count += 1;
                        if count > MAX_RULES_PER_POLICY {
                            return Err(format!(
                                "policy {} expands to more than {MAX_RULES_PER_POLICY} kernel rules; narrow its zones or address objects",
                                policy.id
                            ));
                        }
                        let mut exprs = Vec::new();
                        exprs.extend(meta_matches(MetaKey::Iifname, cstring(src_iface)));
                        exprs.extend(meta_matches(MetaKey::Oifname, cstring(dst_iface)));
                        exprs.extend(cidr_matches(12, *source)?);
                        exprs.extend(cidr_matches(16, *destination)?);
                        exprs.extend(selector.exprs.clone());
                        exprs.push(counter());
                        if policy.log && cfg.settings.logging {
                            exprs.push(log_expr("vela "));
                        }
                        exprs.push(action_expr(selector.action));
                        out.push(rule("forward", exprs.clone()));

                        if policy.nat && policy.action == Action::Permit {
                            let mut nat = exprs;
                            nat.pop();
                            nat.push(masq());
                            nat.push(verdict_expr(NF_ACCEPT));
                            out.push(rule("postrouting", nat));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct Selector {
    exprs: Vec<Expr>,
    action: Action,
}

/// Largest port range expanded into individual kernel rules.
const MAX_RANGE: u16 = 64;

/// Flatten a service or service group into (protocol, port) pairs.
fn service_tuples(cfg: &Config, name: &str, depth: usize, out: &mut Vec<(Proto, Option<u16>)>) {
    if depth > 16 {
        return;
    }
    if let Some(service) = cfg.services.iter().find(|s| s.name == name) {
        if service.ports.is_empty() {
            out.push((service.proto, None));
        }
        for (lo, hi) in &service.ports {
            if hi - lo >= MAX_RANGE {
                // Too wide to expand: match the protocol only would widen the
                // rule, so leave the range to the userspace engine.
                continue;
            }
            for port in *lo..=*hi {
                out.push((service.proto, Some(port)));
            }
        }
    } else if let Some(group) = cfg.service_groups.iter().find(|g| g.name == name) {
        for member in &group.members {
            service_tuples(cfg, member, depth + 1, out);
        }
    }
}

fn selectors(cfg: &Config, policy: &Policy) -> Option<Vec<Selector>> {
    let mut tuples: Vec<(Proto, Option<u16>)> = Vec::new();
    if policy.names_app() {
        // Only custom (port-defined) applications reach here; see kernel_supported.
        for app in &policy.apps {
            if let Some(a) = cfg.apps.iter().find(|a| &a.name == app) {
                tuples.push((a.proto, Some(a.port)));
            }
        }
    } else if policy.services.is_empty() {
        tuples.push((Proto::Any, policy.dst_port));
    } else {
        for name in &policy.services {
            if name == "any" {
                tuples.push((Proto::Any, None));
            } else {
                service_tuples(cfg, name, 0, &mut tuples);
            }
        }
    }

    let mut out = Vec::new();
    for (service_proto, port) in tuples {
        let proto = match (policy.proto, service_proto) {
            (Proto::Any, other) => other,
            (left, Proto::Any) => left,
            (left, right) if left == right => left,
            _ => continue,
        };
        let proto_numbers: Vec<Option<u8>> = match (proto, port) {
            (Proto::Any, Some(_)) => vec![Some(6), Some(17)],
            (Proto::Any, None) => vec![None],
            (proto, _) => vec![proto.number()],
        };
        for proto_number in proto_numbers {
            let mut exprs = Vec::new();
            if let Some(number) = proto_number {
                exprs.extend(meta_matches(MetaKey::L4Proto, vec![number]));
            }
            if let Some(port) = port {
                if matches!(proto_number, Some(6) | Some(17)) {
                    exprs.extend(port_matches(port));
                }
            }
            out.push(Selector { exprs, action: policy.action });
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn dnat_expressions(dnat: &DnatRule) -> Result<Vec<Expr>, String> {
    let mut exprs = cidr_matches(16, dnat.dst)?;
    let proto_number = dnat.proto.number();
    if let Some(number) = proto_number {
        exprs.extend(meta_matches(MetaKey::L4Proto, vec![number]));
    }
    let port_matches_transport = dnat.dst_port.is_some();
    if let Some(port) = dnat.dst_port {
        if matches!(proto_number, Some(6) | Some(17) | None) {
            exprs.extend(port_matches(port));
        }
    }
    exprs.push(counter());
    exprs.push(immediate_value(
        Register::Reg1,
        dnat.to_ip.octets().to_vec(),
    ));
    let mut nat = vec![
        DefaultNla::new(NFTA_NAT_TYPE, be32(NFT_NAT_DNAT)),
        DefaultNla::new(NFTA_NAT_FAMILY, be32(NFPROTO_IPV4)),
        DefaultNla::new(NFTA_NAT_REG_ADDR_MIN, be32(Register::Reg1.into())),
        DefaultNla::new(NFTA_NAT_REG_ADDR_MAX, be32(Register::Reg1.into())),
    ];
    if let Some(port) = dnat.to_port {
        if port_matches_transport {
            exprs.push(immediate_value(Register::Reg2, port.to_be_bytes().to_vec()));
            nat.push(DefaultNla::new(
                NFTA_NAT_REG_PROTO_MIN,
                be32(Register::Reg2.into()),
            ));
            nat.push(DefaultNla::new(
                NFTA_NAT_REG_PROTO_MAX,
                be32(Register::Reg2.into()),
            ));
        }
    }
    exprs.push(raw_expr("nat", nat));
    Ok(exprs)
}

fn resolve_cidrs(cfg: &Config, reference: &AddrRef, depth: usize) -> Result<Vec<Cidr>, String> {
    if depth > 16 {
        return Err("address object nesting is too deep".into());
    }
    match reference {
        AddrRef::Cidr(cidr) => Ok(vec![*cidr]),
        // IPv6 prefixes are enforced by the userspace engine only.
        AddrRef::Cidr6(_) => Ok(Vec::new()),
        AddrRef::Named(name) => {
            if let Some(object) = cfg.addresses.iter().find(|a| &a.name == name) {
                return Ok(object.entries.clone());
            }
            if let Some(group) = cfg.address_groups.iter().find(|g| &g.name == name) {
                let mut out = Vec::new();
                for member in &group.members {
                    out.extend(resolve_cidrs(
                        cfg,
                        &AddrRef::Named(member.clone()),
                        depth + 1,
                    )?);
                }
                return Ok(dedup(out));
            }
            Err(format!("unknown address object '{name}'"))
        }
    }
}

fn dedup(cidrs: Vec<Cidr>) -> Vec<Cidr> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for cidr in cidrs {
        let key = (u32::from(cidr.addr), cidr.prefix);
        if seen.insert(key) {
            out.push(cidr);
        }
    }
    out
}

fn zone_ifaces(cfg: &Config, vdom: &str, zone: &str) -> Vec<String> {
    let mut names: Vec<String> = cfg
        .interfaces
        .iter()
        .filter(|i| i.vdom == vdom && i.zone == zone)
        .map(|i| i.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn cidr_matches(offset: u32, cidr: Cidr) -> Result<Vec<Expr>, String> {
    if cidr.prefix == 0 {
        return Ok(Vec::new());
    }
    // The table is family inet: without this guard an IPv4 address match
    // would compare bytes of an IPv6 header.
    let mut exprs = meta_matches(MetaKey::Nfproto, vec![NFPROTO_IPV4 as u8]);
    exprs.push(payload(PAYLOAD_NETWORK, offset, 4));
    if cidr.prefix < 32 {
        let mask = u32::MAX << (32 - cidr.prefix as u32);
        exprs.push(named_expr(
            "bitwise",
            Expressions::Bitwise(vec![
                Bitwise::SourceRegister(Register::Reg1),
                Bitwise::DestinationRegister(Register::Reg1),
                Bitwise::Length(4),
                Bitwise::Mask(DataAttribute::Value(mask.to_be_bytes().to_vec())),
                Bitwise::Xor(DataAttribute::Value(vec![0u8; 4])),
            ]),
        ));
    }
    exprs.push(cmp_bytes(cidr.addr.octets().to_vec()));
    Ok(exprs)
}

fn payload(base: u32, offset: u32, len: u32) -> Expr {
    named_expr(
        "payload",
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(base),
            Payload::Offset(offset),
            Payload::Len(len),
        ]),
    )
}

fn port_matches(port: u16) -> Vec<Expr> {
    vec![
        payload(PAYLOAD_TRANSPORT, 2, 2),
        cmp_bytes(port.to_be_bytes().to_vec()),
    ]
}

fn meta_matches(key: MetaKey, value: Vec<u8>) -> Vec<Expr> {
    vec![
        named_expr(
            "meta",
            Expressions::Meta(vec![
                Meta::DestinationRegister(Register::Reg1),
                Meta::Key(key),
            ]),
        ),
        cmp_bytes(value),
    ]
}

fn named_expr(name: &str, data: Expressions) -> Expr {
    ListAttribute::Element(vec![
        ExpressionAttribute::Name(name.into()),
        ExpressionAttribute::Data(data),
    ])
}

fn raw_expr(name: &str, attributes: Vec<DefaultNla>) -> Expr {
    ListAttribute::Element(vec![
        ExpressionAttribute::Name(name.into()),
        ExpressionAttribute::Data(Expressions::Other {
            expression_type: name.into(),
            attributes,
        }),
    ])
}

fn cmp_bytes(value: Vec<u8>) -> Expr {
    named_expr(
        "cmp",
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(value)),
        ]),
    )
}

fn cmp_native_u32(value: u32) -> Expr {
    cmp_bytes(value.to_ne_bytes().to_vec())
}

fn immediate_value(register: Register, value: Vec<u8>) -> Expr {
    named_expr(
        "immediate",
        Expressions::Immediate(vec![
            Immediate::DestinationRegister(register),
            Immediate::Data(DataAttribute::Value(value)),
        ]),
    )
}

fn counter() -> Expr {
    raw_expr("counter", Vec::new())
}

fn log_expr(prefix: &str) -> Expr {
    raw_expr(
        "log",
        vec![DefaultNla::new(NFTA_LOG_PREFIX, cstring(prefix))],
    )
}

fn masq() -> Expr {
    raw_expr("masq", Vec::new())
}

fn action_expr(action: Action) -> Expr {
    match action {
        Action::Permit => verdict_expr(NF_ACCEPT),
        Action::Deny => verdict_expr(NF_DROP),
        Action::Reject => raw_expr(
            "reject",
            vec![
                DefaultNla::new(NFTA_REJECT_TYPE, be32(NFT_REJECT_ICMPX_UNREACH)),
                DefaultNla::new(
                    NFTA_REJECT_ICMP_CODE,
                    vec![NFT_REJECT_ICMPX_PORT_UNREACH as u8],
                ),
            ],
        ),
    }
}

fn verdict_expr(code: u32) -> Expr {
    named_expr(
        "immediate",
        Expressions::Immediate(vec![
            Immediate::DestinationRegister(Register::Verdict),
            Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                Verdict::Other(code),
            )])),
        ]),
    )
}

fn cstring(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn be32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn send_batch(messages: &[NfTablesMessage]) -> Result<(), String> {
    let socket = open_socket()?;

    let seq = 1u32;
    let mut payload = Vec::new();
    payload.extend_from_slice(&batch_message(NFNL_MSG_BATCH_BEGIN, seq, false));
    for message in messages {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST;
        match message {
            NfTablesMessage::NewRule(_) => header.flags |= NLM_F_CREATE | NLM_F_APPEND,
            NfTablesMessage::NewTable(_) | NfTablesMessage::NewChain(_) => {
                header.flags |= NLM_F_CREATE
            }
            _ => {}
        }
        header.sequence_number = seq;
        let mut packet = NetlinkMessage::new(
            header,
            NetlinkPayload::from(NetfilterMessage::new(
                NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
                message.clone(),
            )),
        );
        packet.finalize();
        let mut bytes = vec![0u8; packet.buffer_len()];
        packet.serialize(&mut bytes);
        payload.extend_from_slice(&bytes);
    }
    payload.extend_from_slice(&batch_message(NFNL_MSG_BATCH_END, seq, true));

    let sent = socket
        .send(&payload, 0)
        .map_err(|e| format!("send nftables batch: {e}"))?;
    if sent != payload.len() {
        return Err(format!(
            "short nftables batch send ({sent} of {} bytes)",
            payload.len()
        ));
    }

    let mut buffer = [0u8; 64 * 1024];
    let mut receive_buffer = &mut buffer[..];
    let size = socket
        .recv(&mut receive_buffer, 0)
        .map_err(|e| format!("read nftables acknowledgement: {e}"))?;
    if size < 16 {
        return Err(format!("short nftables acknowledgement ({size} bytes)"));
    }
    let length = u32::from_ne_bytes(buffer[..4].try_into().unwrap()) as usize;
    if length < 16 || length > size {
        return Err(format!(
            "invalid nftables acknowledgement length {length} in {size}-byte reply"
        ));
    }
    let packet = <NetlinkMessage<NetfilterMessage>>::deserialize(&buffer[..length])
        .map_err(|e| format!("decode nftables acknowledgement: {e}"))?;
    match packet.payload {
        NetlinkPayload::Error(error) => {
            if let Some(code) = error.code {
                return Err(format!(
                    "nftables batch rejected: {}",
                    std::io::Error::from_raw_os_error(code.get())
                ));
            }
            Ok(())
        }
        NetlinkPayload::Done(_) => Ok(()),
        _ => Err("unexpected nftables acknowledgement payload".into()),
    }
}

fn set_receive_timeout(fd: std::os::unix::io::RawFd) -> Result<(), String> {
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(format!(
            "set netlink socket timeout: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn batch_message(message_type: u16, seq: u32, ack: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&20u32.to_ne_bytes());
    out.extend_from_slice(&message_type.to_ne_bytes());
    let mut flags = NLM_F_REQUEST;
    if ack {
        flags |= NLM_F_ACK;
    }
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.push(libc::AF_UNSPEC as u8);
    out.push(0);
    out.extend_from_slice(&NFNL_SUBSYS_NFTABLES.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample() -> Config {
        Config::parse(
            "system hostname nft-test\n\
             interface eth0 zone lan address 192.0.2.1/24\n\
             interface eth1 zone wan address 198.51.100.1/24\n\
             address web 203.0.113.10/32\n\
             address-group servers web\n\
             service https tcp 443\n\
             policy 20 lan wan @servers any any @https permit nat\n\
             policy 10 wan lan any any icmp any deny\n",
        )
        .unwrap()
    }

    #[test]
    fn plan_uses_only_the_owned_table() {
        let messages = plan(&sample()).unwrap();
        let summary = summarize(&messages);
        assert_eq!(summary.chains, 5);
        assert!(summary.rules > 6);
        let debug = format!("{messages:?}");
        assert!(debug.contains(TABLE));
        assert!(debug.contains("forward"));
    }

    #[test]
    fn named_groups_expand_to_literal_cidrs() {
        let cfg = sample();
        let cidrs = resolve_cidrs(&cfg, &AddrRef::Named("servers".into()), 0).unwrap();
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "203.0.113.10/32");
    }

    #[test]
    fn incompatible_service_protocol_produces_no_rule() {
        let cfg = Config::parse(
            "interface eth0 zone lan address 192.0.2.1/24\n\
             interface eth1 zone wan address 198.51.100.1/24\n\
             service dns udp 53\n\
             policy 1 lan wan any any tcp @dns permit\n",
        )
        .unwrap();
        assert!(selectors(&cfg, &cfg.policies[0]).is_none());
    }

    #[test]
    fn any_protocol_with_port_creates_tcp_and_udp_variants() {
        let cfg = Config::parse(
            "interface eth0 zone lan address 192.0.2.1/24\n\
             interface eth1 zone wan address 198.51.100.1/24\n\
             policy 1 lan wan any any any 443 permit\n",
        )
        .unwrap();
        let selectors = selectors(&cfg, &cfg.policies[0]).unwrap();
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn dnat_private_port_requires_a_public_port() {
        let result = Config::parse(
            "interface eth0 zone lan address 192.0.2.1/24\n\
             dnat 1 tcp any any 203.0.113.10 80\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn dnat_wildcard_destination_has_no_address_match() {
        let cfg = Config::parse(
            "interface eth0 zone lan address 192.0.2.1/24\n\
             interface eth1 zone wan address 198.51.100.1/24\n\
             dnat 1 any any any 203.0.113.10 any\n",
        )
        .unwrap();
        let exprs = dnat_expressions(&cfg.dnat[0]).unwrap();
        let debug = format!("{exprs:?}");
        assert_eq!(exprs.len(), 3);
        assert!(!debug.contains("payload"));
        assert!(!debug.contains("cmp"));
    }

    #[test]
    fn ipv4_address_matches_are_guarded_by_nfproto() {
        let exprs = cidr_matches(12, Cidr::parse("10.0.0.0/8").unwrap()).unwrap();
        let debug = format!("{exprs:?}");
        assert!(debug.contains("Nfproto"), "{debug}");
        assert!(cidr_matches(12, Cidr::ANY).unwrap().is_empty(), "any needs no guard and matches both families");
    }

    #[test]
    fn reject_sets_icmpx_port_unreachable_code() {
        let debug = format!("{:?}", action_expr(Action::Reject));
        assert!(debug.contains("value: [1]"));
        assert!(debug.contains("value: [0, 0, 0, 2]"));
    }

    #[test]
    fn cidr_prefix_contains_mask_and_literal() {
        let exprs = cidr_matches(
            12,
            Cidr {
                addr: Ipv4Addr::new(192, 0, 2, 0),
                prefix: 24,
            },
        )
        .unwrap();
        let debug = format!("{exprs:?}");
        assert!(debug.contains("bitwise"));
        assert!(debug.contains("cmp"));
    }

    // ---------------------------------------------- Stage 2: exactness,
    // tagging, read-back parsing and verification.

    fn two_zone(extra: &str) -> Config {
        Config::parse(&format!(
            "interface eth0 zone lan address 192.0.2.1/24\n\
             interface eth1 zone wan address 198.51.100.1/24\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn exact_configs_have_no_kernel_problems() {
        let cfg = two_zone("policy 10 lan wan any any tcp 443 permit\npolicy 20 lan wan any 203.0.113.0/24 any any deny\n");
        assert!(kernel_problems(&cfg).is_empty(), "{:?}", kernel_problems(&cfg));
        assert!(plan_tagged(&cfg).is_ok());
    }

    #[test]
    fn inspection_profiles_are_refused_not_weakened() {
        let cfg = two_zone("url-filter corp block example.com\npolicy 10 lan wan any any tcp any permit url corp\n");
        let p = kernel_problems(&cfg);
        assert!(p.iter().any(|x| x.contains("policy 10") && x.contains("url")), "{p:?}");
        let err = plan_tagged(&cfg).unwrap_err();
        assert!(err.contains("cannot enforce this configuration exactly"), "{err}");
    }

    #[test]
    fn user_scoped_rules_are_refused() {
        let cfg = two_zone("policy 10 lan wan any any tcp any permit user alice\n");
        assert!(kernel_problems(&cfg).iter().any(|x| x.contains("User-ID")));
    }

    #[test]
    fn deny_with_ipv6_parts_is_refused_because_it_would_widen() {
        let cfg = two_zone("policy 10 lan wan any 2001:db8::/32 any any deny\npolicy 20 lan wan any any any any permit\n");
        let p = kernel_problems(&cfg);
        assert!(p.iter().any(|x| x.contains("policy 10") && x.contains("IPv6")), "{p:?}");
        // The same through a named object.
        let cfg = two_zone("address v6net 2001:db8::/32\npolicy 10 lan wan any @v6net any any deny\n");
        assert!(kernel_problems(&cfg).iter().any(|x| x.contains("IPv6")));
        // A permit with an IPv6 part only narrows, so it is allowed.
        let cfg = two_zone("policy 10 lan wan any 2001:db8::/32 any any permit\n");
        assert!(kernel_problems(&cfg).is_empty());
    }

    #[test]
    fn deny_with_unrepresentable_service_is_refused() {
        let cfg = two_zone("service dns udp 53\npolicy 1 lan wan any any tcp @dns deny\n");
        assert!(kernel_problems(&cfg).iter().any(|x| x.contains("would be skipped")));
    }

    #[test]
    fn userspace_only_features_are_refused() {
        let cfg = two_zone("zone lan syn-flood 100\n");
        assert!(kernel_problems(&cfg).iter().any(|x| x.contains("flood")));
        let cfg = two_zone("system source-rate 100\nsystem source-burst 100\n");
        assert!(kernel_problems(&cfg).iter().any(|x| x.contains("source-rate")));
    }

    #[test]
    fn every_rule_gets_a_unique_generation_tag() {
        let cfg = two_zone("policy 10 lan wan any any tcp 443 permit\npolicy 20 lan wan any any udp 53 permit\n");
        let (messages, expected) = plan_tagged(&cfg).unwrap();
        let rules = messages.iter().filter(|m| matches!(m, NfTablesMessage::NewRule(_))).count();
        assert_eq!(expected.rules.len(), rules);
        let mut tags: Vec<_> = expected.rules.iter().map(|(_, t)| t.clone()).collect();
        tags.sort();
        tags.dedup();
        assert_eq!(tags.len(), rules, "tags are unique");
        let prefix = format!("vela:{:016x}:", expected.generation);
        assert!(expected.rules.iter().all(|(_, t)| t[0] == 0 && usize::from(t[1]) == t.len() - 2 && t[2..].starts_with(prefix.as_bytes()) && *t.last().unwrap() == 0),
            "comment TLV: type 0, length, NUL-terminated text");
        assert_eq!(expected.chains.len(), 5);
        // Same configuration, same generation; a change gives a new one.
        assert_eq!(plan_tagged(&cfg).unwrap().1.generation, expected.generation);
        let other = two_zone("policy 10 lan wan any any tcp 8443 permit\n");
        assert_ne!(plan_tagged(&other).unwrap().1.generation, expected.generation);
    }

    /// Serialize a planned message the way the kernel sends it in a dump.
    fn as_dump_reply(message: &NfTablesMessage) -> Vec<u8> {
        let mut header = NetlinkHeader::default();
        header.flags = 2; // NLM_F_MULTI
        let mut packet = NetlinkMessage::new(
            header,
            NetlinkPayload::from(NetfilterMessage::new(NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0), message.clone())),
        );
        packet.finalize();
        let mut bytes = vec![0u8; packet.buffer_len()];
        packet.serialize(&mut bytes);
        bytes
    }

    fn done() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&20u32.to_ne_bytes());
        b.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        b.extend_from_slice(&[0u8; 14]);
        b
    }

    /// What the kernel would return for a correct install of `expected`.
    fn readback_of(messages: &[NfTablesMessage]) -> (Vec<ActualChain>, Vec<ActualRule>) {
        let mut buf = Vec::new();
        for m in messages {
            if matches!(m, NfTablesMessage::NewChain(_) | NfTablesMessage::NewRule(_)) {
                buf.extend(as_dump_reply(m));
            }
        }
        buf.extend(done());
        let mut out = Vec::new();
        assert!(split_dump(&buf, &mut out).unwrap(), "NLMSG_DONE ends the dump");
        let chains = out.iter().filter(|(t, _)| *t == NFT_MSG_NEWCHAIN).map(|(_, b)| parse_chain(b)).collect();
        let rules = out.iter().filter(|(t, _)| *t == NFT_MSG_NEWRULE).map(|(_, b)| parse_rule(b)).collect();
        (chains, rules)
    }

    #[test]
    fn dump_replies_parse_back_to_tables_chains_hooks_and_tags() {
        let cfg = two_zone("policy 10 lan wan any any tcp 443 permit\n");
        let (messages, expected) = plan_tagged(&cfg).unwrap();
        let (chains, rules) = readback_of(&messages);
        assert_eq!(chains.len(), 5);
        let fwd = chains.iter().find(|c| c.name == "forward").unwrap();
        assert_eq!((fwd.table.as_str(), fwd.policy), (TABLE, Some(NF_DROP)));
        assert_eq!(fwd.hook, Some(u32::from(InetHookNumber::Forward)));
        assert_eq!(rules.len(), expected.rules.len());
        assert_eq!(rules[0].userdata.as_deref(), Some(expected.rules[0].1.as_slice()));
        verify(&expected, &chains, &rules).unwrap();
    }

    #[test]
    fn dump_error_replies_are_reported() {
        let mut b = Vec::new();
        b.extend_from_slice(&36u32.to_ne_bytes());
        b.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        b.extend_from_slice(&[0u8; 10]);
        b.extend_from_slice(&(-2i32).to_ne_bytes()); // -ENOENT
        b.extend_from_slice(&[0u8; 16]);
        let err = split_dump(&b, &mut Vec::new()).unwrap_err();
        assert!(err.contains("No such file"), "{err}");
        assert!(split_dump(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut Vec::new()).is_err(), "bad length");
    }

    #[test]
    fn verify_detects_missing_foreign_reordered_and_changed_state() {
        let cfg = two_zone("policy 10 lan wan any any tcp 443 permit\npolicy 20 lan wan any any udp 53 permit\n");
        let (messages, expected) = plan_tagged(&cfg).unwrap();
        let (chains, rules) = readback_of(&messages);
        let forward: Vec<usize> = rules.iter().enumerate().filter(|(_, r)| r.chain == "forward").map(|(i, _)| i).collect();

        let mut missing = rules.clone();
        missing.remove(*forward.last().unwrap());
        assert!(verify(&expected, &chains, &missing).unwrap_err().iter().any(|p| p.contains("missing")));

        let mut foreign = rules.clone();
        foreign.insert(forward[0], ActualRule { table: TABLE.into(), chain: "forward".into(), userdata: None });
        assert!(verify(&expected, &chains, &foreign).unwrap_err().iter().any(|p| p.contains("not installed by the firewall")));

        let mut reordered = rules.clone();
        reordered.swap(forward[0], *forward.last().unwrap());
        assert!(verify(&expected, &chains, &reordered).unwrap_err().iter().any(|p| p.contains("reordered")));

        let mut opened = chains.clone();
        opened.iter_mut().find(|c| c.name == "forward").unwrap().policy = Some(NF_ACCEPT);
        assert!(verify(&expected, &opened, &rules).unwrap_err().iter().any(|p| p.contains("policy changed")));

        let mut extra = chains.clone();
        extra.push(ActualChain { table: TABLE.into(), name: "sneaky".into(), hook: Some(2), policy: Some(NF_ACCEPT) });
        assert!(verify(&expected, &extra, &rules).is_err());

        assert!(verify(&expected, &[], &[]).unwrap_err()[0].contains("missing"));
        // Another table's rules are not ours to judge.
        let mut other = rules.clone();
        other.push(ActualRule { table: "filter".into(), chain: "forward".into(), userdata: None });
        verify(&expected, &chains, &other).unwrap();
    }
}
