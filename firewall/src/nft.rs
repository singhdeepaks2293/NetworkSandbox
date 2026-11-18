//! Kernel nftables backend.
//!
//! The backend owns exactly one table, `inet vela`, and never flushes or
//! rewrites tables it did not create. Each apply destroys and recreates that
//! table in a single nfnetlink batch so a rejected configuration cannot leave
//! a partially installed ruleset behind. The userspace dataplane remains the
//! default path; callers opt into kernel enforcement explicitly.

use crate::model::{Action, AddrRef, Cidr, Config, DnatRule, Policy, Proto, SnatTarget, APPLICATION_DEFAULT};
use netlink_packet_core::{
    DefaultNla, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_APPEND,
    NLM_F_CREATE, NLM_F_REQUEST,
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
    plan_inner(cfg)
}

/// Apply the configuration with one atomic nfnetlink batch.
pub fn install(cfg: &Config) -> Result<PlanSummary, String> {
    let messages = plan(cfg)?;
    let summary = summarize(&messages);
    send_batch(&messages)?;
    Ok(summary)
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
    let mut socket =
        Socket::new(NETLINK_NETFILTER).map_err(|e| format!("open netfilter socket: {e}"))?;
    socket
        .bind_auto()
        .map_err(|e| format!("bind netfilter socket: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("connect netfilter socket: {e}"))?;
    set_receive_timeout(socket.as_raw_fd())?;

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
}
