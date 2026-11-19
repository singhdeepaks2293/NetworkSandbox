/* NetworkSandbox Firewall UI — configuration object model.
 *
 * Pure functions, no DOM: turn canonical configuration lines (as written by
 * Config::to_text) into form values and back. Option order in build()
 * follows to_text, so parse() then build() is byte-identical; the Node test
 * (tests/ui-model.test.js) checks that for every kind. The server still
 * parses and validates every edit; the checks here only give earlier,
 * friendlier errors.
 */
'use strict';

const Model = (() => {
  const tok = (line) => String(line).trim().split(/\s+/).filter(Boolean);
  // "a, b c" -> "a,b,c"; empty -> fallback
  const list = (s, fallback = 'any') => {
    const parts = String(s ?? '').split(/[\s,]+/).filter(Boolean);
    return parts.length ? parts.join(',') : fallback;
  };
  const words = (s) => String(s ?? '').split(/[\s,]+/).filter(Boolean);
  const lines = (s) => String(s ?? '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const one = (s) => String(s ?? '').trim();
  const isName = (s) => /^[A-Za-z0-9][A-Za-z0-9_.:\\-]*$/.test(s);

  class FormError extends Error {}
  const need = (cond, msg) => { if (!cond) throw new FormError(msg); };
  const name = (v, label = 'Name') => {
    const n = one(v);
    need(n, `${label} is required`);
    need(isName(n), `${label} may contain letters, digits and . _ : - only (no spaces)`);
    return n;
  };
  const optName = (v, label) => (one(v) ? name(v, label) : '');
  const int = (v, label, min = 0, max = 4294967295) => {
    const n = Number(one(v));
    need(one(v) !== '' && Number.isInteger(n) && n >= min && n <= max, `${label} must be a whole number from ${min} to ${max}`);
    return n;
  };

  const PROTOS = ['any', 'tcp', 'udp', 'icmp'];
  const ACTIONS = ['permit', 'deny', 'reject'];
  const POLICY_KV = { name: 'name', app: 'apps', user: 'users', url: 'url', ips: 'ips', av: 'av', shaper: 'shaper', group: 'group' };

  /* Each kind: scope (vdom|global), key(values), parse(lines) -> values,
   * build(values) -> lines, defaults(ctx), fields (form). */
  const K = {};

  K.policy = {
    label: 'Security Policy', scope: 'vdom', sort: (a, b) => a.id - b.id,
    key: (v) => `policy ${v.id}`,
    parse(ls) {
      const t = tok(ls[0]);
      const v = { id: Number(t[1]), srcZones: t[2], dstZones: t[3], src: t[4], dst: t[5], proto: t[6], service: t[7], action: t[8],
        nat: false, log: true, enabled: true, name: '', apps: '', users: '', url: '', ips: '', av: '', shaper: '', group: '' };
      for (let i = 9; i < t.length; i++) {
        const w = t[i];
        if (w === 'nat') v.nat = true;
        else if (w === 'nolog') v.log = false;
        else if (w === 'disable') v.enabled = false;
        else if (POLICY_KV[w]) v[POLICY_KV[w]] = t[++i] ?? '';
      }
      return v;
    },
    build(v) {
      const id = int(v.id, 'ID', 1);
      need(PROTOS.includes(v.proto || 'any'), 'Protocol must be any, tcp, udp or icmp');
      need(ACTIONS.includes(v.action), 'Action must be permit, deny or reject');
      const p = ['policy', id, list(v.srcZones), list(v.dstZones), list(v.src), list(v.dst), v.proto || 'any', list(v.service), v.action];
      if (v.nat) p.push('nat');
      if (!v.log) p.push('nolog');
      if (!v.enabled) p.push('disable');
      const n = optName(v.name, 'Name'); if (n) p.push('name', n);
      if (words(v.apps).length) p.push('app', list(v.apps));
      if (words(v.users).length) p.push('user', list(v.users));
      for (const k of ['url', 'ips', 'av', 'shaper', 'group']) { const x = optName(v[k], k.toUpperCase()); if (x) p.push(k, x); }
      return [p.join(' ')];
    },
    defaults: (ctx) => ({ id: ctx.nextId('policy'), srcZones: '', dstZones: '', src: 'any', dst: 'any', proto: 'any', service: 'any', action: 'permit', nat: false, log: true, enabled: true }),
    fields: [
      { k: 'id', label: 'ID (evaluation order)', type: 'number', help: 'Lower IDs are evaluated first.' },
      { k: 'name', label: 'Name' },
      { section: 'Match' },
      { k: 'srcZones', label: 'Incoming zones', type: 'list', dl: 'zones', help: 'Comma-separated; "any" for all.' },
      { k: 'dstZones', label: 'Outgoing zones', type: 'list', dl: 'zones' },
      { k: 'src', label: 'Source', type: 'list', dl: 'addrs', help: 'CIDR, @object or @group; prefix "!" to negate.' },
      { k: 'dst', label: 'Destination', type: 'list', dl: 'addrs', help: 'CIDR, @object or @group; prefix "!" to negate.' },
      { k: 'proto', label: 'Protocol', type: 'select', options: PROTOS },
      { k: 'service', label: 'Service / port', type: 'list', dl: 'services', help: 'any, a port, @service,… or application-default.' },
      { k: 'apps', label: 'Applications', type: 'list', dl: 'apps', help: 'App-ID names, app groups or category:<name>.' },
      { k: 'users', label: 'Users', type: 'list', dl: 'users', help: 'Users, user groups, known-user or unknown.' },
      { section: 'Action' },
      { k: 'action', label: 'Action', type: 'select', options: ACTIONS },
      { k: 'nat', label: 'Source NAT (masquerade)', type: 'check' },
      { k: 'log', label: 'Log traffic', type: 'check' },
      { k: 'enabled', label: 'Enabled', type: 'check' },
      { section: 'Security profiles' },
      { k: 'group', label: 'Profile group', type: 'select', options: (c) => c.names('profile-group') },
      { k: 'url', label: 'URL filter', type: 'select', options: (c) => c.names('url-filter') },
      { k: 'ips', label: 'IPS profile', type: 'select', options: (c) => c.names('ips-profile') },
      { k: 'av', label: 'AV profile', type: 'select', options: (c) => c.names('av-profile') },
      { k: 'shaper', label: 'Traffic shaper', type: 'select', options: (c) => c.names('shaper') },
    ],
  };

  K.snat = {
    label: 'Source NAT rule', scope: 'vdom', sort: (a, b) => a.id - b.id,
    key: (v) => `snat ${v.id}`,
    parse(ls) {
      const t = tok(ls[0]);
      const v = { id: Number(t[1]), srcZones: t[2], dstZones: t[3], src: t[4], dst: t[5], to: t[6], name: '', enabled: true };
      for (let i = 7; i < t.length; i++) { if (t[i] === 'name') v.name = t[++i] ?? ''; else if (t[i] === 'disable') v.enabled = false; }
      return v;
    },
    build(v) {
      const p = ['snat', int(v.id, 'ID', 1), list(v.srcZones), list(v.dstZones), list(v.src), list(v.dst), one(v.to) || 'masquerade'];
      const n = optName(v.name, 'Name'); if (n) p.push('name', n);
      if (!v.enabled) p.push('disable');
      return [p.join(' ')];
    },
    defaults: (ctx) => ({ id: ctx.nextId('snat'), srcZones: '', dstZones: '', src: 'any', dst: 'any', to: 'masquerade', enabled: true }),
    fields: [
      { k: 'id', label: 'ID', type: 'number' }, { k: 'name', label: 'Name' },
      { k: 'srcZones', label: 'Incoming zones', type: 'list', dl: 'zones' }, { k: 'dstZones', label: 'Outgoing zones', type: 'list', dl: 'zones' },
      { k: 'src', label: 'Source', type: 'list', dl: 'addrs' }, { k: 'dst', label: 'Destination', type: 'list', dl: 'addrs' },
      { k: 'to', label: 'Translate to', help: '"masquerade" (egress interface address) or an IPv4 address.' },
      { k: 'enabled', label: 'Enabled', type: 'check' },
    ],
  };

  K.dnat = {
    label: 'Destination NAT / VIP', scope: 'vdom', sort: (a, b) => a.id - b.id,
    key: (v) => `dnat ${v.id}`,
    parse(ls) {
      const t = tok(ls[0]);
      const v = { id: Number(t[1]), proto: t[2], dst: t[3], dport: t[4], toIp: t[5], toPort: t[6], name: '' };
      for (let i = 7; i < t.length; i++) if (t[i] === 'name') v.name = t[++i] ?? '';
      return v;
    },
    build(v) {
      need(one(v.dst), 'External address is required'); need(one(v.toIp), 'Mapped address is required');
      const port = (x) => (one(x) && one(x) !== 'any' ? int(x, 'Port', 1, 65535) : 'any');
      const p = ['dnat', int(v.id, 'ID', 1), v.proto || 'tcp', one(v.dst), port(v.dport), one(v.toIp), port(v.toPort)];
      const n = optName(v.name, 'Name'); if (n) p.push('name', n);
      return [p.join(' ')];
    },
    defaults: (ctx) => ({ id: ctx.nextId('dnat'), proto: 'tcp', dst: '', dport: '', toIp: '', toPort: '' }),
    fields: [
      { k: 'id', label: 'ID', type: 'number' }, { k: 'name', label: 'Name' },
      { k: 'proto', label: 'Protocol', type: 'select', options: ['tcp', 'udp'] },
      { k: 'dst', label: 'External address', help: 'e.g. 203.0.113.2/32, or "any".' },
      { k: 'dport', label: 'External port', help: 'Port, or "any".' },
      { k: 'toIp', label: 'Mapped (internal) address' }, { k: 'toPort', label: 'Mapped port', help: 'Port, or "any" to keep it.' },
    ],
  };

  const routeKind = (stmt, withName) => ({
    label: stmt === 'route' ? 'Static route (IPv4)' : 'Static route (IPv6)', scope: 'vdom',
    sort: (a, b) => a.dst.localeCompare(b.dst),
    key: (v) => K[stmt].build(v)[0],
    parse(ls) {
      const t = tok(ls[0]);
      const v = { dst: t[1], iface: t[2], via: '', distance: '', name: '' };
      for (let i = 3; i < t.length; i++) {
        if (t[i] === 'via') v.via = t[++i] ?? ''; else if (t[i] === 'distance') v.distance = t[++i] ?? ''; else if (t[i] === 'name') v.name = t[++i] ?? '';
      }
      return v;
    },
    build(v) {
      need(one(v.dst), 'Destination is required'); need(one(v.iface), 'Interface is required');
      const p = [stmt, one(v.dst), one(v.iface)];
      if (one(v.via)) p.push('via', one(v.via));
      if (one(v.distance)) p.push('distance', int(v.distance, 'Distance', 1, 255));
      if (withName) { const n = optName(v.name, 'Name'); if (n) p.push('name', n); }
      return [p.join(' ')];
    },
    defaults: () => ({ dst: '', iface: '', via: '', distance: '', name: '' }),
    fields: [
      { k: 'dst', label: 'Destination', help: stmt === 'route' ? 'CIDR or "default".' : 'IPv6 prefix or "default".' },
      { k: 'iface', label: 'Interface', type: 'select', options: (c) => c.interfaces() },
      { k: 'via', label: 'Gateway', help: 'Next hop; empty for directly connected.' },
      { k: 'distance', label: 'Administrative distance', type: 'number', help: 'Lower wins; empty for the default.' },
      ...(withName ? [{ k: 'name', label: 'Name' }] : []),
    ],
  });
  K.route = routeKind('route', true);
  K.route6 = routeKind('route6', false);

  const membersKind = (stmt, label, memberLabel, dl, help) => ({
    label, scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `${stmt} ${v.name}`,
    parse: (ls) => { const t = tok(ls[0]); return { name: t[1], members: t.slice(2).join('\n') }; },
    build(v) {
      const m = words(v.members);
      need(m.length, `${memberLabel} needs at least one entry`);
      return [[stmt, name(v.name), ...m].join(' ')];
    },
    defaults: () => ({ name: '', members: '' }),
    fields: [{ k: 'name', label: 'Name', wide: true }, { k: 'members', label: memberLabel, type: 'area', wide: true, dl, help: help || 'One per line.' }],
  });
  K.address = membersKind('address', 'Address object', 'Addresses', null, 'One IPv4 or IPv6 address or prefix per line.');
  K['address-group'] = membersKind('address-group', 'Address group', 'Members', 'addrnames', 'Address objects or groups, one per line.');
  K['service-group'] = membersKind('service-group', 'Service group', 'Members', 'svcnames');
  K['app-group'] = membersKind('app-group', 'Application group', 'Applications', 'apps', 'App-ID names, custom apps or category:<name>, one per line.');
  K['user-group'] = membersKind('user-group', 'User group', 'Members', 'users', 'User names or nested groups, one per line.');

  K.service = {
    label: 'Service', scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `service ${v.name}`,
    parse: (ls) => { const t = tok(ls[0]); return { name: t[1], proto: t[2], ports: t[3] ?? '' }; },
    build: (v) => { need(one(v.ports), 'Ports are required'); return [`service ${name(v.name)} ${v.proto} ${list(v.ports, '')}`]; },
    defaults: () => ({ name: '', proto: 'tcp', ports: '' }),
    fields: [{ k: 'name', label: 'Name' }, { k: 'proto', label: 'Protocol', type: 'select', options: ['tcp', 'udp'] },
      { k: 'ports', label: 'Ports', help: 'e.g. 80,443,8000-8080' }],
  };

  K['app-def'] = {
    label: 'Custom application', scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `app-def ${v.name}`,
    parse: (ls) => { const t = tok(ls[0]); return { name: t[1], proto: t[2], port: t[3] }; },
    build: (v) => [`app-def ${name(v.name)} ${v.proto} ${int(v.port, 'Port', 1, 65535)}`],
    defaults: () => ({ name: '', proto: 'tcp', port: '' }),
    fields: [{ k: 'name', label: 'Name' }, { k: 'proto', label: 'Protocol', type: 'select', options: ['tcp', 'udp'] }, { k: 'port', label: 'Port', type: 'number' }],
  };

  K['user-map'] = {
    label: 'Static user mapping', scope: 'global', sort: (a, b) => a.cidr.localeCompare(b.cidr),
    key: (v) => `user-map ${v.cidr}`,
    parse: (ls) => { const t = tok(ls[0]); return { cidr: t[1], user: t[2] }; },
    build: (v) => { need(one(v.cidr), 'Address is required'); return [`user-map ${one(v.cidr)} ${name(v.user, 'User')}`]; },
    defaults: () => ({ cidr: '', user: '' }),
    fields: [{ k: 'cidr', label: 'Address or prefix (IPv4)' }, { k: 'user', label: 'User', dl: 'users' }],
  };

  K['url-filter'] = {
    label: 'URL filter', scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `url-filter ${v.name}`,
    parse(ls) {
      const v = { name: tok(ls[0])[1], block: '', allow: '' };
      for (const l of ls) { const t = tok(l); if (t[2] === 'block') v.block = t.slice(3).join('\n'); if (t[2] === 'allow') v.allow = t.slice(3).join('\n'); }
      return v;
    },
    build(v) {
      const n = name(v.name); const b = words(v.block); const a = words(v.allow);
      need(b.length || a.length, 'Add at least one blocked or allowed domain');
      const out = [];
      if (b.length) out.push(`url-filter ${n} block ${b.join(' ')}`);
      if (a.length) out.push(`url-filter ${n} allow ${a.join(' ')}`);
      return out;
    },
    defaults: () => ({ name: '', block: '', allow: '' }),
    fields: [{ k: 'name', label: 'Name', wide: true }, { k: 'block', label: 'Blocked domains', type: 'area', help: 'One per line; matches the domain and its subdomains.' },
      { k: 'allow', label: 'Allowed domains (exceptions)', type: 'area' }],
  };

  const sigKind = (stmt, sig, label) => ({
    label, scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `${stmt} ${v.name}`,
    parse(ls) {
      const v = { name: tok(ls[0])[1], patterns: [] };
      for (const l of ls) { const t = tok(l); if (t[0] === sig) v.patterns.push(t.slice(3).join(' ')); }
      v.patterns = v.patterns.join('\n');
      return v;
    },
    build(v) {
      const n = name(v.name);
      return [`${stmt} ${n}`, ...lines(v.patterns).map((p, i) => `${sig} ${n} ${i + 1} ${p.split(/\s+/).join(' ')}`)];
    },
    defaults: () => ({ name: '', patterns: '' }),
    fields: [{ k: 'name', label: 'Name', wide: true }, { k: 'patterns', label: 'Signatures', type: 'area', wide: true,
      help: 'One literal pattern per line (\\xNN escapes allowed), matched against payloads.' }],
  });
  K['ips-profile'] = sigKind('ips-profile', 'ips-signature', 'IPS profile');
  K['av-profile'] = sigKind('av-profile', 'av-signature', 'AV profile');

  K.shaper = {
    label: 'Traffic shaper', scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `shaper ${v.name}`,
    parse: (ls) => { const t = tok(ls[0]); return { name: t[1], kbps: t[2] }; },
    build: (v) => [`shaper ${name(v.name)} ${int(v.kbps, 'Rate', 1)}`],
    defaults: () => ({ name: '', kbps: '' }),
    fields: [{ k: 'name', label: 'Name' }, { k: 'kbps', label: 'Rate (kbit/s)', type: 'number' }],
  };

  K['profile-group'] = {
    label: 'Security profile group', scope: 'global', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `profile-group ${v.name}`,
    parse(ls) {
      const t = tok(ls[0]); const v = { name: t[1], url: '', ips: '', av: '' };
      for (let i = 2; i < t.length; i++) if (['url', 'ips', 'av'].includes(t[i])) v[t[i]] = t[++i] ?? '';
      return v;
    },
    build(v) {
      const p = ['profile-group', name(v.name)];
      for (const k of ['url', 'ips', 'av']) { const x = optName(v[k], k.toUpperCase()); if (x) p.push(k, x); }
      need(p.length > 2, 'Pick at least one profile');
      return [p.join(' ')];
    },
    defaults: () => ({ name: '', url: '', ips: '', av: '' }),
    fields: [{ k: 'name', label: 'Name', wide: true },
      { k: 'url', label: 'URL filter', type: 'select', options: (c) => c.names('url-filter') },
      { k: 'ips', label: 'IPS profile', type: 'select', options: (c) => c.names('ips-profile') },
      { k: 'av', label: 'AV profile', type: 'select', options: (c) => c.names('av-profile') }],
  };

  K['default-rule'] = {
    label: 'Default rule', scope: 'vdom',
    sort: (a, b) => (a.kind + (a.zone || '')).localeCompare(b.kind + (b.zone || '')),
    key: (v) => `default-rule ${v.kind}${one(v.zone) ? ` zone ${one(v.zone)}` : ''}`,
    parse(ls) {
      const t = tok(ls[0]); const v = { kind: t[1], action: t[2], zone: '', log: false };
      for (let i = 3; i < t.length; i++) { if (t[i] === 'zone') v.zone = t[++i] ?? ''; else if (t[i] === 'log') v.log = true; }
      return v;
    },
    build(v) {
      need(['intrazone', 'interzone'].includes(v.kind), 'Kind must be intrazone or interzone');
      need(!(v.kind === 'interzone' && one(v.zone)), 'Per-zone overrides apply to intrazone rules only');
      const p = ['default-rule', v.kind, v.action === 'allow' ? 'allow' : 'deny'];
      const z = optName(v.zone, 'Zone'); if (z) p.push('zone', z);
      if (v.log) p.push('log');
      return [p.join(' ')];
    },
    defaults: () => ({ kind: 'intrazone', action: 'deny', zone: '', log: false }),
    fields: [{ k: 'kind', label: 'Kind', type: 'select', options: ['intrazone', 'interzone'] },
      { k: 'action', label: 'Action', type: 'select', options: ['allow', 'deny'] },
      { k: 'zone', label: 'Zone override', dl: 'zones', help: 'Intrazone only; empty applies to every zone.' },
      { k: 'log', label: 'Log', type: 'check' }],
  };

  const FLOODS = [['syn', 'syn-flood'], ['icmp', 'icmp-flood'], ['udp', 'udp-flood']];
  K.zone = {
    label: 'Zone protection', scope: 'vdom', sort: (a, b) => a.name.localeCompare(b.name),
    key: (v) => `zone ${v.name}`,
    parse(ls) {
      const v = { name: tok(ls[0])[1], syn: '', icmp: '', udp: '' };
      for (const l of ls) { const t = tok(l); for (const [k, w] of FLOODS) if (t[2] === w) v[k] = t[3]; }
      return v;
    },
    build(v) {
      const n = name(v.name, 'Zone');
      const out = [];
      for (const [k, w] of FLOODS) if (one(v[k])) out.push(`zone ${n} ${w} ${int(v[k], 'Threshold', 1)}`);
      need(out.length, 'Set at least one threshold (delete the entry to remove protection)');
      return out;
    },
    defaults: () => ({ name: '', syn: '', icmp: '', udp: '' }),
    fields: [{ k: 'name', label: 'Zone', dl: 'zones', wide: true },
      { k: 'syn', label: 'SYN flood (new TCP/s)', type: 'number' }, { k: 'udp', label: 'UDP flood (new flows/s)', type: 'number' },
      { k: 'icmp', label: 'ICMP echo flood (/s)', type: 'number' }],
  };

  K.interface = {
    label: 'Interface', scope: 'vdom', sort: (a, b) => a.name.localeCompare(b.name), fixed: true,
    key: (v) => `interface ${v.name}`,
    parse(ls) {
      const t = tok(ls[0]); const v = { name: t[1], zone: '', address: '', address6: '', mac: '', mtu: '', tokens: t };
      for (let i = 2; i < t.length; i++) if (['zone', 'address', 'address6', 'mac', 'mtu'].includes(t[i])) v[t[i]] = t[++i] ?? '';
      return v;
    },
    // Only the zone can change while running; every other token is kept.
    build(v) {
      const z = name(v.zone, 'Zone');
      const t = [...v.tokens]; const i = t.indexOf('zone');
      need(i > 1, 'interface line has no zone'); t[i + 1] = z;
      return [t.join(' ')];
    },
    fields: [{ k: 'name', label: 'Interface', readonly: true }, { k: 'zone', label: 'Zone', dl: 'zones', help: 'Zone membership changes take effect on commit.' },
      { k: 'address', label: 'IPv4 address', readonly: true }, { k: 'address6', label: 'IPv6 address', readonly: true },
      { k: 'mac', label: 'MAC', readonly: true }, { k: 'mtu', label: 'MTU', readonly: true }],
  };

  K.system = {
    label: 'System setting', scope: 'global',
    key: (v) => `system ${v.name}`,
    parse: (ls) => { const t = tok(ls[0]); return { name: t[1], value: t.slice(2).join(' ') }; },
    build: (v) => { need(one(v.value), 'Value is required'); need(!/\s/.test(one(v.value)), 'Value must be a single word'); return [`system ${v.name} ${one(v.value)}`]; },
  };

  return { K, tok, list, words, FormError };
})();

globalThis.Model = Model;
if (typeof module === 'object' && module.exports) module.exports = Model;
