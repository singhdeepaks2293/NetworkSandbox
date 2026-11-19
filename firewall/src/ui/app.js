/* NetworkSandbox Firewall — management UI application.
 *
 * Every change goes into the candidate configuration (one structured edit
 * per object, validated by the server's parser) and only takes effect on
 * Commit, which shows the diff first. DOM is built with createElement and
 * textContent only: nothing from the configuration is ever parsed as HTML.
 * Depends on model.js (loaded first).
 */
'use strict';

(() => {
  const Model = globalThis.Model;
  const K = Model.K;
  const S = { csrf: '', user: '', role: '', vdom: 'root', page: 'dashboard', model: null, system: null, timer: null, statusTimer: null };
  const WRITE_ROLES = ['super_admin', 'firewall_admin', 'network_engineer'];
  const canWrite = () => WRITE_ROLES.includes(S.role);

  /* ------------------------------------------------------------ DOM helpers */
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
      else if (['value', 'checked', 'disabled', 'readOnly', 'selected', 'hidden'].includes(k)) e[k] = v;
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === undefined || kid === null || kid === false) continue;
      e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return e;
  }
  const $ = (sel, root = document) => root.querySelector(sel);
  const clear = (e) => { while (e.firstChild) e.removeChild(e.firstChild); return e; };
  const chip = (text, kind = '') => h('span', { class: `chip ${kind}` }, text);
  const fmtBytes = (n) => { n = Number(n) || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const fmtNum = (n) => Number(n || 0).toLocaleString();
  const fmtUptime = (s) => { s = Number(s) || 0; const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60); return d ? `${d}d ${hh}h ${m}m` : hh ? `${hh}h ${m}m` : `${m}m ${s % 60}s`; };
  const fmtAgo = (epoch) => { if (!epoch) return '—'; const s = Math.max(0, Math.floor(Date.now() / 1000) - epoch); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`; };
  const fmtTime = (epoch) => (epoch ? new Date(epoch * 1000).toLocaleString() : '—');
  const csv = (s) => String(s || '').split(',').filter(Boolean);
  const listChips = (s, none = 'any') => (csv(s).length ? csv(s).map((x) => chip(x)) : chip(none));

  function toast(msg, kind = '') {
    const t = h('div', { class: `toast ${kind}` }, msg);
    $('#toasts').append(t);
    setTimeout(() => t.remove(), kind === 'bad' ? 7000 : 4000);
  }

  /* ------------------------------------------------------------------- API */
  class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
  async function api(method, path, body, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    let payload;
    if (typeof body === 'string') { headers['content-type'] = 'text/plain'; payload = body; }
    else if (body !== undefined) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
    if (method !== 'GET' && S.csrf) headers['X-VELA-CSRF'] = S.csrf;
    const r = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
    if (r.status === 401 && !path.includes('/auth/login')) { showLogin('Your session has ended. Sign in again.'); throw new ApiError('session expired', 401); }
    const type = r.headers.get('content-type') || '';
    const data = type.includes('json') ? await r.json().catch(() => ({})) : await r.text();
    if (!r.ok) throw new ApiError((data && data.error) || `HTTP ${r.status}`, r.status);
    return data;
  }

  /* --------------------------------------------------------- config model */
  async function loadModel() { S.model = await api('GET', '/api/v1/configuration/model'); renderTop(); }
  async function loadSystem() { try { S.system = await api('GET', '/api/v1/system'); renderTop(); } catch (_) { /* shown by the pill */ } }

  function section(scope) {
    const want = scope === 'global' ? null : S.vdom;
    return (S.model.sections.find((s) => s.vdom === want) || { objects: [] });
  }
  function objects(kind) {
    const k = K[kind];
    const out = section(k.scope).objects.filter((o) => o.kind === kind).map((o) => ({ key: o.key, lines: o.lines, v: k.parse(o.lines) }));
    return k.sort ? out.sort((a, b) => k.sort(a.v, b.v)) : out;
  }
  const ctx = {
    names: (kind) => [''].concat(objects(kind).map((o) => o.v.name)),
    interfaces: () => S.model.interfaces.filter((i) => i.vdom === S.vdom && !i.tunnel).map((i) => i.name),
    nextId: (kind) => { const ids = objects(kind).map((o) => Number(o.v.id) || 0); return ids.length ? Math.ceil((Math.max(...ids) + 1) / 10) * 10 : 10; },
  };
  function datalists() {
    const zones = ['any', ...((S.model.zones || {})[S.vdom] || [])];
    const addrNames = [...objects('address'), ...objects('address-group')].map((o) => o.v.name);
    const svcNames = [...objects('service'), ...objects('service-group')].map((o) => o.v.name);
    const apps = [...objects('app-def'), ...objects('app-group')].map((o) => o.v.name)
      .concat(['ssl', 'web-browsing', 'ssh', 'dns', 'ping', 'unknown-tcp', 'unknown-udp', 'category:social-networking', 'category:file-sharing', 'category:streaming']);
    const users = objects('user-group').map((o) => o.v.name).concat(['known-user', 'unknown']);
    const sets = {
      zones, addrnames: addrNames, svcnames: svcNames, apps, users,
      addrs: ['any', ...addrNames.map((n) => `@${n}`)],
      services: ['any', 'application-default', ...svcNames.map((n) => `@${n}`)],
    };
    return h('div', { hidden: true }, Object.entries(sets).map(([id, vals]) => h('datalist', { id: `dl-${id}` }, vals.map((v) => h('option', { value: v })))));
  }

  /* --------------------------------------------------------------- edits */
  async function submitEdits(edits) {
    const r = await api('POST', '/api/v1/configuration/edit', { base: S.model.base, edits });
    await loadModel();
    toast(`Saved to the candidate — ${r.changes} pending change line(s). Commit to apply.`, 'ok');
    return r;
  }
  function editError(e) {
    if (e.status === 409) return `${e.message}. Another administrator committed a change: discard your candidate or reload, then try again.`;
    return e.message;
  }
  async function removeObject(kind, obj) {
    if (!confirm(`Delete ${obj.key}? This goes into the candidate; nothing changes until you commit.`)) return;
    try { await submitEdits([{ mode: 'delete', vdom: S.vdom, key: obj.key }]); render(); } catch (e) { toast(editError(e), 'bad'); }
  }

  /* --------------------------------------------------------------- modal */
  function modal(title, body, buttons) {
    const dlg = h('dialog', {},
      h('div', { class: 'modal-head' }, title, h('span', { class: 'spacer' }), h('button', { class: 'link', onclick: () => dlg.close() }, 'Close')),
      h('div', { class: 'modal-body' }, body),
      h('div', { class: 'modal-foot' }, buttons));
    dlg.addEventListener('close', () => dlg.remove());
    document.body.append(dlg);
    dlg.showModal();
    return dlg;
  }

  function fieldInput(f, value) {
    const id = `f-${f.k}`;
    if (f.type === 'check') return h('input', { id, type: 'checkbox', checked: !!value, disabled: f.readonly || !canWrite() });
    if (f.type === 'select') {
      const opts = (typeof f.options === 'function' ? f.options(ctx) : f.options).slice();
      if (value && !opts.includes(value)) opts.push(value);
      return h('select', { id, disabled: f.readonly || !canWrite() }, opts.map((o) => h('option', { value: o, selected: o === value }, o === '' ? '— none —' : o)));
    }
    if (f.type === 'area') return h('textarea', { id, readOnly: f.readonly || !canWrite(), value: value ?? '' });
    return h('input', { id, type: f.type === 'number' ? 'number' : 'text', value: value ?? '', readOnly: f.readonly || !canWrite(), list: f.dl ? `dl-${f.dl}` : undefined, autocomplete: 'off' });
  }

  function openForm(kind, obj, opts = {}) {
    const k = K[kind];
    const start = obj ? { ...obj.v } : { ...(k.defaults ? k.defaults(ctx) : {}) };
    if (opts.clone && 'id' in start) start.id = ctx.nextId(kind);
    if (opts.clone && 'name' in start && start.name) start.name = `${start.name}-copy`;
    const err = h('div', { class: 'notice bad form-error', hidden: true });
    const form = h('div', { class: 'form' }, err,
      k.fields.map((f) => f.section
        ? h('div', { class: 'form-section' }, f.section)
        : h('div', { class: `field ${f.type === 'check' ? 'check' : ''} ${f.wide || f.type === 'area' ? 'wide' : ''}` },
          f.type === 'check' ? [fieldInput(f, start[f.k]), h('label', { for: `f-${f.k}` }, f.label)]
            : [h('label', { for: `f-${f.k}` }, f.label), fieldInput(f, start[f.k]), f.help ? h('div', { class: 'help' }, f.help) : null])));
    const verb = obj && !opts.clone ? 'Edit' : 'New';
    const save = h('button', { class: 'primary', onclick: async () => {
      const v = { ...start };
      for (const f of k.fields) {
        if (!f.k) continue;
        const el = $(`#f-${f.k}`, dlg);
        v[f.k] = f.type === 'check' ? el.checked : el.value;
      }
      let lines;
      try { lines = k.build(v); } catch (e) { err.hidden = false; err.textContent = e.message; return; }
      const editsFor = obj && !opts.clone
        ? [{ mode: 'replace', vdom: S.vdom, key: obj.key, lines }]
        : [{ mode: 'create', vdom: S.vdom, lines }];
      save.disabled = true;
      try { await submitEdits(editsFor); dlg.close(); render(); } catch (e) { err.hidden = false; err.textContent = editError(e); save.disabled = false; }
    } }, 'Save to candidate');
    const dlg = modal(`${verb} ${k.label}${obj && !opts.clone ? ` — ${obj.key}` : ''}`, [datalists(), form],
      [h('button', { onclick: () => dlg.close() }, 'Cancel'), canWrite() ? save : null]);
    const first = $('input:not([readonly]):not([type=checkbox]), select, textarea', dlg);
    if (first) first.focus();
  }

  /* -------------------------------------------------------- CRUD tables */
  function crudCard(kind, columns, opts = {}) {
    const k = K[kind];
    const rows = objects(kind);
    const search = h('input', { class: 'search', type: 'search', placeholder: 'Search…' });
    const tbody = h('tbody');
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      clear(tbody);
      const shown = rows.filter((o) => !q || o.lines.join(' ').toLowerCase().includes(q));
      if (!shown.length) tbody.append(h('tr', {}, h('td', { colspan: columns.length + 1, class: 'empty' }, rows.length ? 'No matches' : `No ${k.label.toLowerCase()} entries yet`)));
      for (const o of shown) {
        const tr = h('tr', { class: o.v.enabled === false ? 'disabled' : '' },
          columns.map(([, fn, c]) => h('td', { class: c && c.num ? 'num' : '' }, fn(o.v, o))),
          h('td', { class: 'actions' },
            (opts.rowActions || []).map((a) => a(o)),
            h('button', { class: 'small', onclick: () => openForm(kind, o) }, canWrite() && !opts.readonly ? 'Edit' : 'View'),
            canWrite() && !k.fixed && !opts.readonly ? h('button', { class: 'small', onclick: () => openForm(kind, o, { clone: true }) }, 'Clone') : null,
            canWrite() && !k.fixed && !opts.readonly ? h('button', { class: 'small danger', onclick: () => removeObject(kind, o) }, 'Delete') : null));
        tbody.append(tr);
      }
    };
    search.addEventListener('input', draw);
    draw();
    return h('div', { class: 'card' },
      h('div', { class: 'card-head' }, opts.title || k.label, h('span', { class: 'chip' }, String(rows.length)), h('span', { class: 'spacer' }), search,
        canWrite() && !k.fixed && !opts.readonly ? h('button', { class: 'primary', onclick: () => openForm(kind, null) }, `+ New`) : null),
      opts.intro ? h('div', { class: 'card-body' }, opts.intro) : null,
      h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, columns.map(([label, , c]) => h('th', { class: c && c.num ? 'num' : '' }, label)), h('th', {}))), tbody)));
  }

  const actionChip = (a) => chip(a, a === 'permit' || a === 'allow' ? 'ok' : 'bad');
  const profileChips = (v) => ['group', 'url', 'ips', 'av', 'shaper'].filter((p) => v[p]).map((p) => chip(`${p}: ${v[p]}`, 'info'));
  const hitsFor = (id) => (S.model.hits || []).find((x) => x.vdom === S.vdom && x.id === id);

  /* ------------------------------------------------------------- pages */
  const PAGES = {};
  const page = (id, title, desc, render) => { PAGES[id] = { title, desc, render }; };

  page('dashboard', 'Dashboard', 'Health, enforcement and traffic at a glance.', async (main) => {
    const [sys, mon] = await Promise.all([api('GET', '/api/v1/system'), api('GET', '/api/v1/monitoring').catch(() => ({ monitoring: {} }))]);
    S.system = sys; renderTop();
    const m = mon.monitoring || {};
    const enf = sys.enforcement || {};
    const ok = ['enforcing', 'kernel'].includes(enf.status);
    main.append(
      h('div', { class: `notice ${ok ? 'ok' : enf.status === 'off' ? 'warn' : 'bad'}` },
        ok ? `Enforcing — ${enf.mode === 'kernel' ? 'kernel (nftables) dataplane, verified' : 'userspace dataplane, all interfaces attached'}.`
          : enf.status === 'off' ? 'Dataplane is off (dry run or control plane only): no traffic is being filtered.'
            : 'Degraded — the firewall is not enforcing its policy everywhere:',
        enf.problems && enf.problems.length ? h('ul', {}, enf.problems.map((p) => h('li', {}, p))) : null),
      h('div', { class: 'grid' },
        stat('Accepted', fmtNum(sys.accepted), 'flows permitted'), stat('Denied', fmtNum(sys.denied), 'flows blocked'),
        stat('Sessions', fmtNum(sys.sessions), 'tracked now'), stat('Uptime', fmtUptime(sys.uptime), `revision ${sys.revision}`)),
      h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'System'), h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
          kv('Hostname', sys.hostname), kv('Product', `${sys.product || ''} ${sys.version || ''}`), kv('Dataplane', enf.mode || '—'),
          kv('Config revision', sys.revision), kv('VDOMs', (sys.vdoms || []).join(', '))))),
        h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Resources'), h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
          kv('CPUs', m.cpu_count ?? '—'),
          kv('Memory', m.memory_total_kb ? `${fmtBytes((m.memory_total_kb - m.memory_available_kb) * 1024)} used of ${fmtBytes(m.memory_total_kb * 1024)}` : '—'),
          kv('Disk', m.disk_total_bytes ? `${fmtBytes(m.disk_total_bytes - m.disk_free_bytes)} used of ${fmtBytes(m.disk_total_bytes)}` : '—'),
          kv('Errors', fmtNum(sys.errors)), kv('ARP misses', fmtNum(sys.arp_misses)))))),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Interfaces'),
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, ['Name', 'VDOM', 'Zone', 'Address', 'RX', 'TX'].map((x, i) => h('th', { class: i > 3 ? 'num' : '' }, x)))),
          h('tbody', {}, (sys.interfaces || []).map((i) => h('tr', {},
            h('td', {}, i.name), h('td', {}, i.vdom), h('td', {}, chip(i.zone)), h('td', { class: 'mono' }, i.address || '—'),
            h('td', { class: 'num' }, `${fmtNum(i.rx)} pkts · ${fmtBytes(i.rx_bytes)}`), h('td', { class: 'num' }, `${fmtNum(i.tx)} pkts · ${fmtBytes(i.tx_bytes)}`))))))));
  }, { refresh: 5000 });
  function stat(label, value, sub) { return h('div', { class: 'card stat' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'sub' }, sub)); }
  function kv(k, v) { return [h('dt', {}, k), h('dd', {}, v ?? '—')]; }

  page('interfaces', 'Interfaces & Zones', 'Zone membership of each interface. Adding or removing interfaces needs a restart (System → Configuration → raw editor).', async (main) => {
    main.append(crudCard('interface', [
      ['Interface', (v) => h('b', {}, v.name)], ['Zone', (v) => chip(v.zone, 'info')], ['IPv4', (v) => h('span', { class: 'mono' }, v.address || '—')],
      ['IPv6', (v) => h('span', { class: 'mono' }, v.address6 || '—')], ['MTU', (v) => v.mtu || '1500', { num: true }]]));
  });

  page('routing', 'Static Routing', 'Longest prefix wins; among equal prefixes the lowest distance.', async (main) => {
    const cols = [['Destination', (v) => h('span', { class: 'mono' }, v.dst)], ['Interface', (v) => v.iface], ['Gateway', (v) => h('span', { class: 'mono' }, v.via || 'connected')],
      ['Distance', (v) => v.distance || 'default', { num: true }]];
    main.append(crudCard('route', [...cols, ['Name', (v) => v.name || '']]), crudCard('route6', cols));
  });

  page('policies', 'Security Policies', 'Evaluated in ascending ID order; the first match decides. Unmatched traffic follows the default rules.', async (main) => {
    const all = objects('policy');
    const move = (o, dir) => async () => {
      // Rows are rebuilt per render, so find them by key, not identity.
      const i = all.findIndex((x) => x.key === o.key); const other = i < 0 ? null : all[i + dir];
      if (!other) return;
      const a = K.policy.build({ ...o.v, id: other.v.id })[0];
      const b = K.policy.build({ ...other.v, id: o.v.id })[0];
      try {
        await submitEdits([{ mode: 'delete', vdom: S.vdom, key: o.key }, { mode: 'delete', vdom: S.vdom, key: other.key },
          { mode: 'create', vdom: S.vdom, lines: [a] }, { mode: 'create', vdom: S.vdom, lines: [b] }]);
        render();
      } catch (e) { toast(editError(e), 'bad'); }
    };
    const toggle = (o) => async () => {
      try { await submitEdits([{ mode: 'replace', vdom: S.vdom, key: o.key, lines: K.policy.build({ ...o.v, enabled: !o.v.enabled }) }]); render(); } catch (e) { toast(editError(e), 'bad'); }
    };
    main.append(crudCard('policy', [
      ['ID', (v) => h('b', {}, v.id), { num: true }], ['Name', (v) => v.name || ''],
      ['From → To', (v) => [listChips(v.srcZones), ' → ', listChips(v.dstZones)]],
      ['Source', (v) => h('span', { class: 'mono' }, v.src)], ['Destination', (v) => h('span', { class: 'mono' }, v.dst)],
      ['Service', (v) => [v.proto !== 'any' ? chip(v.proto) : null, h('span', { class: 'mono' }, v.service)]],
      ['App / User', (v) => [v.apps ? listChips(v.apps) : null, v.users ? csv(v.users).map((u) => chip(u, 'warn')) : null]],
      ['Action', (v) => [actionChip(v.action), v.nat ? chip('NAT', 'info') : null, v.log ? null : chip('no log')]],
      ['Profiles', (v) => profileChips(v)],
      ['Hits', (v) => { const x = hitsFor(v.id); return x ? [`${fmtNum(x.packets)} · ${fmtBytes(x.bytes)}`, h('div', { class: 'help' }, fmtAgo(x.last))] : '0'; }, { num: true }],
    ], {
      rowActions: canWrite() ? [
        (o) => h('button', { class: 'small', title: 'Move up', disabled: all.findIndex((x) => x.key === o.key) === 0, onclick: move(o, -1) }, '↑'),
        (o) => h('button', { class: 'small', title: 'Move down', disabled: all.findIndex((x) => x.key === o.key) === all.length - 1, onclick: move(o, 1) }, '↓'),
        (o) => h('button', { class: 'small', onclick: toggle(o) }, o.v.enabled ? 'Disable' : 'Enable'),
      ] : [],
    }));
  });

  page('default-rules', 'Default Rules', 'Apply to traffic no policy matched. Without a rule, both intrazone and interzone traffic are denied.', async (main) => {
    main.append(crudCard('default-rule', [['Kind', (v) => h('b', {}, v.kind)], ['Zone', (v) => v.zone ? chip(v.zone) : 'all zones'], ['Action', (v) => actionChip(v.action)], ['Log', (v) => (v.log ? 'yes' : 'no')]]));
  });

  page('nat', 'NAT', 'Source NAT rulebase (first match, unless the policy itself sets nat) and destination NAT / virtual IPs.', async (main) => {
    main.append(
      crudCard('snat', [['ID', (v) => h('b', {}, v.id), { num: true }], ['Name', (v) => v.name || ''], ['From → To', (v) => [listChips(v.srcZones), ' → ', listChips(v.dstZones)]],
        ['Source', (v) => h('span', { class: 'mono' }, v.src)], ['Destination', (v) => h('span', { class: 'mono' }, v.dst)], ['Translate to', (v) => chip(v.to, 'info')],
        ['Status', (v) => (v.enabled ? chip('enabled', 'ok') : chip('disabled'))]], { title: 'Source NAT' }),
      crudCard('dnat', [['ID', (v) => h('b', {}, v.id), { num: true }], ['Name', (v) => v.name || ''], ['Protocol', (v) => v.proto],
        ['External', (v) => h('span', { class: 'mono' }, `${v.dst}:${v.dport}`)], ['Mapped to', (v) => h('span', { class: 'mono' }, `${v.toIp}:${v.toPort}`)]], { title: 'Destination NAT / Virtual IPs' }));
  });

  page('addresses', 'Addresses', 'Address objects and groups, shared by every VDOM. Reference them in policies as @name.', async (main) => {
    main.append(
      crudCard('address', [['Name', (v) => h('b', {}, v.name)], ['Entries', (v) => Model.words(v.members).map((x) => chip(x))]]),
      crudCard('address-group', [['Name', (v) => h('b', {}, v.name)], ['Members', (v) => Model.words(v.members).map((x) => chip(`@${x}`, 'info'))]]));
  });
  page('services', 'Services', 'Port-based services and groups. Reference them in policies as @name.', async (main) => {
    main.append(
      crudCard('service', [['Name', (v) => h('b', {}, v.name)], ['Protocol', (v) => chip(v.proto)], ['Ports', (v) => h('span', { class: 'mono' }, v.ports)]]),
      crudCard('service-group', [['Name', (v) => h('b', {}, v.name)], ['Members', (v) => Model.words(v.members).map((x) => chip(`@${x}`, 'info'))]]));
  });
  page('applications', 'Applications', 'Built-in App-ID identifies applications from content. Define port-based custom applications and application groups here.', async (main) => {
    main.append(
      crudCard('app-def', [['Name', (v) => h('b', {}, v.name)], ['Protocol', (v) => chip(v.proto)], ['Port', (v) => v.port, { num: true }]], { title: 'Custom applications' }),
      crudCard('app-group', [['Name', (v) => h('b', {}, v.name)], ['Members', (v) => Model.words(v.members).map((x) => chip(x))]]));
  });

  page('urlfilter', 'URL Filtering', 'Host-level filtering by HTTP Host and TLS SNI. Attach a filter to a policy or a profile group.', async (main) => {
    main.append(crudCard('url-filter', [['Name', (v) => h('b', {}, v.name)], ['Blocked', (v) => Model.words(v.block).map((x) => chip(x, 'bad'))], ['Allowed', (v) => Model.words(v.allow).map((x) => chip(x, 'ok'))]]));
  });
  page('ips', 'Intrusion Prevention', 'Literal signature matching on payloads (not a full IPS engine).', async (main) => {
    main.append(crudCard('ips-profile', [['Name', (v) => h('b', {}, v.name)], ['Signatures', (v) => `${v.patterns.split('\n').filter(Boolean).length} pattern(s)`]]));
  });
  page('av', 'Payload Signatures (AV)', 'Literal payload signature matching. This is not a full antivirus engine.', async (main) => {
    main.append(crudCard('av-profile', [['Name', (v) => h('b', {}, v.name)], ['Signatures', (v) => `${v.patterns.split('\n').filter(Boolean).length} pattern(s)`]]));
  });
  page('profile-groups', 'Profile Groups', 'Bundle URL, IPS and AV profiles and attach the group to policies.', async (main) => {
    main.append(crudCard('profile-group', [['Name', (v) => h('b', {}, v.name)], ['Profiles', (v) => profileChips(v)]]));
  });
  page('shapers', 'Traffic Shaping', 'Rate limits that policies can apply to permitted traffic.', async (main) => {
    main.append(crudCard('shaper', [['Name', (v) => h('b', {}, v.name)], ['Rate', (v) => `${fmtNum(v.kbps)} kbit/s`, { num: true }]]));
  });
  page('zone-protection', 'DoS / Zone Protection', 'Per-zone flood thresholds for new flows per second (IPv4 and IPv6 share one counter).', async (main) => {
    main.append(crudCard('zone', [['Zone', (v) => h('b', {}, v.name)], ['SYN flood', (v) => v.syn || 'off', { num: true }], ['UDP flood', (v) => v.udp || 'off', { num: true }], ['ICMP flood', (v) => v.icmp || 'off', { num: true }]]));
  });

  page('userid', 'User-ID', 'IP-to-user mappings: dynamic logins pushed by an identity source, then static user maps.', async (main) => {
    const data = await api('GET', '/api/v1/user-id');
    const ip = h('input', { placeholder: '10.0.0.5' }); const user = h('input', { placeholder: 'alice' }); const ttl = h('input', { type: 'number', placeholder: 'seconds (empty = no expiry)' });
    main.append(
      canWrite() ? h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Add a login mapping'), h('div', { class: 'card-body' }, h('div', { class: 'form' },
        h('div', { class: 'field' }, h('label', {}, 'IPv4 address'), ip), h('div', { class: 'field' }, h('label', {}, 'User'), user),
        h('div', { class: 'field' }, h('label', {}, 'Timeout'), ttl),
        h('div', { class: 'field' }, h('label', {}, ' '), h('button', { class: 'primary', onclick: async () => {
          try { await api('POST', '/api/v1/user-id/login', { ip: ip.value.trim(), user: user.value.trim(), timeout: ttl.value ? Number(ttl.value) : null }); toast('Mapping added', 'ok'); render(); } catch (e) { toast(e.message, 'bad'); }
        } }, 'Add mapping'))))) : null,
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Current mappings', chip(String(data.mappings.length))),
        table(['Address', 'User', 'Source', 'Expires', ''], data.mappings.map((m) => [h('span', { class: 'mono' }, m.ip), h('b', {}, m.user), chip(m.source, m.source === 'dynamic' ? 'info' : ''),
          m.expires_in == null ? 'never' : `${m.expires_in}s`,
          canWrite() && m.source === 'dynamic' ? h('button', { class: 'small danger', onclick: async () => { try { await api('POST', '/api/v1/user-id/logout', { ip: m.ip }); render(); } catch (e) { toast(e.message, 'bad'); } } }, 'Log out') : '']))));
  });
  page('users', 'User Groups & Maps', 'Groups used in user-based policies, and static address-to-user mappings.', async (main) => {
    main.append(
      crudCard('user-group', [['Name', (v) => h('b', {}, v.name)], ['Members', (v) => Model.words(v.members).map((x) => chip(x))]]),
      crudCard('user-map', [['Address', (v) => h('span', { class: 'mono' }, v.cidr)], ['User', (v) => h('b', {}, v.user)]]));
  });

  page('admins', 'Administrators', 'Management accounts, roles and API tokens.', async (main) => {
    let data = { administrators: [] };
    try { data = await api('GET', '/api/v1/administrators'); } catch (e) { main.append(h('div', { class: 'notice warn' }, e.message)); }
    const roles = ['super_admin', 'firewall_admin', 'network_engineer', 'security_analyst', 'auditor'];
    const addAdmin = () => {
      const u = h('input', { id: 'f-u' }); const p = h('input', { id: 'f-p', type: 'password' }); const r = h('select', { id: 'f-r' }, roles.map((x) => h('option', { value: x }, x)));
      const err = h('div', { class: 'notice bad form-error', hidden: true });
      const dlg = modal('New administrator', h('div', { class: 'form' }, err, h('div', { class: 'field' }, h('label', {}, 'Username'), u),
        h('div', { class: 'field' }, h('label', {}, 'Role'), r), h('div', { class: 'field wide' }, h('label', {}, 'Password'), p)),
      [h('button', { onclick: () => dlg.close() }, 'Cancel'), h('button', { class: 'primary', onclick: async () => {
        try { await api('POST', '/api/v1/administrators', { username: u.value.trim(), password: p.value, role: r.value }); dlg.close(); toast('Administrator added', 'ok'); render(); } catch (e) { err.hidden = false; err.textContent = e.message; }
      } }, 'Create')]);
    };
    const tokens = async (a) => {
      const body = h('div', {}); const dlg = modal(`API tokens — ${a.username}`, body, [h('button', { onclick: () => dlg.close() }, 'Close')]);
      const load = async () => {
        clear(body);
        const t = await api('GET', `/api/v1/administrators/${encodeURIComponent(a.username)}/tokens`).catch((e) => ({ error: e.message }));
        if (t.error) { body.append(h('div', { class: 'notice bad' }, t.error)); return; }
        const items = t.tokens || [];
        const nm = h('input', { placeholder: 'automation' }); const days = h('input', { type: 'number', placeholder: 'days (empty = no expiry)' });
        const out = h('div');
        body.append(
          h('div', { class: 'form' }, h('div', { class: 'field' }, h('label', {}, 'Token name'), nm), h('div', { class: 'field' }, h('label', {}, 'Expires in'), days),
            h('div', { class: 'field wide' }, h('button', { class: 'primary', onclick: async () => {
              try { const r = await api('POST', `/api/v1/administrators/${encodeURIComponent(a.username)}/tokens`, { name: nm.value.trim() || 'api', role: a.role, expires_days: days.value ? Number(days.value) : undefined });
                clear(out).append(h('div', { class: 'notice warn' }, 'Copy this token now; it is not shown again: ', h('code', {}, r.token || JSON.stringify(r)))); await load(); body.append(out);
              } catch (e) { toast(e.message, 'bad'); }
            } }, 'Create token'))),
          out,
          table(['ID', 'Name', 'Role', 'Expires', ''], items.map((x) => [h('span', { class: 'mono' }, x.id), x.name, x.role, x.expires ? fmtTime(x.expires) : 'never',
            h('button', { class: 'small danger', onclick: async () => { if (!confirm('Revoke this token?')) return; try { await api('DELETE', `/api/v1/administrators/${encodeURIComponent(a.username)}/tokens/${encodeURIComponent(x.id)}`); await load(); } catch (e) { toast(e.message, 'bad'); } } }, 'Revoke')])));
      };
      load();
    };
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Administrators', h('span', { class: 'spacer' }),
      canWrite() ? h('button', { class: 'primary', onclick: addAdmin }, '+ New') : null),
    table(['Username', 'Role', 'Status', 'Created', 'Tokens', ''], data.administrators.map((a) => [h('b', {}, a.username), chip(a.role, 'info'),
      a.enabled ? chip('enabled', 'ok') : chip('disabled'), fmtTime(a.created), String(a.token_count ?? ''),
      [h('button', { class: 'small', onclick: () => tokens(a) }, 'Tokens'),
        a.username !== S.user ? h('button', { class: 'small danger', onclick: async () => { if (!confirm(`Delete administrator ${a.username}?`)) return; try { await api('DELETE', `/api/v1/administrators/${encodeURIComponent(a.username)}`); render(); } catch (e) { toast(e.message, 'bad'); } } }, 'Delete') : null]]))),
    passwordCard());
  });
  function passwordCard() {
    const cur = h('input', { type: 'password', autocomplete: 'current-password' }); const nw = h('input', { type: 'password', autocomplete: 'new-password' });
    return h('div', { class: 'card' }, h('div', { class: 'card-head' }, `Change my password (${S.user})`), h('div', { class: 'card-body' }, h('div', { class: 'form' },
      h('div', { class: 'field' }, h('label', {}, 'Current password'), cur), h('div', { class: 'field' }, h('label', {}, 'New password'), nw),
      h('div', { class: 'field wide' }, h('button', { class: 'primary', onclick: async () => {
        try { await api('POST', '/api/v1/auth/password', { current: cur.value, password: nw.value }); cur.value = ''; nw.value = ''; toast('Password changed', 'ok'); } catch (e) { toast(e.message, 'bad'); }
      } }, 'Change password')))));
  }

  page('sessions', 'Sessions', 'Flows tracked by the stateful engine (IPv4).', async (main) => {
    const data = await api('GET', `/api/v1/sessions?vdom=${encodeURIComponent(S.vdom)}&limit=500`);
    const list = data.sessions || [];
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Active sessions', chip(`${fmtNum(data.total ?? list.length)}`)),
      table(['Protocol', 'Source', 'Destination', 'NAT', 'Policy', 'Application', 'User', 'Expires in'], list.map((s) => [
        chip(String({ 6: 'tcp', 17: 'udp', 1: 'icmp' }[s.proto] || s.proto)), h('span', { class: 'mono' }, `${s.src}:${s.sport}`), h('span', { class: 'mono' }, `${s.dst}:${s.dport}`),
        h('span', { class: 'mono' }, typeof s.nat === 'object' && s.nat ? JSON.stringify(s.nat) : (s.nat || '—')), String(s.policy), s.app === 'pending' ? chip('pending', 'warn') : chip(s.app),
        s.user || '—', `${s.ttl}s`]))));
  }, { refresh: 5000 });

  page('logs', 'Traffic Log', 'Most recent traffic and security events (in-memory buffer).', async (main) => {
    const q = h('input', { class: 'search', type: 'search', placeholder: 'Filter (server-side)…', value: S.logQuery || '' });
    const data = await api('GET', `/api/v1/logs?limit=500&q=${encodeURIComponent(S.logQuery || '')}`);
    q.addEventListener('change', () => { S.logQuery = q.value; render(); });
    const rows = (data.logs || []).slice().reverse().map((line) => {
      const text = typeof line === 'string' ? line : JSON.stringify(line);
      let e = null; try { e = text.trim().startsWith('{') ? JSON.parse(text) : null; } catch (_) { e = null; }
      const action = e ? e.action : (text.match(/\b(permit|accept|deny|drop|reject)\b/) || [''])[0];
      return [action ? actionChip(action === 'accept' ? 'permit' : action) : '', h('span', { class: 'mono' }, e ? `${e.src}:${e.sport} → ${e.dst}:${e.dport} proto ${e.proto} (${e.from} → ${e.to})${e.policy != null ? ` policy ${e.policy}` : ''} ${e.note || ''}` : text)];
    });
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Events', chip(`${fmtNum(data.total)} matching`), h('span', { class: 'spacer' }), q), table(['Action', 'Event'], rows)));
  }, { refresh: 5000 });

  page('hits', 'Policy Hit Counts', 'Packets and bytes matched per policy since the daemon started.', async (main) => {
    const rows = objects('policy').map((o) => { const x = hitsFor(o.v.id) || {}; return [h('b', {}, o.v.id), o.v.name || '', actionChip(o.v.action), fmtNum(x.packets), fmtBytes(x.bytes), fmtAgo(x.last)]; });
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Hit counts'), table(['ID', 'Name', 'Action', 'Packets', 'Bytes', 'Last hit'], rows, [3, 4])));
  }, { refresh: 10000, reloadModel: true });

  page('settings', 'Settings', 'System settings. Ports, binds, TLS and dataplane mode take effect after a restart.', async (main) => {
    const rows = objects('system');
    const tbody = h('tbody');
    for (const o of rows) {
      const input = h('input', { value: o.v.value, readOnly: !canWrite() });
      const save = h('button', { class: 'small primary', onclick: async () => {
        try { await submitEdits([{ mode: 'replace', vdom: S.vdom, key: o.key, lines: K.system.build({ name: o.v.name, value: input.value }) }]); render(); } catch (e) { toast(editError(e), 'bad'); }
      } }, 'Save');
      tbody.append(h('tr', {}, h('td', {}, h('b', {}, o.v.name)), h('td', {}, input), h('td', { class: 'actions' }, canWrite() ? save : null)));
    }
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'System settings'), h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Setting'), h('th', {}, 'Value'), h('th', {}))), tbody))));
  });

  page('ha', 'High Availability', 'Active-passive pair status.', async (main) => {
    const ha = await api('GET', '/api/v1/ha');
    const act = (path, label) => h('button', { onclick: async () => { try { const r = await api('POST', path); toast(label, 'ok'); clear(out).append(r.status); } catch (e) { toast(e.message, 'bad'); } }, disabled: !ha.enabled || !canWrite() }, label);
    const out = h('pre', { class: 'out' }, ha.status);
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Status', h('span', { class: 'spacer' }), act('/api/v1/ha/suspend', 'Suspend (go passive)'), act('/api/v1/ha/resume', 'Resume')),
      h('div', { class: 'card-body' }, ha.enabled ? null : h('div', { class: 'notice' }, 'HA is not configured. Configure it with ha … lines in the raw editor.'), out)));
  }, { refresh: 5000 });

  page('vpn', 'VPN', 'WireGuard tunnels. Keys are edited in the CLI or raw editor, not through the GUI.', async (main) => {
    const vpn = section('vdom').objects.filter((o) => o.kind === 'vpn');
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'WireGuard tunnels', chip(String(vpn.length))),
      vpn.length ? h('div', { class: 'card-body' }, vpn.map((o) => h('pre', { class: 'out' }, o.lines.map((l) => l.replace(/(private-key|preshared-key)\s+\S+/g, '$1 ********')).join('\n'))))
        : h('div', { class: 'empty' }, 'No tunnels configured in this VDOM.')));
  });

  page('config', 'Configuration', 'Candidate, commit, rollback, backup and the raw configuration editor.', async (main) => {
    const m = S.model;
    const raw = h('textarea', { class: 'big', readOnly: !canWrite() });
    raw.value = await api('GET', m.staged ? '/api/v1/configuration/candidate' : '/api/config');
    const file = h('input', { type: 'file', accept: '.conf,.txt,.json' });
    main.append(
      h('div', { class: 'grid' },
        stat('Running revision', m.revision, m.dataplane === 'kernel' ? 'kernel dataplane' : 'userspace dataplane'),
        stat('Candidate', m.staged ? `${m.changes} change(s)` : 'none', m.staged ? `based on revision ${m.base}` : 'no pending changes')),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Actions'), h('div', { class: 'card-body toolbar' },
        h('button', { class: 'primary', disabled: !m.staged || !canWrite(), onclick: reviewCommit }, 'Review & commit'),
        h('button', { disabled: !m.staged || !canWrite(), onclick: discard }, 'Discard candidate'),
        h('button', { disabled: !canWrite(), onclick: async () => {
          if (!confirm('Restore the previous committed configuration?')) return;
          try { const r = await api('POST', '/api/v1/configuration/rollback'); await loadModel(); toast(`Rolled back to revision ${r.revision}`, 'ok'); render(); } catch (e) { toast(e.message, 'bad'); }
        } }, 'Roll back last commit'),
        h('a', { class: 'btn', href: '/api/v1/configuration/backup', download: 'firewall-backup.json' }, 'Download backup'),
        h('span', { class: 'spacer' }),
        canWrite() ? [file, h('button', { onclick: async () => {
          const f = file.files[0]; if (!f) { toast('Choose a configuration file first', 'bad'); return; }
          let text = await f.text();
          try { const j = JSON.parse(text); if (j && typeof j.config === 'string') text = j.config; } catch (_) { /* plain text */ }
          if (!confirm('Restore this configuration now? It is validated and committed immediately.')) return;
          try { const r = await api('POST', '/api/v1/configuration/restore', { config: text }); await loadModel(); toast(`Restored as revision ${r.revision}`, 'ok'); render(); } catch (e) { toast(e.message, 'bad'); }
        } }, 'Restore file')] : null)),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, m.staged ? 'Candidate configuration (raw)' : 'Running configuration (raw)', h('span', { class: 'spacer' }),
        canWrite() ? h('button', { onclick: async () => {
          try { await api('POST', '/api/v1/configuration/candidate', raw.value, { 'x-config-base': String(m.staged ? m.base : m.revision) }); await loadModel(); toast('Raw configuration validated and staged as the candidate', 'ok'); render(); } catch (e) { toast(editError(e), 'bad'); }
        } }, 'Validate & stage') : null),
      h('div', { class: 'card-body' }, h('div', { class: 'notice warn' }, 'Advanced: the raw editor replaces the whole candidate. Prefer the pages for routine changes.'), raw)));
  });

  page('audit', 'Audit Log', 'Every login, configuration and administrative action.', async (main) => {
    const data = await api('GET', '/api/v1/audit?limit=500');
    main.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Events'),
      table(['Time', 'Administrator', 'Action', 'Detail'], (data.events || []).slice().reverse().map((e) => [fmtTime(e.ts), h('b', {}, e.actor), chip(e.action, e.action.includes('fail') ? 'bad' : 'info'), h('span', { class: 'mono' }, e.detail || '')]))));
  });

  page('match', 'Policy Match Test', 'Which rule would decide a flow — like PAN-OS "test security-policy-match".', async (main) => {
    const zones = (S.model.zones || {})[S.vdom] || [];
    const f = {
      from: h('select', {}, zones.map((z) => h('option', { value: z }, z))), to: h('select', {}, zones.map((z) => h('option', { value: z }, z))),
      src: h('input', { placeholder: '10.0.0.5' }), dst: h('input', { placeholder: '203.0.113.10' }),
      proto: h('select', {}, ['tcp', 'udp', 'icmp'].map((p) => h('option', { value: p }, p))), port: h('input', { type: 'number', placeholder: '443' }),
      app: h('input', { placeholder: 'optional, e.g. ssl', list: 'dl-apps' }), user: h('input', { placeholder: 'optional' }),
    };
    const out = h('div');
    const run = async () => {
      const q = new URLSearchParams({ vdom: S.vdom, ...Object.fromEntries(Object.entries(f).map(([k, e]) => [k, e.value.trim()])) });
      try {
        const r = await api('GET', `/api/v1/tools/policy-match?${q}`);
        const p = r.matched;
        clear(out).append(p
          ? h('div', { class: `notice ${p.action === 'permit' ? 'ok' : 'bad'}` }, h('b', {}, p.default_rule ? `Default rule: ${p.name || p.id}` : `Policy ${p.id}${p.name ? ` (${p.name})` : ''}`), ` → ${p.action}`,
            r.user ? ` · user ${r.user}` : '', r.note ? h('div', { class: 'help' }, r.note) : null)
          : h('div', { class: 'notice bad' }, 'No rule matched: the traffic is dropped.'));
      } catch (e) { clear(out).append(h('div', { class: 'notice bad' }, e.message)); }
    };
    main.append(datalists(), h('div', { class: 'card' }, h('div', { class: 'card-head' }, 'Flow'), h('div', { class: 'card-body' },
      h('div', { class: 'form' }, Object.entries({ from: 'From zone', to: 'To zone', src: 'Source IP', dst: 'Destination IP', proto: 'Protocol', port: 'Destination port', app: 'Application', user: 'User' })
        .map(([k, label]) => h('div', { class: 'field' }, h('label', {}, label), f[k])),
      h('div', { class: 'field wide' }, h('button', { class: 'primary', onclick: run }, 'Test'))), out)));
  });

  function table(headers, rows, numCols = []) {
    return h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, headers.map((x, i) => h('th', { class: numCols.includes(i) ? 'num' : '' }, x)))),
      h('tbody', {}, rows.length ? rows.map((r) => h('tr', {}, r.map((c, i) => h('td', { class: numCols.includes(i) ? 'num' : '' }, c))))
        : h('tr', {}, h('td', { colspan: headers.length, class: 'empty' }, 'Nothing to show')))));
  }

  /* ------------------------------------------------- commit / discard */
  async function reviewCommit() {
    let diff = '';
    try { diff = await api('GET', '/api/v1/configuration/diff'); } catch (e) { toast(e.message, 'bad'); return; }
    const pre = h('div', { class: 'diff' }, diff.split('\n').map((l) => h('span', { class: l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : '' }, `${l}\n`)));
    const err = h('div', { class: 'notice bad', hidden: true });
    const commit = h('button', { class: 'primary', onclick: async () => {
      commit.disabled = true;
      try {
        const r = await api('POST', '/api/v1/configuration/commit');
        dlg.close(); await loadModel(); loadSystem();
        toast(`Committed as revision ${r.revision}${S.model.dataplane === 'kernel' ? ' — kernel ruleset verified' : ''}`, 'ok'); render();
      } catch (e) { err.hidden = false; err.textContent = editError(e); commit.disabled = false; }
    } }, 'Commit');
    const dlg = modal(`Review changes — ${S.model.changes} line(s)`, [h('p', {}, 'Commit applies these changes to the running configuration (and, in kernel mode, to the kernel, verified).'), err, pre],
      [h('button', { class: 'danger', onclick: async () => { dlg.close(); await discard(); } }, 'Discard all'), h('button', { onclick: () => dlg.close() }, 'Keep editing'), commit]);
  }
  async function discard() {
    if (!confirm('Discard every pending change in the candidate?')) return;
    try { await api('DELETE', '/api/v1/configuration/candidate'); await loadModel(); toast('Candidate discarded'); render(); } catch (e) { toast(e.message, 'bad'); }
  }

  /* --------------------------------------------------------------- shell */
  const NAV = [
    ['Overview', [['dashboard', 'Dashboard']]],
    ['Network', [['interfaces', 'Interfaces & Zones'], ['routing', 'Static Routing']]],
    ['Policy & Objects', [['policies', 'Security Policies'], ['default-rules', 'Default Rules'], ['nat', 'NAT'], ['addresses', 'Addresses'], ['services', 'Services'], ['applications', 'Applications']]],
    ['Security Profiles', [['urlfilter', 'URL Filtering'], ['ips', 'Intrusion Prevention'], ['av', 'Payload Signatures (AV)'], ['profile-groups', 'Profile Groups'], ['shapers', 'Traffic Shaping'], ['zone-protection', 'DoS / Zone Protection']]],
    ['User & Authentication', [['userid', 'User-ID'], ['users', 'User Groups & Maps'], ['admins', 'Administrators']]],
    ['Monitor', [['sessions', 'Sessions'], ['logs', 'Traffic Log'], ['hits', 'Policy Hit Counts']]],
    ['System', [['settings', 'Settings'], ['ha', 'High Availability'], ['vpn', 'VPN'], ['config', 'Configuration'], ['audit', 'Audit Log']]],
    ['Tools', [['match', 'Policy Match Test']]],
  ];

  function shell() {
    const app = clear($('#app'));
    app.className = 'shell';
    app.append(
      h('header', { class: 'topbar' },
        h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, 'NS'), 'NetworkSandbox', h('small', {}, 'Firewall')),
        h('span', { id: 'top-host', class: 'user-menu' }),
        h('span', { class: 'spacer' }),
        h('span', { id: 'top-vdom' }),
        h('span', { id: 'top-status', class: 'status-pill' }, h('span', { class: 'dot' }), '…'),
        h('button', { id: 'top-commit', class: 'commit-btn', onclick: () => (S.model && S.model.staged ? reviewCommit() : toast('No pending changes')) }, 'Commit'),
        h('span', { class: 'user-menu' }, `${S.user} · ${S.role}`, h('button', { class: 'small commit-btn', onclick: logout }, 'Log out'))),
      h('nav', { class: 'sidebar' }, NAV.map(([group, items]) => h('div', { class: 'nav-group' }, h('div', {}, group),
        items.map(([id, label]) => h('a', { class: 'nav-item', href: `#${id}`, 'data-page': id }, label))))),
      h('main', { class: 'main', id: 'main' }));
  }

  function renderTop() {
    if (!$('#top-commit')) return;
    const m = S.model; const sys = S.system;
    const c = $('#top-commit');
    c.textContent = m && m.staged ? `Commit (${m.changes})` : 'Commit';
    c.className = `commit-btn ${m && m.staged ? 'pending' : ''}`;
    c.disabled = !canWrite();
    if (sys) {
      $('#top-host').textContent = sys.hostname || '';
      const enf = sys.enforcement || {};
      const pill = $('#top-status');
      const ok = ['enforcing', 'kernel'].includes(enf.status);
      pill.className = `status-pill ${ok ? 'ok' : enf.status === 'off' ? '' : 'bad'}`;
      clear(pill).append(h('span', { class: 'dot' }), ok ? (enf.status === 'kernel' ? 'Kernel · verified' : 'Enforcing') : enf.status === 'off' ? 'Dataplane off' : 'Degraded');
      pill.title = (enf.problems || []).join('\n');
    }
    const vd = $('#top-vdom');
    if (m && vd) {
      clear(vd);
      if ((m.vdoms || []).length > 1) {
        vd.append(h('select', { onchange: (e) => { S.vdom = e.target.value; render(); } }, m.vdoms.map((v) => h('option', { value: v, selected: v === S.vdom }, `VDOM: ${v}`))));
      }
    }
  }

  async function render() {
    const id = PAGES[S.page] ? S.page : 'dashboard';
    const p = PAGES[id];
    for (const a of document.querySelectorAll('.nav-item')) a.classList.toggle('active', a.dataset.page === id);
    const main = $('#main');
    if (!main) return;
    if (S.timer) { clearTimeout(S.timer); S.timer = null; }
    // Navigation can overlap a slow render; only the newest one may paint.
    const seq = (S.renderSeq = (S.renderSeq || 0) + 1);
    const body = h('div');
    const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, p.title), h('p', {}, p.desc)), h('span', { class: 'spacer' }),
      S.model && S.model.staged ? h('span', { class: 'chip warn' }, `${S.model.changes} uncommitted change line(s)`) : null);
    try {
      if (!S.model || (p.opts && p.opts.reloadModel)) await loadModel();
      if (!canWrite() && id !== 'dashboard') body.append(h('div', { class: 'notice' }, `Your role (${S.role}) is read-only: you can view but not change the configuration.`));
      await p.render(body);
    } catch (e) {
      if (e.status === 401) return;
      body.append(h('div', { class: 'notice bad' }, `Could not load this page: ${e.message}`));
    }
    if (seq !== S.renderSeq) return;
    clear(main).append(head, body);
    if (p.opts && p.opts.refresh) S.timer = setTimeout(() => { if (S.page === id && !document.querySelector('dialog[open]')) render(); }, p.opts.refresh);
  }
  // Attach per-page options after registration.
  const pageOpts = { dashboard: { refresh: 5000 }, sessions: { refresh: 5000 }, logs: { refresh: 5000 }, ha: { refresh: 5000 }, hits: { refresh: 10000, reloadModel: true } };
  for (const [id, o] of Object.entries(pageOpts)) if (PAGES[id]) PAGES[id].opts = o;

  function route() { S.page = (location.hash || '#dashboard').slice(1); render(); }

  /* --------------------------------------------------------------- login */
  function showLogin(message) {
    if (S.timer) clearTimeout(S.timer);
    if (S.statusTimer) clearInterval(S.statusTimer);
    S.csrf = ''; S.model = null;
    const app = clear($('#app'));
    app.className = 'login';
    const u = h('input', { id: 'login-user', autocomplete: 'username' }); const p = h('input', { id: 'login-pass', type: 'password', autocomplete: 'current-password' });
    const err = h('div', { class: 'notice bad', hidden: !message }, message || '');
    const submit = async (e) => {
      e.preventDefault();
      try {
        const r = await api('POST', '/api/v1/auth/login', { username: u.value.trim(), password: p.value });
        S.csrf = r.csrf; S.user = r.username; S.role = r.role; start();
      } catch (ex) { err.hidden = false; err.textContent = ex.message; }
    };
    app.append(h('div', { class: 'card' }, h('div', { class: 'brand-mark' }, 'NS'), h('h1', {}, 'NetworkSandbox Firewall'), h('p', {}, 'Sign in to manage this firewall.'),
      h('form', { onsubmit: submit }, err, h('div', { class: 'field' }, h('label', { for: 'login-user' }, 'Username'), u),
        h('div', { class: 'field' }, h('label', { for: 'login-pass' }, 'Password'), p), h('button', { class: 'primary', type: 'submit' }, 'Sign in'))));
    u.focus();
  }
  async function logout() { try { await api('POST', '/api/v1/auth/logout'); } catch (_) { /* already gone */ } showLogin('Signed out.'); }

  async function start() {
    shell();
    await Promise.all([loadModel().catch(() => {}), loadSystem()]);
    if (S.model && !S.model.vdoms.includes(S.vdom)) S.vdom = S.model.vdoms[0] || 'root';
    if (S.statusTimer) clearInterval(S.statusTimer);
    S.statusTimer = setInterval(loadSystem, 10000);
    route();
  }

  window.addEventListener('hashchange', route);
  (async () => {
    try {
      const me = await fetch('/api/v1/auth/me', { credentials: 'same-origin', cache: 'no-store' });
      if (!me.ok) { showLogin(); return; }
      const j = await me.json();
      S.csrf = j.csrf || ''; S.user = j.username || ''; S.role = j.role || '';
      start();
    } catch (_) { showLogin(); }
  })();
})();
