// End-to-end test of the web UI in a headless DOM (jsdom) against a running
// daemon: login, every page renders without errors, objects are created and
// edited through the forms, policies reordered, and the candidate committed.
//
//   npm install jsdom@24              (once, anywhere on NODE_PATH)
//   firewall daemon --config tests/fixtures/ui-sample.conf --dry-run   (admin password in VELA_ADMIN_PASSWORD)
//   VELA_URL=https://127.0.0.1:8080 VELA_PASSWORD=... node tests/ui-e2e.js
'use strict';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const BASE = process.env.VELA_URL || 'https://127.0.0.1:8080';
const USER = process.env.VELA_USER || 'admin';
const PASS = process.env.VELA_PASSWORD || '';
const UI = path.join(__dirname, '..', 'src', 'ui');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function browser() {
  const html = fs.readFileSync(path.join(UI, 'index.html'), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `${BASE}/`, runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  const errors = [];
  let cookie = '';
  w.fetch = async (url, opts = {}) => {
    const headers = { ...(opts.headers || {}), ...(cookie ? { cookie } : {}) };
    const r = await fetch(new URL(url, BASE), { method: opts.method || 'GET', headers, body: opts.body });
    const set = r.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    return r;
  };
  w.confirm = () => true;
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { if (this.open) { this.open = false; this.dispatchEvent(new w.Event('close')); } };
  w.addEventListener('error', (e) => errors.push(e.message));
  w.console.error = (...a) => errors.push(a.join(' '));
  w.eval(fs.readFileSync(path.join(UI, 'model.js'), 'utf8'));
  w.eval(fs.readFileSync(path.join(UI, 'app.js'), 'utf8'));
  const doc = w.document;
  const until = async (pred, what, ms = 6000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) { if (pred()) return; await sleep(25); }
    throw new Error(`timeout waiting for ${what}; errors: ${errors.join(' | ')}`);
  };
  const go = async (page, title) => {
    w.location.hash = page;
    await until(() => doc.querySelector('.page-head h1')?.textContent === title, `page ${page}`);
    await sleep(60);
  };
  const button = (text, root = doc) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
  const toastText = () => [...doc.querySelectorAll('.toast')].map((t) => t.textContent).join(' | ');
  return { w, doc, errors, until, go, button, toastText };
}

(async () => {
  assert(PASS, 'set VELA_PASSWORD');
  const b = await browser();
  const { doc, until, go, button, errors } = b;

  // Login screen first.
  await until(() => doc.querySelector('#login-user'), 'login form');
  doc.querySelector('#login-user').value = USER;
  doc.querySelector('#login-pass').value = PASS;
  doc.querySelector('form').dispatchEvent(new b.w.Event('submit', { cancelable: true }));
  await until(() => doc.querySelector('.page-head h1'), 'first page after login');
  console.log('PASS login');

  // Every page renders without a load error.
  const pages = [...doc.querySelectorAll('.nav-item')].map((a) => [a.dataset.page, a.textContent]);
  const titles = { dashboard: 'Dashboard', av: 'Payload Signatures (AV)' };
  for (const [id, label] of pages) {
    await go(id, titles[id] || label);
    const bad = doc.querySelector('#main .notice.bad');
    assert(!(bad && bad.textContent.startsWith('Could not load')), `${id}: ${bad && bad.textContent}`);
  }
  console.log(`PASS ${pages.length} pages render`);

  // Create a policy through the form.
  await go('policies', 'Security Policies');
  button('+ New').click();
  await until(() => doc.querySelector('dialog[open] #f-id'), 'policy form');
  const dlg = () => doc.querySelector('dialog[open]');
  const set = (k, v) => { const e = dlg().querySelector(`#f-${k}`); if (e.type === 'checkbox') e.checked = v; else e.value = v; };
  set('id', '40'); set('name', 'web-alt'); set('srcZones', 'trust'); set('dstZones', 'untrust'); set('proto', 'tcp'); set('service', '8443'); set('action', 'permit');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg() && b.toastText().includes('Saved to the candidate'), 'policy saved');
  await until(() => [...doc.querySelectorAll('#main tbody tr')].some((tr) => tr.textContent.includes('web-alt')), 'new policy row');
  assert([...doc.querySelectorAll('#main tbody tr')].find((tr) => tr.textContent.includes('web-alt')).textContent.includes('new in candidate'), 'new row is marked');
  assert(button('Commit (1)') || [...doc.querySelectorAll('#top-commit')].some((x) => /Commit \(\d+\)/.test(x.textContent)), 'commit button shows pending changes');
  console.log('PASS create policy via form → candidate');

  // A form error is shown inline, not sent.
  button('+ New').click();
  await until(() => dlg(), 'second form');
  set('id', 'abc');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg().querySelector('.form-error').hidden, 'inline form error');
  button('Cancel', dlg()).click();
  console.log('PASS invalid input rejected in the form');

  // Server-side validation errors come back into the form (unknown address object).
  button('+ New').click();
  await until(() => dlg(), 'third form');
  set('id', '41'); set('srcZones', 'trust'); set('dstZones', 'untrust'); set('src', '@does-not-exist');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg().querySelector('.form-error').hidden, 'server error shown');
  assert(/does-not-exist|unknown/i.test(dlg().querySelector('.form-error').textContent), dlg().querySelector('.form-error').textContent);
  button('Cancel', dlg()).click();
  console.log('PASS server validation error shown in the form');

  // Edit an existing policy and move one down.
  const row = (text) => [...doc.querySelectorAll('#main tbody tr')].find((tr) => tr.textContent.includes(text));
  button('Edit', row('out')).click();
  await until(() => dlg(), 'edit form');
  assert.strictEqual(dlg().querySelector('#f-id').value, '20');
  set('name', 'outbound');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg() && row('outbound'), 'edited policy');
  assert(row('outbound').textContent.includes('changed in candidate'), 'changed row is marked');
  assert(row('udp').textContent.includes('disabled'), 'disabled policy shows a disabled chip');
  const before = [...doc.querySelectorAll('#main tbody tr')].map((tr) => tr.cells[0].textContent);
  button('↓', row('outbound')).click();
  await until(() => row('outbound') && row('outbound').cells[0].textContent === '30', 'policy moved down to id 30');
  assert.strictEqual(row('udp').cells[0].textContent, '20', 'the policy below moved up to id 20');
  console.log(`PASS edit + move down (ids before: ${before.join(',')})`);

  // An address object.
  await go('addresses', 'Addresses');
  button('+ New', doc.querySelector('#main .card')).click();
  await until(() => dlg(), 'address form');
  set('name', 'db-servers'); set('members', '10.2.0.5\n10.2.0.6/32');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg() && row('db-servers'), 'address created');
  console.log('PASS create address object');

  // Review and commit.
  doc.querySelector('#top-commit').click();
  await until(() => dlg() && dlg().querySelector('.diff'), 'diff dialog');
  const diff = dlg().querySelector('.diff').textContent;
  assert(dlg().textContent.includes('Up to date'), 'commit review shows the candidate is current');
  assert(/⋯ \d+ unchanged line/.test(diff), 'unchanged context is collapsed');
  button('Show full diff', dlg()).click();
  assert(dlg().querySelector('.diff').textContent.includes('system hostname'), 'full diff on request');
  button('Show changes only', dlg()).click();
  assert(diff.includes('+policy 40') && diff.includes('db-servers'), diff);
  button('Commit', dlg()).click();
  await until(() => b.toastText().includes('Committed as revision'), 'commit toast');
  const running = await (await b.w.fetch('/api/config')).text();
  assert(running.includes('policy 40 trust untrust any any tcp 8443 permit name web-alt'), running);
  assert(running.includes('address db-servers 10.2.0.5/32 10.2.0.6/32'), running);
  assert(/policy 30 trust untrust !@quarantine any any @basics permit nat name outbound/.test(running), 'policy swapped to id 30 with new name');
  assert(!doc.querySelector('#top-commit').textContent.includes('('), 'no pending changes after commit');
  console.log('PASS review diff + commit → running configuration');

  // Policy match tool.
  await go('match', 'Policy Match Test');
  const f = (i) => doc.querySelectorAll('#main .form input, #main .form select')[i];
  f(0).value = 'trust'; f(1).value = 'untrust'; f(2).value = '10.0.0.5'; f(3).value = '203.0.113.10'; f(4).value = 'tcp'; f(5).value = '8443';
  button('Test').click();
  await until(() => doc.querySelector('#main .notice.ok, #main .notice.bad:not(:first-child)'), 'match result');
  assert(doc.querySelector('#main').textContent.includes('Policy 40'), doc.querySelector('#main').textContent);
  console.log('PASS policy match → policy 40');

  // A deleted policy stays visible, marked, until commit or discard.
  await go('policies', 'Security Policies');
  const byId = (id) => [...doc.querySelectorAll('#main tbody tr')].find((tr) => tr.cells[0].textContent.startsWith(String(id)));
  button('Delete', byId(10)).click();
  await until(() => byId(10) && byId(10).classList.contains('deleted') && byId(10).textContent.includes('deleted in candidate'), 'deleted row marked');
  console.log('PASS change markers: new, changed, deleted, disabled; commit shows up-to-date');

  // Configuration values are rendered as text, never as HTML.
  await go('urlfilter', 'URL Filtering');
  button('+ New').click();
  await until(() => dlg(), 'url filter form');
  set('name', 'xss'); set('block', '<img src=x onerror=alert(1)>.example');
  button('Save to candidate', dlg()).click();
  await until(() => !dlg() && row('xss'), 'url filter created');
  assert(row('xss').textContent.includes('<img'), 'value shown literally');
  assert(!doc.querySelector('#main img'), 'no element was created from configuration text');
  doc.querySelector('#top-commit').click();
  await until(() => dlg() && dlg().querySelector('.diff'), 'diff dialog 2');
  button('Discard all', dlg()).click();
  await until(() => b.toastText().includes('Candidate discarded'), 'discarded');
  console.log('PASS configuration text cannot inject HTML; discard works');

  // A read-only role sees no edit controls, and the server refuses its edits.
  const mk = await b.w.fetch('/api/v1/administrators', { method: 'POST', headers: { 'content-type': 'application/json', 'X-VELA-CSRF': (await (await b.w.fetch('/api/v1/auth/me')).json()).csrf },
    body: JSON.stringify({ username: 'viewer', password: 'Viewer-Passw0rd!', role: 'auditor' }) });
  assert([200, 201].includes(mk.status), `create auditor: ${mk.status}`);
  const ro = await browser();
  await ro.until(() => ro.doc.querySelector('#login-user'), 'login form (auditor)');
  ro.doc.querySelector('#login-user').value = 'viewer';
  ro.doc.querySelector('#login-pass').value = 'Viewer-Passw0rd!';
  ro.doc.querySelector('form').dispatchEvent(new ro.w.Event('submit', { cancelable: true }));
  await ro.until(() => ro.doc.querySelector('.page-head h1'), 'first page (auditor)');
  await ro.go('policies', 'Security Policies');
  assert(!ro.button('+ New') && !ro.button('Delete'), 'no create/delete for a read-only role');
  assert(ro.doc.querySelector('#main').textContent.includes('read-only'), 'read-only notice shown');
  const me = await (await ro.w.fetch('/api/v1/auth/me')).json();
  const denied = await ro.w.fetch('/api/v1/configuration/edit', { method: 'POST', headers: { 'content-type': 'application/json', 'X-VELA-CSRF': me.csrf },
    body: JSON.stringify({ edits: [{ mode: 'delete', vdom: 'root', key: 'policy 10' }] }) });
  assert.strictEqual(denied.status, 403, 'server refuses edits from a read-only role');
  const nocsrf = await b.w.fetch('/api/v1/configuration/edit', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ edits: [{ mode: 'delete', vdom: 'root', key: 'policy 10' }] }) });
  assert.strictEqual(nocsrf.status, 403, 'edits without the CSRF token are refused');
  assert.deepStrictEqual(ro.errors, [], `script errors (auditor): ${ro.errors.join(' | ')}`);
  console.log('PASS read-only role: no edit controls, server 403; CSRF enforced');

  assert.deepStrictEqual(errors, [], `script errors: ${errors.join(' | ')}`);
  console.log('ui-e2e: all checks passed');
  process.exit(0);
})().catch((e) => { console.error('FAIL', e.message); process.exit(1); });
