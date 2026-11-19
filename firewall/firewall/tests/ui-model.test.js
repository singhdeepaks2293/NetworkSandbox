// Round-trip test for the UI object model (src/ui/model.js).
// For every object in a canonical configuration produced by the Rust code,
// parse(lines) then build() must give back exactly the same lines and key.
// Run: node tests/ui-model.test.js   (fixture: tests/fixtures/ui-sample-model.json,
// generated from tests/fixtures/ui-sample.conf via GET /api/v1/configuration/model)
'use strict';
const assert = require('assert');
const path = require('path');
const Model = require(path.join(__dirname, '..', 'src', 'ui', 'model.js'));
const fixture = require(path.join(__dirname, 'fixtures', 'ui-sample-model.json'));

let checked = 0;
const seen = new Set();
for (const section of fixture.sections) {
  for (const obj of section.objects) {
    const kind = Model.K[obj.kind];
    if (!kind) continue;
    const v = kind.parse(obj.lines);
    const out = kind.build(v);
    assert.deepStrictEqual(out, obj.lines, `${obj.key}: build(parse()) changed the lines`);
    if (kind.key && obj.kind !== 'system') assert.strictEqual(kind.key(v), obj.key, `${obj.key}: key mismatch`);
    seen.add(obj.kind);
    checked++;
  }
}
const expected = ['system', 'address', 'address-group', 'service', 'service-group', 'app-def', 'app-group', 'user-group', 'user-map',
  'url-filter', 'ips-profile', 'av-profile', 'shaper', 'profile-group', 'interface', 'route', 'route6', 'policy', 'snat', 'dnat',
  'default-rule', 'zone'];
for (const k of expected) assert(seen.has(k), `fixture has no ${k} object`);

// Validation errors are friendly FormErrors, not crashes.
const err = (fn) => { try { fn(); return null; } catch (e) { return e; } };
assert(err(() => Model.K.policy.build({ id: 'x', action: 'permit' })) instanceof Model.FormError);
assert(err(() => Model.K.address.build({ name: 'has space', members: '10.0.0.1' })) instanceof Model.FormError);
assert(err(() => Model.K['url-filter'].build({ name: 'u', block: '', allow: '' })) instanceof Model.FormError);
assert(err(() => Model.K['default-rule'].build({ kind: 'interzone', action: 'deny', zone: 'dmz' })) instanceof Model.FormError);
// Form input is normalised: comma/space lists, defaults.
assert.deepStrictEqual(Model.K.policy.build({ id: 5, srcZones: 'trust, dmz', dstZones: '', src: '', dst: '10.0.0.0/8', proto: 'tcp',
  service: '443', action: 'deny', nat: false, log: true, enabled: true }), ['policy 5 trust,dmz any any 10.0.0.0/8 tcp 443 deny']);
assert.deepStrictEqual(Model.K['ips-profile'].build({ name: 'edge', patterns: '/etc/passwd\n\n cmd.exe ' }),
  ['ips-profile edge', 'ips-signature edge 1 /etc/passwd', 'ips-signature edge 2 cmd.exe']);
console.log(`ui-model: ${checked} objects round-tripped across ${seen.size} kinds; validation checks passed`);
