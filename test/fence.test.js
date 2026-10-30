const test = require('node:test'); const assert = require('node:assert'); const fs = require('fs'); const path = require('path');
const { parsePolicy, evaluate, validatePolicy, toYaml, serializePolicy, createAuditLog } = require('../src/fence');
const load = (f) => parsePolicy(fs.readFileSync(path.join(__dirname, '..', 'policies', f), 'utf8'));
const guest = load('guest.yaml'), owner = load('owner.json');
const d = (p, tool, args) => evaluate(p, { tool, args }).decision;
test('policies validate', () => { assert.deepStrictEqual(validatePolicy(guest), []); assert.deepStrictEqual(validatePolicy(owner), []); });
test('guest', () => {
  assert.equal(d(guest, 'web.search', { query: 'x' }), 'allow');
  assert.equal(d(guest, 'web.search', {}), 'deny');
  assert.equal(d(guest, 'email.read', {}), 'deny');
  assert.equal(d(guest, 'calendar.freebusy', { days: 7 }), 'allow');
  assert.equal(d(guest, 'calendar.freebusy', { days: 60 }), 'deny');
  assert.equal(d(guest, 'shell.exec', { cmd: 'ls' }), 'deny');
});
test('owner', () => {
  assert.equal(d(owner, 'shell.exec', { cmd: 'ls -la' }), 'allow');
  assert.equal(d(owner, 'shell.exec', { cmd: 'rm -rf /' }), 'deny');
  assert.equal(d(owner, 'shell.exec', { cmd: 'npm publish' }), 'confirm');
  assert.equal(d(owner, 'email.send', { to: 'a@b.com', subject: 's', body: 'b' }), 'confirm');
  assert.equal(d(owner, 'payments.charge', { amountUsd: 40, merchant: 'x' }), 'confirm');
  assert.equal(d(owner, 'payments.charge', { amountUsd: 900, merchant: 'x' }), 'deny');
  assert.equal(d(owner, 'web.fetch', { url: 'https://x' }), 'allow');
});
test('malformed call denied', () => assert.equal(evaluate(owner, {}).decision, 'deny'));

test('policy export round-trips through YAML and JSON', () => {
  for (const p of [guest, owner]) {
    assert.deepStrictEqual(parsePolicy(toYaml(p)), p);
    assert.deepStrictEqual(parsePolicy(serializePolicy(p, 'json')), p);
    assert.deepStrictEqual(parsePolicy(serializePolicy(p, 'yaml')), p);
  }
  const tricky = { name: 'x', default: 'deny', rules: [{ id: 'r', tool: 'a.*', effect: 'allow', reason: 'has, comma: and "quotes"', args: { n: { oneOf: ['true', '12', 'a b', 'x,y'] } } }] };
  assert.deepStrictEqual(parsePolicy(toYaml(tricky)), tricky);
});
test('audit log records timestamped decisions', () => {
  let t = Date.parse('2026-01-02T03:04:05Z');
  const log = createAuditLog({ now: () => t++ });
  log.evaluate(guest, { tool: 'web.search', args: { query: 'x' } });
  const call = { tool: 'shell.exec', args: { cmd: 'ls' } };
  log.record(guest, call, evaluate(guest, call));
  call.args.cmd = 'mutated';
  const e = log.entries();
  assert.equal(e.length, 2);
  assert.deepStrictEqual(e.map((x) => x.seq), [1, 2]);
  assert.equal(e[0].timestamp, '2026-01-02T03:04:05.000Z');
  assert.equal(e[0].decision, 'allow'); assert.equal(e[0].rule, 'guest-web-search'); assert.equal(e[0].policy, 'guest');
  assert.equal(e[1].decision, 'deny'); assert.equal(e[1].args.cmd, 'ls');
  const dump = JSON.parse(JSON.stringify(log.toJSON()));
  assert.equal(dump.count, 2); assert.ok(dump.exportedAt);
  log.clear(); assert.equal(log.entries().length, 0);
});
test('audit log is bounded', () => {
  const log = createAuditLog({ max: 3 });
  for (let i = 0; i < 5; i++) log.evaluate(owner, { tool: 'web.fetch', args: {} });
  assert.deepStrictEqual(log.entries().map((x) => x.seq), [3, 4, 5]);
});
