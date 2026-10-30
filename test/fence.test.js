const test = require('node:test'); const assert = require('node:assert'); const fs = require('fs'); const path = require('path');
const { parsePolicy, evaluate, validatePolicy } = require('../src/fence');
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
