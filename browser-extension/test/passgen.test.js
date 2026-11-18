// Run with: node --test browser-extension/test/
const test = require('node:test');
const assert = require('node:assert');
globalThis.crypto ??= require('node:crypto').webcrypto;
const G = require('../passgen.js');

function fakeInput(attrs) {
  return { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
}

test('default policy is strong and varied', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const pw = G.generate(G.defaultPolicy());
    assert.strictEqual(pw.length, 20);
    for (const set of [G.LOWER, G.UPPER, G.DIGIT, G.DEFAULT_SYMBOLS]) {
      assert.ok([...pw].some((c) => set.includes(c)), pw);
    }
    assert.ok(!seen.has(pw));
    seen.add(pw);
  }
});

test('passwordrules attribute is honoured', () => {
  const p = G.policyForField(fakeInput({ passwordrules: 'minlength: 8; maxlength: 12; required: lower; required: upper; required: digit' }));
  for (let i = 0; i < 100; i++) {
    const pw = G.generate(p);
    assert.ok(pw.length >= 8 && pw.length <= 12, pw);
    assert.match(pw, /^[A-Za-z0-9]+$/);
    assert.match(pw, /[a-z]/); assert.match(pw, /[A-Z]/); assert.match(pw, /[0-9]/);
  }
});

test('maxlength and pattern attributes are honoured', () => {
  const p = G.policyForField(fakeInput({ maxlength: '10', pattern: '[A-Za-z0-9]*[0-9][A-Za-z0-9]*' }));
  p.required = [G.LOWER, G.DIGIT];
  p.allowed = G.LOWER + G.DIGIT;
  for (let i = 0; i < 50; i++) {
    const pw = G.generate(p);
    assert.ok(pw.length === 10, pw);
    assert.match(pw, /^[a-z0-9]+$/);
  }
});

test('overrides: no symbols, custom symbols, length', () => {
  const base = G.defaultPolicy();
  const none = G.applyOverrides(base, { symbols: false, length: 16 });
  for (let i = 0; i < 50; i++) assert.match(G.generate(none), /^[A-Za-z0-9]{16}$/);
  const custom = G.applyOverrides(base, { symbolSet: '-_' });
  for (let i = 0; i < 50; i++) {
    const pw = G.generate(custom);
    assert.match(pw, /^[A-Za-z0-9_-]+$/);
    assert.match(pw, /[-_]/);
  }
});

test('impossible rules raise a readable error', () => {
  const p = G.parseRules('maxlength: 2; required: lower; required: upper; required: digit');
  assert.throws(() => G.generate(p), /too short/);
});
