const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const G = require('../passgen.js');

globalThis.crypto ??= require('node:crypto').webcrypto;
const run = (file, globals) => vm.runInNewContext(readFileSync(join(__dirname, '..', file), 'utf8'), { URL, ...globals });
const loginOrigin = 'https://login.example.test';
const otherOrigin = 'https://other.example.test';

function background({ sessionAvailable = true, urls = [loginOrigin], fillStatus = 'filled' } = {}) {
  const stored = {};
  const nativeCalls = [];
  const fills = [];
  const localWrites = [];
  let receive;
  const runtime = {
    id: 'test-extension',
    onMessage: { addListener: (listener) => { receive = listener; } },
    sendNativeMessage: async (_, message) => {
      nativeCalls.push(message);
      if (message.type === 'get_credential') return { status: 'approved', password: 'fixture', credential_id: '1' };
      return { status: 'saved' };
    },
  };
  const storage = { local: { set: async (values) => localWrites.push(values) } };
  if (sessionAvailable) storage.session = {
    get: async (key) => ({ [key]: stored[key] }),
    set: async (values) => Object.assign(stored, values),
    remove: async (key) => { delete stored[key]; },
  };
  const tabs = {
    onRemoved: { addListener() {} },
    get: async () => ({ url: urls.length > 1 ? urls.shift() : urls[0] }),
    sendMessage: async (...args) => { fills.push(args); return { status: fillStatus }; },
  };
  run('background.js', { browser: { runtime, storage, tabs } });
  return {
    stored, localWrites, nativeCalls, fills,
    page: (message, url) => receive(message, { tab: { id: 7 }, url }),
    popup: (message) => receive(message, { id: runtime.id }),
  };
}

test('pending save can follow same-origin navigation without returning the password to the page', async () => {
  const b = background();
  await b.page({ type: 'capture', password: 'fixture' }, loginOrigin + '/signup');
  const p = await b.page({ type: 'pending' }, loginOrigin + '/welcome');
  assert.equal(p.status, 'ok');
  assert.equal(p.origin, loginOrigin);
  assert.equal(p.captured.password, undefined);
  assert.equal((await b.page({ type: 'save_pending' }, loginOrigin)).status, 'saved');
  assert.equal(b.nativeCalls[0].origin, loginOrigin);
  assert.equal(b.nativeCalls[0].password, 'fixture');
  assert.equal((await b.page({ type: 'pending' }, loginOrigin)).status, 'none');
});

test('another origin in the same tab cannot read, save, update or dismiss a pending login', async () => {
  const b = background();
  await b.page({ type: 'capture', password: 'fixture' }, loginOrigin);
  for (const type of ['pending', 'list_pending', 'save_pending', 'update_pending']) {
    assert.notEqual((await b.page({ type }, otherOrigin)).status, 'ok');
  }
  await b.page({ type: 'dismiss' }, otherOrigin);
  assert.equal(b.nativeCalls.length, 0);
  assert.equal((await b.page({ type: 'pending' }, loginOrigin)).status, 'ok');
});

test('pending login does not fall back to disk-backed extension storage', async () => {
  const b = background({ sessionAvailable: false });
  assert.equal((await b.page({ type: 'capture', password: 'fixture' }, loginOrigin)).status, 'none');
  assert.equal(b.localWrites.length, 0);
});

test('toolbar fill stops if the tab changes origins during approval', async () => {
  const b = background({ urls: [loginOrigin, otherOrigin] });
  const r = await b.popup({ type: 'fill_tab', origin: loginOrigin, tab_id: 7, credential_id: '1' });
  assert.match(r.error, /changed sites/);
  assert.equal(b.nativeCalls.length, 1);
  assert.equal(b.fills.length, 0);
});

test('toolbar fill targets the main frame and reports when no field was filled', async () => {
  const b = background({ fillStatus: 'no_field' });
  const r = await b.popup({ type: 'fill_tab', origin: loginOrigin, tab_id: 7, credential_id: '1' });
  assert.match(r.error, /No password field/);
  assert.equal(b.fills[0][1].origin, loginOrigin);
  assert.equal(b.fills[0][2].frameId, 0);
  assert.equal(b.stored['pending:7'], undefined);
});

test('popup generator uses the length input, not the form length property', async () => {
  const element = () => ({ events: {}, addEventListener(type, fn) { this.events[type] = fn; } });
  const controls = { length: element(), symbols: element(), symbolSet: element() };
  const form = Object.assign(element(), { length: 3, elements: { namedItem: (name) => controls[name] } });
  const nodes = { '#gen-form': form };
  const document = { querySelector: (key) => nodes[key] ??= element() };
  const browser = {
    tabs: { query: async () => [{ url: 'about:blank' }] },
    runtime: { sendMessage: async () => ({ status: 'ok' }) },
  };
  await run('popup.js', { document, browser, UAPassgen: G });
  assert.equal(controls.length.value, '20');
  controls.length.value = '16';
  controls.symbols.checked = false;
  controls.length.events.change();
  assert.match(nodes['#gen-out'].value, /^[A-Za-z0-9]{16}$/);
});
