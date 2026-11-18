const browser = globalThis.browser ?? globalThis.chrome;
const G = globalThis.UAPassgen;

let tab = null;
let origin = null;
let saveTargets = [];
let overrides = null;

const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return n;
}

function send(message) {
  return browser.runtime.sendMessage(Object.assign({ origin }, message)).catch((e) => ({ status: 'error', error: e.message }));
}

function say(target, text, kind) {
  target.textContent = text;
  target.className = 'msg ' + (kind || '');
}

const hostOf = (o) => {
  try {
    return new URL(o).host;
  } catch (_) {
    return o;
  }
};

function policy() {
  return G.applyOverrides(G.defaultPolicy(), overrides);
}

function generate() {
  try {
    return G.generate(policy());
  } catch (e) {
    return '';
  }
}

async function copy(text) {
  await navigator.clipboard.writeText(text);
}

// ---------- saved logins ----------

async function loadLogins() {
  const box = $('#logins');
  box.textContent = '';
  box.appendChild(h('div', { class: 'muted' }, 'Loading…'));
  const r = await send({ type: 'list' });
  box.textContent = '';
  if (r.status !== 'ok') {
    box.appendChild(h('div', { class: 'msg err' }, r.error || 'Could not reach Universal Auth.'));
    return;
  }
  saveTargets = r.save_targets || [origin];
  fillTargets($('#add-form select[name=save_as]'), saveTargets, origin);
  const logins = r.logins || [];
  if (!logins.length) {
    box.appendChild(h('div', { class: 'muted' }, 'None yet.'));
    return;
  }
  for (const l of logins) box.appendChild(loginRow(l));
}

function fillTargets(select, targets, selected) {
  select.textContent = '';
  for (const t of targets) select.appendChild(h('option', { value: t, selected: t === selected ? '' : null }, hostOf(t)));
}

function loginRow(l) {
  const msg = h('div', { class: 'msg' });
  const editHost = h('div');
  const badge = l.match === 'parent' ? h('span', { class: 'badge', title: 'Saved for ' + hostOf(l.resource) }, 'parent')
    : l.match === 'alias' ? h('span', { class: 'badge', title: 'Linked from ' + hostOf(l.resource) }, 'linked') : null;
  const row = h('div', { class: 'login' },
    h('div', { class: 'who' }, h('b', {}, l.account || 'Saved login'), h('span', {}, hostOf(l.resource)), badge),
    h('div', { class: 'btns' },
      h('button', { class: 'p', onclick: async () => {
        say(msg, 'Approve on your phone…', 'wait');
        const r = await send({ type: 'fill_tab', credential_id: l.credential_id, tab_id: tab.id });
        if (r.status === 'filled') window.close();
        else say(msg, r.error || 'Not filled (' + r.status + ').', 'err');
      } }, 'Fill'),
      h('button', { onclick: async () => {
        say(msg, 'Approve on your phone…', 'wait');
        const r = await send({ type: 'reveal', credential_id: l.credential_id });
        if (r.status !== 'approved') return say(msg, r.error || 'Not released (' + r.status + ').', 'err');
        await copy(r.password);
        say(msg, 'Password copied.', 'ok');
      } }, 'Copy password'),
      h('button', { onclick: () => toggleEdit(l, editHost, msg) }, 'Edit'),
      l.match === 'alias' ? h('button', { onclick: async () => {
        const r = await send({ type: 'unlink', resource: l.resource });
        if (r.status === 'ok') loadLogins();
        else say(msg, r.error || 'Not unlinked.', 'err');
      } }, 'Unlink') : null,
      h('button', { class: 'danger', onclick: async () => {
        if (!confirm('Delete the saved login for ' + (l.account || hostOf(l.resource)) + '?')) return;
        say(msg, 'Approve the deletion on your phone…', 'wait');
        const r = await send({ type: 'delete', credential_id: l.credential_id });
        if (r.status === 'deleted') loadLogins();
        else say(msg, r.error || 'Not deleted (' + r.status + ').', 'err');
      } }, 'Delete'),
    ),
    editHost, msg,
  );
  return row;
}

function toggleEdit(l, host, msg) {
  if (host.firstChild) {
    host.textContent = '';
    return;
  }
  const targets = [...new Set([l.resource, ...saveTargets])];
  const form = h('form', {},
    h('label', {}, 'Username'), h('input', { name: 'username', value: l.account || '', autocomplete: 'off' }),
    h('label', {}, 'Password'), h('div', { class: 'pwrow' },
      h('input', { name: 'password', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'new password' }),
      h('button', { type: 'button', title: 'Generate', onclick: () => { form.password.value = generate(); } }, '⚄')),
    h('label', {}, 'Account'), h('input', { name: 'account', value: l.account || '' }),
    h('label', {}, 'Use on'), h('select', { name: 'save_as' }),
    h('div', { class: 'full muted' }, 'Saving replaces the username and password. ',
      h('button', { type: 'button', class: 'link', onclick: async () => {
        say(msg, 'Approve on your phone to load the current values…', 'wait');
        const r = await send({ type: 'reveal', credential_id: l.credential_id });
        if (r.status !== 'approved') return say(msg, r.error || 'Not released.', 'err');
        form.username.value = r.username || '';
        form.password.value = r.password || '';
        say(msg, '', '');
      } }, 'Load current values')),
    h('div', { class: 'full btns' }, h('button', { class: 'p', type: 'submit' }, 'Save changes'), h('button', { type: 'button', onclick: () => { host.textContent = ''; } }, 'Cancel')),
  );
  fillTargets(form.save_as, targets, l.resource);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!form.password.value) return say(msg, 'Enter or generate the password.', 'err');
    say(msg, 'Approve the change on your phone…', 'wait');
    const r = await send({
      type: 'update', credential_id: l.credential_id, username: form.username.value,
      password: form.password.value, account: form.account.value.trim(),
      save_as: form.save_as.value === l.resource ? '' : form.save_as.value,
    });
    if (r.status === 'updated') {
      host.textContent = '';
      loadLogins();
    } else say(msg, r.error || 'Not saved (' + r.status + ').', 'err');
  });
  host.appendChild(form);
}

// ---------- add ----------

function setupAdd() {
  const form = $('#add-form');
  $('#add-toggle').addEventListener('click', () => {
    form.hidden = !form.hidden;
    if (!form.hidden && !form.password.value) form.password.value = generate();
  });
  form.querySelector('[data-gen]').addEventListener('click', () => { form.password.value = generate(); });
  form.querySelector('[data-cancel]').addEventListener('click', () => { form.hidden = true; });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = form.querySelector('.msg');
    if (!form.password.value) return say(msg, 'Enter or generate a password.', 'err');
    say(msg, 'Saving…', '');
    const r = await send({ type: 'save', username: form.username.value, password: form.password.value, account: form.account.value.trim(), save_as: form.save_as.value });
    if (r.status === 'saved') {
      form.reset();
      form.hidden = true;
      loadLogins();
    } else if (r.status === 'exists') {
      say(msg, 'This site already has a login for "' + r.account + '". Edit that one, or use a different account label.', 'err');
    } else say(msg, r.error || 'Not saved.', 'err');
  });
}

// ---------- link ----------

function setupLink() {
  let all = null;
  const box = $('#link-box');
  const results = $('#search-results');
  const render = () => {
    const q = $('#search').value.trim().toLowerCase();
    results.textContent = '';
    if (!all) return;
    const hits = all.filter((l) => !q || l.resource.toLowerCase().includes(q) || (l.account || '').toLowerCase().includes(q)).slice(0, 50);
    if (!hits.length) results.appendChild(h('div', { class: 'muted' }, 'No matches.'));
    for (const l of hits) {
      results.appendChild(h('div', { class: 'login', title: 'Offer this login on ' + hostOf(origin), onclick: async () => {
        const r = await send({ type: 'link', resource: l.resource });
        if (r.status === 'ok') {
          box.hidden = true;
          loadLogins();
        } else say($('#global-msg'), r.error || 'Not linked.', 'err');
      } }, h('div', { class: 'who' }, h('b', {}, hostOf(l.resource)), h('span', {}, l.account || ''))));
    }
  };
  $('#link-toggle').addEventListener('click', async () => {
    box.hidden = !box.hidden;
    if (!box.hidden && !all) {
      results.textContent = 'Loading…';
      const r = await send({ type: 'all_logins' });
      all = r.status === 'ok' ? r.logins.filter((l) => l.resource !== origin) : [];
      render();
      $('#search').focus();
    }
  });
  $('#search').addEventListener('input', render);
}

// ---------- generator ----------

async function setupGenerator() {
  const r = await send({ type: 'overrides_get' });
  overrides = (r && r.overrides) || null;
  const form = $('#gen-form');
  const length = form.elements.namedItem('length');
  const symbols = form.elements.namedItem('symbols');
  const symbolSet = form.elements.namedItem('symbolSet');
  const sync = () => {
    const p = policy();
    length.value = String(G.effectiveLength(p));
    symbols.checked = !(overrides && overrides.symbols === false);
    symbolSet.value = (overrides && overrides.symbolSet) || '';
    $('#gen-desc').textContent = G.describe(p);
    $('#gen-out').value = generate();
  };
  const read = () => {
    const o = { length: parseInt(length.value, 10) || undefined, symbols: symbols.checked };
    if (symbols.checked && symbolSet.value.trim()) o.symbolSet = symbolSet.value.trim();
    overrides = o;
    sync();
  };
  form.addEventListener('submit', (e) => e.preventDefault());
  for (const control of [length, symbols, symbolSet]) control.addEventListener('change', read);
  $('#gen-save').disabled = !origin;
  $('#gen-reset').disabled = !origin;
  $('#gen-again').addEventListener('click', () => { $('#gen-out').value = generate(); });
  $('#gen-copy').addEventListener('click', async () => { await copy($('#gen-out').value); $('#gen-copy').textContent = 'Copied'; });
  $('#gen-save').addEventListener('click', async () => {
    await send({ type: 'overrides_set', overrides: overrides || {} });
    $('#gen-save').textContent = 'Remembered';
  });
  $('#gen-reset').addEventListener('click', async () => {
    await send({ type: 'overrides_set', overrides: null });
    overrides = null;
    sync();
  });
  sync();
}

// ---------- init ----------

(async function init() {
  [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  try {
    const u = new URL(tab.url);
    if (u.protocol === 'http:' || u.protocol === 'https:') origin = u.origin;
  } catch (_) {}
  if (!origin) {
    $('#site').textContent = 'Open a website to manage its logins.';
    for (const id of ['#logins-sec', '#add-sec', '#link-sec']) $(id).hidden = true;
    await setupGenerator();
    return;
  }
  $('#site').textContent = hostOf(origin);
  setupAdd();
  setupLink();
  await Promise.all([loadLogins(), setupGenerator()]);
})();
