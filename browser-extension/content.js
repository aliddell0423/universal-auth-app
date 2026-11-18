const browser = globalThis.browser ?? globalThis.chrome;
const G = globalThis.UAPassgen;

// ---------- field detection ----------

const SIGNUP_RE = /sign\s*-?up|register|create\s+(an\s+)?account|join|get\s+started|new\s+password|change\s+password|reset\s+password|set\s+password/i;
const NEWFIELD_RE = /new|confirm|repeat|retype|again|create|verify/i;
const LOGIN_BUTTON_RE = /log\s*-?in|sign\s*-?in|sign\s*-?up|register|create|continue|next|submit|save|update|change|join/i;

function isPasswordField(el) {
  return el && el.tagName === 'INPUT' && el.type === 'password' && !el.disabled && !el.readOnly;
}

function visible(el) {
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
}

function scopeOf(field) {
  return field.closest('form') || field.form || document;
}

function passwordFields(scope) {
  return [...scope.querySelectorAll('input[type="password"]')].filter((el) => !el.disabled && visible(el));
}

function fieldText(el) {
  return [el.name, el.id, el.getAttribute('autocomplete'), el.getAttribute('aria-label'), el.placeholder]
    .filter(Boolean)
    .join(' ');
}

function isNewPasswordContext(field) {
  const ac = (field.getAttribute('autocomplete') || '').toLowerCase();
  if (ac.includes('new-password')) return true;
  if (ac.includes('current-password')) return false;
  const scope = scopeOf(field);
  if (passwordFields(scope).length >= 2) return true;
  if (NEWFIELD_RE.test(fieldText(field))) return true;
  const form = field.closest('form');
  const context = [
    form && form.getAttribute('action'),
    form && form.id,
    form && [...form.querySelectorAll('button, input[type="submit"]')].map((b) => b.textContent || b.value).join(' '),
    location.pathname,
    document.title,
  ].filter(Boolean).join(' ');
  return SIGNUP_RE.test(context);
}

// newPasswordFields returns the fields that should receive a generated
// password: in a change-password form, the "new" and "confirm" fields but
// not the current one.
function newPasswordFields(field) {
  const all = passwordFields(scopeOf(field));
  if (all.length <= 1) return [field];
  const current = all.filter((el) => /current-password/i.test(el.getAttribute('autocomplete') || '') || /current|old/i.test(fieldText(el)));
  const rest = all.filter((el) => !current.includes(el));
  return rest.length ? rest : all;
}

function findUsernameInput(passwordInput) {
  const scope = scopeOf(passwordInput);
  const pick = (sel) => [...scope.querySelectorAll(sel)].find((el) => visible(el) && !el.disabled);
  const byAuto = pick('input[autocomplete~="username"], input[autocomplete~="email"]');
  if (byAuto) return byAuto;
  const email = pick('input[type="email"]');
  if (email) return email;
  // Otherwise the last text-like input before the password field.
  const inputs = [...scope.querySelectorAll('input')].filter((el) => visible(el) && /^(text|email|tel|)$/.test(el.type));
  let candidate = null;
  for (const el of inputs) {
    if (el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING) candidate = el;
  }
  return candidate || inputs[0] || null;
}

function fillValue(input, value) {
  const v = value || '';
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (setter && setter.set) setter.set.call(input, v);
  else input.value = v;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function fillLogin(passwordInput, credential) {
  const username = findUsernameInput(passwordInput);
  if (username && credential.username) fillValue(username, credential.username);
  fillValue(passwordInput, credential.password);
}

// ---------- shadow-DOM UI ----------

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font: 13px/1.35 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1f2328; }
.panel { background: #fff; border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,.18); width: 320px; overflow: hidden; }
.head { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #f6f8fa; border-bottom: 1px solid #d0d7de; font-weight: 600; }
.head small { font-weight: 400; color: #59636e; }
.x { border: 0; background: none; cursor: pointer; font-size: 16px; color: #59636e; padding: 0 4px; }
.sec { padding: 8px 12px; }
.sec + .sec { border-top: 1px solid #eaeef2; }
.row { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 6px; cursor: pointer; }
.row:hover, .row:focus { background: #eef4ff; outline: none; }
.row .who { flex: 1; min-width: 0; }
.row .who b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row .who span { color: #59636e; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
.badge { font-size: 11px; color: #59636e; border: 1px solid #d0d7de; border-radius: 10px; padding: 0 6px; }
.muted { color: #59636e; font-size: 12px; }
.pw { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 6px 8px; word-break: break-all; margin: 6px 0; user-select: all; }
.btns { display: flex; gap: 6px; flex-wrap: wrap; }
button.b { border: 1px solid #d0d7de; background: #f6f8fa; border-radius: 6px; padding: 5px 10px; cursor: pointer; }
button.b:hover { background: #eef1f4; }
button.p { background: #1f6feb; border-color: #1f6feb; color: #fff; }
button.p:hover { background: #1a5fd0; }
button.link { border: 0; background: none; color: #0969da; cursor: pointer; padding: 0; }
.opts { display: grid; grid-template-columns: auto 1fr; gap: 6px 8px; align-items: center; margin-top: 6px; }
.opts input[type=number] { width: 64px; }
.opts input[type=text] { width: 100%; }
input, select { border: 1px solid #d0d7de; border-radius: 6px; padding: 4px 6px; background: #fff; }
.err { color: #cf222e; font-size: 12px; margin-top: 4px; }
.ok { color: #1a7f37; }
.banner { position: fixed; top: 16px; right: 16px; }
`;

let menu = null; // {host, root, field}
let banner = null;

function makeHost() {
  const host = document.createElement('universal-auth-ui');
  host.style.cssText = 'position:absolute;z-index:2147483647;top:0;left:0;';
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = STYLE;
  root.appendChild(style);
  document.documentElement.appendChild(host);
  return { host, root };
}

function el(tag, attrs, ...children) {
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

function closeMenu() {
  if (menu) {
    menu.host.remove();
    menu = null;
  }
}

function positionMenu() {
  if (!menu) return;
  const r = menu.field.getBoundingClientRect();
  const width = 320;
  let left = r.left + window.scrollX;
  left = Math.min(left, window.scrollX + document.documentElement.clientWidth - width - 8);
  menu.host.style.left = Math.max(window.scrollX + 8, left) + 'px';
  menu.host.style.top = r.bottom + window.scrollY + 4 + 'px';
}

function send(message) {
  return browser.runtime.sendMessage(message).catch((err) => ({ status: 'error', error: err.message }));
}

function siteName() {
  return location.hostname.replace(/^www\./, '');
}

function waitingText(what) {
  return el('div', { class: 'muted' }, what + ' Approve on your phone…');
}

async function openMenu(field) {
  if (menu && menu.field === field) return;
  closeMenu();
  const { host, root } = makeHost();
  menu = { host, root, field };
  positionMenu();

  const body = el('div', { class: 'panel', role: 'dialog', 'aria-label': 'Universal Auth' });
  // Keep focus in the page field while clicking inside the menu.
  body.addEventListener('mousedown', (e) => {
    if (!['INPUT', 'SELECT'].includes(e.target.tagName)) e.preventDefault();
  });
  body.appendChild(el('div', { class: 'head' }, el('span', {}, 'Universal Auth ', el('small', {}, siteName())), el('button', { class: 'x', title: 'Close', onclick: closeMenu }, '×')));
  const loginsSec = el('div', { class: 'sec' }, el('div', { class: 'muted' }, 'Looking up saved logins…'));
  const genSec = el('div', { class: 'sec' });
  const isNew = isNewPasswordContext(field);
  if (isNew) body.append(genSec, loginsSec);
  else body.append(loginsSec, genSec);
  root.appendChild(body);

  renderGenerator(genSec, field, isNew);

  const resp = await send({ type: 'list' });
  if (!menu || menu.field !== field) return;
  loginsSec.textContent = '';
  if (resp.status !== 'ok') {
    loginsSec.appendChild(el('div', { class: 'err' }, resp.error || 'Could not reach Universal Auth.'));
    return;
  }
  const logins = resp.logins || [];
  if (!logins.length) {
    loginsSec.appendChild(el('div', { class: 'muted' }, isNew ? 'No saved login for this site yet. Generate one above; you will be offered to save it after you submit.' : 'No saved login for this site. Use the toolbar button to link one, or sign in and you will be offered to save it.'));
    return;
  }
  loginsSec.appendChild(el('div', { class: 'muted' }, isNew ? 'Saved logins' : 'Fill with'));
  for (const login of logins) {
    const row = el(
      'div',
      { class: 'row', tabindex: '0', role: 'button' },
      el('div', { class: 'who' }, el('b', {}, login.account || 'Saved login'), el('span', {}, login.resource)),
      login.match !== 'exact' ? el('span', { class: 'badge', title: login.match === 'parent' ? 'Saved for a parent domain' : 'Linked to this site' }, login.match === 'parent' ? 'parent' : 'linked') : null,
    );
    const go = async () => {
      row.replaceWith(waitingText('Filling ' + (login.account || 'login') + '.'));
      const r = await send({ type: 'fill', credential_id: login.credential_id });
      if (r.status === 'approved') {
        fillLogin(field, r);
        closeMenu();
      } else if (menu) {
        loginsSec.appendChild(el('div', { class: 'err' }, r.error || 'Not filled.'));
      }
    };
    row.addEventListener('click', go);
    row.addEventListener('keydown', (e) => e.key === 'Enter' && go());
    loginsSec.appendChild(row);
  }
}

async function renderGenerator(sec, field, prominent) {
  const got = await send({ type: 'overrides_get' });
  let overrides = (got && got.overrides) || null;
  const policy = () => G.applyOverrides(G.policyForField(field), overrides);
  let pw = '';
  const preview = el('div', { class: 'pw' });
  const desc = el('div', { class: 'muted' });
  const err = el('div', { class: 'err' });
  const regen = () => {
    err.textContent = '';
    try {
      const p = policy();
      pw = G.generate(p);
      preview.textContent = pw;
      desc.textContent = G.describe(p);
    } catch (e) {
      pw = '';
      preview.textContent = '—';
      err.textContent = e.message;
    }
  };

  const lengthIn = el('input', { type: 'number', min: '4', max: '128' });
  const symIn = el('input', { type: 'checkbox' });
  const setIn = el('input', { type: 'text', placeholder: G.DEFAULT_SYMBOLS });
  const remember = el('input', { type: 'checkbox' });
  const syncOpts = () => {
    const p = policy();
    lengthIn.value = String(G.effectiveLength(p));
    symIn.checked = !(overrides && overrides.symbols === false);
    setIn.value = (overrides && overrides.symbolSet) || '';
    remember.checked = !!overrides;
  };
  const applyOpts = async () => {
    const o = { length: parseInt(lengthIn.value, 10) || undefined, symbols: symIn.checked };
    if (symIn.checked && setIn.value.trim()) o.symbolSet = setIn.value.trim();
    overrides = o;
    if (remember.checked) await send({ type: 'overrides_set', overrides: o });
    regen();
  };
  for (const i of [lengthIn, symIn, setIn]) i.addEventListener('change', applyOpts);
  remember.addEventListener('change', async () => {
    await send({ type: 'overrides_set', overrides: remember.checked ? overrides || {} : null });
    if (!remember.checked) {
      overrides = null;
      syncOpts();
      regen();
    }
  });
  const opts = el('div', { class: 'opts', hidden: '' },
    el('label', {}, 'Length'), lengthIn,
    el('label', {}, 'Symbols'), symIn,
    el('label', {}, 'Only these'), setIn,
    el('label', {}, 'Remember'), el('label', { class: 'muted' }, remember, ' for ' + siteName()),
  );

  const use = () => {
    if (!pw) return;
    for (const f of newPasswordFields(field)) fillValue(f, pw);
    const user = findUsernameInput(field);
    send({ type: 'capture', username: user ? user.value : '', password: pw, generated: true });
    closeMenu();
  };

  const showFull = () => {
    sec.textContent = '';
    sec.append(
      el('div', {}, el('b', {}, 'Strong password')),
      preview, desc,
      el('div', { class: 'btns' },
        el('button', { class: 'b p', onclick: use }, 'Use password'),
        el('button', { class: 'b', onclick: regen, title: 'Another one' }, '↻'),
        el('button', { class: 'link', onclick: () => opts.toggleAttribute('hidden') }, 'Options'),
      ),
      opts, err,
    );
    syncOpts();
    regen();
  };
  if (prominent) showFull();
  else sec.appendChild(el('button', { class: 'link', onclick: showFull }, 'Generate a strong password'));
}

// ---------- save / update banner ----------

function closeBanner() {
  if (banner) {
    banner.host.remove();
    banner = null;
  }
}

async function checkPending() {
  if (banner) return;
  const p = await send({ type: 'pending' });
  if (!p || p.status !== 'ok' || !p.captured) return;
  const listed = await send({ type: 'list_pending' });
  if (!listed || listed.status !== 'ok') return;
  const username = p.captured.username || '';
  const exact = (listed.logins || []).filter((l) => l.match === 'exact' || l.match === 'alias' || l.match === 'parent');
  const same = exact.find((l) => l.account === username) || (!username && exact.length === 1 ? exact[0] : null);
  showBanner(p.origin, username, same, listed.save_targets || [p.origin], p.captured.generated);
}

function showBanner(origin, username, existing, targets, generated) {
  closeBanner();
  const { host, root } = makeHost();
  host.style.position = 'fixed';
  banner = { host, root };
  const box = el('div', { class: 'panel banner' });
  const status = el('div', {});
  const site = new URL(origin).hostname;
  const accountIn = el('input', { type: 'text', value: username, placeholder: 'account label' });
  const targetSel = el('select', {}, targets.map((t) => el('option', { value: t }, new URL(t).hostname)));
  const finish = (text, ok) => {
    status.textContent = '';
    status.appendChild(el('div', { class: ok ? 'ok' : 'err' }, text));
    if (ok) setTimeout(closeBanner, 2500);
  };

  const doUpdate = async (credentialId) => {
    status.textContent = '';
    status.appendChild(waitingText('Updating.'));
    const r = await send({ type: 'update_pending', credential_id: credentialId });
    if (r.status === 'updated') finish('Password updated.', true);
    else finish(r.error || 'Not updated (' + r.status + ').', false);
  };
  const doSave = async () => {
    status.textContent = '';
    status.appendChild(el('div', { class: 'muted' }, 'Saving…'));
    const r = await send({ type: 'save_pending', account: accountIn.value.trim(), save_as: targetSel.value });
    if (r.status === 'saved') finish('Saved to Universal Auth.', true);
    else if (r.status === 'exists') {
      status.textContent = '';
      status.append(
        el('div', {}, 'This site already has a login for "' + (r.account || 'this account') + '".'),
        el('div', { class: 'btns' }, el('button', { class: 'b p', onclick: () => doUpdate(r.credential_id) }, 'Replace it'), el('button', { class: 'b', onclick: closeBanner }, 'Cancel')),
      );
    } else finish(r.error || 'Not saved.', false);
  };
  const dismiss = () => {
    send({ type: 'dismiss' });
    closeBanner();
  };

  box.appendChild(el('div', { class: 'head' }, el('span', {}, existing ? 'Update saved password?' : 'Save this login?'), el('button', { class: 'x', title: 'Close', onclick: dismiss }, '×')));
  const sec = el('div', { class: 'sec' });
  if (existing) {
    sec.append(
      el('div', {}, 'Update the saved password for ', el('b', {}, existing.account || 'this login'), ' on ' + new URL(existing.resource).hostname + '?'),
      el('div', { class: 'muted' }, 'Changing a saved login needs your fingerprint.'),
      el('div', { class: 'btns', style: 'margin-top:8px' }, el('button', { class: 'b p', onclick: () => doUpdate(existing.credential_id) }, 'Update'), el('button', { class: 'b', onclick: dismiss }, 'Not now')),
    );
  } else {
    sec.append(
      el('div', {}, (generated ? 'Save the generated password' : 'Save the password you entered') + ' for ', el('b', {}, site), '?'),
      el('div', { class: 'opts' }, el('label', {}, 'Account'), accountIn, el('label', {}, 'Use on'), targetSel),
      targets.length > 1 ? el('div', { class: 'muted', style: 'margin-top:4px' }, 'Saving for a parent domain also offers it on its subdomains.') : null,
      el('div', { class: 'btns', style: 'margin-top:8px' }, el('button', { class: 'b p', onclick: doSave }, 'Save'), el('button', { class: 'b', onclick: dismiss }, 'Not now')),
    );
  }
  sec.appendChild(status);
  box.appendChild(sec);
  root.appendChild(box);
}

// ---------- submit capture ----------

let captureTimer = null;

function captureFrom(field) {
  if (!field || !field.value) return;
  const fields = passwordFields(scopeOf(field)).filter((f) => f.value);
  if (!fields.length) return;
  const isNew = isNewPasswordContext(field);
  // For change-password forms keep the new password, not the current one.
  const target = isNew ? newPasswordFields(field).find((f) => f.value) || fields[fields.length - 1] : fields[0];
  const user = findUsernameInput(target);
  send({ type: 'capture', username: user ? user.value : '', password: target.value }).then((r) => {
    if (r && r.status === 'ok') {
      clearTimeout(captureTimer);
      // Single-page apps don't navigate; offer the save in place.
      captureTimer = setTimeout(checkPending, 1500);
    }
  });
}

document.addEventListener('submit', (e) => {
  const pw = passwordFields(e.target).find((f) => f.value);
  if (pw) captureFrom(pw);
}, true);

document.addEventListener('click', (e) => {
  const btn = e.target.closest && e.target.closest('button, input[type="submit"], input[type="button"], [role="button"], a');
  if (!btn) return;
  const scope = btn.closest('form') || document;
  const pw = passwordFields(scope).find((f) => f.value);
  if (!pw) return;
  const label = (btn.textContent || btn.value || btn.getAttribute('aria-label') || '').trim();
  if (btn.closest('form') || LOGIN_BUTTON_RE.test(label)) captureFrom(pw);
}, true);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && isPasswordField(e.target)) captureFrom(e.target);
}, true);

// ---------- menu triggers ----------

document.addEventListener('focusin', (e) => {
  const t = e.target;
  if (isPasswordField(t)) openMenu(t);
  else if (menu && !menu.host.contains(t)) closeMenu();
});

document.addEventListener('mousedown', (e) => {
  if (menu && e.target !== menu.host && e.target !== menu.field) closeMenu();
  if (banner && e.composedPath && !e.composedPath().includes(banner.host)) {
    /* banner stays until dismissed */
  }
}, true);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeMenu();
});

window.addEventListener('resize', positionMenu);
window.addEventListener('scroll', positionMenu, true);

// Fill requested from the toolbar popup.
browser.runtime.onMessage.addListener((message) => {
  if (!message || message.type !== 'ua_fill') return;
  const active = document.activeElement;
  const field = isPasswordField(active) ? active : passwordFields(document)[0];
  if (!field) return Promise.resolve({ status: 'no_field' });
  fillLogin(field, message);
  return Promise.resolve({ status: 'filled' });
});

// Offer a save captured on the previous page (top frame only).
if (window.top === window) setTimeout(checkPending, 800);
