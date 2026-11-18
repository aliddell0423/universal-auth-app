const browser = globalThis.browser ?? globalThis.chrome;

const HOST = 'com.aliddell.universalauth';
const PENDING_TTL_MS = 3 * 60 * 1000;
const notificationDedupe = new Map();
const NOTIFICATION_TTL_MS = 30000;

function nativeError(err) {
  return {
    status: 'error',
    code: 'UA-BROWSER-001',
    stage: 'browser.native_messaging',
    error: (err && err.message) || 'Native messaging failed.',
    retryable: false,
    action: 'Check that the native host manifest and binary are installed.',
  };
}

function native(message) {
  return browser.runtime.sendNativeMessage(HOST, message).catch((err) => {
    console.error('Universal Auth native host error:', err);
    return nativeError(err);
  });
}

function originOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch (_) {
    return null;
  }
}

// siteKey groups generator settings by host without the leading www.
function siteKey(origin) {
  try {
    return new URL(origin).hostname.replace(/^www\./, '');
  } catch (_) {
    return origin;
  }
}

// Pending saves survive navigation (the login page is replaced by the next
// page) by living in session storage, keyed by tab.
const session = browser.storage.session || browser.storage.local;

async function getPending(tabId) {
  const key = 'pending:' + tabId;
  const got = await session.get(key);
  const p = got[key];
  if (!p || Date.now() - p.at > PENDING_TTL_MS) return null;
  return p;
}

async function setPending(tabId, value) {
  const key = 'pending:' + tabId;
  if (value) await session.set({ [key]: Object.assign({ at: Date.now() }, value) });
  else await session.remove(key);
}

async function getOverrides(origin) {
  const key = 'gen:' + siteKey(origin);
  const got = await browser.storage.local.get(key);
  return got[key] || null;
}

async function setOverrides(origin, overrides) {
  const key = 'gen:' + siteKey(origin);
  if (overrides) await browser.storage.local.set({ [key]: overrides });
  else await browser.storage.local.remove(key);
}

browser.tabs.onRemoved.addListener((tabId) => {
  setPending(tabId, null);
});

// Messages from content scripts carry no trusted origin; it is always taken
// from the sender frame. Messages from the popup (no sender.tab) may name an
// origin because the popup reads it from the active tab itself.
browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || typeof message.type !== 'string') return;
  const fromPopup = !sender.tab && sender.id === browser.runtime.id;
  if (fromPopup) return handlePopup(message);
  if (!sender.tab || !sender.url) return;
  const origin = originOf(sender.url);
  if (!origin) return Promise.resolve({ status: 'error', error: 'Unsupported page.' });
  return handleContent(message, origin, sender.tab.id);
});

async function handleContent(message, origin, tabId) {
  switch (message.type) {
    case 'list':
      return native({ type: 'list_logins', origin });
    case 'fill': {
      const resp = await native({ type: 'get_credential', origin, credential_id: message.credential_id || '' });
      if (resp.status === 'approved') {
        // Remember what was filled so an unchanged submit doesn't prompt.
        await setPending(tabId, { origin, filled: { credential_id: resp.credential_id, password: resp.password } });
      }
      return resp;
    }
    case 'list_pending': {
      const p = await getPending(tabId);
      if (!p || !p.captured) return { status: 'none' };
      return native({ type: 'list_logins', origin: p.origin });
    }
    case 'save_pending': {
      // Uses the origin recorded when the password was captured, not the
      // page the user has since been redirected to.
      const p = await getPending(tabId);
      if (!p || !p.captured) return { status: 'error', error: 'Nothing to save any more.' };
      const r = await native({ type: 'save_login', origin: p.origin, username: p.captured.username, password: p.captured.password, account: message.account || '', save_as: message.save_as || '' });
      if (r.status === 'saved') await setPending(tabId, null);
      return r;
    }
    case 'update_pending': {
      const p = await getPending(tabId);
      if (!p || !p.captured) return { status: 'error', error: 'Nothing to update any more.' };
      const r = await native({ type: 'update_login', origin: p.origin, credential_id: message.credential_id, username: p.captured.username, password: p.captured.password });
      if (r.status === 'updated') await setPending(tabId, null);
      return r;
    }
    case 'capture': {
      const prev = await getPending(tabId);
      const filled = prev && prev.origin === origin ? prev.filled : null;
      if (filled && filled.password === message.password) return { status: 'unchanged' };
      await setPending(tabId, { origin, filled, captured: { username: message.username || '', password: message.password, generated: !!message.generated } });
      return { status: 'ok' };
    }
    case 'pending': {
      const p = await getPending(tabId);
      if (!p || !p.captured) return { status: 'none' };
      // Offer the save on the page that captured it or the page it led to.
      return { status: 'ok', captured: p.captured, origin: p.origin };
    }
    case 'dismiss':
      await setPending(tabId, null);
      return { status: 'ok' };
    case 'overrides_get':
      return { status: 'ok', overrides: await getOverrides(origin) };
    case 'overrides_set':
      await setOverrides(origin, message.overrides);
      return { status: 'ok' };
    case 'show_notification':
      showNotification(message, origin);
      return;
    default:
      return { status: 'error', error: 'Unknown message.' };
  }
}

async function handlePopup(message) {
  const origin = message.origin ? originOf(message.origin) : null;
  const needOrigin = !['all_logins'].includes(message.type);
  if (needOrigin && !origin) return { status: 'error', error: 'This page is not a website.' };
  switch (message.type) {
    case 'list':
      return native({ type: 'list_logins', origin });
    case 'all_logins':
      return native({ type: 'all_logins' });
    case 'reveal':
      return native({ type: 'get_credential', origin, credential_id: message.credential_id });
    case 'fill_tab': {
      const resp = await native({ type: 'get_credential', origin, credential_id: message.credential_id });
      if (resp.status !== 'approved') return resp;
      await setPending(message.tab_id, { origin, filled: { credential_id: resp.credential_id, password: resp.password } });
      await browser.tabs.sendMessage(message.tab_id, { type: 'ua_fill', username: resp.username, password: resp.password });
      return { status: 'filled' };
    }
    case 'save':
      return native({ type: 'save_login', origin, username: message.username || '', password: message.password, account: message.account || '', save_as: message.save_as || '' });
    case 'update':
      return native({ type: 'update_login', origin, credential_id: message.credential_id, username: message.username || '', password: message.password, account: message.account || '', save_as: message.save_as || '' });
    case 'delete':
      return native({ type: 'delete_login', origin, credential_id: message.credential_id });
    case 'link':
      return native({ type: 'link_site', origin, resource: message.resource });
    case 'unlink':
      return native({ type: 'unlink_site', origin, resource: message.resource });
    case 'overrides_get':
      return { status: 'ok', overrides: await getOverrides(origin) };
    case 'overrides_set':
      await setOverrides(origin, message.overrides);
      return { status: 'ok' };
    default:
      return { status: 'error', error: 'Unknown message.' };
  }
}

function showNotification(message, origin) {
  const now = Date.now();
  const key = `${message.code || 'unknown'}-${origin}`;
  const last = notificationDedupe.get(key);
  if (last && now - last < NOTIFICATION_TTL_MS) return;
  notificationDedupe.set(key, now);
  for (const [k, v] of notificationDedupe) {
    if (now - v > NOTIFICATION_TTL_MS) notificationDedupe.delete(k);
  }
  if (browser.notifications) {
    browser.notifications.create({
      type: 'basic',
      iconUrl: browser.runtime.getURL('icon-128.png'),
      title: 'Universal Auth',
      message: message.error || 'Something went wrong.',
    });
  }
}
