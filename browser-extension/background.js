const notificationDedupe = new Map();
const NOTIFICATION_TTL_MS = 30000;

browser.runtime.onMessage.addListener((message, sender) => {
  if (message.type === 'show_notification') {
    showNotification(message);
    return;
  }

  if (message.type !== 'credential_request') {
    return;
  }

  if (!sender.url) {
    return Promise.resolve({
      status: 'error',
      code: 'UA-BROWSER-004',
      stage: 'browser.background',
      error: 'No sender URL.',
      trace_id: null,
      request_id: null,
      retryable: false,
      action: 'Reload the page and try again.',
    });
  }

  const origin = new URL(sender.url).origin;

  return browser.runtime
    .sendNativeMessage('com.aliddell.universalauth', {
      type: 'get_credential',
      origin: origin,
    })
    .catch((err) => {
      console.error('Universal Auth native host error:', err);
      return {
        status: 'error',
        code: 'UA-BROWSER-001',
        stage: 'browser.native_messaging',
        error: err.message || 'Native messaging failed.',
        trace_id: null,
        request_id: null,
        retryable: false,
        action: 'Check that the native host manifest and binary are installed.',
      };
    });
});

function showNotification(message) {
  const now = Date.now();
  const key = `${message.code || 'unknown'}-${message.origin || 'unknown'}`;
  const last = notificationDedupe.get(key);
  if (last && now - last < NOTIFICATION_TTL_MS) {
    return;
  }
  notificationDedupe.set(key, now);

  // Evict old entries.
  for (const [k, v] of notificationDedupe.entries()) {
    if (now - v > NOTIFICATION_TTL_MS) {
      notificationDedupe.delete(k);
    }
  }

  if (typeof browser !== 'undefined' && browser.notifications) {
    browser.notifications.create({
      type: 'basic',
      title: 'Universal Auth failed',
      message: `${message.code || 'unknown'}: ${message.error || 'Unknown error'}`,
    });
  }
}
