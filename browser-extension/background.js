browser.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== 'credential_request') {
    return;
  }

  if (!sender.url) {
    return Promise.resolve({ status: 'error' });
  }

  const origin = new URL(sender.url).origin;

  return browser.runtime
    .sendNativeMessage('com.aliddell.universalauth', {
      type: 'get_credential',
      origin: origin,
    })
    .catch((err) => {
      console.error('Universal Auth native host error:', err);
      return { status: 'error' };
    });
});
