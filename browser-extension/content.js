let pending = false;

function findUsernameInput(passwordInput) {
  const form = passwordInput.closest('form') || passwordInput.form;
  const scope = form || document;

  let input = scope.querySelector('input[autocomplete="username"]');
  if (input) return input;

  input = scope.querySelector('input[type="email"]');
  if (input) return input;

  const textInputs = scope.querySelectorAll('input[type="text"]');
  for (const el of textInputs) {
    return el;
  }

  return null;
}

function fillValue(input, value) {
  const v = value || '';

  const descriptor = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    'value'
  );
  if (descriptor && descriptor.set) {
    descriptor.set.call(input, v);
  } else {
    input.value = v;
  }

  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function fillLogin(passwordInput, credential) {
  const username = findUsernameInput(passwordInput);
  if (username) {
    fillValue(username, credential.username);
  }
  fillValue(passwordInput, credential.password);
}

document.addEventListener('focusin', async (event) => {
  const target = event.target;
  if (!target || target.tagName !== 'INPUT' || target.type !== 'password') {
    return;
  }
  if (pending) {
    return;
  }

  pending = true;
  try {
    const response = await browser.runtime.sendMessage({ type: 'credential_request' });
    if (!response) {
      console.error('[Universal Auth] no response from background script');
      return;
    }

    if (response.status === 'approved') {
      fillLogin(target, response);
      return;
    }

    console.error('[Universal Auth] credential request failed', {
      status: response.status,
      code: response.code,
      stage: response.stage,
      traceId: response.trace_id,
      requestId: response.request_id,
      error: response.error,
      retryable: response.retryable,
      action: response.action,
    });

    if (response.status === 'error') {
      browser.runtime.sendMessage({
        type: 'show_notification',
        origin: window.location.origin,
        code: response.code,
        error: response.error,
      });
    }
  } catch (err) {
    console.error('Universal Auth content error:', err);
  } finally {
    pending = false;
  }
});
