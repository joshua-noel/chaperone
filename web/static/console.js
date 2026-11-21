// Console behaviour: CSRF for htmx, and the two WebAuthn ceremonies.
// No inline script, no eval (Content-Security-Policy: script-src 'self').
(function () {
  'use strict';

  const csrf = () => document.querySelector('meta[name="csrf-token"]').content;

  function dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function enc(buf) {
    const a = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function say(text, isError) {
    const el = document.getElementById('status');
    if (!el) return;
    el.textContent = text;
    el.className = isError ? 'error' : '';
  }

  async function post(path, body, ceremony) {
    const headers = { 'X-CSRF-Token': csrf() };
    if (ceremony) headers['X-Ceremony-ID'] = ceremony;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
    });
    let data = {};
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const err = new Error(data.error || ('http_' + res.status));
      err.code = data.error || ('http_' + res.status);
      throw err;
    }
    return data;
  }

  function failure(e) {
    if (e && e.name === 'NotAllowedError') return 'Cancelled, or your passkey did not verify you.';
    if (e && e.code === 'attachment_not_allowed') return 'This kind of passkey is not allowed here: this console accepts only a passkey built into this computer, unless its operator allows a security key or a phone.';
    if (e && e.code === 'no_approver') return 'No approver is enrolled. Run chapd enroll.';
    return 'Refused: ' + (e && (e.code || e.message) || 'unknown error');
  }

  async function login() {
    say('Waiting for your passkey...');
    const begun = await post('/login/begin');
    const pk = begun.options.publicKey;
    pk.challenge = dec(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = dec(c.id); });
    const cred = await navigator.credentials.get({ publicKey: pk });
    const r = cred.response;
    const out = {
      id: cred.id,
      rawId: enc(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        authenticatorData: enc(r.authenticatorData),
        clientDataJSON: enc(r.clientDataJSON),
        signature: enc(r.signature),
        userHandle: r.userHandle ? enc(r.userHandle) : undefined,
      },
    };
    const done = await post('/login/finish', JSON.stringify(out), begun.ceremony);
    window.location.assign(done.redirect || '/');
  }

  async function enroll(form, token) {
    if (!token) { say('Open the address that chapd enroll printed, including the part after #.', true); return; }
    say('Waiting for your passkey...');
    const begun = await post('/enroll/begin', {
      token: token,
      name: form.elements.name.value,
      label: form.elements.label.value,
    });
    const pk = begun.options.publicKey;
    pk.challenge = dec(pk.challenge);
    pk.user.id = dec(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = dec(c.id); });
    const cred = await navigator.credentials.create({ publicKey: pk });
    const r = cred.response;
    const out = {
      id: cred.id,
      rawId: enc(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        attestationObject: enc(r.attestationObject),
        clientDataJSON: enc(r.clientDataJSON),
        transports: r.getTransports ? r.getTransports() : undefined,
      },
    };
    await post('/enroll/finish', JSON.stringify(out), begun.ceremony);
    say('Passkey created. Go to the sign-in page to test it.');
    const link = document.createElement('a');
    link.href = '/login';
    link.textContent = ' Sign in';
    document.getElementById('status').appendChild(link);
  }

  function boot() {
    if (document.body) {
      document.body.addEventListener('htmx:configRequest', function (ev) {
        ev.detail.headers['X-CSRF-Token'] = csrf();
      });
      // An error answer (4xx, 5xx) from a console action is an HTML notice: show it.
      document.body.addEventListener('htmx:beforeSwap', function (ev) {
        const xhr = ev.detail.xhr;
        if (xhr.status >= 400 && (xhr.getResponseHeader('Content-Type') || '').indexOf('text/html') === 0) {
          ev.detail.shouldSwap = true;
          ev.detail.isError = false;
        }
      });
      // A form that carries a secret empties itself once the server has taken the request.
      document.body.addEventListener('htmx:afterRequest', function (ev) {
        const el = ev.detail.elt;
        if (ev.detail.successful && el && el.hasAttribute && el.hasAttribute('data-clear-on-success') && el.reset) el.reset();
      });
      document.querySelectorAll('.shell-nav a').forEach(function (a) {
        if (a.getAttribute('href') === window.location.pathname) a.setAttribute('aria-current', 'page');
      });
    }
    const signin = document.querySelector('[data-passkey="login"]');
    if (signin) {
      if (!window.PublicKeyCredential) say('This browser has no passkey support.', true);
      signin.addEventListener('click', function () { login().catch(function (e) { say(failure(e), true); }); });
    }
    const form = document.getElementById('enroll-form');
    if (form) {
      // The one-time token travels in the address fragment, which the browser never
      // sends to a server or a log. Keep it in memory and take it out of the address bar.
      const token = (window.location.hash || '').replace(/^#/, '');
      history.replaceState(null, '', window.location.pathname);
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        enroll(form, token).catch(function (e) { say(failure(e), true); });
      });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
