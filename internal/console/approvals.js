// Approvals screen (ticket L1-12, ADR-004). No inline script, no eval.
//
// Approve: hash the card text this page rendered and compare it with the
// display_sha256 the server computed; only then ask the server for a challenge
// (which covers that same display_sha256), and only then ask for the passkey.
// A page that shows one text while the server signed another fails the first check.
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

  async function displayHash(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return 'sha256:' + Array.from(new Uint8Array(digest), function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  async function post(path, body, extra) {
    const headers = Object.assign({ 'X-CSRF-Token': csrf() }, extra || {});
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
      const err = new Error(data.why || data.error || ('http_' + res.status));
      err.code = data.error || ('http_' + res.status);
      throw err;
    }
    return data;
  }

  function say(card, text, isError) {
    const el = card.querySelector('.approval-status');
    el.textContent = text;
    el.className = 'approval-status' + (isError ? ' error' : '');
  }

  // After "Approved.": an approval only lets the op start. At release the op is checked again and can still be
  // refused (the CI head moved, the policy changed). Follow it and say how it ended, so a spent passkey approval is never silent.
  async function follow(card, id) {
    say(card, 'Approved. Waiting for it to run...');
    let o = { kind: 'waiting', text: '' };
    for (let i = 0; i < 20; i++) {
      const res = await fetch('/approvals/' + encodeURIComponent(id) + '/outcome', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (res.ok) o = await res.json();
      if (o.kind !== 'running' && o.kind !== 'waiting') break;
      await new Promise(function (resolve) { setTimeout(resolve, 1000); });
    }
    if (o.kind === 'ran') {
      say(card, o.text);
      setTimeout(function () { window.location.reload(); }, 2500);
      return;
    }
    if (o.kind === 'no_op') {
      say(card, 'Approved.');
      setTimeout(function () { window.location.reload(); }, 800);
      return;
    }
    const bad = o.kind === 'not_run' || o.kind === 'failed' || o.kind === 'unknown';
    say(card, bad ? o.text : 'Approved. ' + (o.kind === 'running' ? 'It is still running; Recent says how it ended.' : 'Waiting for the orchestrator to start it; Recent says how it ended.'), bad);
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn outcome-actions';
    close.textContent = 'Close';
    close.addEventListener('click', function () { window.location.reload(); });
    card.querySelector('.approval-status').appendChild(close);
  }

  function failure(e) {
    if (e && e.name === 'NotAllowedError') return 'Cancelled, or your passkey did not verify you.';
    return 'Refused: ' + (e && (e.message || e.code) || 'unknown error');
  }

  // choice is set on the phone page: the number the approver tapped. The card
  // text is checked first, so a page that shows one text and signs another
  // denies nothing and matches nothing.
  async function approve(card, choice) {
    const id = card.dataset.approval;
    const pre = card.querySelector('.approval-text');
    const want = pre.dataset.displaySha256;
    say(card, 'Checking the card...');
    if ((await displayHash(pre.textContent)) !== want) {
      throw new Error('the card text on this page does not match its hash; nothing was signed');
    }
    if (choice) {
      const m = await post('/phone/' + encodeURIComponent(id) + '/match', { choice: choice });
      if (!m.matched) {
        say(card, 'Wrong number. This request was denied, and the same action is refused for an hour.', true);
        setTimeout(function () { window.location.reload(); }, 2500);
        return;
      }
    }
    const begun = await post('/approvals/' + encodeURIComponent(id) + '/begin');
    if (begun.display_sha256 !== want) {
      throw new Error('the card changed since this page was loaded; reload and read it again');
    }
    say(card, 'Waiting for your passkey...');
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
    const fin = await post('/approvals/' + encodeURIComponent(id) + '/finish', JSON.stringify(out), { 'X-Challenge-ID': begun.challenge_id });
    if (fin.secret) {
      // A secret write is stored by the same request that records the approval: say what came of it.
      say(card, fin.secret.stored ? 'Approved. ' + fin.secret.title + '. ' + fin.secret.detail : 'Approved, but: ' + fin.secret.title + '. ' + fin.secret.detail, !fin.secret.stored);
      if (fin.secret.stored) {
        setTimeout(function () { window.location.reload(); }, 2500);
      } else {
        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn outcome-actions';
        close.textContent = 'Close';
        close.addEventListener('click', function () { window.location.reload(); });
        card.querySelector('.approval-status').appendChild(close);
      }
      return;
    }
    say(card, 'Approved.');
    await follow(card, id);
  }

  async function deny(card) {
    const id = card.dataset.approval;
    const reason = card.querySelector('input').value.trim();
    if (!reason) throw new Error('write a reason to deny');
    await post('/approvals/' + encodeURIComponent(id) + '/deny', { reason: reason });
    say(card, 'Denied.');
    setTimeout(function () { window.location.reload(); }, 800);
  }

  // The server page: ask for a phone passkey, and spend the approval for its address.
  function bootEnrol() {
    const form = document.getElementById('phone-enroll-form');
    const status = document.getElementById('phone-status');
    const note = function (text, isError) {
      if (!status) return;
      status.textContent = text;
      status.className = isError ? 'error' : '';
    };
    if (form) {
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        post('/phone/enroll', { label: form.elements.label.value })
          .then(function () { window.location.reload(); })
          .catch(function (e) { note(failure(e), true); });
      });
    }
    document.querySelectorAll('[data-action="enrollment"]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        post('/phone/' + encodeURIComponent(btn.dataset.approval) + '/enrollment')
          .then(function (out) {
            const box = document.getElementById('phone-address');
            box.textContent = '';
            const p = document.createElement('p');
            p.appendChild(document.createTextNode('Open this address on the phone before '));
            // localtime.js turns this <time> into local time (the configured zone) with the UTC time after it.
            const when = document.createElement('time');
            when.setAttribute('datetime', out.expires_at);
            when.textContent = out.expires_at;
            p.appendChild(when);
            p.appendChild(document.createTextNode(' (it works once): '));
            const code = document.createElement('code');
            code.textContent = out.address;
            p.appendChild(code);
            box.appendChild(p);
            if (out.qr) {
              const img = document.createElement('img');
              img.src = out.qr;
              img.alt = 'QR code of the enrolment address';
              img.width = 264;
              img.height = 264;
              box.appendChild(img);
            }
            btn.disabled = true;
            note('The approval is spent. Keep this page open until the phone has created its passkey.');
          })
          .catch(function (e) { note(failure(e), true); });
      });
    });
  }

  // A link such as /approvals#title-a-xyz (from the Home page) opens that request. Not on a restricted page (the server
  // drew it: the note with data-restricted): a page opened from a frame link must leave every card folded, so that nothing
  // sits at a predictable place for a second click. The hold on acting controls is in frame-guard.js.
  function openFromHash() {
    if (document.querySelector('[data-restricted]')) return;
    const m = /^#title-(.+)$/.exec(window.location.hash);
    const line = m && document.getElementById('title-' + m[1]);
    const fold = line && line.closest('details');
    if (fold) fold.open = true;
  }

  function boot() {
    openFromHash();
    document.querySelectorAll('article.approval').forEach(function (card) {
      if (!window.PublicKeyCredential) say(card, 'This browser has no passkey support.', true);
      const approveBtn = card.querySelector('[data-action="approve"]');
      if (approveBtn) {
        approveBtn.addEventListener('click', function () {
          approve(card).catch(function (e) { say(card, failure(e), true); });
        });
      }
      card.querySelectorAll('[data-number]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          card.querySelectorAll('[data-number]').forEach(function (b) { b.disabled = true; });
          approve(card, btn.dataset.number).catch(function (e) {
            card.querySelectorAll('[data-number]').forEach(function (b) { b.disabled = false; });
            say(card, failure(e), true);
          });
        });
      });
      card.querySelector('[data-action="deny"]').addEventListener('click', function () {
        deny(card).catch(function (e) { say(card, failure(e), true); });
      });
    });
    bootEnrol();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
