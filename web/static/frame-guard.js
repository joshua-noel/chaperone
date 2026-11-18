// Clickjacking guard for a console page shown in a frame (a page of another origin put the console in a frame).
//
// The operator signs what he can see. In a frame a page that frames us can clip, cover, fade or move us, so:
//
//  1. Every control that does something (a button, a submit input, anything with hx-post) is held (aria-disabled, and
//     every click on it stopped). When the control sits in an approval card (article.approval) the block that is signed
//     must also be plainly visible: the card TEXT (.approval-text, every line the hash covers; the technical details and
//     fingerprint are folded) and the ACTIONS (.approval-actions: Approve, Deny), each fully inside the viewport and not
//     covered, transformed or made transparent (IntersectionObserver v2: `isVisible`, `trackVisibility`, ratio 1). The
//     card's own summary line and header are not part of it. A control is armed only after the control and that block
//     have been continuously visible for MIN_MS.
//  2. A block taller than the frame can never be fully in view: the card then says "This card is long: approve it in
//     Chaperone" and links to the console's own window (a same-origin link: no relaxation needed).
//  3. Anything that could move or resize what the operator sees (a scroll, a resize, the tab hiding, the window losing
//     focus, any "not visible" report) disarms every control at once; it re-arms only after a fresh visible period.
//  4. A click is checked again when it happens (pending observer reports are applied first): it counts only if the
//     control and the block are visible now and have been for MIN_MS. Otherwise it is stopped in the capture phase,
//     before htmx or the approval script sees it.
//  5. A browser that cannot report visibility (no `isVisible`) gets no working control in a frame, only one unheld link
//     that opens the page in its own window.
//  6. A link that opens a new tab is opened by this script FAST_MS after an allowed click, never at once (see openLater()):
//     the second click of a double-click pair is then still stopped in the frame, not delivered to the new tab. A middle
//     click and a click with a modifier key take the same road, and a second click anywhere in the frame cancels the open.
//     The tab opens with ?from=frame, which the server answers with a restricted page (no live button, every card folded).
//     This is defence in depth: a page that frames us can open console pages itself, and the server refuses those (see
//     Console.restricted in guard.go); the guarantee does not rest on anything in the frame.
//
// In the top window (a page that is not framed) this file only holds every acting control until the page has been visible
// and focused for HOLD_MS and a person has done something (moved the pointer, pressed a key, touched, or changed focus
// without a mouse press): see holdTopLevel(). No inline script, no eval (Content-Security-Policy: script-src 'self').
(function () {
  'use strict';
  if (window.top === window.self) { holdTopLevel(); return; }

  const MIN_MS = 800;
  const RETRY_MS = 700; // see retryLater()
  const FAST_MS = 600;  // two clicks closer than this are a fast pair: the second never counts
  // Links too: "opens in Chaperone" opens a signed-in top-level page that has no guard, so a click on one must be as deliberate
  // as a click on a button. A link is judged on its own visibility only (it signs nothing, and the long-card link has to
  // work exactly when the card is not fully in view).
  const CONTROLS = 'button, input[type="submit"], input[type="button"], a[href], [hx-post], [hx-put], [hx-delete]';
  const CARD = 'article.approval';
  const supported = 'IntersectionObserver' in window && 'isVisible' in IntersectionObserverEntry.prototype;
  const OPTIONS = { threshold: [0, 0.5, 0.99, 1], trackVisibility: true, delay: 200 };

  const controls = new Map(); // control -> { el, card, ctrlOk, since, timer }
  const cards = new Map();    // card -> { el, parts: [{ el, ok, sig }], ok, long, users: Set(state), note }
  const partOf = new Map();   // observed part (text or actions) -> its card entry

  const now = function () { return performance.now(); };
  const fullyVisible = function (e) { return e.isVisible && e.intersectionRatio >= 0.99; };

  function paint(s, armed, why) {
    const el = s.el;
    el.dataset.frameVisible = armed ? '1' : '0';
    // Not the disabled attribute: Basecoat dims a disabled button (opacity .5) and IntersectionObserver v2 reports a
    // faded element as not visible, so a held button could never be judged visible and would never arm. Held is
    // aria-disabled plus the data attribute; clicks and Enter/Space on it are stopped below.
    if (armed) { el.removeAttribute('aria-disabled'); el.removeAttribute('title'); }
    else { el.setAttribute('aria-disabled', 'true'); if (why) el.title = why; }
  }

  function cardOk(s) { return !s.card || cards.get(s.card).ok; }

  // armed: the control and the signed block are visible now and have been for MIN_MS.
  function armed(s) { return s.ctrlOk && cardOk(s) && s.since > 0 && now() - s.since >= MIN_MS; }

  function why(s) {
    if (!supported) return 'This browser cannot tell that this button is visible; open the console in its own window';
    if (s.card && !cards.get(s.card).ok) {
      return cards.get(s.card).long
        ? 'This card is long: approve it in Chaperone (its own window)'
        : 'The whole card text and the buttons have to be in view. Make the frame taller or open the console in its own window';
    }
    return 'Waiting until this button is plainly visible';
  }

  function evaluate(s) {
    clearTimeout(s.timer);
    if (!(s.ctrlOk && cardOk(s))) { s.since = 0; paint(s, false, why(s)); return; }
    if (s.since === 0) s.since = now();
    if (armed(s)) { paint(s, true); return; }
    paint(s, false, why(s));
    s.timer = setTimeout(function () { evaluate(s); }, MIN_MS - (now() - s.since) + 20);
  }

  // The height of the signed block as laid out now: from the top of the card text to the bottom of the buttons.
  function blockHeight(c) {
    const t = c.parts[0], a = c.parts[1];
    if (!t || !a) return 0;
    return Math.max(0, a.el.getBoundingClientRect().bottom - t.el.getBoundingClientRect().top);
  }

  function noteFor(c) {
    if (!c.note) {
      c.note = document.createElement('p');
      c.note.className = 'frame-note';
      c.note.setAttribute('role', 'status');
      c.note.appendChild(document.createTextNode(''));
      const a = document.createElement('a');
      a.href = '/approvals?from=frame#title-' + (c.el.dataset.approval || ''); // the mark is in the link: a context-menu open carries it
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = 'Open it in Chaperone';
      c.note.appendChild(a);
      // After the card, never above the signed block: a note above it would push the block down by its own height, and
      // a block that only fits without the note could then never fit (the note stays because the block is not in view).
      // It is outside .approval-text: the signed text is not touched.
      c.el.appendChild(c.note);
      // A short inline badge in the card's summary line says the same at a glance; it adds no height.
      const line = c.el.querySelector('.approval-line');
      if (line) {
        c.badge = document.createElement('span');
        c.badge.className = 'badge';
        c.badge.dataset.tone = 'warning';
        line.insertBefore(c.badge, line.querySelector('.line-age'));
      }
    }
    c.note.firstChild.nodeValue = c.long
      ? 'This card is long: approve it in Chaperone. '
      : 'Approve and Deny work only while the whole card text and both buttons are in view. Part of it is hidden or the frame is too short: make the frame taller, or ';
    if (c.badge) c.badge.textContent = c.long ? 'long: open in Chaperone' : 'not fully in view';
    return c.note;
  }

  // A report as one string: visible or not, how much, and where the visible part is. A different string than the last
  // one for the same target means it moved, resized or was covered: the visible period starts over.
  function signature(e) {
    const r = e.intersectionRect;
    return [e.isVisible ? 1 : 0, e.intersectionRatio.toFixed(3), r.x, r.y, r.width, r.height].join();
  }

  // Registered FIRST, before any observer exists: whatever throws later, a click on a control that is not armed is
  // still stopped (allowed() answers no when it cannot judge).
  // A click or key press on a control that is not armed stops here, in the capture phase, ahead of htmx and the page's
  // own handlers. (Tab and the arrow keys are left alone: moving focus does nothing.) The second click of a fast pair
  // (a double-click, or two clicks within FAST_MS) never counts: a lure that swaps what is under the pointer after the
  // first click gets only the first.
  let lastClick = -Infinity;
  // A link that opens a new tab (target=_blank) is not followed by the browser: the page opens it itself, FAST_MS after
  // the click. The new tab is a signed-in top-level page with no guard; if it opened at once, the second click of a
  // double-click pair (a lure that says "click twice") would land on it, on a predictable Approve button. Opened after
  // the fast-pair window, the second click of a pair still lands here, where it is stopped and cancels the open.
  let pendingOpen = 0;
  function cancelOpen() { clearTimeout(pendingOpen); pendingOpen = 0; }
  function openLater(a) {
    let url;
    try { url = new URL(a.href, window.location.href); } catch (err) { return; }
    if (url.origin !== window.location.origin) return; // every link here is the console's own
    url.searchParams.set('from', 'frame'); // the server draws a page opened this way restricted (Console.restricted)
    pendingOpen = setTimeout(function () { pendingOpen = 0; window.open(url.href, '_blank', 'noopener'); }, FAST_MS + 50);
  }
  function stop(e) {
    if (e.type === 'dblclick') { e.preventDefault(); e.stopImmediatePropagation(); return; }
    if ((e.type === 'keydown' || e.type === 'keyup') && e.key !== 'Enter' && e.key !== ' ') return;
    if (e.type === 'auxclick' && e.button !== 1) return; // a right click opens a menu, nothing else
    const clicky = e.type === 'click' || e.type === 'auxclick';
    // A click anywhere in the frame (a control or not) while an open is pending cancels that open; the click is then the
    // second of a pair.
    const pending = clicky && pendingOpen !== 0;
    if (pending) cancelOpen();
    const el = e.target instanceof Element ? e.target.closest(CONTROLS) : null;
    if (!el) return;
    let fast = pending;
    if (clicky) {
      // On a control: a click within FAST_MS of the last click on a control, or a double-click, is a fast pair.
      fast = fast || e.detail >= 2 || now() - lastClick < FAST_MS;
      lastClick = now();
    }
    if (fast || !(el.dataset.frameFree === '1' || allowed(el))) {
      e.preventDefault();
      e.stopImmediatePropagation();
      disarmAll(); // a click on a held control is itself a sign something is wrong: start the visible period again
      return;
    }
    // The browser never opens a window from an armed link by itself: a click on target=_blank, a middle click, or a click
    // with a modifier key (new window, new tab) is turned into the delayed open.
    if (clicky && el.matches('a[href]') && (el.matches('[target="_blank"]') || e.type === 'auxclick' ||
        e.ctrlKey || e.shiftKey || e.metaKey || e.altKey)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      openLater(el);
    }
  }
  ['click', 'auxclick', 'dblclick', 'submit', 'keydown', 'keyup', 'pointerup', 'mouseup'].forEach(function (t) {
    document.addEventListener(t, stop, true);
  });

  // A card is in view when every part of the signed block is (a card with no text or no actions element can never be).
  function updateCard(c) {
    c.ok = c.parts.length === 2 && c.parts.every(function (p) { return p.ok; });
    c.long = blockHeight(c) > window.innerHeight;
    noteFor(c).hidden = c.ok;
    if (c.badge) c.badge.hidden = c.ok;
  }

  function onControlReports(entries) {
    entries.forEach(function (e) {
      const s = controls.get(e.target);
      if (!s) return;
      const sig = signature(e);
      if (s.sig !== undefined && s.sig !== sig) s.since = 0;
      s.sig = sig;
      s.ctrlOk = fullyVisible(e);
      evaluate(s);
    });
  }

  function onCardReports(entries) {
    entries.forEach(function (e) {
      const c = partOf.get(e.target);
      if (!c) return;
      const p = c.parts.find(function (x) { return x.el === e.target; });
      const sig = signature(e);
      const moved = p.sig !== undefined && p.sig !== sig;
      p.sig = sig;
      p.ok = fullyVisible(e);
      updateCard(c);
      c.users.forEach(function (s) { if (moved) s.since = 0; evaluate(s); });
    });
  }

  // The observers are made after the click listeners above and inside a try: if the browser throws here, there is no
  // observer, nothing is ever judged visible, and every control stays held.
  let ctrlObserver = null;
  let cardObserver = null;
  if (supported) {
    try {
      ctrlObserver = new IntersectionObserver(onControlReports, OPTIONS);
      cardObserver = new IntersectionObserver(onCardReports, OPTIONS);
    } catch (err) {
      ctrlObserver = null;
      cardObserver = null;
    }
  }

  function guard(el) {
    if (controls.has(el) || el.dataset.frameFree === '1') return;
    const s = { el: el, card: el.matches('a') ? null : el.closest(CARD), ctrlOk: false, since: 0, timer: 0 };
    controls.set(el, s);
    // Held first, whatever happens next: a control that cannot be judged stays held (fail closed).
    el.dataset.frameVisible = '0';
    el.setAttribute('aria-disabled', 'true');
    // The card entry exists before anything reads it (why() and cardOk() look it up).
    if (s.card) {
      let c = cards.get(s.card);
      if (!c) {
        const parts = [s.card.querySelector('.approval-text'), s.card.querySelector('.approval-actions')].filter(Boolean)
          .map(function (x) { return { el: x, ok: false, sig: undefined }; });
        c = { el: s.card, parts: parts, ok: false, long: false, users: new Set(), note: null };
        cards.set(s.card, c);
        parts.forEach(function (p) { partOf.set(p.el, c); if (cardObserver) cardObserver.observe(p.el); });
      }
      c.users.add(s);
    }
    paint(s, false, why(s));
    if (ctrlObserver) ctrlObserver.observe(el);
  }

  function scan(root) {
    if (root.nodeType !== 1) return;
    if (root.matches(CONTROLS)) guard(root);
    root.querySelectorAll(CONTROLS).forEach(guard);
  }

  // Disarm everything now and ask the browser for a fresh report on each control and card part (observe again: a first
  // report always follows). Re-arming then needs a new visible period.
  function disarmAll() {
    cancelOpen(); // a pending new tab belongs to a click that was judged before whatever just moved
    controls.forEach(function (s) {
      clearTimeout(s.timer);
      s.ctrlOk = false;
      s.since = 0;
      paint(s, false, why(s));
      if (ctrlObserver) { ctrlObserver.unobserve(s.el); ctrlObserver.observe(s.el); }
    });
    cards.forEach(function (c) {
      c.parts.forEach(function (p) {
        p.ok = false;
        if (cardObserver) { cardObserver.unobserve(p.el); cardObserver.observe(p.el); }
      });
      c.ok = false;
    });
    retryLater();
  }

  // A report asked for right after a scroll or resize can say "not visible" (the browser wants the target to have held still
  // for the observer's delay) and then, with nothing changing, never says anything again. So whatever is still not in view
  // is looked at again after RETRY_MS: slower than the observer's delay, so each look can finish before the next starts
  // (a 250 ms version restarted every look before it could answer and nothing ever armed). It stops when everything is in
  // view; a control that is really hidden is looked at again every RETRY_MS, which costs nothing.
  let retryTimer = 0;
  function retryLater() {
    clearTimeout(retryTimer);
    retryTimer = setTimeout(function () {
      if (!ctrlObserver || !cardObserver) return;
      let pending = false;
      controls.forEach(function (s) { if (!s.ctrlOk) { pending = true; ctrlObserver.unobserve(s.el); ctrlObserver.observe(s.el); } });
      cards.forEach(function (c) { c.parts.forEach(function (p) { if (!p.ok) { pending = true; cardObserver.unobserve(p.el); cardObserver.observe(p.el); } }); });
      if (pending) retryLater();
    }, RETRY_MS);
  }

  // Apply the reports the browser has queued but not delivered, then judge the control as it is now.
  function allowed(el) {
    if (!ctrlObserver || !cardObserver) return false; // cannot judge: held
    {
      ctrlObserver.takeRecords().forEach(function (e) { const s = controls.get(e.target); if (s) { s.ctrlOk = fullyVisible(e); if (!s.ctrlOk) s.since = 0; } });
      cardObserver.takeRecords().forEach(function (e) {
        const c = partOf.get(e.target);
        if (!c) return;
        const p = c.parts.find(function (x) { return x.el === e.target; });
        p.ok = fullyVisible(e);
        c.ok = c.parts.length === 2 && c.parts.every(function (x) { return x.ok; });
        if (!c.ok) c.users.forEach(function (s) { s.since = 0; });
      });
    }
    const s = controls.get(el);
    return !!s && armed(s);
  }

  // A page that frames us can move the frame without any event inside it. The browser reports a cross-origin frame's
  // position only through the visibility report, which it sends when visibility or a threshold changes: a changed report
  // (see signature()) starts the visible period over. A move that leaves the report unchanged (the frame stays fully
  // visible and the same size) cannot be seen from inside the frame: see ADR-004 amendment 12. (An earlier version asked for a
  // new report every 250 ms; each first report said "not visible" and the controls never armed, so that is gone.)

  ['scroll', 'resize'].forEach(function (t) { window.addEventListener(t, disarmAll, { capture: true, passive: true }); });
  // blur is capture-phase too (it does not bubble), so it fires for every element that loses focus: pressing the mouse on
  // Approve or on the reason field moves focus, and that must not disarm the click that follows. Only the window's own
  // blur counts.
  window.addEventListener('blur', function (e) { if (e.target === window) disarmAll(); }, { capture: true, passive: true });
  document.addEventListener('visibilitychange', disarmAll);

  function boot() {
    document.documentElement.dataset.framed = '1';
    scan(document.body);
    // Secret entry is never shown in a frame. A link here opens it in the console's own window: that navigation starts
    // in this page, so it is same-origin and needs no relaxation of the fetch-metadata check.
    const links = document.createElement('p');
    links.className = 'frame-links';
    const a = document.createElement('a');
    a.href = '/secrets?from=frame';
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = 'Secrets: opens in Chaperone';
    links.appendChild(a);
    document.body.appendChild(links);
    scan(links); // the link is held like any control (the scan above ran before it existed)
    // htmx swaps in new buttons (a status line with a Close button, a reloaded card): guard them as they arrive.
    new MutationObserver(function (muts) {
      muts.forEach(function (m) { m.addedNodes.forEach(scan); });
    }).observe(document.body, { childList: true, subtree: true });
    if (!supported) {
      const note = document.createElement('p');
      note.setAttribute('role', 'alert');
      note.className = 'frame-note';
      note.appendChild(document.createTextNode('This browser cannot prove that a button is visible, so its buttons are switched off in a frame. '));
      // The one working link here. Nothing can judge a link in this browser, so it is not held (data-frame-free); it still
      // goes through the fast-pair rule and the delayed open above.
      const open = document.createElement('a');
      open.href = window.location.pathname + '?from=frame';
      open.target = '_blank';
      open.rel = 'noopener';
      open.dataset.frameFree = '1';
      open.textContent = 'Open the console in its own window';
      note.appendChild(open);
      document.body.insertBefore(note, document.body.firstChild);
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();

// The top window. Every acting control is held (aria-disabled, and every click on it stopped before htmx or the page's own
// script sees it) until BOTH: the page has been visible and focused for HOLD_MS (reset by the window losing focus and by
// the tab hiding), and a person has done something that a page that has only just appeared under a still pointer has not:
// a real mouse move (a move with a distance: the browser's own synthetic move after a layout change has none), a key
// press, a touch, or a focus change that no mouse press caused (this is how a screen reader or Tab arrives, and a mouse
// press on a button moves focus after the pointerdown, so it does not count). This is the second line behind the server's
// restricted page (Console.restricted); it bounds a second click that arrives a little after the page does. Nothing
// here knows how the page was opened. Sign-in and enrolment grant nothing and are not held; the phone page is never
// framed and its number buttons are not held.
function holdTopLevel() {
  'use strict';
  const HOLD_MS = 1000;
  const ACTS = 'button, input[type="submit"], input[type="button"], [hx-post], [hx-put], [hx-delete], a[data-reopen]';
  const EXEMPT = '[data-passkey], [data-number], #enroll';
  const t = function () { return performance.now(); };
  const loadedAt = t();
  const present = function () { return document.visibilityState === 'visible' && document.hasFocus(); };
  let moved = false;
  let since = present() ? t() : 0; // when the page last became visible and focused; 0 while it is not
  let lastDown = -Infinity;
  let timer = 0;
  let note = null;

  const ready = function () { return moved && since > 0 && t() - since >= HOLD_MS; };
  const acting = function (n) {
    const el = n instanceof Element ? n.closest(ACTS) : null;
    return el && !el.matches(EXEMPT) ? el : null;
  };

  function paint() {
    const r = ready();
    document.querySelectorAll(ACTS).forEach(function (el) {
      if (el.matches(EXEMPT) || el.disabled) return;
      if (r) { if (el.dataset.held) { el.removeAttribute('aria-disabled'); delete el.dataset.held; } }
      else { el.setAttribute('aria-disabled', 'true'); el.dataset.held = '1'; }
    });
    clearTimeout(timer);
    if (!r && moved && since > 0) timer = setTimeout(paint, Math.max(0, HOLD_MS - (t() - since)) + 20);
    if (r && note) { note.remove(); note = null; }
  }
  function person() { if (!moved) { moved = true; paint(); } }
  function restart() { since = present() ? t() : 0; paint(); }
  function say(text) {
    if (!note) {
      note = document.createElement('p');
      note.className = 'frame-note';
      note.setAttribute('role', 'status');
      const host = document.getElementById('main') || document.body;
      host.insertBefore(note, host.firstChild);
    }
    note.textContent = text;
  }

  // Registered first, in the capture phase: a click on a held control never reaches htmx or the page's own handler. A
  // middle click on a held link is stopped too.
  ['click', 'auxclick'].forEach(function (type) {
    document.addEventListener(type, function (e) {
      if (!acting(e.target) || ready()) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      say(moved ? 'This page was only just shown or focused. Wait a moment, then try again.' : 'Move the pointer or press Tab, then try again.');
    }, true);
  });
  // Only the window's own blur counts: blur is capture-phase here and fires for every element that loses focus.
  window.addEventListener('blur', function (e) { if (e.target === window) { since = 0; paint(); } }, true);
  window.addEventListener('focus', function (e) { if (e.target === window) restart(); }, true);
  document.addEventListener('visibilitychange', restart);
  document.addEventListener('mousemove', function (e) { if ((e.movementX || 0) !== 0 || (e.movementY || 0) !== 0) person(); }, true);
  document.addEventListener('pointerdown', function (e) { lastDown = t(); if (e.pointerType !== 'mouse') person(); }, true);
  document.addEventListener('keydown', person, true);
  document.addEventListener('focusin', function () { if (t() - loadedAt > 500 && t() - lastDown > 400) person(); }, true);

  function boot() {
    // "Re-open here" is held like a button (ACTS) and goes to the page without the mark and without the address hash: the
    // operator lands on the folded list.
    restart();
    new MutationObserver(paint).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
}
