// Times in the zone the server is set to show (CHAP_TIMEZONE, UTC by default), with the UTC time shown next to each one.
//
// The server writes every time as UTC (RFC 3339) in <time datetime="...">...</time>. This turns the text of each such
// element into "2026-11-01 22:15" in that zone and adds a muted <span class="utc">(2026-11-02 02:15 UTC)</span>
// inside it, as visible text: a title is not reachable by keyboard, touch or most screen readers, and the ledger filters
// take UTC. The span sits inside the <time> so a stacked table cell (phone width) keeps it as one grid item. A <time>
// whose text is not its own datetime (the "4 min ago" in Recent) is left as it is. Without script the UTC text stays.
// The zone comes from <meta name="time-zone"> in the layout, an IANA name or "UTC". Without that meta (or with a name this
// browser does not know) the browser's own zone is used.
// No inline script, no eval (Content-Security-Policy: script-src 'self').
(function () {
  'use strict';
  let fmt;

  // format makes the formatter for the configured zone, or for the browser's own zone when none is given or known.
  function format() {
    const meta = document.querySelector && document.querySelector('meta[name="time-zone"]');
    const opts = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
    if (meta && meta.content) {
      try { return new Intl.DateTimeFormat('en-GB', Object.assign({ timeZone: meta.content }, opts)); } catch (e) { /* unknown name */ }
    }
    return new Intl.DateTimeFormat('en-GB', opts);
  }

  // clock formats a Date to the minute in the configured zone: "2026-11-01 22:15".
  function clock(d) {
    if (!fmt) fmt = format();
    const p = {};
    fmt.formatToParts(d).forEach(function (x) { p[x.type] = x.value; });
    return p.year + '-' + p.month + '-' + p.day + ' ' + p.hour + ':' + p.minute;
  }

  // utcClock formats a Date to the minute in UTC: "2026-11-02 02:15".
  function utcClock(d) {
    return d.toISOString().slice(0, 16).replace('T', ' ');
  }

  function convert(el) {
    const utc = el.getAttribute('datetime');
    if (el.dataset.local === '1' || !utc || el.textContent.trim() !== utc) return;
    const d = new Date(utc);
    if (isNaN(d.getTime())) return;
    el.textContent = clock(d);
    const span = document.createElement('span');
    span.className = 'utc muted';
    span.textContent = '(' + utcClock(d) + ' UTC)';
    el.append(' ', span);
    el.dataset.local = '1';
  }

  function scan(root) {
    if (root.nodeType !== 1) return;
    if (root.matches('time[datetime]')) convert(root);
    root.querySelectorAll('time[datetime]').forEach(convert);
  }

  function boot() {
    scan(document.body);
    new MutationObserver(function (muts) {
      muts.forEach(function (m) { m.addedNodes.forEach(scan); });
    }).observe(document.body, { childList: true, subtree: true });
  }

  // A test under Node loads this file with a stub document and calls convert; a browser has no module.
  if (typeof module !== 'undefined' && module.exports) { module.exports = { convert: convert }; return; }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
