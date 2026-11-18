// A held control must look held, whatever its variant. This renders a static page that links the real console.css and the
// vendored Basecoat in a headless Chromium and compares, state by state, a held DESTRUCTIVE button with a held NEUTRAL
// (default variant) button: if the held style leaks any of Basecoat's destructive hover, focus or ring colours, the two
// differ. A live destructive button is the control: it must differ from the held one, so the check is not blind.
//
// Not run by CI (it needs a browser and playwright-core, which the Go workflow does not install). Run it by hand after a
// change to web/static/console.css or to the vendored Basecoat:
//
//   PLAYWRIGHT_CORE=<path to the playwright-core package> BROWSER=<path to a Chromium or Edge executable> \
//     node scripts/held-style/check.cjs [--css-dir <dir with console.css>] [--base-dir <dir with basecoat.min.css>] [--out <dir>]
//
// With no PLAYWRIGHT_CORE or no BROWSER it prints "skipped" and exits 0. A parity failure exits 1.
'use strict';
const fs = require('fs');
const path = require('path');

const arg = (name, dflt) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : dflt; };
const cssDir = path.resolve(arg('--css-dir', path.join(__dirname, '..', '..', 'web', 'static')));
const baseDir = path.resolve(arg('--base-dir', path.join(__dirname, '..', '..', 'web', 'static', 'vendor')));
const outDir = path.resolve(arg('--out', path.join(__dirname, 'out')));

if (!process.env.PLAYWRIGHT_CORE || !process.env.BROWSER || !fs.existsSync(process.env.BROWSER)) {
  console.log('skipped: set PLAYWRIGHT_CORE (the playwright-core package) and BROWSER (a Chromium or Edge executable)');
  process.exit(0);
}
const { chromium } = require(process.env.PLAYWRIGHT_CORE);
fs.mkdirSync(outDir, { recursive: true });

const url = (p) => 'file:///' + path.resolve(p).replace(/\\/g, '/');
const PROPS = ['color', 'background-color', 'border-color', 'box-shadow', 'outline-color', 'outline-style'];
const STATES = ['rest', 'hover', 'focus-visible', 'active'];
// held-top: a control held on a top-level page (data-held). held-framed: held by the frame guard (data-frame-visible="0").
const html = `<!doctype html>
<html lang="en" data-framed>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${url(path.join(baseDir, 'basecoat.min.css'))}">
<link rel="stylesheet" href="${url(path.join(cssDir, 'console.css'))}">
</head>
<body><main class="shell-main">
<h1>Held buttons</h1>
<p>
<button id="top-destructive" class="btn" data-variant="destructive" type="button" data-held="1" aria-disabled="true">Deny (held)</button>
<button id="top-neutral" class="btn" type="button" data-held="1" aria-disabled="true">Approve (held)</button>
<button id="framed-destructive" class="btn" data-variant="destructive" type="button" data-frame-visible="0" aria-disabled="true">Deny (framed hold)</button>
<button id="framed-neutral" class="btn" type="button" data-frame-visible="0" aria-disabled="true">Approve (framed hold)</button>
<button id="live-destructive" class="btn" data-variant="destructive" type="button">Deny (live)</button>
</p></main></body></html>`;
const file = path.join(outDir, 'held.html');
fs.writeFileSync(file, html);

async function read(page, sel) {
  await page.waitForTimeout(450); // Basecoat transitions colours (150 ms); read the settled value
  return page.$eval(sel, (e, props) => Object.fromEntries(props.map((p) => [p, getComputedStyle(e).getPropertyValue(p)])), PROPS);
}

// Puts the element into one state and returns its computed values. Real input: hover moves the pointer, focus-visible is
// reached with the Tab key, active holds the mouse button down.
async function inState(page, id, state) {
  const sel = '#' + id;
  await page.mouse.move(0, 0);
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  if (state === 'hover') await page.hover(sel);
  if (state === 'active') { await page.hover(sel); await page.mouse.down(); }
  if (state === 'focus-visible') {
    await page.evaluate(() => document.body.focus());
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press('Tab');
      if (await page.evaluate((i2) => document.activeElement && document.activeElement.id === i2, id)) break;
    }
  }
  const v = await read(page, sel);
  if (state === 'active') await page.mouse.up();
  return v;
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.BROWSER, headless: true });
  const result = { states: {}, failures: [] };
  try {
    for (const [w, h] of [[1440, 400], [390, 520]]) {
      const page = await browser.newPage({ viewport: { width: w, height: h } });
      await page.goto(url(file));
      if (w === 1440) {
        for (const st of STATES) {
          const row = {};
          for (const id of ['top-destructive', 'top-neutral', 'framed-destructive', 'framed-neutral', 'live-destructive']) row[id] = await inState(page, id, st);
          result.states[st] = row;
          for (const ctx of ['top', 'framed']) {
            for (const p of PROPS) {
              const a = row[ctx + '-destructive'][p], b = row[ctx + '-neutral'][p];
              if (a !== b) result.failures.push(`${ctx} hold, ${st}: ${p}: destructive "${a}" differs from neutral "${b}"`);
            }
            const same = PROPS.every((p) => row[ctx + '-destructive'][p] === row['live-destructive'][p]);
            if (same) result.failures.push(`${ctx} hold, ${st}: the held destructive button is identical to the live one (the check is blind)`);
          }
        }
      }
      await page.screenshot({ path: path.join(outDir, `held-${w}.png`) });
      await page.close();
    }
  } finally {
    await browser.close();
  }
  fs.writeFileSync(path.join(outDir, 'held.json'), JSON.stringify(result, null, 1));
  const lines = ['| context | state | property | held destructive | held neutral | equal |', '|---|---|---|---|---|---|'];
  for (const st of STATES) for (const ctx of ['top', 'framed']) for (const p of PROPS) {
    const a = result.states[st][ctx + '-destructive'][p], b = result.states[st][ctx + '-neutral'][p];
    lines.push(`| ${ctx} | ${st} | ${p} | ${a} | ${b} | ${a === b ? 'yes' : '**NO**'} |`);
  }
  fs.writeFileSync(path.join(outDir, 'parity.md'), lines.join('\n') + '\n');
  if (result.failures.length) {
    console.log(result.failures.join('\n'));
    console.log(`FAIL: ${result.failures.length} difference(s); see parity.md`);
    process.exit(1);
  }
  console.log('ok: a held destructive button is identical to a held neutral button in rest, hover, focus-visible and active, top-level and framed');
})().catch((e) => { console.error(e); process.exit(2); });
