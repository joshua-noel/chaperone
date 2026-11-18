// Follows the operating system's light or dark setting. Basecoat reads the "dark" class on <html>.
// Loaded in <head> without defer so the page never flashes the wrong theme.
(function () {
  'use strict';
  const m = window.matchMedia('(prefers-color-scheme: dark)');
  const apply = function () { document.documentElement.classList.toggle('dark', m.matches); };
  apply();
  m.addEventListener('change', apply);
})();

// ?embed=1: a page shown inside another application drops the console's own header and navigation. This changes layout
// only. It is not a security setting: anyone can add the query, and the frame guard (frame-guard.js) never reads it.
if (new URLSearchParams(window.location.search).get('embed') === '1') document.documentElement.dataset.embed = '1';

// On a phone the nav is one scrolling row: bring the current page's link into view.
document.addEventListener('DOMContentLoaded', function () {
  const a = document.querySelector('.shell-nav a[aria-current="page"]');
  if (a && a.scrollIntoView) a.scrollIntoView({ block: 'nearest', inline: 'center' });
});
