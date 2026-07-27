const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

global.document = {
  createElement() {
    return {
      value: '',
      set textContent(value) { this.value = String(value); },
      get innerHTML() {
        return this.value.replace(/[&<>"']/g, char => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[char]);
      }
    };
  }
};
global.window = {};
require('./catalog.js');

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'catalog.fixture.json'), 'utf8')
);

test('icons stay lazy without using display-none hiding', () => {
  const html = window.VoliCatalog.icon(
    { n: 'googlechrome', i: 'https://example.com/icon.svg' },
    'package-icon'
  );
  assert.match(html, /<span class="icon-fallback">g<\/span>/);
  assert.match(html, /<img src="https:\/\/example\.com\/icon\.svg"[^>]+loading="lazy"/);
  assert.doesNotMatch(html, /\shidden/);
});

test('search pages preserve lazy icon loading and combobox state', () => {
  const index = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const search = fs.readFileSync(path.join(__dirname, '..', 'search.html'), 'utf8');
  assert.match(index, /\.quick-icon img\s*\{[^}]*opacity:\s*0/s);
  assert.match(search, /\.package-icon img\s*\{[^}]*opacity:\s*0/s);
  assert.match(index, /role="combobox"[^>]+aria-controls="search-results"/);
  assert.match(index, /setAttribute\('aria-activedescendant', rendered\[active\]\.id\)/);
  assert.match(index, /function render\(\)\s*\{[\s\S]*?setActive\(-1\);\s*rendered = \[\];/);
});

test('icon lifecycle reveals cached images and removes failed ones', () => {
  const classes = [];
  const cached = {
    complete: true,
    naturalWidth: 32,
    addEventListener() {}
  };
  window.VoliCatalog.wireIcon({
    querySelector() { return cached; },
    classList: { add(value) { classes.push(value); } }
  });
  assert.deepEqual(classes, ['has-image']);

  const listeners = {};
  let removed = false;
  const failed = {
    complete: false,
    naturalWidth: 0,
    addEventListener(name, callback) { listeners[name] = callback; },
    remove() { removed = true; }
  };
  window.VoliCatalog.wireIcon({
    querySelector() { return failed; },
    classList: { add() {} }
  });
  listeners.error();
  assert.equal(removed, true);
});

test('optional catalog metadata degrades safely', () => {
  assert.equal(window.VoliCatalog.updated({}), 0);
  assert.equal(window.VoliCatalog.updated({ u: 1785000000 }), 1785000000000);
  assert.equal(window.VoliCatalog.updated({ u: '2026-07-26T00:00:00Z' }), 1785024000000);
  assert.equal(window.VoliCatalog.provenance({}), '');
  assert.equal(window.VoliCatalog.provenance({ p: 'Official' }), 'official');
  assert.equal(window.VoliCatalog.provenance({ p: 'unknown' }), '');
});

test('install commands follow package kind and selected agent', () => {
  assert.equal(window.VoliCatalog.command({ n: 'ripgrep', k: 'app' }), 'voli install ripgrep');
  assert.equal(
    window.VoliCatalog.command({ n: 'tdd', k: 'skill' }, 'cursor'),
    'voli install skill/tdd --for cursor'
  );
  assert.equal(
    window.VoliCatalog.command({ n: 'tdd', k: 'skill' }),
    'voli install skill/tdd --for codex'
  );
});

test('kind filtering returns only the selected catalog kind', () => {
  assert.deepEqual(
    window.VoliCatalog.filterKind(fixture, 'app').map(pkg => pkg.n),
    ['ripgrep', 'legacy-app']
  );
  assert.deepEqual(
    window.VoliCatalog.filterKind(fixture, 'skill').map(pkg => pkg.n),
    ['tdd', 'frontend-design']
  );
});

test('skill tab fixture renders agent-ready commands and initializes from the URL', () => {
  const search = fs.readFileSync(path.join(__dirname, '..', 'search.html'), 'utf8');
  const commands = window.VoliCatalog.filterKind(fixture, 'skill').map(pkg =>
    window.VoliCatalog.command(pkg)
  );
  assert.deepEqual(commands, [
    'voli install skill/tdd --for codex',
    'voli install skill/frontend-design --for codex'
  ]);
  assert.match(search, /get\('kind'\) === 'skill'/);
  assert.match(search, /class="agent-select"/);
  assert.match(search, /class="package-kind">skill/);
});
