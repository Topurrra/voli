const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const asset = name => path.join(__dirname, name);
const page = name => path.join(__dirname, '..', name);
const read = file => fs.readFileSync(file, 'utf8');

// A real browser serialises a text node by escaping & < > and U+00A0 only -
// quotes come back out verbatim. The mock must be no stronger than that, or it
// hides attribute-context escaping bugs in every sink that uses escape().
function stubElement() {
  return {
    value: '',
    innerHTML: '',
    hidden: false,
    classList: { add() {}, remove() {}, contains() { return false; } },
    set textContent(value) { this.value = String(value); },
    get textContent() { return this.value; },
    setAttribute() {},
    removeAttribute() {},
    addEventListener() {},
    appendChild() {},
    contains() { return false; },
    querySelector() { return null; }
  };
}

const elements = {};
global.document = {
  createElement() {
    const node = stubElement();
    Object.defineProperty(node, 'innerHTML', {
      get() {
        return this.value.replace(/[&<> ]/g, char => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;', ' ': '&nbsp;'
        })[char]);
      },
      set(value) { this.value = String(value); }
    });
    return node;
  },
  getElementById(id) {
    if (!elements[id]) elements[id] = stubElement();
    return elements[id];
  },
  addEventListener() {}
};
global.window = {};
require('./catalog.js');
require('./site-header.js');

const fixture = JSON.parse(read(asset('catalog.fixture.json')));

test('the DOM mock escapes like a browser, not more', () => {
  const node = document.createElement('div');
  node.textContent = `& < > " '  `;
  assert.equal(node.innerHTML, `&amp; &lt; &gt; " ' &nbsp;`);
});

test('icons stay lazy without using display-none hiding', () => {
  const html = window.VoliCatalog.icon(
    { n: 'googlechrome', i: 'https://example.com/icon.svg' },
    'package-icon'
  );
  assert.match(html, /<span class="icon-fallback">g<\/span>/);
  assert.match(html, /<img src="https:\/\/example\.com\/icon\.svg"[^>]+loading="lazy"/);
  assert.doesNotMatch(html, /\shidden/);
});

test('escape neutralises both quote characters', () => {
  assert.equal(window.VoliCatalog.escape(`<a href="x">&'`), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;');
  assert.equal(window.VoliCatalog.escape(null), '');
  assert.equal(window.VoliCatalog.escape(undefined), '');
});

test('a hostile package name cannot break out of an attribute', () => {
  const hostile = 'evil" onmouseover="alert(1)';
  const attribute = 'aria-label="Copy ' + window.VoliCatalog.escape(hostile) + '"';
  // Exactly two double quotes: the ones this template opened and closed.
  assert.equal((attribute.match(/"/g) || []).length, 2);
  // The handler survives only as inert text inside the label, never as an attribute.
  assert.doesNotMatch(attribute, /onmouseover="/);
  assert.match(attribute, /^aria-label="[^"]*"$/);

  const command = window.VoliCatalog.command({ n: hostile, k: 'skill' }, 'codex');
  assert.equal((window.VoliCatalog.escape(command).match(/"/g) || []).length, 0);
});

test('icon sources must be absolute https URLs', () => {
  const hostile = { n: 'evil', i: 'https://cdn.example.com/a".svg" onerror="alert(1)' };
  const html = window.VoliCatalog.icon(hostile, 'package-icon');
  assert.doesNotMatch(html, /onerror="/);
  // URL normalisation percent-encodes the quotes, so the attribute stays intact.
  assert.match(html, /src="https:\/\/cdn\.example\.com\/a%22\.svg%22%20onerror=%22alert\(1\)"/);

  for (const source of ['javascript:alert(1)', 'http://example.com/i.png', 'data:image/svg+xml,x', '/relative.png', '']) {
    assert.doesNotMatch(
      window.VoliCatalog.icon({ n: 'x', i: source }, 'package-icon'),
      /<img/,
      'rejected source leaked into an img: ' + source
    );
  }
  // A valid https homepage still yields a favicon.
  assert.match(
    window.VoliCatalog.icon({ n: 'x', h: 'https://example.com/tool' }, 'package-icon'),
    /<img src="https:\/\/example\.com\/favicon\.ico"/
  );
});

test('the injected header exposes a wired combobox', () => {
  const header = document.getElementById('site-header').innerHTML;
  assert.match(header, /role="combobox"[^>]*aria-controls="search-results"/);
  assert.match(header, /aria-expanded="false"/);
  assert.match(header, /id="search-results"[^>]*role="listbox"/);
  // The header must not re-download the 280KB logo just to draw a 60px avatar.
  assert.doesNotMatch(header, /logo\.png/);
});

test('the shared header owns the lazy-icon and activedescendant behaviour', () => {
  const css = read(asset('site-header.css'));
  const js = read(asset('site-header.js'));
  assert.match(css, /\.quick-icon img\s*\{[^}]*opacity:\s*0/s);
  assert.match(css, /\.quick-icon\.has-image img\s*\{[^}]*opacity:\s*1/s);
  assert.match(js, /setAttribute\('aria-activedescendant', rendered\[active\]\.id\)/);
  assert.match(js, /removeAttribute\('aria-activedescendant'\)/);
  // aria-expanded must survive a tab-out, not only Escape and outside clicks.
  assert.match(js, /addEventListener\('focusout'/);
  assert.match(read(page('search.html')), /\.package-icon img\s*\{[^}]*opacity:\s*0/s);
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
    'voli install skill/tdd --for ' + window.VoliCatalog.defaultAgent
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

test('every offered agent is a real CLI target', () => {
  const source = read(
    path.join(__dirname, '..', '..', 'crates', 'voli-core', 'src', 'agent_targets_generated.rs')
  );
  const block = source.match(/pub const SKILL_TARGET_IDS[^;]*;/);
  assert.ok(block, 'SKILL_TARGET_IDS not found - update this test if the CLI moved it');
  const cliTargets = [...block[0].matchAll(/"([^"]+)"/g)].map(match => match[1]);

  assert.deepEqual(window.VoliCatalog.agents, cliTargets);
  assert.ok(cliTargets.includes(window.VoliCatalog.defaultAgent));

  const offered = [...window.VoliCatalog.agentOptions().matchAll(/value="([^"]+)"/g)]
    .map(match => match[1]);
  assert.deepEqual([...offered].sort(), [...cliTargets].sort(), 'picker drifted from the CLI');
  assert.equal(new Set(offered).size, offered.length, 'an agent is listed twice');
  assert.equal(offered[0], window.VoliCatalog.defaultAgent);
});

test('the skill catalog is advertised as live, not deferred', () => {
  // 267 skills ship in packages.json; the docs claimed the catalog was unpublished.
  const skills = window.VoliCatalog.filterKind(fixture, 'skill');
  assert.deepEqual(
    skills.map(pkg => window.VoliCatalog.command(pkg)),
    ['voli install skill/tdd --for codex', 'voli install skill/frontend-design --for codex']
  );
  for (const file of ['docs.html', 'index.html', 'search.html']) {
    const html = read(page(file));
    assert.doesNotMatch(html, /skill catalog is deferred|coming online|once those assets ship/i, file);
  }
  assert.match(read(page('search.html')), /get\('kind'\) === 'skill'/);
  assert.match(read(page('search.html')), /class="package-kind">skill/);
});

test('result rendering is capped so a one-letter query cannot build 2,600 cards', () => {
  const html = read(page('search.html'));
  const size = html.match(/var PAGE = (\d+);/);
  assert.ok(size, 'search.html lost its page size');
  assert.ok(Number(size[1]) > 0 && Number(size[1]) <= 100, 'page size is not a sensible cap');
  // The render loop must be bounded by the page size, not by the match count.
  assert.match(html, /var visible = Math\.min\(shown, matches\.length\);/);
  assert.match(html, /for \(var i = 0; i < visible; i\+\+\)/);
  assert.match(html, /Showing '/);
});
