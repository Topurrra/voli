/* ==========================================================================
   Shared site header. Injects the header markup into the
   <header class="site" id="site-header"></header> placeholder present on every
   page, then wires the package-search popover (via assets/catalog.js).
   Must load AFTER catalog.js. Guards against double-init.
   ========================================================================== */
(function () {
  'use strict';

  if (window.__voliSiteHeader) return;
  window.__voliSiteHeader = true;

  var host = document.getElementById('site-header');
  if (!host) return;

  host.innerHTML = [
    '<nav class="nav" aria-label="Primary">',
    '  <a class="brand" href="index.html#top">',
    '    <img src="assets/favicon-64.png" alt="" width="60" height="60">',
    '    Voli<span class="brand-tag"><span class="brand-dot">·</span><code>The Bear That Delivers</code></span>',
    '  </a>',
    '  <form class="header-search" id="header-search" action="search.html" role="search">',
    '    <div class="header-search-field">',
    '      <svg class="header-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">',
    '        <circle cx="11" cy="11" r="8"></circle>',
    '        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>',
    '      </svg>',
    '      <input class="header-search-input" id="pkg-search" name="q" type="search" placeholder="Search packages" autocomplete="off" spellcheck="false" role="combobox" aria-label="Search packages" aria-controls="search-results" aria-expanded="false" aria-autocomplete="list" aria-haspopup="listbox">',
    '      <kbd class="header-search-key" aria-hidden="true">/</kbd>',
    '    </div>',
    '    <div class="header-search-popover" id="search-popover" hidden>',
    '      <p class="quick-status" id="search-status" aria-live="polite"></p>',
    '      <div id="search-results" role="listbox" aria-label="Package suggestions"></div>',
    '      <a class="quick-all" id="search-all" href="search.html"><span>View all results</span><span aria-hidden="true">→</span></a>',
    '    </div>',
    '  </form>',
    '  <div class="nav-links">',
    '    <a class="navlink" href="docs.html">Docs</a>',
    '    <a class="navlink" href="search.html">Packages</a>',
    '    <a class="icon-btn" href="https://github.com/Topurrra/voli" aria-label="voli on GitHub" rel="noopener">',
    '      <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>',
    '    </a>',
    '    <a class="btn btn-cream btn-sm nav-cta" href="index.html#install">Install</a>',
    '  </div>',
    '</nav>'
  ].join('\n');

  var foot = document.getElementById('site-footer');
  if (foot) {
    foot.innerHTML = [
      '<div class="foot">',
      '  <div class="foot-links">',
      '    <a href="https://github.com/Topurrra/voli" target="_blank" rel="noopener noreferrer">GitHub</a>',
      '    <a href="https://github.com/Topurrra/voli-registry" target="_blank" rel="noopener noreferrer">Registry</a>',
      '    <a href="https://github.com/Topurrra/voli/tree/main/license" target="_blank" rel="noopener noreferrer">License</a>',
      '    <p class="made">Made with &#128059; <a href="https://github.com/Topurrra" target="_blank" rel="noopener noreferrer">By Topurrra</a> &middot; a fast, no-admin package manager for Windows.</p>',
      '  </div>',
      '</div>'
    ].join('\n');
  }

  initSearch();

  // ---- Header package search (ported from the old inline index.html block) ----
  function initSearch() {
    if (typeof window.VoliCatalog === 'undefined') return; // catalog.js absent: form still submits natively

    var form = document.getElementById('header-search');
    var input = document.getElementById('pkg-search');
    var results = document.getElementById('search-results');
    var popover = document.getElementById('search-popover');
    var status = document.getElementById('search-status');
    var all = document.getElementById('search-all');
    var pkgs = null;
    var active = -1;
    var rendered = [];
    var timer = null;

    function open() {
      popover.hidden = false;
      input.setAttribute('aria-expanded', 'true');
    }

    function close() {
      popover.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      setActive(-1);
    }

    function render() {
      var query = input.value.trim();
      setActive(-1);
      rendered = [];
      results.innerHTML = '';
      if (!query) {
        close();
        return;
      }

      var searchable = pkgs.filter(function (pkg) {
        var kind = VoliCatalog.kind(pkg);
        return kind === 'app' || kind === 'skill';
      });
      var matches = VoliCatalog.search(searchable, query);
      var total = matches.length;
      var show = matches.slice(0, 5);
      status.textContent = total
        ? total + ' package' + (total === 1 ? '' : 's') + ' found'
        : 'No matching packages';
      all.href = 'search.html?q=' + encodeURIComponent(query);
      all.firstElementChild.textContent = total ? 'View all ' + total + ' results' : 'Search the full catalog';

      for (var j = 0; j < show.length; j++) {
        (function (item) {
          var p = item.p;
          var row = document.createElement('button');
          var command = VoliCatalog.command(p);
          var isSkill = VoliCatalog.kind(p) === 'skill';
          row.type = 'button';
          row.id = 'search-option-' + rendered.length;
          row.className = 'quick-result';
          row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', 'false');
          row.setAttribute('aria-label', 'Copy ' + command);
          // The popover has no agent picker, so a skill row says which agent the
          // copied command targets; search.html is where you change it.
          row.innerHTML =
            VoliCatalog.icon(p, 'quick-icon') +
            '<span><span class="quick-name">' + VoliCatalog.escape(p.n) +
            (isSkill ? '<span class="quick-kind">skill</span>' : '') + '</span>' +
            '<span class="quick-meta">' + VoliCatalog.escape(p.v + ' · ' + (p.d || 'No description')) + '</span></span>' +
            '<span class="quick-copy">Copy' +
            (isSkill ? ' · ' + VoliCatalog.escape(VoliCatalog.defaultAgent) : '') + '</span>';
          VoliCatalog.wireIcon(row.querySelector('.quick-icon'));
          row.addEventListener('click', function () { copyText(command, row); });
          results.appendChild(row);
          rendered.push(row);
        })(show[j]);
      }
      open();
    }

    function loadAndRender() {
      if (!input.value.trim()) {
        close();
        return;
      }
      status.textContent = 'Loading catalog...';
      setActive(-1);
      rendered = [];
      results.innerHTML = '';
      open();
      VoliCatalog.load().then(function (data) {
        pkgs = data;
        render();
      }).catch(function () {
        status.innerHTML = 'Search unavailable: <a href="https://github.com/Topurrra/voli-registry/tree/main/manifests" rel="noopener">browse the registry on GitHub</a>';
      });
    }

    function copyText(text, row) {
      function done() {
        if (row.classList.contains('copied')) return;
        var label = row.querySelector('.quick-copy');
        var original = label.textContent;
        row.classList.add('copied');
        label.textContent = 'Copied';
        setTimeout(function () {
          row.classList.remove('copied');
          label.textContent = original;
        }, 1400);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fb(text); done(); });
      } else {
        fb(text);
        done();
      }
    }

    function fb(text) {
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (e) { }
      document.body.removeChild(ta);
    }

    function setActive(idx) {
      if (active >= 0 && active < rendered.length) {
        rendered[active].classList.remove('active');
        rendered[active].setAttribute('aria-selected', 'false');
      }
      active = idx;
      if (active >= 0 && active < rendered.length) {
        rendered[active].classList.add('active');
        rendered[active].setAttribute('aria-selected', 'true');
        input.setAttribute('aria-activedescendant', rendered[active].id);
      } else {
        input.removeAttribute('aria-activedescendant');
      }
    }

    form.addEventListener('submit', function (e) {
      if (!input.value.trim()) e.preventDefault();
    });

    input.addEventListener('focus', function () {
      if (input.value.trim()) loadAndRender();
    });
    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(loadAndRender, 80);
    });

    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        close();
        input.blur();
        return;
      }
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive(Math.min(active + 1, rendered.length - 1)); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); setActive(Math.max(active - 1, 0)); return; }
      if (e.key === 'Enter' && active >= 0 && active < rendered.length) {
        e.preventDefault();
        rendered[active].click();
      }
    });

    document.addEventListener('click', function (e) {
      if (!form.contains(e.target)) close();
    });

    // Tabbing out of the combobox must collapse it too, or aria-expanded lies.
    form.addEventListener('focusout', function (e) {
      if (!form.contains(e.relatedTarget)) close();
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === '/' && document.activeElement !== input && !e.ctrlKey && !e.metaKey) {
        var tag = document.activeElement.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        e.preventDefault();
        input.focus();
      }
    });
  }
})();
