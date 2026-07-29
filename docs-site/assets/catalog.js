(function () {
  'use strict';

  var DATA_URL = 'https://raw.githubusercontent.com/Topurrra/voli-registry/main/packages.json';

  // Mirrors SKILL_TARGET_IDS in crates/voli-core/src/agent_targets_generated.rs.
  // catalog.test.js diffs the two, so a CLI resync fails the suite instead of
  // silently shipping `--for <unknown>` to the site.
  var AGENTS = ['adal', 'aider-desk', 'antigravity', 'antigravity-cli', 'astrbot', 'augment',
    'autohand-code', 'bob', 'claude-code', 'cline', 'codearts-agent', 'codebuddy', 'codemaker',
    'codestudio', 'codex', 'command-code', 'continue', 'cortex', 'crush', 'cursor', 'deepagents',
    'dexto', 'droid', 'firebender', 'forgecode', 'gemini-cli', 'github-copilot', 'grok',
    'hermes-agent', 'iflow-cli', 'inference-sh', 'jazz', 'junie', 'kilo', 'kimchi',
    'kimi-code-cli', 'kiro-cli', 'kode', 'lingma', 'loaf', 'mcpjam', 'mistral-vibe', 'moxby',
    'mux', 'neovate', 'ona', 'openhands', 'pi', 'pochi', 'qoder', 'qoder-cn', 'qwen-code',
    'reasonix', 'roo', 'rovodev', 'tabnine-cli', 'terramind', 'tinycloud', 'trae', 'trae-cn',
    'warp', 'windsurf', 'zcode', 'zed', 'zencoder', 'zenflow'];

  // Surfaced first in the picker; the rest stay one scroll away.
  var COMMON_AGENTS = ['codex', 'claude-code', 'cursor', 'windsurf', 'github-copilot',
    'gemini-cli', 'zed', 'cline', 'roo', 'continue', 'warp', 'kiro-cli'];

  var DEFAULT_AGENT = 'codex';

  var packages = null;
  var pending = null;

  function load() {
    if (packages) return Promise.resolve(packages);
    if (pending) return pending;

    pending = fetch(DATA_URL).then(function (response) {
      if (!response.ok) throw new Error(String(response.status));
      return response.json();
    }).then(function (data) {
      packages = data;
      return data;
    }).finally(function () {
      pending = null;
    });

    return pending;
  }

  function rank(pkg, query) {
    var name = pkg.n.toLowerCase();
    var bins = (pkg.b || []).join(' ').toLowerCase();
    var description = (pkg.d || '').toLowerCase();

    if (name === query) return 0;
    if (name.indexOf(query) === 0) return 1;
    if (name.indexOf(query) !== -1) return 2;
    if (bins.indexOf(query) !== -1) return 3;
    if (description.indexOf(query) !== -1) return 4;
    return -1;
  }

  function search(data, value) {
    var query = value.trim().toLowerCase();
    if (!query) return [];

    var matches = [];
    for (var i = 0; i < data.length; i++) {
      var score = rank(data[i], query);
      if (score >= 0) matches.push({ p: data[i], r: score });
    }
    matches.sort(function (a, b) {
      return a.r - b.r || a.p.n.localeCompare(b.p.n);
    });
    return matches;
  }

  var ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  // Escapes for both text and double/single-quoted attribute contexts. Do not
  // swap this back to textContent -> innerHTML: that leaves " and ' untouched,
  // which is a breakout in every `attr="' + escape(x) + '"` sink below.
  function escapeHtml(value) {
    return (value == null ? '' : String(value)).replace(/[&<>"']/g, function (char) {
      return ESCAPES[char];
    });
  }

  function highlight(value, query) {
    var text = value == null ? '' : String(value);
    var needle = query.trim().toLowerCase();
    if (!needle) return escapeHtml(text);

    var lower = text.toLowerCase();
    var output = '';
    var cursor = 0;
    var index;
    while ((index = lower.indexOf(needle, cursor)) !== -1) {
      output += escapeHtml(text.slice(cursor, index));
      output += '<mark>' + escapeHtml(text.slice(index, index + needle.length)) + '</mark>';
      cursor = index + needle.length;
    }
    return output + escapeHtml(text.slice(cursor));
  }

  function icon(pkg, className) {
    var initial = (pkg.n.match(/[a-z0-9]/i) || ['?'])[0];
    var source = httpsUrl(pkg.i) || favicon(pkg.h);
    var image = source
      ? '<img src="' + escapeHtml(source) + '" alt="" loading="lazy" referrerpolicy="no-referrer">'
      : '';
    return '<span class="' + className + '" aria-hidden="true">' +
      '<span class="icon-fallback">' + escapeHtml(initial) + '</span>' + image + '</span>';
  }

  // pkg.i and pkg.h are upstream-controlled. Only absolute https URLs reach an
  // src/href; href normalisation also percent-encodes quotes and angle brackets.
  function httpsUrl(value) {
    try {
      var url = new URL(value);
      return url.protocol === 'https:' ? url.href : '';
    } catch (e) {
      return '';
    }
  }

  function favicon(homepage) {
    var url = httpsUrl(homepage);
    return url ? new URL(url).origin + '/favicon.ico' : '';
  }

  function wireIcon(root) {
    var image = root.querySelector('img');
    if (!image) return;
    function loaded() {
      root.classList.add('has-image');
    }
    function failed() {
      image.remove();
    }
    image.addEventListener('load', loaded);
    image.addEventListener('error', failed);
    if (image.complete && image.naturalWidth) loaded();
  }

  function updated(pkg) {
    var value = pkg.u;
    if (typeof value === 'number') return value < 1000000000000 ? value * 1000 : value;
    var parsed = Date.parse(value || '');
    return isNaN(parsed) ? 0 : parsed;
  }

  function provenance(pkg) {
    var value = String(pkg.p || '').toLowerCase();
    return value === 'official' || value === 'community' ? value : '';
  }

  function kind(pkg) {
    return String(pkg && pkg.k || 'app').toLowerCase();
  }

  function filterKind(data, selected) {
    return data.filter(function (pkg) { return kind(pkg) === selected; });
  }

  function command(pkg, agent) {
    if (typeof pkg === 'string') return 'voli install ' + pkg;
    if (kind(pkg) === 'skill') {
      return 'voli install skill/' + pkg.n + ' --for ' + (agent || DEFAULT_AGENT);
    }
    return 'voli install ' + pkg.n;
  }

  // Built once: 65 <option>s per result card adds up fast.
  var agentMarkup = null;

  function agentOptions() {
    if (agentMarkup === null) {
      var rest = AGENTS.filter(function (id) { return COMMON_AGENTS.indexOf(id) === -1; });
      agentMarkup =
        '<optgroup label="Common">' + optionList(COMMON_AGENTS) + '</optgroup>' +
        '<optgroup label="All agents">' + optionList(rest) + '</optgroup>';
    }
    return agentMarkup;
  }

  function optionList(ids) {
    return ids.map(function (id) {
      return '<option value="' + escapeHtml(id) + '">' + escapeHtml(id) + '</option>';
    }).join('');
  }

  window.VoliCatalog = {
    load: load,
    search: search,
    escape: escapeHtml,
    highlight: highlight,
    icon: icon,
    wireIcon: wireIcon,
    updated: updated,
    provenance: provenance,
    kind: kind,
    filterKind: filterKind,
    command: command,
    agents: AGENTS,
    agentOptions: agentOptions,
    defaultAgent: DEFAULT_AGENT
  };
})();
