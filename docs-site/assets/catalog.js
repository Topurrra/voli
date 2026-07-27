(function () {
  'use strict';

  var DATA_URL = 'https://raw.githubusercontent.com/Topurrra/voli-registry/main/packages.json';
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

  function escapeHtml(value) {
    var node = document.createElement('div');
    node.textContent = value == null ? '' : String(value);
    return node.innerHTML;
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
    var source = pkg.i || favicon(pkg.h);
    var image = source
      ? '<img src="' + escapeHtml(source) + '" alt="" loading="lazy" referrerpolicy="no-referrer">'
      : '';
    return '<span class="' + className + '" aria-hidden="true">' +
      '<span class="icon-fallback">' + escapeHtml(initial) + '</span>' + image + '</span>';
  }

  function favicon(homepage) {
    try {
      var url = new URL(homepage);
      return url.protocol === 'https:' ? url.origin + '/favicon.ico' : '';
    } catch (e) {
      return '';
    }
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
      return 'voli install skill/' + pkg.n + ' --for ' + (agent || 'codex');
    }
    return 'voli install ' + pkg.n;
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
    command: command
  };
})();
