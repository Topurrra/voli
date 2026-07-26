(function () {
  'use strict';

  var DATA_URL = 'https://raw.githubusercontent.com/Topurrra/voli-registry/main/packages.json';
  var packages = null;
  var pending = null;

  function load() {
    if (packages) return Promise.resolve(packages);
    if (pending) return pending;

    var cached = null;
    try {
      cached = sessionStorage.getItem('voli-pkgs');
    } catch (e) {
      // Continue without browser storage.
    }
    if (cached) {
      try {
        packages = JSON.parse(cached);
        return Promise.resolve(packages);
      } catch (e) {
        sessionStorage.removeItem('voli-pkgs');
      }
    }

    pending = fetch(DATA_URL).then(function (response) {
      if (!response.ok) throw new Error(String(response.status));
      return response.json();
    }).then(function (data) {
      packages = data;
      try {
        sessionStorage.setItem('voli-pkgs', JSON.stringify(data));
      } catch (e) {
        // The catalog still works when browser storage is unavailable.
      }
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
    var image = pkg.i
      ? '<img src="' + escapeHtml(pkg.i) + '" alt="" loading="lazy" referrerpolicy="no-referrer" hidden>'
      : '';
    return '<span class="' + className + '" aria-hidden="true">' +
      '<span class="icon-fallback">' + escapeHtml(initial) + '</span>' + image + '</span>';
  }

  function wireIcon(root) {
    var image = root.querySelector('img');
    if (!image) return;
    function loaded() {
      image.hidden = false;
      root.classList.add('has-image');
    }
    function failed() {
      image.remove();
    }
    image.addEventListener('load', loaded);
    image.addEventListener('error', failed);
    if (image.complete) {
      if (image.naturalWidth) loaded();
      else failed();
    }
  }

  window.VoliCatalog = {
    load: load,
    search: search,
    escape: escapeHtml,
    highlight: highlight,
    icon: icon,
    wireIcon: wireIcon,
    command: function (name) { return 'voli install ' + name; }
  };
})();
