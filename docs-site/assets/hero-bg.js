/* voli hero background — animated mesh gradient + film grain, WebGL.
 *
 * Domain-warped fbm noise drives a slow-flowing gradient in the voli palette,
 * with per-pixel grain composited on top. The grain is what reads as "white
 * dots everywhere" — it is generated per pixel per frame, so it shimmers and
 * never lands on a fixed grid the way a CSS radial-gradient dot pattern does.
 *
 * Fails safe: if WebGL is unavailable or a shader fails to compile, nothing is
 * touched and the CSS .tk-mesh fallback in index.html stays visible.
 * Honours prefers-reduced-motion (renders a single static frame).
 * Pauses when the hero scrolls out of view or the tab is hidden.
 */
(function () {
  'use strict';

  var hero = document.querySelector('.hero');
  var canvas = document.getElementById('hero-bg');
  if (!hero || !canvas) return;

  var gl = canvas.getContext('webgl', { antialias: false, alpha: false, depth: false, stencil: false })
        || canvas.getContext('experimental-webgl', { antialias: false, alpha: false });
  if (!gl) return; // no WebGL -> CSS mesh fallback stays

  var VERT = [
    'attribute vec2 a_pos;',
    'void main(){ gl_Position = vec4(a_pos, 0.0, 1.0); }'
  ].join('\n');

  var FRAG = [
    'precision highp float;',
    'uniform vec2 u_res;',
    'uniform float u_time;',

    /* value noise + fbm */
    'vec2 hash2(vec2 p){',
    '  p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));',
    '  return fract(sin(p) * 43758.5453);',
    '}',
    'float noise(vec2 p){',
    '  vec2 i = floor(p), f = fract(p);',
    '  vec2 u = f * f * (3.0 - 2.0 * f);',
    '  float a = dot(-1.0 + 2.0 * hash2(i),               f);',
    '  float b = dot(-1.0 + 2.0 * hash2(i + vec2(1.,0.)), f - vec2(1.,0.));',
    '  float c = dot(-1.0 + 2.0 * hash2(i + vec2(0.,1.)), f - vec2(0.,1.));',
    '  float d = dot(-1.0 + 2.0 * hash2(i + vec2(1.,1.)), f - vec2(1.,1.));',
    '  return 0.5 + 0.5 * mix(mix(a, b, u.x), mix(c, d, u.x), u.y);',
    '}',
    'float fbm(vec2 p){',
    '  float v = 0.0, a = 0.5;',
    '  for (int i = 0; i < 4; i++) { v += a * noise(p); p *= 2.03; a *= 0.5; }',
    '  return v;',
    '}',

    /* per-pixel grain */
    'float grain(vec2 co, float seed){',
    '  return fract(sin(dot(co + seed, vec2(12.9898, 78.233))) * 43758.5453);',
    '}',

    'void main(){',
    '  vec2 uv = gl_FragCoord.xy / u_res;',
    '  vec2 p = uv; p.x *= u_res.x / u_res.y;',
    '  float t = u_time * 0.045;',

    /* two rounds of domain warping = organic, non-repeating flow */
    '  vec2 q = vec2(fbm(p * 1.4 + t), fbm(p * 1.4 + vec2(3.1, 1.7) - t));',
    '  vec2 r = vec2(fbm(p * 1.8 + 2.0 * q + vec2(1.7, 9.2) + 0.15 * t),',
    '                fbm(p * 1.8 + 2.0 * q + vec2(8.3, 2.8) - 0.12 * t));',
    '  float f = fbm(p * 1.6 + 2.2 * r);',

    /* voli palette */
    '  vec3 base  = vec3(0.000, 0.078, 0.063);',  // deep green-black
    '  vec3 verm  = vec3(0.929, 0.318, 0.149);',  // #ED5126
    '  vec3 amber = vec3(0.878, 0.635, 0.235);',  // #E0A23C
    '  vec3 sage  = vec3(0.545, 0.639, 0.600);',  // #8BA399

    '  vec3 col = base;',
    '  col = mix(col, verm  * 0.60, smoothstep(0.34, 0.95, f) * 0.85);',
    '  col = mix(col, amber * 0.42, smoothstep(0.55, 1.00, f * 0.9 + r.x * 0.3) * 0.45);',
    '  col = mix(col, sage  * 0.26, smoothstep(0.20, 0.72, q.y) * 0.30);',

    /* fade to the page colour at the edges */
    '  float vig = smoothstep(1.30, 0.28, length((uv - 0.5) * vec2(1.12, 1.38)));',
    '  col = mix(base, col, vig);',

    /* the "white dots" — grain, quantised to ~24fps so it flickers like film */
    '  float g = grain(gl_FragCoord.xy, floor(u_time * 24.0));',
    '  col += (g - 0.5) * 0.055;',

    '  gl_FragColor = vec4(col, 1.0);',
    '}'
  ].join('\n');

  function compile(type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) { gl.deleteShader(s); return null; }
    return s;
  }

  var vs = compile(gl.VERTEX_SHADER, VERT);
  var fs = compile(gl.FRAGMENT_SHADER, FRAG);
  if (!vs || !fs) return;

  var prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
  gl.useProgram(prog);

  // fullscreen triangle
  var buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  var loc = gl.getAttribLocation(prog, 'a_pos');
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  var uRes = gl.getUniformLocation(prog, 'u_res');
  var uTime = gl.getUniformLocation(prog, 'u_time');

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 1.5); // cap: grain needs no retina
    var w = Math.max(1, Math.round(hero.clientWidth * dpr));
    var h = Math.max(1, Math.round(hero.clientHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w; canvas.height = h;
      gl.viewport(0, 0, w, h);
    }
    gl.uniform2f(uRes, w, h);
  }

  function draw(tSeconds) {
    gl.uniform1f(uTime, tSeconds);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  resize();
  hero.classList.add('shader-on'); // hides the CSS fallback layers

  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) { draw(12.0); return; } // one static, good-looking frame

  var running = true, visible = true, start = performance.now(), raf = 0;

  function frame(now) {
    raf = 0;
    if (!running || !visible) return;
    resize();
    draw((now - start) / 1000);
    raf = requestAnimationFrame(frame);
  }
  function kick() { if (!raf && running && visible) raf = requestAnimationFrame(frame); }

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      visible = entries[0].isIntersecting;
      if (visible) kick();
    }, { threshold: 0 }).observe(hero);
  }
  document.addEventListener('visibilitychange', function () {
    running = !document.hidden;
    if (running) kick();
  });
  window.addEventListener('resize', function () { resize(); kick(); });

  kick();
})();
