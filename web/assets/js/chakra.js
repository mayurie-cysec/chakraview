/* ==========================================================================
   The Sudarshana Chakra — ChakraView's mark, drawn as SVG and animated in CSS.

   Built in JavaScript rather than hand-written markup because the geometry is
   deeply repetitive: ten concentric rings of flames, teeth, beads, blades,
   lotus petals, yantra triangles and spokes, each needing exact polar
   placement. Generating it keeps every ring true and lets one function serve
   the 36px header mark and the 420px hero wheel.

   The ten layers, outermost first:

     1  jwala    24 flames licking outward past the rim
     2  rim      double rim with 72 teeth and 12 heavier studs
     3  mani     24-bead ring
     4  mantra   120 fine inscription ticks
     5  shatkona two interlocking triangles, counter-rotating, behind the blades
     6  blades   12 flame-shaped discus blades — the signature layer
     7  padma    16-petal lotus seat
     8  antara   12-bead inner ring
     9  spokes   16-spoke inner wheel + hub rings
    10  sparks   8 orbiting glyphs

   Each layer turns at its own speed and direction, so the wheel reads as one
   object with real depth rather than a single flat image spinning. Rotation
   lives in CSS (.chakra [data-spin] in chakraview.css) so the browser
   composites it on the GPU and prefers-reduced-motion can stop all of it.

   Usage:
     <div data-chakra data-size="420" data-detail="full"></div>
     <script src="assets/js/chakra.js"></script>

   detail: "full" every layer · "mid" the structural ones · "mark" a legible
   silhouette for small sizes.
   ========================================================================== */

(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var TAU = Math.PI * 2;

  // Palette — mirrors the Sanatan tokens in chakraview.css.
  var C = {
    ember:    "#9a3412",
    bhagwa:   "#e05c0c",
    saffron:  "#ff7a18",
    marigold: "#fcb13f",
    brass:    "#f5c542",
    amber:    "#b45309",
    white:    "#fffbeb",
    void:     "#0c0705"
  };

  function el(name, attrs) {
    var node = document.createElementNS(SVG_NS, name);
    for (var key in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, key)) {
        node.setAttribute(key, String(attrs[key]));
      }
    }
    return node;
  }

  /* Polar to cartesian, centred on the 200,200 origin of the viewBox. */
  function pt(radius, angle) {
    return [
      (200 + Math.cos(angle) * radius).toFixed(1),
      (200 + Math.sin(angle) * radius).toFixed(1)
    ];
  }

  function group(spin, extra) {
    var g = el("g", extra || {});
    if (spin) g.setAttribute("data-spin", spin);
    return g;
  }

  /* ── Shape builders ─────────────────────────────────────────────────── */

  /* A discus blade: a tapered flame sweeping from the inner seat out past
     the lotus, asymmetric so the wheel has an obvious direction of travel. */
  function bladePath(i, count, inner, outer, spread) {
    var a = (i / count) * TAU;
    var half = (TAU / count) * spread;
    var b1 = pt(inner, a - half);
    var b2 = pt(inner, a + half);
    var tip = pt(outer, a + half * 0.62);
    var lead = pt((inner + outer) * 0.54, a - half * 1.45);
    // The trailing control sits close to the tip, so the point stays sharp
    // instead of rounding off into a petal.
    var trail = pt(outer * 0.86, a + half * 0.78);
    return "M" + b1 + " Q" + lead + " " + tip +
           " Q" + trail + " " + b2 + " Z";
  }

  /* A corona flame: narrow, slightly swept, licking outward. */
  function flamePath(i, count, inner, outer) {
    var a = (i / count) * TAU;
    var half = (TAU / count) * 0.30;
    var b1 = pt(inner, a - half);
    var b2 = pt(inner, a + half);
    var tip = pt(outer, a + half * 0.9);
    var mid = pt((inner + outer) / 2, a - half * 0.5);
    return "M" + b1 + " Q" + mid + " " + tip + " L" + b2 + " Z";
  }

  /* A lotus petal: a pointed oval seated under the blades. */
  function petalPath(i, count, inner, outer) {
    var a = (i / count) * TAU;
    var half = (TAU / count) * 0.5;
    var b1 = pt(inner, a - half);
    var b2 = pt(inner, a + half);
    var tip = pt(outer, a);
    var c1 = pt((inner + outer) * 0.62, a - half * 1.15);
    var c2 = pt((inner + outer) * 0.62, a + half * 1.15);
    return "M" + b1 + " Q" + c1 + " " + tip + " Q" + c2 + " " + b2 + " Z";
  }

  function trianglePath(radius, rotation) {
    var points = [];
    for (var i = 0; i < 3; i++) {
      points.push(pt(radius, rotation + (i / 3) * TAU).join(","));
    }
    return "M" + points.join(" L") + " Z";
  }

  /* ── Gradients ──────────────────────────────────────────────────────── */

  function defs(uid) {
    var d = el("defs", {});

    var halo = el("radialGradient", { id: uid + "halo" });
    halo.appendChild(el("stop", { offset: "0%",  "stop-color": C.saffron, "stop-opacity": ".55" }));
    halo.appendChild(el("stop", { offset: "45%", "stop-color": C.bhagwa,  "stop-opacity": ".30" }));
    halo.appendChild(el("stop", { offset: "100%","stop-color": C.void,    "stop-opacity": "0" }));
    d.appendChild(halo);

    var rim = el("linearGradient", { id: uid + "rim", x1: "0", y1: "0", x2: "1", y2: "1" });
    rim.appendChild(el("stop", { offset: "0%",   "stop-color": C.brass }));
    rim.appendChild(el("stop", { offset: "48%",  "stop-color": C.saffron }));
    rim.appendChild(el("stop", { offset: "100%", "stop-color": C.ember }));
    d.appendChild(rim);

    var blade = el("linearGradient", { id: uid + "blade", x1: "0", y1: "0", x2: "0.2", y2: "1" });
    blade.appendChild(el("stop", { offset: "0%",   "stop-color": C.brass,    "stop-opacity": ".98" }));
    blade.appendChild(el("stop", { offset: "42%",  "stop-color": C.marigold, "stop-opacity": ".92" }));
    blade.appendChild(el("stop", { offset: "100%", "stop-color": C.bhagwa,   "stop-opacity": ".40" }));
    d.appendChild(blade);

    var flame = el("linearGradient", { id: uid + "flame", x1: "0", y1: "1", x2: "0", y2: "0" });
    flame.appendChild(el("stop", { offset: "0%",   "stop-color": C.saffron, "stop-opacity": ".75" }));
    flame.appendChild(el("stop", { offset: "100%", "stop-color": C.brass,   "stop-opacity": "0" }));
    d.appendChild(flame);

    var petal = el("linearGradient", { id: uid + "petal", x1: "0", y1: "0", x2: "0", y2: "1" });
    petal.appendChild(el("stop", { offset: "0%",   "stop-color": C.marigold, "stop-opacity": ".55" }));
    petal.appendChild(el("stop", { offset: "100%", "stop-color": C.ember,    "stop-opacity": ".22" }));
    d.appendChild(petal);

    var hub = el("radialGradient", { id: uid + "hub" });
    hub.appendChild(el("stop", { offset: "0%",   "stop-color": C.white }));
    hub.appendChild(el("stop", { offset: "38%",  "stop-color": C.brass }));
    hub.appendChild(el("stop", { offset: "100%", "stop-color": C.amber }));
    d.appendChild(hub);

    return d;
  }

  /* ── Layers ─────────────────────────────────────────────────────────── */

  function jwala(uid) {                       // 1 — corona flames
    var g = group("jwala");
    for (var i = 0; i < 24; i++) {
      g.appendChild(el("path", {
        d: flamePath(i, 24, 172, i % 2 ? 190 : 198),
        fill: "url(#" + uid + "flame)"
      }));
    }
    return g;
  }

  function rim(uid, full) {                   // 2 — toothed double rim
    var g = group("rim");
    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: 170, fill: "none",
      stroke: "url(#" + uid + "rim)", "stroke-width": full ? 2.6 : 9
    }));
    if (!full) return g;

    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: 161, fill: "none",
      stroke: C.ember, "stroke-width": 1.1, "stroke-opacity": ".8"
    }));
    for (var t = 0; t < 72; t++) {
      var a = (t / 72) * TAU;
      var major = t % 6 === 0;
      var p1 = pt(161, a);
      var p2 = pt(major ? 178 : 170, a);
      g.appendChild(el("line", {
        x1: p1[0], y1: p1[1], x2: p2[0], y2: p2[1],
        stroke: major ? C.brass : C.saffron,
        "stroke-width": major ? 2.2 : 0.9,
        "stroke-opacity": major ? ".95" : ".45"
      }));
    }
    for (var s = 0; s < 12; s++) {            // heavier studs
      var ps = pt(166, (s / 12) * TAU + TAU / 24);
      g.appendChild(el("circle", {
        cx: ps[0], cy: ps[1], r: 2.6, fill: C.brass, "fill-opacity": ".9"
      }));
    }
    return g;
  }

  function mani() {                           // 3 — bead ring
    var g = group("mani");
    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: 152, fill: "none",
      stroke: C.ember, "stroke-width": 0.9, "stroke-opacity": ".65"
    }));
    for (var i = 0; i < 24; i++) {
      var p = pt(152, (i / 24) * TAU);
      g.appendChild(el("circle", {
        cx: p[0], cy: p[1], r: i % 2 ? 1.8 : 3.4,
        fill: i % 2 ? C.marigold : C.brass,
        "fill-opacity": i % 2 ? ".7" : ".95"
      }));
    }
    return g;
  }

  function mantra() {                         // 4 — inscription ticks
    var g = group("mantra");
    for (var i = 0; i < 120; i++) {
      var a = (i / 120) * TAU;
      var p1 = pt(140, a);
      var p2 = pt(i % 5 === 0 ? 148 : 145, a);
      g.appendChild(el("line", {
        x1: p1[0], y1: p1[1], x2: p2[0], y2: p2[1],
        stroke: i % 5 === 0 ? C.marigold : C.bhagwa,
        "stroke-width": i % 5 === 0 ? 1.3 : 0.7,
        "stroke-opacity": i % 5 === 0 ? ".8" : ".4"
      }));
    }
    return g;
  }

  function blades(uid, count, full) {         // 5 — the discus blades
    var g = group("blades");
    for (var i = 0; i < count; i++) {
      g.appendChild(el("path", {
        d: bladePath(i, count, 84, 137, 0.34),
        fill: "url(#" + uid + "blade)",
        stroke: C.saffron,
        "stroke-width": full ? 0.9 : 1.8,
        "stroke-opacity": ".6",
        "stroke-linejoin": "round"
      }));
    }
    return g;
  }

  function padma(uid) {                       // 6 — lotus seat
    var g = group("padma");
    for (var i = 0; i < 16; i++) {
      g.appendChild(el("path", {
        d: petalPath(i, 16, 54, 82),
        fill: "url(#" + uid + "petal)",
        stroke: C.marigold,
        "stroke-width": 0.8,
        "stroke-opacity": ".55"
      }));
    }
    return g;
  }

  function shatkona() {                       // 5a — yantra underlay
    var g = group("yantra");
    g.appendChild(el("path", {
      d: trianglePath(118, -Math.PI / 2), fill: "none",
      stroke: C.brass, "stroke-width": 1.2, "stroke-opacity": ".38",
      "stroke-linejoin": "round"
    }));
    var down = group("yantra-rev");
    down.appendChild(el("path", {
      d: trianglePath(118, Math.PI / 2), fill: "none",
      stroke: C.saffron, "stroke-width": 1.2, "stroke-opacity": ".34",
      "stroke-linejoin": "round"
    }));
    g.appendChild(down);
    return g;
  }

  function antara() {                         // 8a — inner bead ring
    var g = group("antara");
    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: 47, fill: "none",
      stroke: C.ember, "stroke-width": 0.9, "stroke-opacity": ".7"
    }));
    for (var i = 0; i < 12; i++) {
      var p = pt(47, (i / 12) * TAU);
      g.appendChild(el("circle", {
        cx: p[0], cy: p[1], r: 1.9, fill: C.brass, "fill-opacity": ".85"
      }));
    }
    return g;
  }

  function spokes(uid, count, full) {         // 8 — inner wheel
    var g = group("inner");
    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: 38, fill: "none",
      stroke: C.marigold, "stroke-width": full ? 1.2 : 4, "stroke-opacity": ".8"
    }));
    for (var i = 0; i < count; i++) {
      var a = (i / count) * TAU;
      var p1 = pt(20, a);
      var p2 = pt(38, a);
      g.appendChild(el("line", {
        x1: p1[0], y1: p1[1], x2: p2[0], y2: p2[1],
        stroke: i % 2 ? C.saffron : C.brass,
        "stroke-width": full ? 1.6 : 3,
        "stroke-opacity": ".85"
      }));
    }
    return g;
  }

  function bindu(uid, full) {                 // 9 — the hub
    var g = group(null);
    g.setAttribute("data-pulse", "");
    g.appendChild(el("circle", {
      cx: 200, cy: 200, r: full ? 19 : 24, fill: "url(#" + uid + "hub)"
    }));
    if (full) {
      g.appendChild(el("circle", {
        cx: 200, cy: 200, r: 12.5, fill: "none",
        stroke: C.amber, "stroke-width": 1.3, "stroke-opacity": ".8"
      }));
      g.appendChild(el("circle", {
        cx: 200, cy: 200, r: 5, fill: C.white, "fill-opacity": ".95"
      }));
    }
    return g;
  }

  function sparks() {                         // 10 — orbiting glyphs
    var g = group("sparks");
    for (var i = 0; i < 8; i++) {
      var p = pt(192, (i / 8) * TAU + 0.2);
      var s = el("text", {
        x: p[0], y: p[1],
        "text-anchor": "middle", "dominant-baseline": "central",
        fill: i % 2 ? C.marigold : C.brass,
        "font-size": i % 2 ? 11 : 15
      });
      s.setAttribute("data-flicker", "");
      s.style.animationDelay = (i * 0.32).toFixed(2) + "s";
      s.textContent = "✦";
      g.appendChild(s);
    }
    return g;
  }

  /* ── Assembly ───────────────────────────────────────────────────────── */

  var seq = 0;

  function build(size, detail) {
    // Gradient ids must be unique per instance — several wheels share a page.
    var uid = "cv" + (seq++) + "-";
    var full = detail === "full";
    var mark = detail === "mark";

    var svg = el("svg", {
      class: "chakra",
      viewBox: "0 0 400 400",
      width: size,
      height: size,
      role: "img",
      "aria-label": "The Sudarshana Chakra, turning"
    });
    svg.appendChild(defs(uid));

    if (!mark) {
      var halo = el("circle", { cx: 200, cy: 200, r: 158, fill: "url(#" + uid + "halo)" });
      halo.setAttribute("class", "chakra-glow");
      svg.appendChild(halo);
    }

    if (full) svg.appendChild(jwala(uid));
    svg.appendChild(rim(uid, !mark));
    if (!mark) svg.appendChild(mani());
    if (full) svg.appendChild(mantra());
    if (!mark) svg.appendChild(shatkona());
    svg.appendChild(blades(uid, mark ? 8 : 12, !mark));
    // The lotus belongs in the mid tier too: without it the yantra triangles
    // sit over an empty centre and read as a stray shape rather than a layer.
    if (!mark) svg.appendChild(padma(uid));
    if (!mark) svg.appendChild(antara());
    svg.appendChild(spokes(uid, mark ? 6 : 16, !mark));
    svg.appendChild(bindu(uid, !mark));
    if (full) svg.appendChild(sparks());

    return svg;
  }

  /* Scatter twinkling sparkles across a container, behind its content. */
  function sparkField(host, count) {
    var field = document.createElement("div");
    field.className = "spark-field";
    field.setAttribute("aria-hidden", "true");
    for (var i = 0; i < count; i++) {
      var star = document.createElement("i");
      star.textContent = i % 3 === 0 ? "✧" : "✦";
      star.style.left = (Math.random() * 98).toFixed(2) + "%";
      star.style.top = (Math.random() * 96).toFixed(2) + "%";
      star.style.fontSize = (7 + Math.random() * 9).toFixed(1) + "px";
      star.style.animationDelay = (Math.random() * 4.5).toFixed(2) + "s";
      field.appendChild(star);
    }
    host.appendChild(field);
  }

  function mount() {
    var hosts = document.querySelectorAll("[data-chakra]");
    for (var i = 0; i < hosts.length; i++) {
      var host = hosts[i];
      if (host.dataset.mounted) continue;
      host.dataset.mounted = "1";
      host.appendChild(build(
        parseInt(host.dataset.size, 10) || 360,
        host.dataset.detail || "full"
      ));
    }
    var fields = document.querySelectorAll("[data-sparks]");
    for (var j = 0; j < fields.length; j++) {
      if (fields[j].dataset.sparked) continue;
      fields[j].dataset.sparked = "1";
      sparkField(fields[j], parseInt(fields[j].dataset.sparks, 10) || 18);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }

  window.ChakraMark = { build: build, mount: mount, sparkField: sparkField };
})();
