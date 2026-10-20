/* ==========================================================================
   The Sudarshana Chakra — ChakraView's mark, drawn as SVG and animated in CSS.

   Built in JavaScript rather than hand-written markup because the geometry is
   repetitive: five concentric rings of blades, teeth, spokes and sparks, each
   needing exact polar placement. Generating it keeps the shapes true and lets
   one function serve the 34px header mark and the 420px hero wheel.

   Rotation lives in CSS (see .chakra [data-spin] in chakraview.css) so the
   browser composites it on the GPU and prefers-reduced-motion can stop it.

   Usage:
     <div data-chakra data-size="420" data-detail="full"></div>
     <script src="assets/js/chakra.js"></script>
   ========================================================================== */

(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var TAU = Math.PI * 2;

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
  function point(radius, angle) {
    return [200 + Math.cos(angle) * radius, 200 + Math.sin(angle) * radius];
  }

  /* One blade of the discus: a tapered flame that sweeps from the inner ring
     out past the rim, which is what makes the wheel read as a weapon rather
     than a gear. */
  function bladePath(index, count, inner, outer, spread) {
    var angle = (index / count) * TAU;
    var half = (TAU / count) * spread;
    var base1 = point(inner, angle - half);
    var base2 = point(inner, angle + half);
    var tip = point(outer, angle + half * 0.35);
    var curve = point((inner + outer) / 2, angle - half * 1.25);
    return (
      "M" + base1[0].toFixed(1) + "," + base1[1].toFixed(1) +
      " Q" + curve[0].toFixed(1) + "," + curve[1].toFixed(1) +
      " " + tip[0].toFixed(1) + "," + tip[1].toFixed(1) +
      " L" + base2[0].toFixed(1) + "," + base2[1].toFixed(1) + " Z"
    );
  }

  function group(spin) {
    var g = el("g", {});
    if (spin) g.setAttribute("data-spin", spin);
    return g;
  }

  function build(size, detail) {
    var full = detail !== "mark";
    var svg = el("svg", {
      class: "chakra",
      viewBox: "0 0 400 400",
      width: size,
      height: size,
      role: "img",
      "aria-label": "The Sudarshana Chakra, turning"
    });

    /* ── Gradients and the glow behind the wheel ── */
    var defs = el("defs", {});

    var glow = el("radialGradient", { id: "cvGlow" });
    glow.appendChild(el("stop", { offset: "0%", "stop-color": "#c084fc", "stop-opacity": ".85" }));
    glow.appendChild(el("stop", { offset: "55%", "stop-color": "#7c3aed", "stop-opacity": ".35" }));
    glow.appendChild(el("stop", { offset: "100%", "stop-color": "#09060f", "stop-opacity": "0" }));
    defs.appendChild(glow);

    var rim = el("linearGradient", { id: "cvRim", x1: "0", y1: "0", x2: "1", y2: "1" });
    rim.appendChild(el("stop", { offset: "0%", "stop-color": "#fbbf24" }));
    rim.appendChild(el("stop", { offset: "50%", "stop-color": "#a855f7" }));
    rim.appendChild(el("stop", { offset: "100%", "stop-color": "#5b21b6" }));
    defs.appendChild(rim);

    var blade = el("linearGradient", { id: "cvBlade", x1: "0", y1: "0", x2: "0", y2: "1" });
    blade.appendChild(el("stop", { offset: "0%", "stop-color": "#c084fc", "stop-opacity": ".95" }));
    blade.appendChild(el("stop", { offset: "100%", "stop-color": "#7c3aed", "stop-opacity": ".25" }));
    defs.appendChild(blade);

    var hub = el("radialGradient", { id: "cvHub" });
    hub.appendChild(el("stop", { offset: "0%", "stop-color": "#fffbeb" }));
    hub.appendChild(el("stop", { offset: "45%", "stop-color": "#fbbf24" }));
    hub.appendChild(el("stop", { offset: "100%", "stop-color": "#d97706" }));
    defs.appendChild(hub);

    svg.appendChild(defs);

    if (full) {
      var halo = el("circle", { cx: 200, cy: 200, r: 150, fill: "url(#cvGlow)" });
      halo.setAttribute("class", "chakra-glow");
      svg.appendChild(halo);
    }

    /* ── Ring 1: outer rim with teeth ── */
    var rimGroup = group("rim");
    rimGroup.appendChild(el("circle", {
      cx: 200, cy: 200, r: 168, fill: "none",
      stroke: "url(#cvRim)", "stroke-width": full ? 2.5 : 10
    }));
    if (full) {
      rimGroup.appendChild(el("circle", {
        cx: 200, cy: 200, r: 158, fill: "none",
        stroke: "#5b21b6", "stroke-width": 1, "stroke-opacity": ".7"
      }));
      /* 48 teeth around the rim — the serrated edge of the discus. */
      for (var t = 0; t < 48; t++) {
        var a = (t / 48) * TAU;
        var p1 = point(158, a);
        var p2 = point(t % 4 === 0 ? 176 : 168, a);
        rimGroup.appendChild(el("line", {
          x1: p1[0].toFixed(1), y1: p1[1].toFixed(1),
          x2: p2[0].toFixed(1), y2: p2[1].toFixed(1),
          stroke: t % 4 === 0 ? "#fbbf24" : "#a855f7",
          "stroke-width": t % 4 === 0 ? 2 : 1,
          "stroke-opacity": t % 4 === 0 ? ".9" : ".5"
        }));
      }
    }
    svg.appendChild(rimGroup);

    /* ── Ring 2: the blades ── */
    var bladeCount = full ? 12 : 8;
    var bladeGroup = group("blades");
    for (var b = 0; b < bladeCount; b++) {
      bladeGroup.appendChild(el("path", {
        d: bladePath(b, bladeCount, 74, 152, 0.42),
        fill: "url(#cvBlade)",
        stroke: "#a855f7",
        "stroke-width": full ? 1 : 2,
        "stroke-opacity": ".55"
      }));
    }
    svg.appendChild(bladeGroup);

    /* ── Ring 3: mid ring with lotus petals ── */
    var midGroup = group("mid");
    midGroup.appendChild(el("circle", {
      cx: 200, cy: 200, r: 96, fill: "none",
      stroke: "#7c3aed", "stroke-width": full ? 1.6 : 6, "stroke-opacity": ".85"
    }));
    if (full) {
      for (var m = 0; m < 24; m++) {
        var pm = point(96, (m / 24) * TAU);
        midGroup.appendChild(el("circle", {
          cx: pm[0].toFixed(1), cy: pm[1].toFixed(1),
          r: m % 2 === 0 ? 3.2 : 1.6,
          fill: m % 2 === 0 ? "#c084fc" : "#fbbf24",
          "fill-opacity": m % 2 === 0 ? ".9" : ".65"
        }));
      }
    }
    svg.appendChild(midGroup);

    /* ── Ring 4: inner spokes ── */
    var innerGroup = group("inner");
    innerGroup.appendChild(el("circle", {
      cx: 200, cy: 200, r: 58, fill: "none",
      stroke: "#c084fc", "stroke-width": full ? 1.3 : 5, "stroke-opacity": ".8"
    }));
    var spokes = full ? 16 : 6;
    for (var s = 0; s < spokes; s++) {
      var ang = (s / spokes) * TAU;
      var i1 = point(26, ang);
      var i2 = point(58, ang);
      innerGroup.appendChild(el("line", {
        x1: i1[0].toFixed(1), y1: i1[1].toFixed(1),
        x2: i2[0].toFixed(1), y2: i2[1].toFixed(1),
        stroke: s % 2 === 0 ? "#fbbf24" : "#a855f7",
        "stroke-width": full ? 1.8 : 3.5,
        "stroke-opacity": ".85"
      }));
    }
    svg.appendChild(innerGroup);

    /* ── Hub ── */
    var hubGroup = group(null);
    hubGroup.setAttribute("data-pulse", "");
    hubGroup.appendChild(el("circle", {
      cx: 200, cy: 200, r: full ? 22 : 26, fill: "url(#cvHub)"
    }));
    if (full) {
      hubGroup.appendChild(el("circle", {
        cx: 200, cy: 200, r: 11, fill: "none",
        stroke: "#7c3aed", "stroke-width": 1.6, "stroke-opacity": ".75"
      }));
    }
    svg.appendChild(hubGroup);

    /* ── Ring 5: orbiting sparks ── */
    if (full) {
      var sparkGroup = group("sparks");
      for (var k = 0; k < 8; k++) {
        var ps = point(188, (k / 8) * TAU + 0.2);
        var spark = el("text", {
          x: ps[0].toFixed(1), y: ps[1].toFixed(1),
          "text-anchor": "middle", "dominant-baseline": "central",
          fill: k % 2 === 0 ? "#fbbf24" : "#c084fc",
          "font-size": k % 2 === 0 ? 15 : 11
        });
        spark.setAttribute("data-flicker", "");
        spark.style.animationDelay = (k * 0.32).toFixed(2) + "s";
        spark.textContent = "✦";
        sparkGroup.appendChild(spark);
      }
      svg.appendChild(sparkGroup);
    }

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
