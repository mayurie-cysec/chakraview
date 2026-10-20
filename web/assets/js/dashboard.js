/* ==========================================================================
   Dashboard client.

   Posts a scan config, then consumes a server-sent-event stream of progress
   and renders it. Every value from the server reaches the DOM through
   textContent and nodes built by hand, never through innerHTML: scan output
   is attacker-influenced (page titles, service banners, hostnames supplied by
   third-party sources) and must not be able to inject markup into this page.
   ========================================================================== */

(function () {
  "use strict";

  var SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var PASSIVE_SET = ["github", "infra", "dns", "archive", "dorks"];
  var FAST_SET = ["infra", "dns", "subs", "http", "takeover"];

  var chakras = [];
  var state = { id: null, source: null, running: false, summary: null, filter: "all" };

  var $ = function (id) { return document.getElementById(id); };

  function show(node, visible) { node.hidden = !visible; }

  function message(text, kind) {
    var box = $("msg");
    box.textContent = "";
    if (!text) { box.classList.remove("on"); return; }
    var strong = document.createElement("strong");
    strong.textContent = kind === "error" ? "Could not start. " : "Note. ";
    box.appendChild(strong);
    box.appendChild(document.createTextNode(text));
    box.classList.add("on");
    box.classList.toggle("danger", kind === "error");
  }

  /* ── Setup ──────────────────────────────────────────────────────────── */

  function loadChakras() {
    return fetch("/api/chakras")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        chakras = data.chakras || [];
        renderPicks();
        renderRunList();
      })
      .catch(function () {
        message("Could not reach the ChakraView server. Is it still running?", "error");
      });
  }

  function renderPicks() {
    var host = $("chakra-picks");
    host.textContent = "";
    chakras.forEach(function (chakra) {
      var label = document.createElement("label");
      label.className = "check";
      var box = document.createElement("input");
      box.type = "checkbox";
      box.name = "chakra";
      box.value = chakra.key;
      box.checked = true;
      label.appendChild(box);
      label.appendChild(document.createTextNode(
        chakra.name.charAt(0) + chakra.name.slice(1).toLowerCase()
      ));
      var tag = document.createElement("em");
      tag.style.cssText = "color:var(--faint);font-size:11px;margin-left:5px";
      tag.textContent = chakra.key;
      label.appendChild(tag);
      label.title = chakra.sub;
      host.appendChild(label);
    });
  }

  function renderRunList() {
    var list = $("runlist");
    list.textContent = "";
    chakras.forEach(function (chakra) {
      var row = document.createElement("li");
      row.className = "runrow";
      row.id = "row-" + chakra.key;
      row.dataset.state = "idle";

      var dot = document.createElement("span");
      dot.className = "dot";

      var who = document.createElement("span");
      who.className = "who";
      who.textContent = chakra.num + ". " + chakra.name;
      var tag = document.createElement("em");
      tag.textContent = chakra.key;
      who.appendChild(tag);

      var pct = document.createElement("span");
      pct.className = "pct";
      pct.textContent = "—";

      var task = document.createElement("span");
      task.className = "task";
      task.textContent = "waiting";

      var meter = document.createElement("span");
      meter.className = "meter";
      var fill = document.createElement("i");
      fill.style.width = "0%";
      meter.appendChild(fill);

      row.appendChild(dot);
      row.appendChild(who);
      row.appendChild(pct);
      row.appendChild(task);
      row.appendChild(meter);
      list.appendChild(row);
    });
  }

  function picked() {
    var boxes = document.querySelectorAll('input[name="chakra"]');
    var keys = [];
    for (var i = 0; i < boxes.length; i++) {
      if (boxes[i].checked) keys.push(boxes[i].value);
    }
    return keys;
  }

  function setPicks(keys) {
    var boxes = document.querySelectorAll('input[name="chakra"]');
    for (var i = 0; i < boxes.length; i++) {
      boxes[i].checked = keys.indexOf(boxes[i].value) !== -1;
    }
  }

  function formats() {
    var boxes = document.querySelectorAll('input[name="fmt"]');
    var out = [];
    for (var i = 0; i < boxes.length; i++) {
      if (boxes[i].checked) out.push(boxes[i].value);
    }
    return out;
  }

  /* ── Feed ───────────────────────────────────────────────────────────── */

  var feedCount = 0;

  function feed(source, text, kind) {
    var list = $("feed");
    if (feedCount === 0) list.textContent = "";
    feedCount++;

    var item = document.createElement("li");
    if (kind) item.className = kind;
    var src = document.createElement("span");
    src.className = "src";
    src.textContent = source;
    var msg = document.createElement("span");
    msg.className = "msg";
    msg.textContent = text;
    item.appendChild(src);
    item.appendChild(msg);
    list.appendChild(item);

    /* Keep the DOM bounded — a deep scan emits thousands of lines. */
    while (list.children.length > 300) list.removeChild(list.firstChild);
    list.scrollTop = list.scrollHeight;
  }

  /* ── Event handling ─────────────────────────────────────────────────── */

  function row(key) { return $("row-" + key); }

  function handle(payload) {
    var key = payload.key;

    switch (payload.event) {
      case "start":
        $("run-title").textContent = "Formation running against " + payload.target;
        (payload.chakras || []).forEach(function (k) {
          var r = row(k);
          if (r) r.dataset.state = "queued";
        });
        break;

      case "chakra_start":
        if (row(key)) {
          row(key).dataset.state = "running";
          row(key).querySelector(".task").textContent = "starting";
        }
        break;

      case "task":
        if (row(key)) {
          row(key).querySelector(".task").textContent = payload.label;
          row(key).querySelector(".pct").textContent = payload.total
            ? "0 / " + payload.total : "…";
          row(key).querySelector(".meter i").style.width = "0%";
        }
        break;

      case "advance":
        if (row(key) && payload.total) {
          var ratio = Math.min(100, (payload.done / payload.total) * 100);
          row(key).querySelector(".meter i").style.width = ratio.toFixed(1) + "%";
          row(key).querySelector(".pct").textContent =
            payload.done + " / " + payload.total;
        }
        break;

      case "hit":
        feed(key, payload.text);
        break;

      case "note":
        feed(key, payload.text, "note");
        break;

      case "finding":
        feed((payload.chakra || "").toLowerCase(),
             payload.severity + " · " + payload.title, "find");
        break;

      case "chakra_done":
        /* The module's own summary — the line worth keeping on screen. */
        if (row(key) && row(key).dataset.state !== "skipped" && payload.summary) {
          row(key).querySelector(".task").textContent = payload.summary;
        }
        break;

      case "chakra_elapsed":
        /* The engine's timing. Completes the row without replacing the
           summary the module already reported. */
        if (row(key) && row(key).dataset.state !== "skipped") {
          row(key).dataset.state = "done";
          row(key).querySelector(".meter i").style.width = "100%";
          row(key).querySelector(".pct").textContent = payload.seconds + "s";
        }
        break;

      case "chakra_skip":
        if (row(key)) {
          row(key).dataset.state = "skipped";
          row(key).querySelector(".task").textContent = "skipped — " + payload.reason;
          row(key).querySelector(".pct").textContent = "—";
        }
        break;

      case "done":
        state.summary = payload.summary;
        renderResults(payload.summary, payload.reports || {});
        finish(payload.state === "cancelled"
          ? "Scan stopped. Partial results below."
          : null);
        break;

      case "error":
        message(payload.message, "error");
        finish(null);
        break;

      case "close":
        finish(null);
        break;
    }
  }

  /* ── Results ────────────────────────────────────────────────────────── */

  function tile(key, value) {
    var box = document.createElement("div");
    box.className = "tile";
    var k = document.createElement("div");
    k.className = "k";
    k.textContent = key;
    var v = document.createElement("div");
    v.className = "v";
    v.textContent = value;
    box.appendChild(k);
    box.appendChild(v);
    return box;
  }

  function renderResults(summary, reports) {
    show($("pane-results"), true);

    var riskClass = {
      CRITICAL: "critical", HIGH: "high", MEDIUM: "medium",
      LOW: "low", CLEAN: "info"
    }[summary.risk_label] || "info";

    $("risk-label").textContent = summary.risk_label;
    $("risk-label").style.color = "var(--sev-" + riskClass + ")";
    $("risk-score").textContent = summary.risk_score + " / 100";
    $("risk-time").textContent = summary.duration + "s";
    $("risk-meter").style.width = summary.risk_score + "%";

    var sevline = $("sevline");
    sevline.textContent = "";
    SEVERITIES.forEach(function (name) {
      var count = (summary.severity_counts || {})[name] || 0;
      if (!count) return;
      var badge = document.createElement("span");
      badge.className = "sev " + name.toLowerCase();
      badge.textContent = count + " " + name;
      sevline.appendChild(badge);
    });

    var tiles = $("tiles");
    tiles.textContent = "";
    var counts = summary.counts || {};
    tiles.appendChild(tile("Findings", counts.findings || 0));
    tiles.appendChild(tile("Subdomains", counts.subdomains || 0));
    tiles.appendChild(tile("Resolving", counts.resolved || 0));
    tiles.appendChild(tile("Live hosts", counts.alive || 0));
    tiles.appendChild(tile("Open ports", counts.open_ports || 0));
    tiles.appendChild(tile("Takeover", counts.takeover || 0));
    tiles.appendChild(tile("JS secrets", counts.secrets || 0));
    tiles.appendChild(tile("Endpoints", counts.endpoints || 0));

    renderFilters(summary);
    renderFindings(summary.findings || []);
    renderHosts(summary.hosts || []);
    renderTakeover(summary.takeover || []);
    renderRunDetail(summary);
    renderDownloads(reports);
  }

  function renderFilters(summary) {
    var host = $("sev-filters");
    host.textContent = "";
    var counts = summary.severity_counts || {};

    function button(level, label) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.dataset.level = level;
      btn.textContent = label;
      btn.setAttribute("aria-pressed", String(state.filter === level));
      btn.addEventListener("click", function () {
        state.filter = level;
        renderFindings(summary.findings || []);
        renderFilters(summary);
      });
      return btn;
    }

    host.appendChild(button("all", "All (" + (summary.findings || []).length + ")"));
    SEVERITIES.forEach(function (name) {
      if (counts[name]) {
        host.appendChild(button(
          name.toLowerCase(),
          name.charAt(0) + name.slice(1).toLowerCase() + " (" + counts[name] + ")"
        ));
      }
    });
  }

  function renderFindings(findings) {
    var host = $("findings");
    host.textContent = "";

    var shown = findings.filter(function (f) {
      return state.filter === "all" ||
        String(f.severity).toLowerCase() === state.filter;
    });

    if (!shown.length) {
      var none = document.createElement("p");
      none.style.color = "var(--faint)";
      none.textContent = findings.length
        ? "No findings at this severity."
        : "No findings recorded.";
      host.appendChild(none);
      return;
    }

    shown.forEach(function (f) {
      var level = String(f.severity).toLowerCase();
      var card = document.createElement("article");
      card.className = "find " + level;

      var badge = document.createElement("span");
      badge.className = "sev " + level;
      badge.textContent = f.severity;
      card.appendChild(badge);

      var title = document.createElement("h3");
      title.textContent = f.title;
      card.appendChild(title);

      var dl = document.createElement("dl");
      function pair(term, value, cls) {
        if (!value) return;
        var dt = document.createElement("dt");
        dt.textContent = term;
        var dd = document.createElement("dd");
        if (cls) dd.className = cls;
        dd.textContent = value;
        dl.appendChild(dt);
        dl.appendChild(dd);
      }
      pair("Chakra", f.chakra);
      pair("Asset", f.asset);
      pair("Detail", f.detail);
      pair("Evidence", f.evidence, "ev");
      pair("Remediation", f.remediation, "fix");

      if (f.references && f.references.length) {
        var dt = document.createElement("dt");
        dt.textContent = "References";
        var dd = document.createElement("dd");
        f.references.slice(0, 3).forEach(function (ref, index) {
          if (!/^https?:\/\//.test(ref)) return;
          if (index) dd.appendChild(document.createTextNode(" · "));
          var link = document.createElement("a");
          link.href = ref;
          link.target = "_blank";
          link.rel = "noopener noreferrer nofollow";
          link.textContent = ref.replace(/^https?:\/\//, "").slice(0, 60);
          dd.appendChild(link);
        });
        if (dd.childNodes.length) { dl.appendChild(dt); dl.appendChild(dd); }
      }

      card.appendChild(dl);
      host.appendChild(card);
    });
  }

  function table(headers, rows) {
    var wrap = document.createElement("table");
    var thead = document.createElement("thead");
    var hrow = document.createElement("tr");
    headers.forEach(function (name) {
      var th = document.createElement("th");
      th.scope = "col";
      th.textContent = name;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    wrap.appendChild(thead);

    var tbody = document.createElement("tbody");
    rows.forEach(function (cells) {
      var tr = document.createElement("tr");
      cells.forEach(function (cell) {
        var td = document.createElement("td");
        if (cell && cell.nodeType) td.appendChild(cell);
        else td.textContent = cell === null || cell === undefined ? "—" : String(cell);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    wrap.appendChild(tbody);
    return wrap;
  }

  function statusBadge(status) {
    var badge = document.createElement("span");
    if (status === null || status === undefined) {
      badge.className = "sev info";
      badge.textContent = "—";
      return badge;
    }
    var level = "info";
    if (status >= 200 && status < 300) level = "low";
    else if (status === 401 || status === 403) level = "medium";
    else if (status >= 500) level = "high";
    badge.className = "sev " + level;
    badge.textContent = String(status);
    return badge;
  }

  function renderHosts(hosts) {
    var host = $("hosts");
    host.textContent = "";
    if (!hosts.length) {
      host.innerHTML = '<p style="color:var(--faint);padding:16px">' +
        "No subdomains collected.</p>";
      return;
    }
    host.appendChild(table(
      ["Status", "Host", "Address", "Title", "Technology", "Ports", "Sources"],
      hosts.map(function (h) {
        var name;
        if (h.url) {
          name = document.createElement("a");
          name.href = h.url;
          name.target = "_blank";
          name.rel = "noopener noreferrer nofollow";
          name.textContent = h.host;
        } else {
          name = document.createElement("code");
          name.textContent = h.host;
        }
        return [
          statusBadge(h.status),
          name,
          (h.ips || []).join(", ") || "—",
          h.title || "—",
          (h.tech || []).join(", ") || "—",
          (h.ports || []).join(", ") || "—",
          (h.sources || []).join(", ")
        ];
      })
    ));
  }

  function renderTakeover(hits) {
    var host = $("takeover");
    host.textContent = "";
    if (!hits.length) {
      var ok = document.createElement("p");
      ok.style.color = "var(--ok)";
      ok.textContent = "No dangling CNAMEs found.";
      host.appendChild(ok);
      return;
    }
    var wrap = document.createElement("div");
    wrap.className = "scroll";
    wrap.appendChild(table(
      ["Host", "CNAME", "Service", "Confidence", "Signal"],
      hits.map(function (h) {
        var badge = document.createElement("span");
        badge.className = "sev " + (h.confidence === "high" ? "high" : "medium");
        badge.textContent = h.confidence;
        return [h.host, h.cname, h.service, badge, h.signal];
      })
    ));
    host.appendChild(wrap);
  }

  function renderRunDetail(summary) {
    var host = $("rundetail");
    host.textContent = "";

    function block(title, items, style) {
      if (!items || !items.length) return;
      var head = document.createElement("h3");
      head.style.cssText = "font-size:12px;letter-spacing:.12em;" +
        "text-transform:uppercase;color:" + (style || "var(--violet)") +
        ";margin:18px 0 9px";
      head.textContent = title;
      host.appendChild(head);
      var list = document.createElement("ul");
      list.className = "pills";
      items.forEach(function (item) {
        var li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
      });
      host.appendChild(list);
    }

    var techs = Object.keys(summary.technologies || {}).map(function (name) {
      return name + " ×" + summary.technologies[name];
    });
    block("Technologies identified", techs);
    block("Skipped chakras", summary.skipped || []);
    block("Errors", summary.errors || [], "var(--sev-high)");

    if (!host.childNodes.length) {
      var none = document.createElement("p");
      none.style.color = "var(--faint)";
      none.textContent = "Nothing skipped, nothing failed.";
      host.appendChild(none);
    }
  }

  function renderDownloads(reports) {
    var host = $("downloads");
    host.textContent = "";
    var names = Object.keys(reports || {});
    if (!names.length) return;

    var label = document.createElement("span");
    label.style.cssText = "font-size:12px;color:var(--faint);align-self:center";
    label.textContent = "Reports written:";
    host.appendChild(label);

    names.forEach(function (fmt) {
      var link = document.createElement("a");
      link.className = "btn btn-ghost btn-sm";
      link.href = "/api/report/" + encodeURIComponent(reports[fmt]);
      link.textContent = fmt.toUpperCase();
      link.setAttribute("download", reports[fmt]);
      host.appendChild(link);
    });
  }

  /* ── Lifecycle ──────────────────────────────────────────────────────── */

  function finish(note) {
    state.running = false;
    $("btn-start").disabled = false;
    $("btn-start").textContent = "Run scan again";
    show($("btn-stop"), false);
    if (state.source) { state.source.close(); state.source = null; }
    if (note) message(note, "note");
  }

  function start(event) {
    event.preventDefault();
    if (state.running) return;

    var domain = $("domain").value.trim();
    if (!domain) {
      message("Enter a target domain first.", "error");
      $("domain").focus();
      return;
    }
    var keys = picked();
    if (!keys.length) {
      message("Select at least one chakra.", "error");
      return;
    }

    message("", null);
    feedCount = 0;
    state.filter = "all";
    renderRunList();
    show($("pane-idle"), false);
    show($("pane-run"), true);
    show($("pane-results"), false);
    $("feed").innerHTML =
      '<li class="empty"><span class="msg">waiting for the first result…</span></li>';

    $("btn-start").disabled = true;
    $("btn-start").textContent = "Running…";
    show($("btn-stop"), true);
    state.running = true;

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain: domain,
        only: keys.length === chakras.length ? [] : keys,
        passive_only: $("passive").checked,
        deep: $("deep").checked,
        ports: $("ports").value,
        concurrency: parseInt($("concurrency").value, 10) || 50,
        formats: formats()
      })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error(data.error || "Request rejected.");
          return data;
        });
      })
      .then(function (data) {
        state.id = data.id;
        $("run-title").textContent = "Formation running against " + data.target;
        state.source = new EventSource("/api/events/" + data.id);
        state.source.onmessage = function (e) {
          try { handle(JSON.parse(e.data)); } catch (err) { /* ignore a bad frame */ }
        };
        state.source.onerror = function () {
          if (state.running) {
            message("Lost the event stream. The scan may still be running — "
              + "check the terminal.", "error");
          }
          finish(null);
        };
      })
      .catch(function (err) {
        message(err.message || "Could not start the scan.", "error");
        finish(null);
      });
  }

  function stop() {
    if (!state.id) return;
    $("btn-stop").disabled = true;
    $("btn-stop").textContent = "Stopping…";
    fetch("/api/stop/" + state.id, { method: "POST" })
      .catch(function () { /* the done event will arrive regardless */ })
      .then(function () {
        $("btn-stop").disabled = false;
        $("btn-stop").textContent = "Stop";
      });
  }

  function tabs() {
    var buttons = document.querySelectorAll('.tabs [role="tab"]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function (e) {
        var target = e.currentTarget;
        for (var j = 0; j < buttons.length; j++) {
          var selected = buttons[j] === target;
          buttons[j].setAttribute("aria-selected", String(selected));
          $(buttons[j].getAttribute("aria-controls")).hidden = !selected;
        }
      });
    }
  }

  function pickButtons() {
    var buttons = document.querySelectorAll("[data-pick]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function (e) {
        var mode = e.currentTarget.dataset.pick;
        if (mode === "all") {
          setPicks(chakras.map(function (c) { return c.key; }));
        } else if (mode === "none") {
          setPicks([]);
        } else if (mode === "passive") {
          setPicks(PASSIVE_SET);
          $("passive").checked = true;
        } else if (mode === "fast") {
          setPicks(FAST_SET);
          $("passive").checked = false;
        }
      });
    }
  }

  function init() {
    loadChakras();
    $("scan-form").addEventListener("submit", start);
    $("btn-stop").addEventListener("click", stop);
    tabs();
    pickButtons();

    /* Passive mode and the active chakras are mutually exclusive — reflect
       that in the UI instead of letting the server silently drop them. */
    $("passive").addEventListener("change", function () {
      var active = ["subs", "http", "takeover", "ports", "js"];
      var boxes = document.querySelectorAll('input[name="chakra"]');
      for (var i = 0; i < boxes.length; i++) {
        if (active.indexOf(boxes[i].value) !== -1) {
          boxes[i].disabled = $("passive").checked;
          boxes[i].parentElement.style.opacity = $("passive").checked ? ".45" : "1";
        }
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
