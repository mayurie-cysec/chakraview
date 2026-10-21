/* ==========================================================================
   Scan history.

   Everything on this page comes from the server, scoped to the signed-in
   account in SQL. A scan id is a random token, but ownership is still
   checked on every read, so knowing one is not enough to see it.

   Running scans are polled rather than streamed: this page only needs to
   know that a scan is alive and roughly how far along it is. The dashboard
   is where the live event stream belongs.
   ========================================================================== */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var PAGE = 25;
  var state = { status: "", offset: 0, total: 0, timer: null };

  var FILTERS = [
    ["", "All"],
    ["active", "Running"],
    ["completed", "Completed"],
    ["failed", "Failed"],
    ["cancelled", "Stopped"],
    ["interrupted", "Interrupted"]
  ];

  function message(text) {
    var box = $("msg");
    box.textContent = text || "";
    box.style.display = text ? "block" : "none";
  }

  function renderFilters() {
    var host = $("filters");
    host.textContent = "";
    FILTERS.forEach(function (pair) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = pair[1];
      btn.setAttribute("aria-pressed", String(state.status === pair[0]));
      btn.addEventListener("click", function () {
        state.status = pair[0];
        state.offset = 0;
        load();
      });
      host.appendChild(btn);
    });
  }

  function renderLive(active) {
    var box = $("live"), rows = $("live-rows");
    rows.textContent = "";
    if (!active.length) { box.classList.remove("on"); return; }
    box.classList.add("on");

    active.forEach(function (scan) {
      var row = document.createElement("div");
      row.className = "live-row";

      var target = document.createElement("span");
      target.className = "target";
      target.textContent = scan.target;
      row.appendChild(target);

      row.appendChild(CV.statusBadge(scan.status));

      var since = document.createElement("span");
      since.style.color = "var(--faint)";
      since.textContent = "started " + CV.when(scan.started_at || scan.created_at);
      row.appendChild(since);

      var right = document.createElement("span");
      right.className = "right";
      var watch = document.createElement("a");
      watch.className = "btn btn-ghost btn-sm";
      watch.href = "dashboard.html?scan=" + encodeURIComponent(scan.id);
      watch.textContent = "Watch";
      right.appendChild(watch);
      row.appendChild(right);

      rows.appendChild(row);
    });
  }

  function cell(text) {
    var td = document.createElement("td");
    td.textContent = text === null || text === undefined ? "—" : String(text);
    return td;
  }

  function renderTable(scans) {
    var wrap = $("table-wrap");
    wrap.textContent = "";

    if (!scans.length) {
      wrap.className = "";
      var empty = document.createElement("div");
      empty.className = "empty";
      var art = document.createElement("div");
      art.setAttribute("data-chakra", "");
      art.setAttribute("data-size", "120");
      art.setAttribute("data-detail", "mid");
      art.style.margin = "0 auto";
      empty.appendChild(art);
      var p = document.createElement("p");
      p.textContent = state.status
        ? "No scans with this status."
        : "No scans yet. Start one from the dashboard and it will appear here.";
      empty.appendChild(p);
      wrap.appendChild(empty);
      if (window.ChakraMark) window.ChakraMark.mount();
      return;
    }

    wrap.className = "scroll";
    var table = document.createElement("table");
    var thead = document.createElement("thead");
    var hrow = document.createElement("tr");
    ["Target", "Status", "Risk", "Findings", "Started", "Duration", ""]
      .forEach(function (name) {
        var th = document.createElement("th");
        th.scope = "col";
        th.textContent = name;
        hrow.appendChild(th);
      });
    thead.appendChild(hrow);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    scans.forEach(function (scan) {
      var tr = document.createElement("tr");

      var tdTarget = document.createElement("td");
      var name = document.createElement("span");
      name.className = "target";
      name.textContent = scan.target;
      tdTarget.appendChild(name);
      var meta = document.createElement("span");
      meta.className = "meta";
      var chakras = (scan.config && scan.config.chakras) || [];
      meta.textContent = chakras.length + " chakras" +
        (scan.config && scan.config.passive_only ? " · passive only" : "") +
        (scan.config && scan.config.deep ? " · deep" : "");
      tdTarget.appendChild(meta);
      tr.appendChild(tdTarget);

      var tdStatus = document.createElement("td");
      tdStatus.appendChild(CV.statusBadge(scan.status));
      if (scan.error) {
        var err = document.createElement("span");
        err.className = "meta";
        err.textContent = scan.error;
        tdStatus.appendChild(err);
      }
      tr.appendChild(tdStatus);

      var tdRisk = document.createElement("td");
      tdRisk.className = "risk";
      if (scan.risk_label) {
        var badge = document.createElement("span");
        badge.className = "sev " + ({
          CRITICAL: "critical", HIGH: "high", MEDIUM: "medium",
          LOW: "low", CLEAN: "info"
        }[scan.risk_label] || "info");
        badge.textContent = scan.risk_label + " " + (scan.risk_score || 0);
        tdRisk.appendChild(badge);
      } else {
        tdRisk.textContent = "—";
      }
      tr.appendChild(tdRisk);

      tr.appendChild(cell((scan.counts && scan.counts.findings) ?? "—"));
      tr.appendChild(cell(CV.when(scan.started_at || scan.created_at)));
      tr.appendChild(cell(CV.duration(scan.duration)));

      var tdActions = document.createElement("td");
      var open = document.createElement("a");
      open.className = "rowbtn";
      open.href = "dashboard.html?scan=" + encodeURIComponent(scan.id);
      open.textContent = scan.status === "running" ? "Watch" : "Open";
      tdActions.appendChild(open);

      if (scan.status !== "running" && scan.status !== "queued") {
        var del = document.createElement("button");
        del.type = "button";
        del.className = "rowbtn danger";
        del.textContent = "Delete";
        del.addEventListener("click", function () { remove(scan, del); });
        tdActions.appendChild(del);
      }
      tr.appendChild(tdActions);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
  }

  function remove(scan, button) {
    if (!window.confirm("Delete the scan of " + scan.target +
        "? Its stored report entry and event history go with it.")) return;
    button.disabled = true;
    CV.api("/api/scan/" + encodeURIComponent(scan.id), { method: "DELETE" })
      .then(load)
      .catch(function (err) { message(err.message); button.disabled = false; });
  }

  function renderPager() {
    var host = $("pager");
    host.textContent = "";
    if (state.total <= PAGE) return;

    function button(label, delta, enabled) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "rowbtn";
      b.textContent = label;
      b.disabled = !enabled;
      b.addEventListener("click", function () {
        state.offset = Math.max(0, state.offset + delta);
        load();
      });
      return b;
    }
    host.appendChild(button("← Newer", -PAGE, state.offset > 0));
    var label = document.createElement("span");
    label.textContent = (state.offset + 1) + "–" +
      Math.min(state.offset + PAGE, state.total) + " of " + state.total;
    host.appendChild(label);
    host.appendChild(button("Older →", PAGE, state.offset + PAGE < state.total));
  }

  function load() {
    var url = "/api/history?limit=" + PAGE + "&offset=" + state.offset +
      (state.status ? "&status=" + encodeURIComponent(state.status) : "");
    return CV.api(url).then(function (data) {
      state.total = data.total || 0;
      $("subtitle").textContent = state.total === 0
        ? "Nothing scanned from this account yet."
        : state.total + " scan" + (state.total === 1 ? "" : "s") +
          " recorded. Scans run on the server, so closing this page does not stop one.";
      renderFilters();
      renderLive(data.active || []);
      renderTable(data.scans || []);
      renderPager();
      message("");

      /* Poll only while something is actually running. */
      clearTimeout(state.timer);
      if ((data.active || []).length) {
        state.timer = setTimeout(load, 4000);
      }
    }).catch(function (err) {
      if (err.message !== "Not signed in.") message(err.message);
    });
  }

  CV.load().then(load).catch(function () { /* redirected to login */ });
})();
