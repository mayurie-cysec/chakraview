/* ==========================================================================
   Shared session plumbing for the signed-in pages.

   Exposes window.CV with an api() wrapper that attaches the CSRF token to
   every state-changing request and sends the browser to the login page on a
   401. The token is held in memory only — never in localStorage, where any
   injected script on this origin could read it.

   Nothing here is a security control. The server re-checks the session and
   the CSRF token on every request; this just avoids pointless round trips
   and keeps the UI honest about who is signed in.
   ========================================================================== */

(function () {
  "use strict";

  var csrf = null;
  var user = null;

  function toLogin() {
    var next = encodeURIComponent(location.pathname);
    location.replace("/login.html?next=" + next);
  }

  function api(url, options) {
    options = options || {};
    var method = (options.method || "GET").toUpperCase();
    var headers = Object.assign({}, options.headers || {});
    if (method !== "GET" && method !== "HEAD") {
      headers["Content-Type"] = "application/json";
      if (csrf) headers["X-CSRF-Token"] = csrf;
    }
    return fetch(url, {
      method: method,
      headers: headers,
      credentials: "same-origin",
      body: options.body ? JSON.stringify(options.body) : undefined
    }).then(function (response) {
      if (response.status === 401) { toLogin(); throw new Error("Not signed in."); }
      return response.json().catch(function () { return {}; })
        .then(function (data) {
          if (!response.ok) {
            var err = new Error(data.error || ("Request failed (" + response.status + ")"));
            err.status = response.status;
            throw err;
          }
          return data;
        });
    });
  }

  function load() {
    return fetch("/api/auth/status", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.authenticated) { toLogin(); throw new Error("Not signed in."); }
        csrf = data.csrf;
        user = data.user;
        paintUser();
        return data;
      });
  }

  function paintUser() {
    var host = document.querySelector("[data-user-chip]");
    if (!host || !user) return;
    host.textContent = "";

    var name = document.createElement("span");
    name.className = "chip";
    name.textContent = user.username + (user.is_admin ? " · admin" : "");
    host.appendChild(name);

    var out = document.createElement("button");
    out.type = "button";
    out.className = "btn btn-ghost btn-sm";
    out.textContent = "Sign out";
    out.addEventListener("click", function () {
      api("/api/auth/logout", { method: "POST" })
        .catch(function () {})
        .then(function () { location.replace("/login.html"); });
    });
    host.appendChild(out);
  }

  /* Status vocabulary, shared by the dashboard and the history page so one
     scan never shows two different words for the same state. */
  var STATUS = {
    queued:      { label: "Pending",     tone: "info"     },
    running:     { label: "Running",     tone: "medium"   },
    completed:   { label: "Completed",   tone: "low"      },
    failed:      { label: "Failed",      tone: "critical" },
    cancelled:   { label: "Stopped",     tone: "info"     },
    interrupted: { label: "Interrupted", tone: "high"     }
  };

  function statusBadge(status) {
    var meta = STATUS[status] || { label: status || "Unknown", tone: "info" };
    var el = document.createElement("span");
    el.className = "sev " + meta.tone;
    el.textContent = meta.label;
    return el;
  }

  function when(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    var today = new Date();
    var sameDay = d.toDateString() === today.toDateString();
    return sameDay
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : d.toLocaleDateString([], { day: "2-digit", month: "short" }) + " " +
        d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function duration(seconds) {
    if (seconds === null || seconds === undefined) return "—";
    if (seconds < 60) return seconds.toFixed(0) + "s";
    var m = Math.floor(seconds / 60), s = Math.round(seconds % 60);
    return m + "m " + (s < 10 ? "0" : "") + s + "s";
  }

  window.CV = {
    api: api,
    load: load,
    statusBadge: statusBadge,
    STATUS: STATUS,
    when: when,
    duration: duration,
    get user() { return user; },
    get csrf() { return csrf; }
  };
})();
