/* ==========================================================================
   Sign-in: password, then a time-based code.

   The client here decides nothing. It posts credentials, renders whatever
   the server says, and follows the redirect. Every check that matters —
   whether the password is right, whether the code is valid, whether the
   account is locked — happens on the server, and the only thing that proves
   a successful sign-in is the HttpOnly session cookie the server sets.
   ========================================================================== */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var state = { challenge: null };

  function message(text, kind) {
    var box = $("msg");
    box.textContent = text || "";
    box.className = "msg" + (text ? " on " + (kind || "err") : "");
  }

  function busy(button, on, label) {
    button.disabled = on;
    button.textContent = on ? "Working…" : label;
  }

  function post(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {}; })
        .then(function (data) {
          if (!response.ok) {
            var err = new Error(data.error || "Sign-in failed.");
            err.status = response.status;
            throw err;
          }
          return data;
        });
    });
  }

  function showTotp(enrol) {
    $("form-password").hidden = true;
    $("form-totp").hidden = false;
    if (enrol && enrol.secret) {
      $("enrol").hidden = false;
      $("enrol-secret").textContent = enrol.secret;
      $("totp-sub").textContent =
        "Add the key below to an authenticator app, then enter the code it shows.";
    }
    $("code").focus();
  }

  function done() {
    /* The server decides where we land; this is only a convenience. */
    var next = new URLSearchParams(location.search).get("next");
    var safe = (next && /^\/[A-Za-z0-9._\-\/]*$/.test(next)) ? next : "/dashboard.html";
    location.replace(safe);
  }

  function onPassword(event) {
    event.preventDefault();
    message("");
    var button = $("btn-password");
    busy(button, true, "Continue");
    post("/api/auth/login", {
      username: $("username").value.trim(),
      password: $("password").value
    }).then(function (data) {
      if (data.stage === "totp") {
        state.challenge = data.challenge;
        showTotp(data.enrol);
      } else {
        done();
      }
    }).catch(function (err) {
      message(err.message, "err");
      $("password").value = "";
      $("password").focus();
    }).finally(function () {
      busy(button, false, "Continue");
    });
  }

  function onTotp(event) {
    event.preventDefault();
    message("");
    var code = $("code").value.replace(/\D/g, "");
    if (code.length !== 6) {
      message("Enter the six digits from your authenticator app.", "err");
      return;
    }
    var button = $("btn-totp");
    busy(button, true, "Sign in");
    post("/api/auth/totp", { challenge: state.challenge, code: code })
      .then(done)
      .catch(function (err) {
        message(err.message, "err");
        $("code").value = "";
        $("code").focus();
      })
      .finally(function () { busy(button, false, "Sign in"); });
  }

  function init() {
    $("form-password").addEventListener("submit", onPassword);
    $("form-totp").addEventListener("submit", onTotp);
    /* Only digits in the code box, and submit as soon as six are present. */
    $("code").addEventListener("input", function (e) {
      var cleaned = e.target.value.replace(/\D/g, "").slice(0, 6);
      e.target.value = cleaned;
      if (cleaned.length === 6) $("form-totp").requestSubmit();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else { init(); }
})();
