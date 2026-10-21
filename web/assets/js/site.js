/* ==========================================================================
   Shared page behaviour: the copyright year, scroll reveals, and nav state.
   Everything here degrades to a fully usable page if the script never runs.
   ========================================================================== */

(function () {
  "use strict";

  /* ── Copyright year ──
     Written at render time so the footer never shows a stale year. The markup
     ships with the current year as a fallback for a no-script visitor. */
  function stampYear() {
    var nodes = document.querySelectorAll("[data-year]");
    var year = String(new Date().getFullYear());
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = year;
  }

  /* ── Scroll reveals ──
     Opt-in via .reveal. Without IntersectionObserver, or with reduced motion
     requested, everything is shown immediately rather than hidden forever. */
  function revealOnScroll() {
    var items = document.querySelectorAll(".reveal");
    if (!items.length) return;

    var reduced = window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduced || !("IntersectionObserver" in window)) {
      for (var i = 0; i < items.length; i++) items[i].classList.add("in");
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("in");
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -10% 0px", threshold: 0.08 });

    /* Stagger siblings slightly so a grid animates as a wave, not a block. */
    for (var j = 0; j < items.length; j++) {
      items[j].style.transitionDelay = ((j % 6) * 55) + "ms";
      observer.observe(items[j]);
    }
  }

  /* ── Nav state ──
     Marks the link matching the current file so screen readers and sighted
     users both get the "you are here" signal. */
  function markCurrentPage() {
    var here = (location.pathname.split("/").pop() || "index.html").toLowerCase();
    var links = document.querySelectorAll(".nav-links a[href]");
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute("href");
      if (!href || href.charAt(0) === "#" || href.indexOf("//") !== -1) continue;
      if (href.toLowerCase() === here) links[i].setAttribute("aria-current", "page");
    }
  }

  function init() {
    stampYear();
    revealOnScroll();
    markCurrentPage();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
