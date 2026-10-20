"""Report writers — txt, json, md and a self-contained html page.

Everything written here goes through modules.shuddhi first. A report is the
artefact that gets forwarded to other people, so untrusted strings collected
from a target must not be able to inject markup into it or escape sequences
into whatever terminal cats it.
"""

from __future__ import annotations

import json
import os
import time

from core.context import CHAKRA_BY_KEY
from core.models import ScanResult, Severity
from modules import shuddhi

FORMATS = ("txt", "json", "md", "html")

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def write_all(result: ScanResult, out_dir: str, formats: list[str]) -> dict[str, str]:
    """Write each requested format and return {format: path}."""
    requested = list(FORMATS) if "all" in formats else [f for f in formats if f in FORMATS]
    if not requested:
        return {}

    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(result.started_at))
    base = f"chakraview_{shuddhi.sanitize_filename(result.target)}_{stamp}"

    writers = {"txt": _write_txt, "json": _write_json, "md": _write_md, "html": _write_html}
    paths: dict[str, str] = {}
    for fmt in requested:
        path = os.path.join(out_dir, f"{base}.{fmt}")
        writers[fmt](result, path)
        paths[fmt] = path
    return paths


# ── JSON ──────────────────────────────────────────────────────────────────

def _write_json(result: ScanResult, path: str) -> None:
    payload = shuddhi.sanitize_tree(result.to_dict(), max_len=4000)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)


# ── Plain text ────────────────────────────────────────────────────────────

def _rule(char: str = "=", width: int = 78) -> str:
    return char * width


def _write_txt(result: ScanResult, path: str) -> None:
    clean = shuddhi.sanitize
    lines: list[str] = []
    add = lines.append

    add(_rule())
    add(f"CHAKRAVIEW RECONNAISSANCE REPORT")
    add(_rule())
    add(f"Target        : {clean(result.target)}")
    add(f"Scan start    : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.started_at))}")
    add(f"Duration      : {result.duration:.1f}s")
    add(f"Risk          : {result.risk_label} ({result.risk_score}/100)")
    counts = result.severity_counts()
    add("Findings      : " + ", ".join(f"{counts[s]} {s}" for s in SEV_ORDER if counts[s]))
    add(f"Chakras run   : {', '.join(result.args.get('chakras', []))}")
    if result.skipped:
        add(f"Skipped       : {', '.join(clean(s) for s in result.skipped)}")
    add("")
    add("This report is reconnaissance output. Every item requires manual")
    add("confirmation against the live target before it is reported as a")
    add("vulnerability.")
    add("")

    # ── Findings ──
    add(_rule())
    add("FINDINGS")
    add(_rule())
    findings = result.findings_sorted()
    if not findings:
        add("None recorded.")
    for index, finding in enumerate(findings, 1):
        add("")
        add(f"[{index:03d}] {finding.severity.label} — {clean(finding.title)}")
        add(f"      Chakra      : {clean(finding.chakra)}")
        add(f"      Asset       : {clean(finding.asset)}")
        if finding.detail:
            add(f"      Detail      : {clean(finding.detail, max_len=2000)}")
        if finding.evidence:
            add(f"      Evidence    : {clean(finding.evidence, max_len=1000)}")
        if finding.remediation:
            add(f"      Remediation : {clean(finding.remediation, max_len=1000)}")
        for reference in finding.references[:4]:
            add(f"      Reference   : {clean(reference)}")

    # ── Infrastructure ──
    add("")
    add(_rule())
    add("INFRASTRUCTURE")
    add(_rule())
    infra = result.infra or {}
    for record in infra.get("addresses", []) or []:
        add(f"  {record.get('ip','')}  {clean(record.get('org',''))}")
        if record.get("reverse_dns"):
            add(f"      PTR     : {clean(record['reverse_dns'])}")
        if record.get("cdn"):
            add(f"      CDN/WAF : {clean(record['cdn'])}")
        if record.get("cloud"):
            add(f"      Cloud   : {clean(record['cloud'])}")
    if infra.get("technologies"):
        add("  Technologies: " + ", ".join(
            f"{clean(k)} ({v})" for k, v in infra["technologies"].items()
        ))

    # ── DNS ──
    add("")
    add(_rule())
    add("DNS")
    add(_rule())
    for rtype, values in (result.dns.get("records") or {}).items():
        for value in values:
            add(f"  {rtype:<6} {clean(value, max_len=400)}")
    if result.dns.get("spf"):
        add(f"  SPF    all={result.dns['spf'].get('all','none')} "
            f"lookups={result.dns['spf'].get('lookups',0)}")
    if result.dns.get("dmarc"):
        add(f"  DMARC  p={result.dns['dmarc'].get('policy','none')}")
    if result.dns.get("dkim_selectors"):
        add(f"  DKIM   selectors: {', '.join(result.dns['dkim_selectors'])}")
    for ns, names in (result.dns.get("axfr") or {}).items():
        add(f"  AXFR OPEN on {clean(ns)} — {len(names)} records")

    # ── Hosts ──
    add("")
    add(_rule())
    add(f"SUBDOMAINS — {len(result.subdomains)} collected, "
        f"{len(result.hosts_resolved())} resolving, {len(result.hosts_alive())} responding")
    add(_rule())
    for entry in sorted(result.subdomains.values(), key=lambda e: e.host):
        bits = [f"  {clean(entry.host):<52}"]
        bits.append(f"{str(entry.status or '-'):>4}")
        bits.append(f"{','.join(entry.ips[:2]):<32}")
        if entry.cname:
            bits.append(f"CNAME={clean(entry.cname)}")
        if entry.tech:
            bits.append(f"[{', '.join(entry.tech[:4])}]")
        if entry.ports:
            bits.append(f"ports={','.join(str(p) for p in entry.ports)}")
        if entry.title:
            bits.append(f'"{clean(entry.title, max_len=70)}"')
        add(" ".join(bits))
        add(f"      sources: {', '.join(sorted(entry.sources))}")

    # ── Takeover ──
    if result.takeover:
        add("")
        add(_rule())
        add("SUBDOMAIN TAKEOVER CANDIDATES")
        add(_rule())
        for hit in result.takeover:
            add(f"  {clean(hit['host'])}")
            add(f"      CNAME   : {clean(hit['cname'])}")
            add(f"      Service : {clean(hit['service'])}")
            add(f"      Signal  : {clean(hit['signal'])}")

    # ── Secrets ──
    if result.secrets:
        add("")
        add(_rule())
        add("SECRETS IN CLIENT-SIDE JAVASCRIPT")
        add(_rule())
        for secret in result.secrets:
            add(f"  [{secret['severity']}] {clean(secret['type'])}")
            add(f"      Source  : {clean(secret['source'], max_len=300)}")
            add(f"      Value   : {clean(secret['match'])}  (redacted)")

    # ── Endpoints ──
    if result.endpoints:
        add("")
        add(_rule())
        add(f"API ENDPOINTS RECOVERED — {len(result.endpoints)}")
        add(_rule())
        for endpoint in result.endpoints:
            add(f"  {clean(endpoint, max_len=300)}")

    # ── Archive ──
    archive = result.archive or {}
    if archive.get("found"):
        add("")
        add(_rule())
        add("ARCHIVE")
        add(_rule())
        add(f"  {archive.get('total', 0)} archived URLs indexed")
        for item in archive.get("sensitive", [])[:60]:
            add(f"  [{item['severity']}] {clean(item['url'], max_len=300)}")
        if archive.get("interesting_parameters"):
            add("")
            add("  Parameters mapping to known vulnerability classes:")
            for name, info in sorted(archive["interesting_parameters"].items()):
                add(f"    {clean(name):<22} {clean(info['reason']):<36} "
                    f"({info['count']} URLs)")

    # ── Dorks ──
    dorks = (result.dorks or {}).get("queries") or []
    if dorks:
        add("")
        add(_rule())
        add(f"DORK ARSENAL — {len(dorks)} queries")
        add(_rule())
        current_group = ""
        for dork in dorks:
            if dork["group"] != current_group:
                current_group = dork["group"]
                add("")
                add(f"  {current_group}")
            add(f"    {dork['query']}")

    if result.errors:
        add("")
        add(_rule())
        add("ERRORS")
        add(_rule())
        for error in result.errors:
            add(f"  {clean(error)}")

    add("")
    add(_rule())
    add("Generated by ChakraView — authorised reconnaissance only.")
    add(_rule())

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# ── Markdown ──────────────────────────────────────────────────────────────

def _write_md(result: ScanResult, path: str) -> None:
    esc = shuddhi.escape_markdown
    clean = shuddhi.sanitize
    lines: list[str] = []
    add = lines.append

    counts = result.severity_counts()
    add(f"# ChakraView report — `{clean(result.target)}`")
    add("")
    add(f"**Risk:** {result.risk_label} ({result.risk_score}/100) · "
        f"**Duration:** {result.duration:.1f}s · "
        f"**Scanned:** {time.strftime('%Y-%m-%d %H:%M', time.localtime(result.started_at))}")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity in SEV_ORDER:
        add(f"| {severity} | {counts[severity]} |")
    add("")
    add("> Reconnaissance output. Confirm every item against the live target "
        "before reporting it as a vulnerability.")
    add("")

    add("## Findings")
    add("")
    findings = result.findings_sorted()
    if not findings:
        add("_None recorded._")
    for finding in findings:
        add(f"### `{finding.severity.label}` {esc(finding.title)}")
        add("")
        add(f"- **Chakra:** {esc(finding.chakra)}")
        add(f"- **Asset:** `{esc(finding.asset)}`")
        if finding.detail:
            add(f"- **Detail:** {esc(finding.detail, max_len=2000)}")
        if finding.evidence:
            add(f"- **Evidence:** `{esc(finding.evidence, max_len=600)}`")
        if finding.remediation:
            add(f"- **Remediation:** {esc(finding.remediation, max_len=600)}")
        for reference in finding.references[:4]:
            add(f"- **Reference:** {esc(reference)}")
        add("")

    alive = sorted(result.hosts_alive(), key=lambda e: (e.status or 999, e.host))
    if alive:
        add("## Live hosts")
        add("")
        add("| Status | Host | Title | Technology | Ports |")
        add("|---|---|---|---|---|")
        for entry in alive:
            add(f"| {entry.status or '-'} | `{esc(entry.host)}` | "
                f"{esc(entry.title, max_len=80)} | {esc(', '.join(entry.tech[:5]))} | "
                f"{esc(', '.join(str(p) for p in entry.ports))} |")
        add("")

    if result.takeover:
        add("## Subdomain takeover candidates")
        add("")
        add("| Host | CNAME | Service | Signal |")
        add("|---|---|---|---|")
        for hit in result.takeover:
            add(f"| `{esc(hit['host'])}` | `{esc(hit['cname'])}` | "
                f"{esc(hit['service'])} | {esc(hit['signal'])} |")
        add("")

    if result.secrets:
        add("## Secrets in client-side JavaScript")
        add("")
        add("| Severity | Type | Source | Value (redacted) |")
        add("|---|---|---|---|")
        for secret in result.secrets:
            add(f"| {secret['severity']} | {esc(secret['type'])} | "
                f"{esc(secret['source'], max_len=140)} | `{esc(secret['match'])}` |")
        add("")

    if result.endpoints:
        add("## API endpoints recovered")
        add("")
        for endpoint in result.endpoints[:300]:
            add(f"- `{esc(endpoint)}`")
        add("")

    dorks = (result.dorks or {}).get("queries") or []
    if dorks:
        add("## Dork arsenal")
        add("")
        current_group = ""
        for dork in dorks:
            if dork["group"] != current_group:
                current_group = dork["group"]
                add(f"### {esc(current_group)}")
                add("")
            google = dork["urls"].get("Google", "")
            add(f"- [`{esc(dork['query'])}`]({google})")
        add("")

    add("---")
    add("")
    add("Generated by [ChakraView](https://github.com/mayurie-cysec/chakraview) "
        "— authorised reconnaissance only.")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# ── HTML ──────────────────────────────────────────────────────────────────
# Self-contained: one file, no external requests, so a report stays readable
# after it is emailed, archived or opened offline. The palette mirrors
# core/theme.py and web/assets/css/chakraview.css.

_FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Ccircle cx='16' cy='16' r='14' fill='none' stroke='%23a855f7' stroke-width='2'/%3E"
    "%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%23c084fc' stroke-width='1.5'/%3E"
    "%3Ccircle cx='16' cy='16' r='2.5' fill='%23fbbf24'/%3E"
    "%3Cg stroke='%23a855f7' stroke-width='1.5'%3E"
    "%3Cpath d='M16 2v6M16 24v6M2 16h6M24 16h6'/%3E"
    "%3Cpath d='M6.1 6.1l4.3 4.3M21.6 21.6l4.3 4.3M25.9 6.1l-4.3 4.3M10.4 21.6l-4.3 4.3'/%3E"
    "%3C/g%3E%3C/svg%3E"
)

_HTML_CSS = """
:root{
  --void:#09060f; --abyss:#0b0713; --surface:#130c1f; --border:#2a1b3d;
  --purple-deep:#5b21b6; --purple:#7c3aed; --violet:#a855f7; --lilac:#c084fc;
  --orb:#9333ea; --gold:#fbbf24; --saffron:#f59e0b;
  --text:#ede9fe; --muted:#9f8fc0; --faint:#6b5b8a;
  --sev-critical:#ff3366; --sev-high:#ff7a45; --sev-medium:#fbbf24;
  --sev-low:#38bdf8; --sev-info:#8b7cb8; --ok:#34d399;
  --radius:14px; --maxw:1180px;
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--void); color:var(--text);
  font:15px/1.65 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  /* Dot grid over two fixed radial orbs — the ground the whole UI sits on. */
  background-image:
    radial-gradient(circle at 18% 8%, rgba(147,51,234,.20), transparent 46%),
    radial-gradient(circle at 86% 72%, rgba(124,58,237,.16), transparent 50%),
    radial-gradient(rgba(168,85,247,.085) 1px, transparent 1px);
  background-size:auto,auto,22px 22px;
  background-attachment:fixed,fixed,fixed;
  overflow-x:hidden;            /* no horizontal scroll, ever */
}
.wrap{max-width:var(--maxw); margin:0 auto; padding:0 20px}
a{color:var(--lilac); text-decoration:none; border-bottom:1px solid rgba(192,132,252,.3)}
a:hover{color:var(--gold); border-bottom-color:var(--gold)}
a:focus-visible,button:focus-visible{outline:2px solid var(--violet); outline-offset:3px; border-radius:4px}

/* ── Header ── */
header{border-bottom:1px solid var(--border); background:rgba(11,7,19,.9);
  backdrop-filter:blur(10px); position:sticky; top:0; z-index:20}
.bar{display:flex; align-items:center; gap:14px; padding:16px 0; flex-wrap:wrap}
.logo{display:flex; align-items:center; gap:11px; border:0; flex-shrink:0}
.logo svg{width:34px; height:34px; animation:spin 24s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.logo svg{animation:none}}
.logo b{font-size:17px; letter-spacing:.16em; color:var(--text); font-weight:700}
.logo span{color:var(--violet)}
.spacer{flex:1 1 auto}
.chip{font-size:11.5px; letter-spacing:.1em; text-transform:uppercase;
  padding:5px 11px; border-radius:999px; border:1px solid var(--border);
  color:var(--muted); background:var(--surface); white-space:nowrap}

/* ── Hero ── */
.hero{padding:40px 0 26px}
.eyebrow{font-size:11.5px; letter-spacing:.3em; text-transform:uppercase; color:var(--violet)}
h1{margin:10px 0 6px; font-size:clamp(26px,5vw,42px); line-height:1.12; letter-spacing:-.02em;
  word-break:break-word}
h1 .t{background:linear-gradient(100deg,var(--gold),var(--violet));
  -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent;
  color:var(--gold)}
.sub{color:var(--muted); margin:0}

/* ── Stats ── */
.stats{display:grid; gap:12px; margin:26px 0;
  grid-template-columns:repeat(auto-fit,minmax(152px,1fr))}
.stat{background:var(--abyss); border:1px solid var(--border);
  border-radius:var(--radius); padding:15px 17px; position:relative; overflow:hidden}
.stat::after{content:""; position:absolute; inset:0 0 auto; height:2px;
  background:linear-gradient(90deg,transparent,var(--violet),transparent); opacity:.6}
.stat .k{font-size:11px; letter-spacing:.13em; text-transform:uppercase; color:var(--faint)}
.stat .v{font-size:26px; font-weight:700; margin-top:5px; line-height:1.1}
.meter{height:7px; border-radius:99px; background:var(--surface);
  overflow:hidden; margin-top:10px}
.meter i{display:block; height:100%; border-radius:99px;
  background:linear-gradient(90deg,var(--purple),var(--violet),var(--gold))}

/* ── Sections ── */
section{margin:40px 0}
h2{font-size:20px; margin:0 0 4px; display:flex; align-items:center; gap:10px;
  flex-wrap:wrap}
h2 .num{font-size:11px; letter-spacing:.2em; color:var(--violet);
  border:1px solid var(--border); border-radius:999px; padding:3px 9px}
h2 .sp{color:var(--lilac)}
.lede{color:var(--muted); margin:0 0 16px; font-size:14px}

/* ── Tables: scroll inside their own box, never the page ── */
.scroll{overflow-x:auto; border:1px solid var(--border); border-radius:var(--radius);
  background:var(--abyss); -webkit-overflow-scrolling:touch}
table{border-collapse:collapse; width:100%; min-width:620px; font-size:13.5px}
th,td{text-align:left; padding:10px 13px; border-bottom:1px solid rgba(42,27,61,.65);
  vertical-align:top}
th{font-size:10.5px; letter-spacing:.14em; text-transform:uppercase; color:var(--faint);
  background:var(--surface); position:sticky; top:0; z-index:1; white-space:nowrap}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:rgba(124,58,237,.07)}
code,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:12.5px}
td code{color:var(--lilac); word-break:break-all}

/* ── Severity badges ── */
.sev{display:inline-block; font-size:10.5px; font-weight:700; letter-spacing:.1em;
  padding:3px 8px; border-radius:5px; white-space:nowrap; text-transform:uppercase}
.sev.critical{background:rgba(255,51,102,.16); color:var(--sev-critical);
  border:1px solid rgba(255,51,102,.4)}
.sev.high{background:rgba(255,122,69,.16); color:var(--sev-high);
  border:1px solid rgba(255,122,69,.4)}
.sev.medium{background:rgba(251,191,36,.14); color:var(--sev-medium);
  border:1px solid rgba(251,191,36,.38)}
.sev.low{background:rgba(56,189,248,.14); color:var(--sev-low);
  border:1px solid rgba(56,189,248,.36)}
.sev.info{background:rgba(139,124,184,.14); color:var(--sev-info);
  border:1px solid rgba(139,124,184,.34)}

/* ── Finding cards ── */
.find{background:var(--abyss); border:1px solid var(--border);
  border-left:3px solid var(--violet); border-radius:var(--radius);
  padding:17px 19px; margin-bottom:13px}
.find.critical{border-left-color:var(--sev-critical)}
.find.high{border-left-color:var(--sev-high)}
.find.medium{border-left-color:var(--sev-medium)}
.find.low{border-left-color:var(--sev-low)}
.find.info{border-left-color:var(--sev-info)}
.find h3{margin:9px 0 9px; font-size:16px; line-height:1.35; word-break:break-word}
.find dl{display:grid; grid-template-columns:106px 1fr; gap:7px 15px; margin:0; font-size:13.5px}
.find dt{color:var(--faint); font-size:11px; letter-spacing:.11em; text-transform:uppercase;
  padding-top:2px}
.find dd{margin:0; min-width:0; overflow-wrap:anywhere}
.find dd.ev{color:var(--lilac); font-family:ui-monospace,Menlo,monospace; font-size:12.5px}
.find dd.fix{color:var(--ok)}
@media (max-width:620px){.find dl{grid-template-columns:1fr; gap:2px 0}
  .find dt{margin-top:9px}}

/* ── Filter buttons ── */
.filters{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px}
.filters button{font:inherit; font-size:12px; letter-spacing:.06em; cursor:pointer;
  background:var(--surface); color:var(--muted); border:1px solid var(--border);
  border-radius:999px; padding:6px 14px}
.filters button[aria-pressed="true"]{background:var(--purple); color:#fff;
  border-color:var(--violet)}
.filters button:hover{color:var(--text); border-color:var(--violet)}

/* ── Pills & lists ── */
.pills{display:flex; flex-wrap:wrap; gap:7px; padding:0; margin:0; list-style:none}
.pills li{font-size:12.5px; padding:4px 11px; border-radius:999px;
  background:var(--surface); border:1px solid var(--border); color:var(--muted)}
.cols{columns:2 300px; column-gap:26px}
.cols li{break-inside:avoid}
ul.plain{list-style:none; padding:0; margin:0}
ul.plain li{padding:5px 0; border-bottom:1px solid rgba(42,27,61,.5); font-size:13px;
  overflow-wrap:anywhere}
.group h4{margin:20px 0 8px; font-size:13px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--violet)}
.empty{color:var(--faint); font-style:italic}

/* ── Note / footer ── */
.note{border:1px solid var(--border); border-left:3px solid var(--gold);
  background:rgba(251,191,36,.055); border-radius:var(--radius);
  padding:14px 17px; color:var(--muted); font-size:13.5px; margin:22px 0}
footer{border-top:1px solid var(--border); margin-top:54px; padding:26px 0 36px;
  color:var(--faint); font-size:13px}
footer .fl{display:flex; gap:16px; flex-wrap:wrap; align-items:center}
@media print{
  body{background:#fff; color:#111}
  header{position:static}
  .filters,.logo svg{display:none}
  .find,.scroll,.stat{border-color:#ccc; background:#fff}
  a{color:#4c1d95}
}
"""

_LOGO_SVG = (
    '<svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
    '<circle cx="16" cy="16" r="14" fill="none" stroke="#a855f7" stroke-width="1.6"/>'
    '<circle cx="16" cy="16" r="7.5" fill="none" stroke="#c084fc" stroke-width="1.2"/>'
    '<circle cx="16" cy="16" r="2.4" fill="#fbbf24"/>'
    '<g stroke="#a855f7" stroke-width="1.2">'
    '<path d="M16 2v6M16 24v6M2 16h6M24 16h6"/>'
    '<path d="M6.1 6.1l4.3 4.3M21.6 21.6l4.3 4.3M25.9 6.1l-4.3 4.3M10.4 21.6l-4.3 4.3"/>'
    "</g></svg>"
)

_FILTER_JS = """
(function(){
  var buttons = document.querySelectorAll('.filters button');
  var cards = document.querySelectorAll('.find');
  if (!buttons.length || !cards.length) return;
  function apply(level){
    for (var i = 0; i < cards.length; i++){
      var show = level === 'all' || cards[i].classList.contains(level);
      cards[i].hidden = !show;
    }
    for (var j = 0; j < buttons.length; j++){
      buttons[j].setAttribute('aria-pressed',
        String(buttons[j].dataset.level === level));
    }
  }
  for (var k = 0; k < buttons.length; k++){
    buttons[k].addEventListener('click', function(e){
      apply(e.currentTarget.dataset.level);
    });
  }
  apply('all');
})();
"""


def _h(value, max_len: int = 4000) -> str:
    """Sanitize then HTML-escape. Every untrusted value goes through this."""
    return shuddhi.escape_html(value, max_len=max_len)


def _write_html(result: ScanResult, path: str) -> None:
    counts = result.severity_counts()
    findings = result.findings_sorted()
    target = _h(result.target, max_len=253)
    infra = result.infra or {}
    archive = result.archive or {}
    year = time.strftime("%Y")
    scanned = time.strftime("%Y-%m-%d %H:%M", time.localtime(result.started_at))

    out: list[str] = []
    add = out.append

    # ── Head ──
    add("<!doctype html>")
    add('<html lang="en"><head>')
    add('<meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>ChakraView — {target} reconnaissance report</title>")
    add(f'<meta name="description" content="ChakraView reconnaissance report for '
        f'{target}: {len(findings)} findings, risk {result.risk_label} '
        f'({result.risk_score}/100), {len(result.subdomains)} subdomains collected '
        f'and {len(result.hosts_alive())} live hosts.">')
    add('<meta name="robots" content="noindex, nofollow">')
    add(f'<meta name="generator" content="ChakraView 2.0">')
    add('<meta name="color-scheme" content="dark">')
    add(f'<link rel="icon" href="{_FAVICON}">')
    add(f"<style>{_HTML_CSS}</style>")
    add("</head><body>")

    # ── Header ──
    add('<header><div class="wrap bar">')
    add('<a class="logo" href="#top" aria-label="ChakraView — back to top">'
        f'{_LOGO_SVG}<b>CHAKRA<span>VIEW</span></b></a>')
    add('<div class="spacer"></div>')
    add(f'<span class="chip">{len(findings)} findings</span>')
    add(f'<span class="chip">risk {result.risk_label.lower()}</span>')
    add(f'<span class="chip">{scanned}</span>')
    add("</div></header>")

    add('<main class="wrap" id="top">')

    # ── Hero ──
    add('<div class="hero">')
    add('<p class="eyebrow">☸ Reconnaissance report</p>')
    add(f'<h1>Target fortress <span class="t">{target}</span></h1>')
    add(f'<p class="sub">Ten chakras · {result.duration:.1f}s · '
        f'{len(result.args.get("chakras", []))} modules executed</p>')
    add("</div>")

    # ── Stats ──
    add('<div class="stats">')
    add(f'<div class="stat"><div class="k">Risk score</div>'
        f'<div class="v">{result.risk_score}<span style="font-size:14px;color:var(--faint)">/100</span></div>'
        f'<div class="meter"><i style="width:{result.risk_score}%"></i></div></div>')
    for label, value in (
        ("Findings", len(findings)),
        ("Subdomains", len(result.subdomains)),
        ("Live hosts", len(result.hosts_alive())),
        ("Open ports", sum(len(v) for v in (infra.get("open_ports") or {}).values())),
        ("JS secrets", len(result.secrets)),
        ("Endpoints", len(result.endpoints)),
    ):
        add(f'<div class="stat"><div class="k">{label}</div><div class="v">{value}</div></div>')
    add("</div>")

    add('<div class="note"><strong>Reconnaissance output.</strong> Every item here '
        "requires manual confirmation against the live target before it is "
        "reported as a vulnerability. Archive and search-engine results show what "
        "was once reachable, not necessarily what is reachable now.</div>")

    # ── Findings ──
    add('<section id="findings"><h2><span class="num">I</span>'
        '<span class="sp">✦</span> Findings</h2>')
    if findings:
        breakdown = ", ".join(f"{counts[s]} {s.lower()}" for s in SEV_ORDER if counts[s])
        add(f'<p class="lede">{len(findings)} recorded — {breakdown}.</p>')
    else:
        add('<p class="lede">None recorded.</p>')

    if findings:
        add('<div class="filters" role="group" aria-label="Filter findings by severity">')
        add('<button type="button" data-level="all" aria-pressed="true">All</button>')
        for severity in SEV_ORDER:
            if counts[severity]:
                add(f'<button type="button" data-level="{severity.lower()}" '
                    f'aria-pressed="false">{severity.title()} ({counts[severity]})</button>')
        add("</div>")

        for finding in findings:
            level = finding.severity.label.lower()
            add(f'<article class="find {level}">')
            add(f'<span class="sev {level}">{finding.severity.label}</span>')
            add(f"<h3>{_h(finding.title, max_len=300)}</h3>")
            add("<dl>")
            add(f"<dt>Chakra</dt><dd>{_h(finding.chakra, max_len=40)}</dd>")
            add(f'<dt>Asset</dt><dd><code>{_h(finding.asset, max_len=400)}</code></dd>')
            if finding.detail:
                add(f"<dt>Detail</dt><dd>{_h(finding.detail, max_len=2500)}</dd>")
            if finding.evidence:
                add(f'<dt>Evidence</dt><dd class="ev">{_h(finding.evidence, max_len=1200)}</dd>')
            if finding.remediation:
                add(f'<dt>Remediation</dt><dd class="fix">{_h(finding.remediation, max_len=900)}</dd>')
            if finding.references:
                links = " · ".join(
                    f'<a href="{_h(r, max_len=300)}" rel="noopener noreferrer nofollow" '
                    f'target="_blank">{_h(r, max_len=90)}</a>'
                    for r in finding.references[:3]
                    if str(r).startswith(("http://", "https://"))
                )
                if links:
                    add(f"<dt>References</dt><dd>{links}</dd>")
            add("</dl></article>")
    add("</section>")

    # ── Infrastructure ──
    addresses = infra.get("addresses") or []
    if addresses:
        add('<section id="infra"><h2><span class="num">II</span>'
            '<span class="sp">✦</span> Infrastructure</h2>')
        add('<p class="lede">Every address the apex answers with, enriched and '
            "classified.</p>")
        add('<div class="scroll"><table><thead><tr><th>Address</th>'
            "<th>Organisation</th><th>Reverse DNS</th><th>Location</th>"
            "<th>Edge / cloud</th></tr></thead><tbody>")
        for record in addresses:
            edge = record.get("cdn") or record.get("cloud") or "—"
            location = ", ".join(
                p for p in (record.get("city"), record.get("country")) if p
            ) or "—"
            add(f'<tr><td><code>{_h(record.get("ip"), 60)}</code></td>'
                f'<td>{_h(record.get("org"), 200) or "—"}</td>'
                f'<td><code>{_h(record.get("reverse_dns"), 253) or "—"}</code></td>'
                f'<td>{_h(location, 120)}</td>'
                f'<td>{_h(edge, 80)}</td></tr>')
        add("</tbody></table></div>")
        technologies = infra.get("technologies") or {}
        if technologies:
            add('<h4 style="color:var(--violet);margin:22px 0 8px;font-size:13px;'
                'letter-spacing:.1em;text-transform:uppercase">Technologies identified</h4>')
            add('<ul class="pills">')
            for name, count in technologies.items():
                add(f"<li>{_h(name, 60)} <span style=\"color:var(--faint)\">×{count}</span></li>")
            add("</ul>")
        add("</section>")

    # ── DNS ──
    records = (result.dns or {}).get("records") or {}
    if records:
        add('<section id="dns"><h2><span class="num">III</span>'
            '<span class="sp">✦</span> DNS &amp; mail posture</h2>')
        add('<div class="scroll"><table><thead><tr><th>Type</th><th>Value</th>'
            "</tr></thead><tbody>")
        for rtype, values in records.items():
            for value in values:
                add(f"<tr><td><strong>{_h(rtype, 10)}</strong></td>"
                    f'<td><code>{_h(value, 600)}</code></td></tr>')
        add("</tbody></table></div>")

        posture: list[str] = []
        spf = (result.dns or {}).get("spf")
        dmarc = (result.dns or {}).get("dmarc")
        selectors = (result.dns or {}).get("dkim_selectors") or []
        posture.append(
            f"SPF <code>{_h(spf.get('all') or 'no all mechanism', 20)}</code>, "
            f"{spf.get('lookups', 0)} lookups" if spf else "SPF <strong>absent</strong>"
        )
        posture.append(
            f"DMARC <code>p={_h(dmarc.get('policy') or 'none', 20)}</code>"
            if dmarc else "DMARC <strong>absent</strong>"
        )
        posture.append(
            f"DKIM selectors: {_h(', '.join(selectors), 300)}"
            if selectors else "DKIM <strong>no common selector found</strong>"
        )
        add('<ul class="pills" style="margin-top:14px">'
            + "".join(f"<li>{item}</li>" for item in posture) + "</ul>")

        tenants = (result.dns or {}).get("saas_tenants") or []
        if tenants:
            add('<h4 style="color:var(--violet);margin:22px 0 8px;font-size:13px;'
                'letter-spacing:.1em;text-transform:uppercase">'
                "Third-party tenants verified via DNS</h4>")
            add('<ul class="pills">'
                + "".join(f"<li>{_h(t, 80)}</li>" for t in tenants) + "</ul>")
        add("</section>")

    # ── Hosts ──
    hosts = sorted(result.subdomains.values(), key=lambda e: (e.status or 999, e.host))
    if hosts:
        alive_count = len(result.hosts_alive())
        add('<section id="hosts"><h2><span class="num">IV</span>'
            '<span class="sp">✦</span> Subdomains</h2>')
        add(f'<p class="lede">{len(hosts)} collected · '
            f"{len(result.hosts_resolved())} resolving · {alive_count} responding to "
            "HTTP. Sources are listed so each result can be traced back.</p>")
        add('<div class="scroll"><table><thead><tr><th>Status</th><th>Host</th>'
            "<th>Address</th><th>Title</th><th>Technology</th><th>Ports</th>"
            "<th>Sources</th></tr></thead><tbody>")
        for entry in hosts:
            status = entry.status
            if status is None:
                badge = '<span class="sev info">—</span>'
            elif 200 <= status < 300:
                badge = f'<span class="sev low">{status}</span>'
            elif status in (401, 403):
                badge = f'<span class="sev medium">{status}</span>'
            elif status >= 500:
                badge = f'<span class="sev high">{status}</span>'
            else:
                badge = f'<span class="sev info">{status}</span>'
            link = (f'<a href="{_h(entry.url, 400)}" target="_blank" '
                    f'rel="noopener noreferrer nofollow">{_h(entry.host, 253)}</a>'
                    if entry.url else f"<code>{_h(entry.host, 253)}</code>")
            add(f"<tr><td>{badge}</td><td>{link}</td>"
                f'<td><code>{_h(", ".join(entry.ips[:3]), 200) or "—"}</code></td>'
                f'<td>{_h(entry.title, 160) or "—"}</td>'
                f'<td>{_h(", ".join(entry.tech[:6]), 200) or "—"}</td>'
                f'<td><code>{_h(", ".join(str(p) for p in entry.ports), 200) or "—"}</code></td>'
                f'<td style="color:var(--faint);font-size:12px">'
                f'{_h(", ".join(sorted(entry.sources)), 300)}</td></tr>')
        add("</tbody></table></div></section>")

    # ── Takeover ──
    if result.takeover:
        add('<section id="takeover"><h2><span class="num">V</span>'
            '<span class="sp">✦</span> Subdomain takeover candidates</h2>')
        add('<p class="lede">A CNAME into a provider whose resource is '
            "unclaimed. Confirm by attempting to register the name at the "
            "provider, with the client's written approval.</p>")
        add('<div class="scroll"><table><thead><tr><th>Host</th><th>CNAME</th>'
            "<th>Service</th><th>Confidence</th><th>Signal</th></tr></thead><tbody>")
        for hit in result.takeover:
            add(f'<tr><td><code>{_h(hit.get("host"), 253)}</code></td>'
                f'<td><code>{_h(hit.get("cname"), 253)}</code></td>'
                f'<td>{_h(hit.get("service"), 80)}</td>'
                f'<td><span class="sev {"high" if hit.get("confidence")=="high" else "medium"}">'
                f'{_h(hit.get("confidence"), 20)}</span></td>'
                f'<td>{_h(hit.get("signal"), 300)}</td></tr>')
        add("</tbody></table></div></section>")

    # ── Secrets ──
    if result.secrets:
        add('<section id="secrets"><h2><span class="num">VI</span>'
            '<span class="sp">✦</span> Secrets in client-side JavaScript</h2>')
        add('<p class="lede">Values are redacted here. Anything shipped to a '
            "browser is readable by every visitor and should be rotated "
            "regardless of whether it is currently in use.</p>")
        add('<div class="scroll"><table><thead><tr><th>Severity</th><th>Type</th>'
            "<th>Source</th><th>Value</th><th>Context</th></tr></thead><tbody>")
        for secret in result.secrets:
            level = str(secret.get("severity", "info")).lower()
            add(f'<tr><td><span class="sev {level}">{_h(secret.get("severity"), 20)}</span></td>'
                f'<td>{_h(secret.get("type"), 100)}</td>'
                f'<td><code>{_h(secret.get("source"), 400)}</code></td>'
                f'<td><code>{_h(secret.get("match"), 100)}</code></td>'
                f'<td style="color:var(--faint);font-size:12px">'
                f'{_h(secret.get("context"), 240)}</td></tr>')
        add("</tbody></table></div></section>")

    # ── Endpoints ──
    if result.endpoints:
        add('<section id="endpoints"><h2><span class="num">VII</span>'
            '<span class="sp">✦</span> API endpoints recovered</h2>')
        add(f'<p class="lede">{len(result.endpoints)} routes extracted from '
            "first-party scripts. Test each for authorisation, not just "
            "authentication.</p>")
        add('<ul class="plain cols">')
        for endpoint in result.endpoints[:500]:
            add(f"<li><code>{_h(endpoint, 400)}</code></li>")
        add("</ul>")
        if len(result.endpoints) > 500:
            add(f'<p class="lede">… and {len(result.endpoints) - 500} more in the '
                "JSON report.</p>")
        add("</section>")

    # ── Archive ──
    if archive.get("found"):
        add('<section id="archive"><h2><span class="num">VIII</span>'
            '<span class="sp">✦</span> Archive</h2>')
        add(f'<p class="lede">{archive.get("total", 0)} archived URLs indexed. '
            "Paths below were deleted from the site but the files are often "
            "still served.</p>")
        sensitive = archive.get("sensitive") or []
        if sensitive:
            add('<div class="scroll"><table><thead><tr><th>Severity</th>'
                "<th>Extension</th><th>Archived URL</th></tr></thead><tbody>")
            for item in sensitive[:120]:
                level = str(item.get("severity", "info")).lower()
                add(f'<tr><td><span class="sev {level}">{_h(item.get("severity"), 20)}</span></td>'
                    f'<td><code>{_h(item.get("ext"), 20)}</code></td>'
                    f'<td><code>{_h(item.get("url"), 500)}</code></td></tr>')
            add("</tbody></table></div>")
        parameters = archive.get("interesting_parameters") or {}
        if parameters:
            add('<h4 style="color:var(--violet);margin:24px 0 8px;font-size:13px;'
                'letter-spacing:.1em;text-transform:uppercase">'
                "Parameters mapping to known vulnerability classes</h4>")
            add('<div class="scroll"><table><thead><tr><th>Parameter</th>'
                "<th>Suggested class</th><th>URLs</th><th>Sample</th>"
                "</tr></thead><tbody>")
            for name, info in sorted(parameters.items()):
                level = str(info.get("severity", "info")).lower()
                add(f"<tr><td><code>{_h(name, 80)}</code></td>"
                    f'<td><span class="sev {level}">{_h(info.get("reason"), 120)}</span></td>'
                    f'<td>{info.get("count", 0)}</td>'
                    f'<td><code>{_h(info.get("sample"), 400)}</code></td></tr>')
            add("</tbody></table></div>")
        add("</section>")

    # ── Dorks ──
    dork_data = result.dorks or {}
    queries = dork_data.get("queries") or []
    if queries:
        add('<section id="dorks"><h2><span class="num">IX</span>'
            '<span class="sp">✦</span> Dork arsenal</h2>')
        add(f'<p class="lede">{len(queries)} queries, each a live link. '
            f'{_h(dork_data.get("note"), 400)}</p>')
        current_group = ""
        for dork in queries:
            if dork["group"] != current_group:
                if current_group:
                    add("</ul></div>")
                current_group = dork["group"]
                add(f'<div class="group"><h4>{_h(current_group, 80)}</h4>'
                    '<ul class="plain">')
            engines = " · ".join(
                f'<a href="{_h(url, 900)}" target="_blank" '
                f'rel="noopener noreferrer nofollow">{_h(engine, 30)}</a>'
                for engine, url in dork["urls"].items()
            )
            add(f'<li><code>{_h(dork["query"], 400)}</code><br>'
                f'<span style="font-size:12px">{engines}</span></li>')
        if current_group:
            add("</ul></div>")

        platforms = dork_data.get("platforms") or {}
        for name, links in platforms.items():
            add(f'<div class="group"><h4>{_h(name, 80)}</h4><ul class="plain">')
            for link in links:
                add(f'<li><a href="{_h(link.get("url"), 900)}" target="_blank" '
                    f'rel="noopener noreferrer nofollow">'
                    f'{_h(link.get("label"), 200)}</a></li>')
            add("</ul></div>")
        add("</section>")

    # ── Run metadata ──
    add('<section id="run"><h2><span class="num">X</span>'
        '<span class="sp">✦</span> Run detail</h2>')
    add('<div class="scroll"><table><thead><tr><th>Setting</th><th>Value</th>'
        "</tr></thead><tbody>")
    for key, value in (result.args or {}).items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        add(f"<tr><td>{_h(key, 60)}</td><td><code>{_h(value, 600)}</code></td></tr>")
    add(f"<tr><td>duration</td><td><code>{result.duration:.1f}s</code></td></tr>")
    add("</tbody></table></div>")
    if result.skipped:
        add('<h4 style="color:var(--violet);margin:22px 0 8px;font-size:13px;'
            'letter-spacing:.1em;text-transform:uppercase">Skipped</h4>')
        add('<ul class="pills">'
            + "".join(f"<li>{_h(s, 120)}</li>" for s in result.skipped) + "</ul>")
    if result.errors:
        add('<h4 style="color:var(--sev-high);margin:22px 0 8px;font-size:13px;'
            'letter-spacing:.1em;text-transform:uppercase">Errors</h4>')
        add('<ul class="plain">'
            + "".join(f"<li>{_h(e, 400)}</li>" for e in result.errors) + "</ul>")
    add("</section>")

    add("</main>")

    # ── Footer: dynamic year, working links only ──
    add("<footer><div class=\"wrap fl\">")
    add(f"<span>© {year} ChakraView</span>")
    add('<a href="https://github.com/mayurie-cysec/chakraview" target="_blank" '
        'rel="noopener noreferrer">Source</a>')
    add('<a href="https://github.com/mayurie-cysec/chakraview/issues" target="_blank" '
        'rel="noopener noreferrer">Report an issue</a>')
    add('<a href="#top">Back to top</a>')
    add('<span style="margin-left:auto">Authorised reconnaissance only</span>')
    add("</div></footer>")

    add(f"<script>{_FILTER_JS}</script>")
    add("</body></html>")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out))
