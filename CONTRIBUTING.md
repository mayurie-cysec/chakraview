# Contributing to ChakraView

Contributions are welcome — new chakras, better fingerprints, new passive
sources, bug fixes.

## Before you start

```bash
git clone https://github.com/mayurie-cysec/chakraview
cd chakraview
pip install -r requirements.txt
python3 chakraview.py --list-chakras
```

## Adding a chakra

Three steps.

**1. Write the module** in `modules/`, named after a Mahabharata figure whose
role matches what the module does. It exposes one function:

```python
async def run(ctx: Context) -> None: ...
```

`ctx` gives you everything:

| Attribute | What it is |
|---|---|
| `ctx.target` | The normalised domain |
| `ctx.cfg` | The operator's `Config` — concurrency, timeout, limits, flags |
| `ctx.http` | Shared rate-limited async HTTP client. Returns `None` instead of raising |
| `ctx.resolver` | Shared cached async DNS resolver |
| `ctx.result` | The `ScanResult` — report findings and hosts here |
| `ctx.progress` | Progress and live results. Never `print()` |
| `ctx.cancelled()` | True when the operator stopped the scan — check it in long loops |

**2. Register it** in `CHAKRAS` in `core/context.py` (key, roman numeral,
icon, name, one-line description). The CLI, `--only`, `--skip` and the web
dashboard all read that list.

**3. Map it** in `RUNNERS` in `core/engine.py`.

### What a module must do

- **Never print.** Use `ctx.progress.task()`, `.advance()`, `.hit()`,
  `.note()` and `.chakra_done()`. The terminal UI and the web dashboard are
  both driven by those calls.
- **Never raise for a network failure.** `ctx.http` already returns `None` on
  failure and `ctx.resolver` returns an empty list. A third-party source that
  is down should return nothing, not end the scan.
- **Sanitize everything external.** Any string from a target or a third-party
  API goes through `shuddhi.sanitize()` before it reaches the result. See the
  note in `modules/shuddhi.py` for why.
- **Report findings, not text.** `ctx.result.report(severity, title, ...)`
  with `detail`, `evidence` and `remediation` filled in. A finding without
  evidence is not actionable.
- **Respect the limits.** `ctx.cfg` carries `concurrency`,
  `max_probe_hosts`, `timeout` and `deep`. Honour them.
- **Add a passive source rather than a louder active one** where the same
  information is available either way.

### Severity

| Level | Means |
|---|---|
| `CRITICAL` | Direct access to data or code execution. Exposed `.git`, open Redis, a live credential. |
| `HIGH` | A clear path to compromise that needs one more step. Takeover candidate, exposed database port, SPF `+all`. |
| `MEDIUM` | A real weakness requiring conditions. Missing DMARC, directory listing, wildcard CORS. |
| `LOW` | Hardening gap or useful context. Missing security headers, deprecated SPF mechanism. |
| `INFO` | Attack surface, not a weakness. Discovered hosts, technologies, prepared dorks. |

Do not inflate severity. A tool that calls everything HIGH gets ignored.

### Avoiding false positives

The single most important rule. Two examples from the existing code:

- **Takeover** (`ekalavya.py`) never reports on a matching CNAME alone — the
  provider's unclaimed-name response has to confirm it.
- **Enumeration** (`karna.py`) detects wildcard DNS before trusting any
  bruteforce result, because a wildcard domain otherwise reports every
  candidate as live.

If a check can produce noise, make it require a second signal.

## Working on the web UI

```bash
python3 chakraview.py --serve
python3 tools/check_links.py --external   # run this before you open a PR
```

The checker verifies internal links, in-page anchors, titles, meta
descriptions, favicons, alt text, image size budgets, form labelling and
dead buttons. It must pass.

Palette values live in `core/theme.py` and are mirrored in
`web/assets/css/chakraview.css`. Change one, change the other.

Never put a value from a scan into `innerHTML`. Scan output is
attacker-influenced; use `textContent` or build nodes.

## Reporting a security issue in ChakraView itself

Open an issue prefixed `[VULNERABILITY]`. If it is sensitive, say so in the
issue without the details and a maintainer will follow up.
