#!/usr/bin/env python3
"""
ChakraView — strategic reconnaissance formation.

Ten chakras run in order against one target: GitHub OSINT, infrastructure,
DNS and mail posture, archive archaeology, subdomain enumeration, HTTP
probing, takeover detection, port scanning, JavaScript mining and a dork
arsenal. Findings are collected into one model and written out as text, JSON,
Markdown or a self-contained HTML page.

    python3 chakraview.py -d example.com
    python3 chakraview.py -d example.com --deep -f all
    python3 chakraview.py -d example.com --passive-only
    python3 chakraview.py --serve

Authorised reconnaissance only. Several chakras send traffic to the target.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.context import CHAKRA_KEYS, CHAKRAS, PORT_PROFILES, Config  # noqa: E402
from core.engine import normalise_target, run_scan  # noqa: E402
from core.report import FORMATS, write_all  # noqa: E402
from core.ui import TerminalUI  # noqa: E402

VERSION = "2.0.0"

EPILOG = f"""
chakras (use with --only / --skip):
  {', '.join(CHAKRA_KEYS)}

port profiles:
  {', '.join(PORT_PROFILES)}  (or a comma-separated list: --ports 22,80,443)

environment:
  GITHUB_TOKEN             unlocks GitHub code search — the chakra that finds
                           committed credentials. Read-only scope is enough.
  SECURITYTRAILS_API_KEY   extra passive subdomain source
  VT_API_KEY               extra passive subdomain source (VirusTotal)
  LEAKIX_API_KEY           extra passive subdomain source
  OTX_API_KEY              richer AlienVault OTX passive DNS
  URLSCAN_API_KEY          higher urlscan.io rate limit

examples:
  chakraview.py -d example.com
  chakraview.py -d example.com --deep -f all -o ./reports
  chakraview.py -d example.com --passive-only          # no traffic to target
  chakraview.py -d example.com --only subs,http,takeover
  chakraview.py -d example.com --skip ports,js --plain
  chakraview.py --serve --port 8787                    # web dashboard
"""


def _csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chakraview",
        description="ChakraView — strategic reconnaissance formation for security researchers.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group("target")
    target.add_argument("-d", "--domain", help="Target domain (example.com, or a full URL)")

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", default="reports", metavar="DIR",
                        help="Report directory (default: reports)")
    output.add_argument("-f", "--format", default="txt", metavar="LIST",
                        help=f"Comma-separated: {', '.join(FORMATS)}, or 'all' (default: txt)")
    output.add_argument("--no-report", action="store_true",
                        help="Print to the terminal only, write nothing to disk")
    output.add_argument("--plain", action="store_true",
                        help="No colour and no animation — for logs and pipes")
    output.add_argument("--quiet", action="store_true",
                        help="Suppress progress; print the summary only")
    output.add_argument("--no-banner", action="store_true", help="Skip the banner")

    scope = parser.add_argument_group("scope")
    scope.add_argument("--only", type=_csv, default=[], metavar="LIST",
                       help="Run only these chakras")
    scope.add_argument("--skip", type=_csv, default=[], metavar="LIST",
                       help="Skip these chakras")
    scope.add_argument("--passive-only", action="store_true",
                       help="Third-party sources only — sends no traffic to the target")
    scope.add_argument("--deep", action="store_true",
                       help="Raise every limit: more ports, more hosts, more scripts")

    tuning = parser.add_argument_group("tuning")
    tuning.add_argument("-c", "--concurrency", type=int, default=50, metavar="N",
                        help="Concurrent requests (default: 50)")
    tuning.add_argument("-t", "--timeout", type=float, default=10.0, metavar="SEC",
                        help="Per-request timeout (default: 10)")
    tuning.add_argument("--retries", type=int, default=1, metavar="N",
                        help="Retries per failed request (default: 1)")
    tuning.add_argument("-w", "--wordlist", default="", metavar="FILE",
                        help="Subdomain wordlist (default: built-in curated list)")
    tuning.add_argument("--ports", default="top25", metavar="PROFILE",
                        help=f"{', '.join(PORT_PROFILES)} or a comma-separated list")
    tuning.add_argument("--max-probe-hosts", type=int, default=400, metavar="N",
                        help="Cap on hosts probed over HTTP (default: 400)")
    tuning.add_argument("--verify-tls", action="store_true",
                        help="Verify TLS certificates (off by default — recon hits "
                             "hosts with broken or self-signed certificates)")
    tuning.add_argument("--github-token", default="", metavar="TOKEN",
                        help="GitHub token (prefer the GITHUB_TOKEN env var)")

    web = parser.add_argument_group("web dashboard")
    web.add_argument("--serve", action="store_true",
                     help="Serve the landing page and scan dashboard")
    web.add_argument("--host", default="127.0.0.1", metavar="ADDR",
                     help="Bind address for --serve (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8787, metavar="PORT",
                     help="Port for --serve (default: 8787)")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--list-chakras", action="store_true",
                      help="List the chakras and exit")
    misc.add_argument("-V", "--version", action="version",
                      version=f"ChakraView {VERSION}")
    return parser


def list_chakras() -> None:
    print(f"\nChakraView {VERSION} — ten chakras\n")
    for chakra in CHAKRAS:
        print(f"  {chakra['num']:>5}. {chakra['key']:<9} {chakra['name']:<13} "
              f"{chakra['sub']}")
    print("\n  Use --only or --skip with the key in the second column.\n")


def resolve_config(args: argparse.Namespace) -> tuple[Config | None, str]:
    """Validate arguments into a Config, or return an error message."""
    target = normalise_target(args.domain or "")
    if not target:
        return None, f"'{args.domain}' is not a usable domain name."
    if "." not in target:
        return None, (f"'{target}' has no dot — ChakraView needs a registrable "
                      "domain such as example.com.")

    formats = _csv(args.format)
    if "all" in formats:
        formats = list(FORMATS)
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        return None, (f"unknown report format(s): {', '.join(unknown)}. "
                      f"Choose from {', '.join(FORMATS)} or 'all'.")

    for name, values in (("--only", args.only), ("--skip", args.skip)):
        bad = [v for v in values if v not in CHAKRA_KEYS]
        if bad:
            return None, (f"{name}: unknown chakra(s) {', '.join(bad)}. "
                          f"Valid keys: {', '.join(CHAKRA_KEYS)}")

    custom_ports: list[int] = []
    ports_profile = args.ports.strip().lower()
    if ports_profile not in PORT_PROFILES:
        try:
            custom_ports = [int(p) for p in _csv(args.ports)]
        except ValueError:
            return None, (f"--ports: '{args.ports}' is neither a profile "
                          f"({', '.join(PORT_PROFILES)}) nor a list of port numbers.")
        out_of_range = [p for p in custom_ports if not 1 <= p <= 65535]
        if out_of_range:
            return None, f"--ports: out of range: {out_of_range}"

    if args.wordlist and not os.path.isfile(args.wordlist):
        return None, f"--wordlist: no such file: {args.wordlist}"

    if args.concurrency < 1:
        return None, "--concurrency must be at least 1."
    if args.timeout <= 0:
        return None, "--timeout must be greater than 0."

    cfg = Config(
        domain=target,
        out_dir=args.output,
        formats=formats,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=max(0, args.retries),
        wordlist=args.wordlist,
        only=args.only,
        skip=args.skip,
        passive_only=args.passive_only,
        ports_profile=ports_profile if not custom_ports else "custom",
        custom_ports=custom_ports,
        max_probe_hosts=args.max_probe_hosts,
        deep=args.deep,
        github_token=args.github_token,
        plain=args.plain,
        quiet=args.quiet,
        no_banner=args.no_banner,
        verify_tls=args.verify_tls,
    )

    if not cfg.active_chakras():
        return None, "every chakra is disabled — check --only / --skip."
    return cfg, ""


async def scan(cfg: Config, ui: TerminalUI, write: bool) -> int:
    ui.banner()
    ui.target_header(cfg.domain, len(cfg.active_chakras()))
    ui.start()

    interrupted = False
    try:
        result = await run_scan(cfg, progress=ui)
    except KeyboardInterrupt:
        ui.stop()
        ui.error("interrupted — retreating from Kurukshetra.")
        return 130
    finally:
        ui.stop()

    ui.render_results(result)

    if write:
        try:
            paths = write_all(result, cfg.out_dir, cfg.formats)
            ui.report_saved(paths)
        except OSError as exc:
            ui.error(f"could not write report: {exc}")
            return 1

    ui.closing()
    return 0 if not interrupted else 130


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_chakras:
        list_chakras()
        return 0

    if args.serve:
        from server.app import serve

        return serve(args.host, args.port)

    if not args.domain:
        parser.print_usage()
        print("\nchakraview: a target is required — pass -d example.com, "
              "or --serve for the web dashboard.\n")
        return 2

    cfg, error = resolve_config(args)
    if cfg is None:
        print(f"\nchakraview: {error}\n", file=sys.stderr)
        return 2

    try:
        return asyncio.run(scan(cfg, TerminalUI(cfg), write=not args.no_report))
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted — retreating from Kurukshetra.\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
