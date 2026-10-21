"""The orchestrator — runs the ten chakras in order against one target.

The engine owns the HTTP client and resolver lifecycle, decides which chakras
run, and guarantees that a module raising an exception degrades that one
chakra instead of ending the scan. Front ends (CLI and web) construct a
Config and a ProgressSink and call run_scan; neither knows what a module does.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from core.context import CHAKRA_BY_KEY, CHAKRA_KEYS, Config, Context, ProgressSink
from core.models import ScanResult
from core.net import HttpClient, Resolver
from modules import (
    abhimanyu,
    arjuna,
    ashwatthama,
    brahmastra,
    drona,
    ekalavya,
    karna,
    sahadeva,
    sanjaya,
    shakuni,
)

# Chakra key → the module that implements it.
RUNNERS: dict[str, Callable] = {
    "github": shakuni.run,
    "infra": sanjaya.run,
    "dns": drona.run,
    "archive": ashwatthama.run,
    "subs": karna.run,
    "http": arjuna.run,
    "takeover": ekalavya.run,
    "ports": abhimanyu.run,
    "js": sahadeva.run,
    "dorks": brahmastra.run,
}


def normalise_target(raw: str) -> str:
    """Accept a URL, a host with a port, or a bare domain; return the hostname."""
    from modules import shuddhi

    target = (raw or "").strip().lower()
    for prefix in ("http://", "https://", "//"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split("?")[0].split("#")[0]
    if "@" in target:
        target = target.rsplit("@", 1)[1]
    target = target.split(":")[0].strip(".")
    return shuddhi.normalise_host(target)


async def run_scan(
    cfg: Config,
    progress: ProgressSink | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> ScanResult:
    """Run every enabled chakra and return the populated result."""
    progress = progress or ProgressSink()
    cancelled = cancelled or (lambda: False)

    result = ScanResult(target=cfg.domain, args=cfg.to_dict())
    result.on_finding = lambda f: progress.finding(
        f.chakra, f.severity.label, f.title, f.asset
    )

    async with HttpClient(
        concurrency=cfg.concurrency,
        timeout=cfg.timeout,
        retries=cfg.retries,
        verify=cfg.verify_tls,
    ) as http:
        resolver = Resolver(concurrency=max(50, cfg.concurrency * 2), timeout=min(cfg.timeout, 5.0))
        ctx = Context(
            result=result,
            cfg=cfg,
            http=http,
            resolver=resolver,
            progress=progress,
            cancelled=cancelled,
        )

        # The apex is always part of the result, so it is probed and scanned
        # alongside everything enumeration turns up.
        result.add_subdomain(cfg.domain, "target")

        for key in CHAKRA_KEYS:
            if cancelled():
                result.skipped.append(f"{key} (cancelled)")
                continue

            enabled, reason = cfg.enabled(key)
            if not enabled:
                result.skipped.append(f"{key} ({reason})")
                progress.chakra_skip(key, reason)
                continue

            runner = RUNNERS.get(key)
            if runner is None:
                continue

            progress.chakra_start(key)
            started = time.time()
            try:
                await runner(ctx)
            except asyncio.CancelledError:
                result.skipped.append(f"{key} (cancelled)")
                raise
            except Exception as exc:
                # One broken chakra must not cost the operator the whole scan.
                name = CHAKRA_BY_KEY[key]["name"]
                message = f"{name}: {type(exc).__name__}: {exc}"
                result.errors.append(message)
                progress.note(key, f"failed — {type(exc).__name__}: {exc}")
            finally:
                progress.chakra_elapsed(key, time.time() - started)

    result.finished_at = time.time()
    return result
