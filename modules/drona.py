"""
DRONA — the teacher who reads the whole field.

Pulls the full record set for the apex, then audits the two things that are
almost always misconfigured and almost never tested: the mail-spoofing
posture (SPF/DMARC/DKIM) and whether any nameserver will hand over the entire
zone. An open AXFR is a complete map of internal infrastructure, and a
missing DMARC policy means anyone can send mail as the domain — both are
findings a client can act on the same day.
"""

from __future__ import annotations

import asyncio
import re

from core.context import Context
from core.models import Severity
from core.net import HAS_DNSPYTHON
from modules import shuddhi

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]

# Selectors worth probing. Most providers publish DKIM under a predictable
# name, so a short list finds the signing key without a brute force.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "zoho", "mandrill", "sendgrid",
    "mailjet", "amazonses", "pm", "fm1", "everlytickey1", "smtp",
]

# TXT fragments that identify which SaaS products the domain has verified.
# Each one is a tenant worth checking for its own misconfiguration.
SAAS_VERIFICATION = {
    "MS=": "Microsoft 365",
    "google-site-verification": "Google Workspace",
    "atlassian-domain-verification": "Atlassian",
    "docusign": "DocuSign",
    "adobe-idp-site-verification": "Adobe",
    "zoho-verification": "Zoho",
    "slack-domain-verification": "Slack",
    "stripe-verification": "Stripe",
    "shopify": "Shopify",
    "facebook-domain-verification": "Meta",
    "dropbox-domain-verification": "Dropbox",
    "status-page-domain-verification": "Statuspage",
    "logmein-verification": "LogMeIn",
    "citrix-verification": "Citrix",
    "miro-verification": "Miro",
    "notion-domain-verification": "Notion",
    "canva-site-verification": "Canva",
    "zapier-domain-verification": "Zapier",
    "mongodb-site-verification": "MongoDB Atlas",
    "workplace-domain-verification": "Workplace",
}

_SPF_LOOKUP_MECHANISMS = re.compile(r"\b(include|a|mx|ptr|exists|redirect)[:=]?", re.I)


def _parse_spf(record: str) -> dict:
    """Extract the parts of an SPF record that determine whether it works."""
    tokens = record.split()
    all_qualifier = ""
    for token in tokens:
        if token.lower() in ("all", "+all", "-all", "~all", "?all"):
            all_qualifier = token.lower()
            if all_qualifier == "all":
                all_qualifier = "+all"
    lookups = len(_SPF_LOOKUP_MECHANISMS.findall(record)) - (
        1 if record.lower().startswith("v=spf1") else 0
    )
    return {
        "record": record,
        "all": all_qualifier,
        "lookups": max(0, lookups),
        "has_ptr": " ptr" in f" {record.lower()}",
    }


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            tags[name.strip().lower()] = value.strip()
    return {
        "record": record,
        "policy": tags.get("p", "").lower(),
        "subdomain_policy": tags.get("sp", "").lower(),
        "pct": tags.get("pct", "100"),
        "rua": tags.get("rua", ""),
        "has_reporting": bool(tags.get("rua") or tags.get("ruf")),
    }


async def _try_axfr(nameserver: str, domain: str, timeout: float = 6.0) -> list[str]:
    """Attempt a zone transfer. Returns the record names if the server allows it."""
    if not HAS_DNSPYTHON:
        return []

    ns_ips = await _resolve_ns(nameserver, timeout)
    for ns_ip in ns_ips[:2]:
        names = await _axfr_zone(ns_ip, domain, timeout)
        if names:
            return names
    return []


async def _resolve_ns(nameserver: str, timeout: float) -> list[str]:
    """Resolve a nameserver name to addresses so AXFR can target it directly."""
    import dns.asyncresolver

    try:
        answer = await asyncio.wait_for(
            dns.asyncresolver.resolve(nameserver, "A"), timeout=timeout
        )
        return [r.to_text() for r in answer]
    except Exception:
        return []


async def _axfr_zone(ns_ip: str, domain: str, timeout: float) -> list[str]:
    """Run the transfer in a thread — dnspython's AXFR path is synchronous."""
    import dns.query
    import dns.zone

    def _transfer() -> list[str]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            return [str(name) for name in zone.nodes]
        except Exception:
            return []

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _transfer), timeout=timeout + 4
        )
    except asyncio.TimeoutError:
        return []


async def run(ctx: Context) -> None:
    target = ctx.target
    res = ctx.result
    key = "dns"

    # ── Record sweep ──────────────────────────────────────────────────────
    ctx.progress.task(key, "Collecting records", total=len(RECORD_TYPES))
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        values = await ctx.resolver.query(target, rtype)
        if values:
            records[rtype] = [shuddhi.sanitize(v, max_len=512) for v in values]
        ctx.progress.advance(key)

    res.dns = {"records": records}
    txt_records = records.get("TXT", [])
    nameservers = [n.rstrip(".") for n in records.get("NS", [])]
    ctx.progress.note(key, f"{sum(len(v) for v in records.values())} records across {len(records)} types")

    # ── SPF ───────────────────────────────────────────────────────────────
    spf_raw = next((t for t in txt_records if t.lower().startswith("v=spf1")), "")
    if spf_raw:
        spf = _parse_spf(spf_raw)
        res.dns["spf"] = spf
        if spf["all"] == "+all":
            res.report(
                Severity.HIGH,
                "SPF record permits any sender (+all)",
                asset=target,
                detail="The SPF record ends in +all, which authorises every host "
                       "on the internet to send mail as this domain. It is "
                       "functionally worse than having no SPF record, because "
                       "receivers treat forged mail as explicitly authorised.",
                evidence=spf_raw,
                chakra="DRONA",
                remediation="Replace +all with -all once the legitimate senders "
                            "are enumerated in the record.",
                references=["https://www.rfc-editor.org/rfc/rfc7208"],
            )
        elif spf["all"] in ("?all", ""):
            res.report(
                Severity.MEDIUM,
                "SPF record has no enforcing all mechanism",
                asset=target,
                detail="Without a terminating -all or ~all, receivers have no "
                       "instruction for mail from unlisted hosts and will "
                       "generally deliver it.",
                evidence=spf_raw,
                chakra="DRONA",
                remediation="Terminate the record with ~all while monitoring, "
                            "then move to -all.",
            )
        if spf["lookups"] > 10:
            res.report(
                Severity.LOW,
                f"SPF record exceeds the 10 DNS-lookup limit ({spf['lookups']})",
                asset=target,
                detail="RFC 7208 caps SPF evaluation at 10 DNS lookups. Past "
                       "that, receivers return permerror and the policy stops "
                       "being applied at all.",
                evidence=spf_raw,
                chakra="DRONA",
                remediation="Flatten or consolidate include: mechanisms to get "
                            "back under ten lookups.",
            )
        if spf["has_ptr"]:
            res.report(
                Severity.LOW,
                "SPF record uses the deprecated ptr mechanism",
                asset=target,
                detail="The ptr mechanism is deprecated by RFC 7208 and is "
                       "ignored or treated as an error by several large "
                       "receivers, weakening the policy.",
                evidence=spf_raw,
                chakra="DRONA",
            )
    else:
        res.report(
            Severity.MEDIUM,
            "No SPF record published",
            asset=target,
            detail="With no SPF record, receivers have no list of authorised "
                   "senders for this domain, so mail forged from it is "
                   "materially more likely to be delivered.",
            chakra="DRONA",
            remediation="Publish a TXT record listing legitimate senders and "
                        "terminate it with -all.",
        )

    # ── DMARC ─────────────────────────────────────────────────────────────
    ctx.progress.task(key, "Auditing mail policy")
    dmarc_records = await ctx.resolver.query(f"_dmarc.{target}", "TXT")
    dmarc_raw = next(
        (shuddhi.sanitize(r) for r in dmarc_records if r.lower().startswith("v=dmarc1")), ""
    )
    if dmarc_raw:
        dmarc = _parse_dmarc(dmarc_raw)
        res.dns["dmarc"] = dmarc
        if dmarc["policy"] in ("none", ""):
            res.report(
                Severity.MEDIUM,
                "DMARC policy is set to none",
                asset=target,
                detail="p=none tells receivers to take no action on messages "
                       "that fail authentication, so the record reports on "
                       "spoofing without preventing any of it.",
                evidence=dmarc_raw,
                chakra="DRONA",
                remediation="Move to p=quarantine and then p=reject once the "
                            "aggregate reports show legitimate senders pass.",
                references=["https://www.rfc-editor.org/rfc/rfc7489"],
            )
        if not dmarc["has_reporting"]:
            res.report(
                Severity.LOW,
                "DMARC record requests no aggregate reports",
                asset=target,
                detail="With no rua= address, nobody receives the reports that "
                       "would reveal ongoing spoofing of the domain.",
                evidence=dmarc_raw,
                chakra="DRONA",
            )
        if dmarc["pct"].isdigit() and int(dmarc["pct"]) < 100:
            res.report(
                Severity.LOW,
                f"DMARC policy applied to only {dmarc['pct']}% of mail",
                asset=target,
                detail="pct= below 100 leaves the remaining share of failing "
                       "mail subject to no policy at all.",
                evidence=dmarc_raw,
                chakra="DRONA",
            )
    else:
        res.report(
            Severity.MEDIUM,
            "No DMARC record published",
            asset=target,
            detail="Without a DMARC policy at _dmarc." + target + ", SPF and "
                   "DKIM failures carry no instruction, and the domain can be "
                   "spoofed in display-name and envelope positions that SPF "
                   "alone does not cover.",
            chakra="DRONA",
            remediation="Publish _dmarc TXT with v=DMARC1; p=reject and an rua "
                        "reporting address.",
        )

    # ── DKIM ──────────────────────────────────────────────────────────────
    # Two traps here. A domain can publish a wildcard under _domainkey, which
    # makes every selector appear to exist; and a record with an empty p= is a
    # revoked or null key, which is the opposite of a working selector. Both
    # have to be excluded or this reports twenty signing keys on a domain that
    # signs nothing.
    ctx.progress.task(key, "Probing DKIM selectors", total=len(DKIM_SELECTORS) + 1)

    def _is_live_key(values: list[str]) -> bool:
        for value in values:
            low = value.lower().replace(" ", "")
            if "v=dkim1" not in low:
                continue
            match = re.search(r"p=([a-z0-9+/=]*)", low)
            if match and match.group(1):
                return True
        return False

    wildcard_probe = await ctx.resolver.query(
        f"chakraview-no-such-selector._domainkey.{target}", "TXT"
    )
    ctx.progress.advance(key)
    dkim_wildcard = bool(wildcard_probe)

    found_selectors: list[str] = []
    null_selectors: list[str] = []

    async def probe_selector(selector: str) -> None:
        values = await ctx.resolver.query(f"{selector}._domainkey.{target}", "TXT")
        if values and not dkim_wildcard:
            if _is_live_key(values):
                found_selectors.append(selector)
            elif any("v=dkim1" in v.lower() for v in values):
                null_selectors.append(selector)
        ctx.progress.advance(key)

    await asyncio.gather(*(probe_selector(s) for s in DKIM_SELECTORS))
    found_selectors.sort()
    null_selectors.sort()

    res.dns["dkim_selectors"] = found_selectors
    res.dns["dkim_null_selectors"] = null_selectors
    res.dns["dkim_wildcard"] = dkim_wildcard

    if dkim_wildcard:
        ctx.progress.note(key, "wildcard _domainkey record — selector probing skipped")
        res.report(
            Severity.INFO,
            "Wildcard DKIM record published",
            asset=target,
            detail="Every name under _domainkey." + target + " answers, so "
                   "individual selectors cannot be enumerated. A wildcard with "
                   "an empty p= is the documented way to state that the domain "
                   "signs no mail.",
            evidence="; ".join(shuddhi.sanitize(v, max_len=120) for v in wildcard_probe[:2]),
            chakra="DRONA",
        )
    elif null_selectors:
        res.report(
            Severity.LOW,
            f"{len(null_selectors)} DKIM selectors publish a revoked key",
            asset=target,
            detail="These selectors resolve but carry an empty p= value, which "
                   "revokes the key. Mail signed with them fails verification.",
            evidence=", ".join(null_selectors[:10]),
            chakra="DRONA",
            remediation="Publish a current public key, or remove the selector "
                        "records entirely.",
        )

    if records.get("MX") and not found_selectors and not dkim_wildcard:
        res.report(
            Severity.LOW,
            "No DKIM selector found for a mail-receiving domain",
            asset=target,
            detail="The domain publishes MX records but none of the common "
                   "DKIM selectors resolve to a usable key, so outbound mail is "
                   "likely unsigned and DMARC alignment rests on SPF alone.",
            evidence=f"probed {len(DKIM_SELECTORS)} selectors",
            chakra="DRONA",
            remediation="Enable DKIM signing at the mail provider and publish "
                        "the selector record.",
        )

    # ── CAA ───────────────────────────────────────────────────────────────
    if not records.get("CAA"):
        res.report(
            Severity.INFO,
            "No CAA record published",
            asset=target,
            detail="Any certificate authority may issue for this domain. A CAA "
                   "record restricts issuance to the CAs actually in use.",
            chakra="DRONA",
            remediation="Publish a CAA record naming the authorised CAs.",
        )

    # ── SaaS tenants visible in TXT ───────────────────────────────────────
    tenants = sorted({
        label for token, label in SAAS_VERIFICATION.items()
        for t in txt_records if token.lower() in t.lower()
    })
    res.dns["saas_tenants"] = tenants
    if tenants:
        res.report(
            Severity.INFO,
            f"{len(tenants)} third-party services verified via DNS",
            asset=target,
            detail="Domain-verification TXT records disclose which SaaS "
                   "products the organisation uses. Each is a tenant that "
                   "belongs in scope — SSO, guest access and public sharing "
                   "settings are configured per tenant.",
            evidence=", ".join(tenants),
            chakra="DRONA",
        )
        ctx.progress.hit(key, f"SaaS tenants: {', '.join(tenants[:6])}")

    # ── Zone transfer ─────────────────────────────────────────────────────
    if nameservers and not ctx.cfg.passive_only:
        ctx.progress.task(key, "Testing zone transfer", total=len(nameservers))
        res.dns["axfr"] = {}
        for ns in nameservers:
            if ctx.cancelled():
                break
            names = await _try_axfr(ns, target, timeout=min(ctx.cfg.timeout, 8.0))
            ctx.progress.advance(key)
            if names:
                res.dns["axfr"][ns] = names[:500]
                for name in names:
                    host = shuddhi.normalise_host(
                        target if name == "@" else f"{name}.{target}"
                    )
                    if host:
                        res.add_subdomain(host, "axfr")
                res.report(
                    Severity.CRITICAL,
                    "DNS zone transfer (AXFR) allowed",
                    asset=ns,
                    detail=f"The nameserver {ns} served the full zone for "
                           f"{target} to an unauthenticated request, disclosing "
                           f"{len(names)} record names. This is a complete map "
                           "of the domain's infrastructure, including hosts that "
                           "were never meant to be discoverable.",
                    evidence=f"dig AXFR {target} @{ns} → {len(names)} records",
                    chakra="DRONA",
                    remediation="Restrict AXFR to authorised secondary "
                                "nameservers with an allow-transfer ACL or TSIG.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                )
                ctx.progress.hit(key, f"AXFR OPEN on {ns} — {len(names)} records")

    summary_bits = [f"{len(records)} record types"]
    if dkim_wildcard:
        summary_bits.append("DKIM: wildcard")
    elif found_selectors:
        summary_bits.append(f"DKIM: {len(found_selectors)}")
    if tenants:
        summary_bits.append(f"{len(tenants)} SaaS tenants")
    if res.dns.get("axfr"):
        summary_bits.append("AXFR OPEN")
    ctx.progress.chakra_done(key, " · ".join(summary_bits))
