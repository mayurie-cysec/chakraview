"""
SANJAYA — infrastructure sight.

Resolves every address the apex answers with (not just the first), enriches
each one through ipinfo, and decides whether what we are looking at is the
origin or a CDN edge. That distinction drives the rest of the engagement: if
the apex sits behind Cloudflare, port scanning the apex tells you about
Cloudflare, and the real work is origin discovery.
"""

from __future__ import annotations

from core.context import Context
from core.models import Severity
from modules import shuddhi

# Matched against the ipinfo org/ASN string. Hitting one of these means the
# address in hand is an edge node, not the customer's own infrastructure.
CDN_WAF_SIGNATURES: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "incapsula": "Imperva Incapsula",
    "imperva": "Imperva",
    "sucuri": "Sucuri",
    "stackpath": "StackPath",
    "cloudfront": "AWS CloudFront",
    "amazon cloudfront": "AWS CloudFront",
    "edgecast": "Edgecast",
    "limelight": "Limelight",
    "cdn77": "CDN77",
    "bunnycdn": "Bunny CDN",
    "bunny.net": "Bunny CDN",
    "keycdn": "KeyCDN",
    "azure front door": "Azure Front Door",
    "frontdoor": "Azure Front Door",
    "google cloud cdn": "Google Cloud CDN",
    "qrator": "Qrator",
    "ddos-guard": "DDoS-Guard",
    "x4b": "X4B",
    "arvancloud": "ArvanCloud",
    "gcore": "G-Core Labs",
    "myracloud": "Myra Security",
    "f5": "F5",
}

# Hyperscalers. Not a CDN, but knowing the host tells you which metadata
# endpoint, which bucket naming scheme and which IAM mistakes to look for.
CLOUD_SIGNATURES: dict[str, str] = {
    "amazon": "AWS",
    "aws": "AWS",
    "microsoft": "Azure",
    "azure": "Azure",
    "google": "GCP",
    "digitalocean": "DigitalOcean",
    "linode": "Linode / Akamai",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
    "scaleway": "Scaleway",
    "contabo": "Contabo",
}


def _classify(org: str) -> tuple[str, str]:
    """Return (cdn_name, cloud_name); either may be empty."""
    low = org.lower()
    cdn = next((label for sig, label in CDN_WAF_SIGNATURES.items() if sig in low), "")
    cloud = "" if cdn else next(
        (label for sig, label in CLOUD_SIGNATURES.items() if sig in low), ""
    )
    return cdn, cloud


async def _enrich(ctx: Context, ip: str) -> dict:
    """ipinfo lookup for one address. Free tier, no key, 50k/month."""
    data = await ctx.http.json(f"https://ipinfo.io/{ip}/json")
    if not isinstance(data, dict):
        return {"ip": ip, "org": "", "city": "", "region": "", "country": "", "hostname": ""}
    return {
        "ip": ip,
        "org": shuddhi.sanitize(data.get("org", ""), max_len=160),
        "city": shuddhi.sanitize(data.get("city", ""), max_len=80),
        "region": shuddhi.sanitize(data.get("region", ""), max_len=80),
        "country": shuddhi.sanitize(data.get("country", ""), max_len=8),
        "hostname": shuddhi.sanitize(data.get("hostname", ""), max_len=253),
    }


async def run(ctx: Context) -> None:
    target = ctx.target
    res = ctx.result
    key = "infra"

    ctx.progress.task(key, "Resolving apex addresses")
    ipv4 = await ctx.resolver.query(target, "A")
    ipv6 = await ctx.resolver.query(target, "AAAA")
    addresses = ipv4 + ipv6

    if not addresses:
        res.infra = {"resolved": False, "note": "Apex does not resolve"}
        res.report(
            Severity.INFO,
            "Apex domain does not resolve",
            asset=target,
            detail="No A or AAAA record on the apex. The domain may be parked, "
                   "internal-only, or serving from subdomains exclusively.",
            chakra="SANJAYA",
        )
        ctx.progress.note(key, "apex does not resolve")
        return

    ctx.progress.task(key, "Enriching addresses", total=len(addresses))
    records = []
    for ip in addresses:
        record = await _enrich(ctx, ip)
        record["reverse_dns"] = shuddhi.sanitize(
            await ctx.resolver.reverse(ip), max_len=253
        )
        cdn, cloud = _classify(record["org"])
        record["cdn"] = cdn
        record["cloud"] = cloud
        records.append(record)
        ctx.progress.advance(key)
        ctx.progress.hit(key, f"{ip}  {record['org'] or 'unknown org'}")

    # Record the addresses on the apex's own subdomain entry so it is treated
    # as a resolved host by every later chakra, even when enumeration is skipped.
    apex_entry = res.add_subdomain(target, "target")
    apex_entry.ips = addresses
    if not apex_entry.cname:
        apex_entry.cname = await ctx.resolver.cname(target)

    primary = records[0]
    cdns = sorted({r["cdn"] for r in records if r["cdn"]})
    clouds = sorted({r["cloud"] for r in records if r["cloud"]})

    res.infra = {
        "resolved": True,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "addresses": records,
        "ip": primary["ip"],
        "org": primary["org"],
        "city": primary["city"],
        "country": primary["country"],
        "reverse_dns": primary["reverse_dns"] or "None",
        "cdn": bool(cdns),
        "cdn_names": cdns,
        "cloud_names": clouds,
    }

    if cdns:
        provider = ", ".join(cdns)
        res.infra["observation"] = (
            f"Behind {provider}. The origin address is masked — pivot to "
            "historical DNS, SPF/MX records, or subdomains that bypass the edge."
        )
        res.report(
            Severity.INFO,
            f"Edge protection in front of apex ({provider})",
            asset=target,
            detail=f"Apex resolves to {provider} infrastructure, so the origin "
                   "server address is not directly visible. Scans against these "
                   "addresses describe the CDN, not the customer.",
            evidence=", ".join(r["ip"] for r in records if r["cdn"]),
            chakra="SANJAYA",
            remediation="Confirm the origin only accepts traffic from the edge, "
                        "so a leaked origin IP cannot be reached directly.",
        )
    else:
        res.infra["observation"] = (
            f"Direct origin exposed on {primary['ip']}"
            + (f" ({primary['org']})" if primary["org"] else "")
        )
        res.report(
            Severity.LOW,
            "Origin address directly exposed",
            asset=target,
            detail="No CDN or WAF sits in front of the apex, so the origin host "
                   "is reachable directly and absorbs traffic and scans itself.",
            evidence=f"{primary['ip']} {primary['org']}".strip(),
            chakra="SANJAYA",
            remediation="Consider fronting the origin with a CDN/WAF and "
                        "restricting origin access to the edge ranges.",
        )

    if len(addresses) > 4 and not cdns:
        res.report(
            Severity.INFO,
            f"Apex answers with {len(addresses)} addresses",
            asset=target,
            detail="A large address pool usually means round-robin load "
                   "balancing. Test every address — configuration frequently "
                   "drifts between nodes in the pool.",
            evidence=", ".join(addresses[:12]),
            chakra="SANJAYA",
        )

    ctx.progress.chakra_done(
        key,
        f"{len(addresses)} address(es)"
        + (f" · {', '.join(cdns)}" if cdns else " · direct origin"),
    )
