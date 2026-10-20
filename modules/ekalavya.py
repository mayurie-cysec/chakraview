"""
EKALAVYA — the one who claims what was never granted to him.

Subdomain takeover: a CNAME still points at a SaaS provider after the
account, bucket or app behind it is gone. Anyone can register the vacant name
at that provider and serve content from the organisation's own hostname,
which breaks every assumption built on domain trust — session cookies scoped
to the parent domain, OAuth redirect allowlists, CSP source lists and
password-manager autofill.

Detection requires two signals, not one. A CNAME into a known provider is
normal and expected; it is only a finding when the provider also returns its
specific "this name is unclaimed" response. Matching on the CNAME alone is
how these tools generate false positives.
"""

from __future__ import annotations

import asyncio

from core.context import Context
from core.models import Severity, Subdomain

# (service, cname_fragments, body_fingerprints, nxdomain_is_enough)
#
# nxdomain_is_enough marks providers where the CNAME target itself failing to
# resolve is the takeover condition — mostly Azure resources, where claiming
# the name recreates the DNS entry.
FINGERPRINTS: list[tuple[str, tuple[str, ...], tuple[str, ...], bool]] = [
    ("GitHub Pages", ("github.io", "github.map.fastly.net"),
     ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"), False),
    ("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
     ("No such app", "There's nothing here, yet."), False),
    ("AWS S3", ("s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com"),
     ("NoSuchBucket", "The specified bucket does not exist"), False),
    ("Shopify", ("myshopify.com", "shops.myshopify.com"),
     ("Sorry, this shop is currently unavailable", "Only one step left!"), False),
    ("Fastly", ("fastly.net", "fastlylb.net"),
     ("Fastly error: unknown domain",), False),
    ("Pantheon", ("pantheonsite.io", "pantheon.io"),
     ("The gods are wise", "404 error unknown site"), False),
    ("Tumblr", ("domains.tumblr.com", "tumblr.com"),
     ("Whatever you were looking for doesn't currently exist at this address",), False),
    ("WordPress.com", ("wordpress.com",),
     ("Do you want to register",), False),
    ("Zendesk", ("zendesk.com",),
     ("Help Center Closed", "this help center no longer exists"), False),
    ("Desk.com", ("desk.com",),
     ("Sorry, We Couldn't Find That Page",), False),
    ("Campaign Monitor", ("createsend.com", "createsend.net"),
     ("Trying to access your account?", "double-check the address"), False),
    ("Statuspage", ("statuspage.io",),
     ("You are being redirected", "Better Status Communication"), False),
    ("Surge.sh", ("surge.sh",), ("project not found",), False),
    ("Bitbucket", ("bitbucket.io",), ("Repository not found",), False),
    ("Intercom", ("custom.intercom.help", "intercom.help"),
     ("This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"), False),
    ("Webflow", ("proxy-ssl.webflow.com", "proxy.webflow.com", "webflow.io"),
     ("The page you are looking for doesn't exist or has been moved",), False),
    ("Ghost", ("ghost.io",),
     ("The thing you were looking for is no longer here", "Domain error"), False),
    ("Help Scout", ("helpscoutdocs.com",),
     ("No settings were found for this company",), False),
    ("Helpjuice", ("helpjuice.com",), ("We could not find what you're looking for",), False),
    ("Cargo Collective", ("cargocollective.com",), ("404 Not Found",), False),
    ("Feedpress", ("redirect.feedpress.me",), ("The feed has not been found",), False),
    ("Kajabi", ("endpoint.mykajabi.com",), ("The page you were looking for doesn't exist",), False),
    ("Thinkific", ("thinkific.com",), ("You may have mistyped the address or the page may have moved",), False),
    ("Teamwork", ("teamwork.com",), ("Oops - We didn't find your site",), False),
    ("Aha!", ("ideas.aha.io",), ("There is no portal here", "sending you back to Aha!"), False),
    ("Netlify", ("netlify.app", "netlify.com", "bitballoon.com"),
     ("Not Found - Request ID", "404 Not Found"), False),
    ("Readme.io", ("readme.io",), ("Project doesnt exist", "project doesn't exist"), False),
    ("Strikingly", ("s.strikinglydns.com", "strikinglydns.com"),
     ("page not found", "But if you're looking to build your own website"), False),
    ("Uberflip", ("read.uberflip.com",),
     ("Non-hub domain", "The URL you've accessed does not provide a hub"), False),
    ("Unbounce", ("unbouncepages.com",),
     ("The requested URL was not found on this server",), False),
    ("UptimeRobot", ("stats.uptimerobot.com",), ("page not found",), False),
    ("UserVoice", ("uservoice.com",), ("This UserVoice subdomain is currently available",), False),
    ("Big Cartel", ("bigcartel.com",), ("Oops! We couldn", "t find that page"), False),
    ("Acquia", ("acquia-sites.com", "acquia-test.co"),
     ("The site you are looking for could not be found", "Web Site Not Found"), False),
    ("Agile CRM", ("agilecrm.com",), ("Sorry, this page is no longer available",), False),
    ("Brightcove", ("brightcovegallery.com", "bcvp0rtal.com"),
     ("Error Code: 404",), False),
    ("Launchrock", ("launchrock.com",),
     ("It looks like you may have taken a wrong turn somewhere",), False),
    ("Vend", ("vendecommerce.com",),
     ("Looks like you've traveled too far into cyberspace",), False),
    ("Short.io", ("cname.short.io", "short.io"), ("Link does not exist",), False),
    ("Hatena Blog", ("hatenablog.com",), ("404 Blog is not found",), False),
    ("GitBook", ("gitbook.io", "gitbook.com"),
     ("If you need specifics, here's the error", "Domain not found"), False),
    ("Frontify", ("frontify.com",), ("404 - Page Not Found",), False),
    ("Kinsta", ("kinsta.cloud",), ("No Site For Domain",), False),
    ("Anima", ("animaapp.io",),
     ("If this is your website and you've just created it",), False),
    ("Wishpond", ("wishpond.com",), ("https://www.wishpond.com/404?campaign=true",), False),
    ("Smugmug", ("domains.smugmug.com",), ("Page Not Found",), False),
    ("Tave", ("clientaccess.tave.com",), ("Error 404",), False),
    ("AfterShip", ("aftership.com",), ("Oops.", "Something went wrong"), False),
    # NXDOMAIN-only providers: no HTTP response to fingerprint against.
    ("Azure App Service", ("azurewebsites.net",), (), True),
    ("Azure Cloud App", ("cloudapp.azure.com", "cloudapp.net"), (), True),
    ("Azure Traffic Manager", ("trafficmanager.net",), (), True),
    ("Azure Blob Storage", ("blob.core.windows.net",), (), True),
    ("Azure CDN", ("azureedge.net",), (), True),
    ("Azure API Management", ("azure-api.net",), (), True),
    ("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), (), True),
    ("AWS CloudFront", ("cloudfront.net",), ("The request could not be satisfied", "ERROR: The request could not be satisfied"), False),
    ("Google Cloud Storage", ("storage.googleapis.com", "c.storage.googleapis.com"),
     ("NoSuchBucket", "The specified bucket does not exist"), False),
]


def _match_service(cname: str) -> tuple[str, tuple[str, ...], bool] | None:
    low = cname.lower()
    for service, fragments, bodies, nx_only in FINGERPRINTS:
        if any(fragment in low for fragment in fragments):
            return service, bodies, nx_only
    return None


async def _check(ctx: Context, entry: Subdomain) -> dict | None:
    """Return a takeover candidate dict, or None."""
    cname = entry.cname or await ctx.resolver.cname(entry.host)
    if not cname:
        return None
    entry.cname = cname

    matched = _match_service(cname)
    if matched is None:
        return None
    service, body_fingerprints, nx_only = matched

    # Does the CNAME target itself still resolve?
    target_ips = await ctx.resolver.resolve_a(cname)

    if nx_only:
        if target_ips:
            return None
        return {
            "host": entry.host,
            "cname": cname,
            "service": service,
            "signal": "CNAME target does not resolve (NXDOMAIN)",
            "confidence": "high",
        }

    # Otherwise require the provider's unclaimed-name response.
    if not body_fingerprints:
        return None
    for scheme in ("https", "http"):
        resp = await ctx.http.get(f"{scheme}://{entry.host}")
        if resp is None:
            continue
        try:
            body = resp.text[:60_000]
        except (UnicodeDecodeError, ValueError):
            continue
        for fingerprint in body_fingerprints:
            if fingerprint.lower() in body.lower():
                return {
                    "host": entry.host,
                    "cname": cname,
                    "service": service,
                    "signal": f"provider returned its unclaimed-name page: "
                              f"{fingerprint!r}",
                    "confidence": "high",
                    "status": resp.status_code,
                }
        break

    if not target_ips:
        return {
            "host": entry.host,
            "cname": cname,
            "service": service,
            "signal": "CNAME points at the provider but the target does not resolve",
            "confidence": "medium",
        }
    return None


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "takeover"

    # Any collected name can be dangling, including ones that do not resolve —
    # an NXDOMAIN with a live CNAME is the classic takeover shape.
    candidates = list(res.subdomains.values())
    if not candidates:
        ctx.progress.note(key, "no hosts to check")
        return

    ctx.progress.task(key, f"Checking {len(candidates)} hosts for dangling CNAMEs",
                      total=len(candidates))
    sem = asyncio.Semaphore(ctx.cfg.concurrency)
    hits: list[dict] = []

    async def check(entry: Subdomain) -> None:
        if ctx.cancelled():
            ctx.progress.advance(key)
            return
        async with sem:
            try:
                result = await _check(ctx, entry)
            except Exception as exc:
                res.errors.append(f"ekalavya/{entry.host}: {type(exc).__name__}")
                result = None
        ctx.progress.advance(key)
        if result:
            hits.append(result)
            ctx.progress.hit(key, f"TAKEOVER {result['service']} → {result['host']}")

    await asyncio.gather(*(check(e) for e in candidates))

    res.takeover = hits
    for hit in hits:
        severity = Severity.HIGH if hit["confidence"] == "high" else Severity.MEDIUM
        res.report(
            severity,
            f"Subdomain takeover possible via {hit['service']}",
            asset=hit["host"],
            detail=f"{hit['host']} is a CNAME to {hit['cname']} ({hit['service']}) "
                   f"but the resource behind it is unclaimed — {hit['signal']}. "
                   "Registering that name at the provider serves attacker "
                   "content from this hostname, which defeats controls that "
                   "trust the domain: cookies scoped to the parent domain, "
                   "OAuth redirect allowlists, CSP source lists and SSO flows.",
            evidence=f"{hit['host']} CNAME {hit['cname']} — {hit['signal']}",
            chakra="EKALAVYA",
            remediation="Remove the DNS record, or re-claim the resource at the "
                        "provider before anyone else does.",
            references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
        )

    cname_count = sum(1 for e in res.subdomains.values() if e.cname)
    ctx.progress.chakra_done(
        key,
        f"{cname_count} CNAMEs reviewed · "
        + (f"{len(hits)} takeover candidate(s)" if hits else "none dangling"),
    )
