"""
BRAHMASTRA — the weapon of last resort, aimed by hand.

Dork generation. The previous version emitted plain query strings an operator
had to retype into a search engine. These are emitted as ready URLs, and they
are built from what the scan actually discovered — the technologies arjuna
fingerprinted, the subdomains karna found, the GitHub org shakuni identified —
so the queries are specific to this target instead of being a generic list.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from core.context import Context
from core.models import Severity
from core.net import apex_domain

# Engines a dork can be handed to directly.
ENGINES: dict[str, str] = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "Startpage": "https://www.startpage.com/sp/search?query={q}",
}

# Technology-specific dorks, keyed by the label arjuna reports.
TECH_DORKS: dict[str, list[str]] = {
    "WordPress": [
        'site:{d} inurl:wp-content/uploads filetype:php',
        'site:{d} inurl:wp-json/wp/v2/users',
        'site:{d} inurl:wp-content/debug.log',
    ],
    "Jenkins": [
        'site:{d} inurl:jenkins inurl:script',
        'site:{d} inurl:/job/ "Console Output"',
    ],
    "Jira": [
        'site:{d} inurl:jira inurl:ViewUserHover.jspa',
        'site:{d} inurl:/secure/Dashboard.jspa',
    ],
    "Confluence": ['site:{d} inurl:/display/ "Confluence"'],
    "GitLab": ['site:{d} inurl:/explore/projects'],
    "Grafana": ['site:{d} inurl:/d/ OR inurl:/dashboard/db/'],
    "Swagger UI": ['site:{d} inurl:swagger-ui OR inurl:api-docs'],
    "GraphQL": ['site:{d} inurl:graphql OR inurl:graphiql'],
    "Drupal": ['site:{d} inurl:/node/ OR inurl:/user/login'],
    "phpMyAdmin": ['site:{d} inurl:phpmyadmin'],
    "Tomcat": ['site:{d} inurl:/manager/html OR inurl:/host-manager'],
    "ASP.NET": ['site:{d} filetype:config OR inurl:web.config', 'site:{d} inurl:trace.axd'],
    "Keycloak": ['site:{d} inurl:/auth/realms/'],
    "Spring Boot": ['site:{d} inurl:/actuator'],
    "Magento": ['site:{d} inurl:/downloader OR inurl:/admin'],
}


def _build(domain: str, github_org: str) -> list[dict]:
    """The base arsenal, grouped so an operator can work through it in order."""
    d = domain
    groups: list[tuple[str, list[str]]] = [
        ("Credentials & secrets", [
            f'site:github.com "{d}" password OR secret OR api_key',
            f'site:gitlab.com "{d}" password OR token',
            f'site:pastebin.com "{d}"',
            f'site:gist.github.com "{d}"',
            f'site:trello.com "{d}"',
            f'site:jsfiddle.net OR site:codepen.io OR site:replit.com "{d}"',
            f'site:stackoverflow.com "{d}" password OR config OR connection string',
            f'site:scribd.com OR site:slideshare.net "{d}" confidential',
        ]),
        ("Exposed files", [
            f'site:{d} filetype:env OR filetype:sql OR filetype:bak OR filetype:log',
            f'site:{d} filetype:xml inurl:config',
            f'site:{d} filetype:json inurl:api',
            f'site:{d} filetype:pem OR filetype:key OR filetype:ppk',
            f'site:{d} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{d} filetype:pdf "internal use only" OR "confidential"',
            f'site:{d} filetype:conf OR filetype:cnf OR filetype:ini',
            f'site:{d} ext:bak OR ext:old OR ext:orig OR ext:save',
        ]),
        ("Admin & login", [
            f'site:{d} inurl:admin OR inurl:login OR inurl:dashboard',
            f'site:{d} inurl:wp-admin OR inurl:phpmyadmin OR inurl:adminer',
            f'site:{d} intitle:"login" OR intitle:"sign in" -inurl:blog',
            f'site:{d} inurl:console OR inurl:manager OR inurl:portal',
        ]),
        ("Errors & disclosure", [
            f'site:{d} "Warning: mysql_" OR "ORA-" OR "syntax error"',
            f'site:{d} "Index of /" intitle:"Index of"',
            f'site:{d} "Fatal error" OR "Uncaught exception" OR "Traceback"',
            f'site:{d} intext:"sql syntax near" OR intext:"unclosed quotation mark"',
            f'site:{d} "phpinfo()" OR intitle:"phpinfo()"',
            f'site:{d} intext:"Whitelabel Error Page" OR intext:"Werkzeug Debugger"',
        ]),
        ("Dev, staging & internal", [
            f'site:{d} inurl:dev OR inurl:staging OR inurl:test OR inurl:uat',
            f'site:{d} inurl:internal OR inurl:intranet OR inurl:private',
            f'site:{d} inurl:debug OR inurl:trace OR inurl:_profiler',
            f'site:{d} inurl:.git OR inurl:.svn OR inurl:.env',
        ]),
        ("APIs & documentation", [
            f'site:{d} inurl:swagger OR inurl:api-docs OR inurl:openapi',
            f'site:{d} inurl:graphql OR inurl:graphiql',
            f'site:{d} inurl:/api/ intext:"apiKey" OR intext:"bearer"',
            f'site:{d} inurl:postman OR inurl:redoc',
        ]),
        ("Cloud storage", [
            f'site:s3.amazonaws.com "{d}"',
            f'site:blob.core.windows.net "{d}"',
            f'site:storage.googleapis.com "{d}"',
            f'site:digitaloceanspaces.com "{d}"',
            f'"{d}" inurl:s3.amazonaws.com OR inurl:s3-website',
        ]),
        ("People & phishing surface", [
            f'site:linkedin.com/in "{d}"',
            f'site:{d} intext:"@{d}" filetype:pdf OR filetype:docx',
            f'"@{d}" -site:{d} email',
        ]),
    ]
    if github_org:
        groups.append(("GitHub organisation", [
            f'site:github.com/{github_org} password OR secret OR token',
            f'site:github.com/{github_org} filename:.env',
            f'site:github.com "{github_org}" "BEGIN RSA PRIVATE KEY"',
        ]))

    return [
        {"group": name, "query": query, "urls": {
            engine: template.format(q=quote_plus(query))
            for engine, template in ENGINES.items()
        }}
        for name, queries in groups for query in queries
    ]


def _platform_links(domain: str, github_org: str, ips: list[str]) -> dict[str, list[dict]]:
    """Pre-built searches on platforms that are not general search engines."""
    links: dict[str, list[dict]] = {
        "GitHub code search": [
            {"label": f'"{domain}" with password', "url": f"https://github.com/search?type=code&q=%22{quote_plus(domain)}%22+password"},
            {"label": f'"{domain}" in .env files', "url": f"https://github.com/search?type=code&q=%22{quote_plus(domain)}%22+filename%3A.env"},
            {"label": f'"{domain}" with AWS keys', "url": f"https://github.com/search?type=code&q=%22{quote_plus(domain)}%22+AWS_SECRET_ACCESS_KEY"},
            {"label": f'"{domain}" with private keys', "url": f"https://github.com/search?type=code&q=%22{quote_plus(domain)}%22+%22BEGIN+RSA+PRIVATE+KEY%22"},
        ],
        "Shodan": [
            {"label": f"hostname:{domain}", "url": f"https://www.shodan.io/search?query=hostname%3A{quote_plus(domain)}"},
            {"label": f"ssl.cert.subject.CN:{domain}", "url": f"https://www.shodan.io/search?query=ssl.cert.subject.CN%3A%22{quote_plus(domain)}%22"},
            {"label": f"ssl:{domain} http.title filtered", "url": f"https://www.shodan.io/search?query=ssl%3A%22{quote_plus(domain)}%22+-http.title%3A%22403%22"},
        ],
        "Censys": [
            {"label": f"names: {domain}", "url": f"https://search.censys.io/search?resource=hosts&q=names%3A{quote_plus(domain)}"},
            {"label": "certificate subject", "url": f"https://search.censys.io/search?resource=certificates&q=names%3A{quote_plus(domain)}"},
        ],
        "FOFA": [
            {"label": f"domain={domain}", "url": f"https://en.fofa.info/result?qbase64={quote_plus(domain)}"},
        ],
        "Certificate transparency": [
            {"label": "crt.sh certificates", "url": f"https://crt.sh/?q=%25.{quote_plus(domain)}"},
            {"label": "Censys certificates", "url": f"https://search.censys.io/search?resource=certificates&q={quote_plus(domain)}"},
        ],
        "Archives": [
            {"label": "Wayback CDX (all URLs)", "url": f"https://web.archive.org/cdx/search/cdx?url=*.{quote_plus(domain)}&output=text&fl=original&collapse=urlkey"},
            {"label": "Wayback calendar", "url": f"https://web.archive.org/web/*/{quote_plus(domain)}/*"},
        ],
        "Breach & paste monitoring": [
            {"label": "Have I Been Pwned (domain)", "url": f"https://haveibeenpwned.com/DomainSearch"},
            {"label": "DeHashed", "url": f"https://dehashed.com/search?query={quote_plus(domain)}"},
            {"label": "IntelligenceX", "url": f"https://intelx.io/?s={quote_plus(domain)}"},
        ],
        "Passive DNS & infrastructure": [
            {"label": "SecurityTrails history", "url": f"https://securitytrails.com/domain/{quote_plus(domain)}/history/a"},
            {"label": "ViewDNS reverse IP", "url": f"https://viewdns.info/reverseip/?host={quote_plus(domain)}&t=1"},
            {"label": "urlscan.io", "url": f"https://urlscan.io/domain/{quote_plus(domain)}"},
        ],
    }
    if github_org:
        links["GitHub organisation"] = [
            {"label": f"{github_org} repositories", "url": f"https://github.com/{quote_plus(github_org)}?tab=repositories"},
            {"label": f"{github_org} members", "url": f"https://github.com/orgs/{quote_plus(github_org)}/people"},
        ]
    if ips:
        links["Reverse IP"] = [
            {"label": f"Shodan {ip}", "url": f"https://www.shodan.io/host/{quote_plus(ip)}"}
            for ip in ips[:5]
        ]
    return links


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "dorks"
    apex = apex_domain(ctx.target)

    github_org = ""
    profile = (res.github or {}).get("org_profile") or {}
    if profile.get("login"):
        github_org = profile["login"]

    ctx.progress.task(key, "Composing dork arsenal")
    dorks = _build(apex, github_org)

    # Add dorks for every technology the scan actually fingerprinted.
    technologies = list((res.infra or {}).get("technologies") or {})
    tech_dorks: list[dict] = []
    for tech in technologies:
        for template in TECH_DORKS.get(tech, []):
            query = template.format(d=apex)
            tech_dorks.append({
                "group": f"Technology: {tech}",
                "query": query,
                "urls": {
                    engine: template_url.format(q=quote_plus(query))
                    for engine, template_url in ENGINES.items()
                },
            })
    dorks.extend(tech_dorks)

    # Subdomain-specific dorks for the most interesting hosts found.
    gated = [
        entry for entry in res.hosts_alive()
        if entry.status in (401, 403) or any(
            token in entry.host for token in ("admin", "internal", "dev", "stage", "test", "api")
        )
    ][:10]
    for entry in gated:
        query = f"site:{entry.host}"
        dorks.append({
            "group": "Discovered hosts",
            "query": query,
            "urls": {
                engine: template.format(q=quote_plus(query))
                for engine, template in ENGINES.items()
            },
        })

    ips = [a["ip"] for a in (res.infra or {}).get("addresses", []) if a.get("ip")]
    platforms = _platform_links(apex, github_org, ips)

    res.dorks = {
        "queries": dorks,
        "platforms": platforms,
        "note": "Paste into the engine of choice, or open the prepared links. "
                "Search-engine results are historical — confirm each hit "
                "against the live application before reporting it.",
    }

    res.report(
        Severity.INFO,
        f"{len(dorks)} targeted search queries prepared",
        asset=apex,
        detail=f"{len(dorks)} dorks across {len({d['group'] for d in dorks})} "
               f"categories, including {len(tech_dorks)} built from the "
               "technologies fingerprinted on this target, plus prepared "
               f"searches on {len(platforms)} external platforms. These require "
               "manual review — a search engine index is evidence of what was "
               "once reachable, not proof of what is reachable now.",
        evidence=f"groups: {', '.join(sorted({d['group'] for d in dorks}))}",
        chakra="BRAHMASTRA",
    )

    ctx.progress.chakra_done(
        key, f"{len(dorks)} queries · {len(platforms)} platform link sets"
    )
