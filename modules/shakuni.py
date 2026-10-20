"""
SHAKUNI — the strategist who wins by knowing the other side's people.

GitHub OSINT. The original version exited immediately without a token, which
meant the chakra did nothing for anyone who had not set one up. It now runs
unauthenticated (GitHub allows 60 requests an hour that way) and says plainly
which capabilities the missing token costs, because code search — the part
that actually finds leaked credentials — is authenticated-only.

Nothing here touches the target. Every request goes to api.github.com.
"""

from __future__ import annotations

import asyncio
import re

from core.context import Context
from core.models import Severity
from core.net import apex_domain
from modules import shuddhi

API = "https://api.github.com"

# Filenames that are findings on their own when they appear in a repository
# that also references the target domain.
SENSITIVE_FILENAMES = re.compile(
    r"(^|/)(\.env(\.|$)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
    r"id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem$|.*\.ppk$|.*\.pfx$|.*\.p12$|"
    r".*\.kdbx$|credentials$|secrets?\.(ya?ml|json|js|ts|py|xml|txt)$|"
    r"settings\.py$|local\.settings\.json$|wp-config\.php$|web\.config$|"
    r"database\.ya?ml$|application\.properties$|terraform\.tfstate$|"
    r"\.aws/credentials$|kubeconfig$|\.dockercfg$|\.docker/config\.json$|"
    r"service[-_]?account.*\.json$|dump\.sql$|backup\.sql$)",
    re.I,
)

# Code-search queries that have the highest hit rate for real leaks.
CODE_SEARCH_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" filename:.env',
    '"{domain}" AWS_SECRET_ACCESS_KEY',
    '"{domain}" filename:credentials',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" authorization bearer',
]


def _headers(token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "github"
    token = ctx.cfg.github_token
    headers = _headers(token)
    apex = apex_domain(ctx.target)
    org_name = apex.split(".")[0]

    data: dict = {
        "authenticated": bool(token),
        "org": org_name,
        "repos": [],
        "members": [],
        "emails": [],
        "leaks": [],
        "rate_limited": False,
    }
    res.github = data

    if not token:
        ctx.progress.note(
            key,
            "no GITHUB_TOKEN — running unauthenticated (60 req/hr, code search unavailable)",
        )
        res.report(
            Severity.INFO,
            "GitHub code search skipped — no API token",
            asset=ctx.target,
            detail="Code search is the part of GitHub reconnaissance that finds "
                   "committed credentials, and GitHub requires authentication "
                   "for it. Set GITHUB_TOKEN with a read-only token and re-run "
                   "this chakra for full coverage.",
            chakra="SHAKUNI",
        )

    # ── Organisation ──────────────────────────────────────────────────────
    ctx.progress.task(key, f"Looking up organisation '{org_name}'")
    org = await ctx.http.json(f"{API}/orgs/{org_name}", headers=headers)
    if isinstance(org, dict) and org.get("login"):
        data["org_profile"] = {
            "login": shuddhi.sanitize(org.get("login", ""), max_len=80),
            "name": shuddhi.sanitize(org.get("name") or "", max_len=120),
            "email": shuddhi.sanitize(org.get("email") or "", max_len=160),
            "blog": shuddhi.sanitize(org.get("blog") or "", max_len=200),
            "public_repos": org.get("public_repos", 0),
            "location": shuddhi.sanitize(org.get("location") or "", max_len=120),
        }
        ctx.progress.hit(key, f"org {org_name}: {org.get('public_repos', 0)} public repos")

        # ── Repositories ──────────────────────────────────────────────────
        ctx.progress.task(key, "Listing public repositories")
        repos = await ctx.http.json(
            f"{API}/orgs/{org_name}/repos?per_page=100&sort=pushed", headers=headers
        )
        if isinstance(repos, list):
            for repo in repos:
                if not isinstance(repo, dict):
                    continue
                data["repos"].append({
                    "full_name": shuddhi.sanitize(repo.get("full_name", ""), max_len=140),
                    "description": shuddhi.sanitize(repo.get("description") or "", max_len=200),
                    "language": shuddhi.sanitize(repo.get("language") or "", max_len=40),
                    "pushed_at": shuddhi.sanitize(repo.get("pushed_at") or "", max_len=32),
                    "stars": repo.get("stargazers_count", 0),
                    "url": shuddhi.sanitize(repo.get("html_url", ""), max_len=200),
                })
            ctx.progress.note(key, f"{len(data['repos'])} public repositories")

        # ── Members ───────────────────────────────────────────────────────
        ctx.progress.task(key, "Listing public members")
        members = await ctx.http.json(
            f"{API}/orgs/{org_name}/members?per_page=100", headers=headers
        )
        if isinstance(members, list):
            data["members"] = [
                shuddhi.sanitize(m.get("login", ""), max_len=60)
                for m in members if isinstance(m, dict) and m.get("login")
            ]
            if data["members"]:
                ctx.progress.hit(key, f"{len(data['members'])} public org members")

    # ── Contributor identities and commit emails ──────────────────────────
    # Commit metadata carries the author email, which is how corporate address
    # formats leak and how a password-spray list gets built.
    top_repos = data["repos"][:8]
    if top_repos:
        ctx.progress.task(key, "Reading commit authors", total=len(top_repos))
        sem = asyncio.Semaphore(5)
        emails: set[str] = set()
        contributors: set[str] = set()

        async def read_commits(repo: dict) -> None:
            async with sem:
                commits = await ctx.http.json(
                    f"{API}/repos/{repo['full_name']}/commits?per_page=100", headers=headers
                )
            ctx.progress.advance(key)
            if not isinstance(commits, list):
                return
            for commit in commits:
                if not isinstance(commit, dict):
                    continue
                author = (commit.get("commit") or {}).get("author") or {}
                email = shuddhi.sanitize(author.get("email") or "", max_len=160).lower()
                if email and "noreply" not in email and "@" in email:
                    emails.add(email)
                login = ((commit.get("author") or {}) or {}).get("login") or ""
                if login:
                    contributors.add(shuddhi.sanitize(login, max_len=60))

        await asyncio.gather(*(read_commits(r) for r in top_repos))
        data["emails"] = sorted(emails)
        data["contributors"] = sorted(contributors)

        corporate = sorted(e for e in emails if e.endswith(f"@{apex}"))
        if corporate:
            res.report(
                Severity.LOW,
                f"{len(corporate)} corporate email addresses in public commit history",
                asset=ctx.target,
                detail="Commit metadata in public repositories exposes the "
                       "organisation's email address format and a list of real "
                       "staff addresses. That is the input for credential "
                       "stuffing and for targeted phishing.",
                evidence=", ".join(corporate[:12]),
                chakra="SHAKUNI",
                remediation="Ask contributors to enable commit email privacy in "
                            "their GitHub settings.",
            )
            ctx.progress.hit(key, f"{len(corporate)} corporate emails in commits")

    # ── Code search (authenticated only) ──────────────────────────────────
    if token:
        ctx.progress.task(key, "Searching code for leaks", total=len(CODE_SEARCH_QUERIES))
        for template in CODE_SEARCH_QUERIES:
            if ctx.cancelled():
                break
            query = template.format(domain=apex)
            resp = await ctx.http.get(
                f"{API}/search/code",
                headers=headers,
                params={"q": query, "per_page": 20},
            )
            ctx.progress.advance(key)
            if resp is None:
                continue
            if resp.status_code == 403:
                data["rate_limited"] = True
                ctx.progress.note(key, "GitHub code search rate limit reached")
                break
            if resp.status_code != 200:
                continue
            try:
                payload = resp.json()
            except ValueError:
                continue

            for item in payload.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                repo = (item.get("repository") or {}).get("full_name", "")
                path = item.get("path", "")
                entry = {
                    "repo": shuddhi.sanitize(repo, max_len=140),
                    "path": shuddhi.sanitize(path, max_len=200),
                    "url": shuddhi.sanitize(item.get("html_url", ""), max_len=300),
                    "query": query,
                    "sensitive_filename": bool(SENSITIVE_FILENAMES.search(path or "")),
                }
                if entry not in data["leaks"]:
                    data["leaks"].append(entry)

            # Code search is limited to 10 requests/minute even with a token.
            await asyncio.sleep(6.5)

        high_value = [leak for leak in data["leaks"] if leak["sensitive_filename"]]
        if high_value:
            res.report(
                Severity.HIGH,
                f"{len(high_value)} sensitive files on GitHub reference this domain",
                asset=ctx.target,
                detail="Public code search returned files whose names indicate "
                       "credentials or infrastructure configuration, in "
                       "repositories that mention the target domain. Each needs "
                       "manual review — a real credential here is already "
                       "public and already indexed.",
                evidence="; ".join(f"{leak['repo']}/{leak['path']}" for leak in high_value[:8]),
                chakra="SHAKUNI",
                remediation="Review each hit. Rotate anything live, then purge "
                            "it from git history — deleting the file is not "
                            "enough, the commit still serves it.",
            )
            for leak in high_value[:10]:
                ctx.progress.hit(key, f"LEAK {leak['repo']}/{leak['path']}")

        if data["leaks"] and not high_value:
            res.report(
                Severity.INFO,
                f"{len(data['leaks'])} public code results mention this domain",
                asset=ctx.target,
                detail="None of the filenames look like credential stores, but "
                       "the matches show where the domain appears in public "
                       "code and are worth a skim for hardcoded hostnames and "
                       "internal URLs.",
                evidence="; ".join(f"{leak['repo']}/{leak['path']}" for leak in data["leaks"][:8]),
                chakra="SHAKUNI",
            )

    if data["repos"]:
        res.report(
            Severity.INFO,
            f"{len(data['repos'])} public repositories under '{org_name}'",
            asset=f"github.com/{org_name}",
            detail="Public repositories disclose the technology stack, internal "
                   "service names and deployment patterns, which narrows the "
                   "rest of the engagement considerably.",
            evidence=", ".join(r["full_name"] for r in data["repos"][:12]),
            chakra="SHAKUNI",
        )

    summary = f"{len(data['repos'])} repos · {len(data['members'])} members"
    if data["emails"]:
        summary += f" · {len(data['emails'])} emails"
    if data["leaks"]:
        summary += f" · {len(data['leaks'])} code hits"
    if not token:
        summary += " (unauthenticated)"
    ctx.progress.chakra_done(key, summary)
