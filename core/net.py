"""Networking primitives every chakra shares.

Three things live here because getting them wrong once is worse than getting
them wrong in ten modules: a single rate-limited async HTTP client, an async
DNS resolver with a cache, and a plain TCP connect helper. Every call returns
a value or None — modules are never expected to catch transport exceptions.
"""

from __future__ import annotations

import asyncio
import random
import socket
import string
from typing import Any

import httpx

try:
    import dns.asyncresolver
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    import dns.zone
    import dns.asyncquery

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - degrade to stdlib resolution
    HAS_DNSPYTHON = False

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 ChakraView/2.0"
)

# Public resolvers, so a poisoned or filtered local resolver does not silently
# shrink the subdomain enumeration results.
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]


class HttpClient:
    """Rate-limited async HTTP client with retries and no exceptions escaping."""

    def __init__(
        self,
        concurrency: int = 50,
        timeout: float = 10.0,
        retries: int = 1,
        verify: bool = False,
        follow_redirects: bool = True,
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._retries = max(0, retries)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)),
            verify=verify,
            follow_redirects=follow_redirects,
            limits=httpx.Limits(
                max_connections=concurrency, max_keepalive_connections=concurrency // 2 or 1
            ),
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response | None:
        """Return a Response, or None if every attempt failed."""
        attempts = self._retries + 1
        async with self._sem:
            for attempt in range(attempts):
                try:
                    return await self._client.request(method, url, **kwargs)
                except (httpx.HTTPError, OSError, ValueError):
                    if attempt + 1 < attempts:
                        await asyncio.sleep(0.4 * (attempt + 1))
            return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("HEAD", url, **kwargs)

    async def json(self, url: str, **kwargs: Any) -> Any:
        """GET and parse JSON, returning None on any transport or parse failure."""
        resp = await self.get(url, **kwargs)
        if resp is None or resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    async def text(self, url: str, **kwargs: Any) -> str | None:
        resp = await self.get(url, **kwargs)
        if resp is None or resp.status_code != 200:
            return None
        return resp.text


class Resolver:
    """Async DNS resolver with an in-process cache.

    Enumeration re-queries the same apex and the same wildcard probes many
    times; caching turns that into one query and keeps us well clear of
    resolver rate limits.
    """

    def __init__(self, concurrency: int = 100, timeout: float = 4.0, nameservers: list[str] | None = None) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._cache: dict[tuple[str, str], Any] = {}
        # Names the resolver has already said do not exist. NXDOMAIN is a
        # statement about the name itself, not about one record type, so
        # every later query for that name can be answered from here.
        self._nxdomain: set[str] = set()
        self.timeout = timeout
        self._resolver = None
        if HAS_DNSPYTHON:
            self._resolver = dns.asyncresolver.Resolver(configure=True)
            self._resolver.nameservers = nameservers or self._default_nameservers()
            self._resolver.timeout = timeout
            self._resolver.lifetime = timeout + 1.0
            self._resolver.rotate = True

    @staticmethod
    def _default_nameservers() -> list[str]:
        """Public resolvers first, with the system's own kept as a fallback.

        Public resolvers give consistent results and are not subject to a
        corporate resolver's filtering or split-horizon views. But some
        networks block outbound DNS entirely, and silently resolving nothing
        would look like a target with no subdomains — so the system resolver
        stays in the list behind them.
        """
        servers = list(PUBLIC_RESOLVERS)
        try:
            system = dns.resolver.Resolver(configure=True).nameservers
        except Exception:
            system = []
        for server in system:
            address = str(server)
            if address not in servers:
                servers.append(address)
        return servers

    async def query(self, name: str, rdtype: str = "A") -> list[str]:
        """Return record values as strings. Empty list means no answer."""
        name = name.strip().rstrip(".").lower()
        if not name:
            return []
        cache_key = (name, rdtype)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if name in self._nxdomain:
            return []

        values: list[str] = []
        async with self._sem:
            if self._resolver is not None:
                try:
                    answer = await self._resolver.resolve(name, rdtype)
                    values = [r.to_text().strip('"') for r in answer]
                except dns.resolver.NXDOMAIN:
                    self._nxdomain.add(name)
                except Exception:
                    values = []
            elif rdtype in ("A", "AAAA"):
                try:
                    loop = asyncio.get_running_loop()
                    family = socket.AF_INET6 if rdtype == "AAAA" else socket.AF_INET
                    infos = await loop.getaddrinfo(name, None, family=family)
                    values = sorted({i[4][0] for i in infos})
                except (socket.gaierror, OSError):
                    values = []

        self._cache[cache_key] = values
        return values

    async def resolve_a(self, name: str) -> list[str]:
        """A records, falling back to AAAA so IPv6-only hosts are not missed.

        The fallback is skipped when the A query returned NXDOMAIN: the name
        does not exist at all, so asking for a second record type is a wasted
        round trip. Enumeration spends most of its lookups on names that do
        not exist, which makes this the difference between one query per dead
        host and two.
        """
        ips = await self.query(name, "A")
        if ips or name.strip().rstrip(".").lower() in self._nxdomain:
            return ips
        return await self.query(name, "AAAA")

    async def cname(self, name: str) -> str:
        records = await self.query(name, "CNAME")
        return records[0].rstrip(".").lower() if records else ""

    async def wildcard_ips(self, domain: str, probes: int = 3) -> set[str]:
        """Detect a wildcard record by resolving names that cannot exist.

        Without this a wildcard domain reports every single bruteforce
        candidate as live, which is the classic way these tools produce
        hundreds of worthless 'findings'.
        """
        collected: set[str] = set()
        for _ in range(probes):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            collected.update(await self.resolve_a(f"{rand}.{domain}"))
        return collected

    async def reverse(self, ip: str) -> str:
        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return ""


async def tcp_open(host: str, port: int, timeout: float = 2.5) -> bool:
    """True if a TCP connection completes. Used by the port scan and probes."""
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        return True
    except (asyncio.TimeoutError, OSError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass


async def grab_banner(host: str, port: int, timeout: float = 2.5) -> str:
    """Read whatever a service volunteers on connect (SSH, SMTP, FTP, ...)."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(160), timeout=timeout)
        return data.decode("utf-8", "replace").strip()
    except (asyncio.TimeoutError, OSError):
        return ""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass


def apex_domain(host: str) -> str:
    """Best-effort registrable domain.

    Handles the common two-label public suffixes (co.uk, com.au, co.in ...)
    without pulling in a full public-suffix-list dependency.
    """
    host = host.strip().lower().rstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    second_level = {
        "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil", "in",
    }
    if len(parts) >= 3 and parts[-2] in second_level and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
