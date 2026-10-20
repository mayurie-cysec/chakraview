"""
ABHIMANYU — the one who breaks into the formation.

A TCP connect scan across the live hosts, with a banner grab on anything that
answers. The point is not a port list; it is finding the services that should
never have been reachable from the internet — a database, a cache with no
auth, a container API, an admin panel on a high port.

Connect scanning is deliberate: it completes the handshake, so a result is a
service that genuinely accepted a connection rather than an inference from a
half-open probe.
"""

from __future__ import annotations

import asyncio

from core.context import Context
from core.models import Severity, Subdomain
from core.net import grab_banner, tcp_open
from modules import shuddhi

SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    79: "Finger", 80: "HTTP", 81: "HTTP-alt", 88: "Kerberos", 110: "POP3",
    111: "rpcbind", 123: "NTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE", 512: "rexec", 513: "rlogin", 514: "syslog", 515: "LPD",
    587: "SMTP-sub", 623: "IPMI", 631: "IPP", 636: "LDAPS", 873: "rsync",
    902: "VMware", 989: "FTPS-data", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1099: "Java RMI", 1433: "MSSQL", 1521: "Oracle DB",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2095: "Webmail", 2096: "Webmail-SSL",
    2181: "ZooKeeper", 2375: "Docker API", 2376: "Docker API TLS",
    2379: "etcd", 3000: "Dev server / Grafana", 3128: "Squid proxy",
    3268: "LDAP-GC", 3306: "MySQL", 3389: "RDP", 4040: "Spark UI",
    4443: "HTTPS-alt", 4444: "Metasploit / alt", 4567: "Sinatra",
    4848: "GlassFish", 5000: "Dev server / Docker registry", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM", 6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic",
    7077: "Spark master", 7474: "Neo4j", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8009: "AJP", 8080: "HTTP-proxy", 8081: "HTTP-alt", 8088: "Hadoop",
    8089: "Splunk", 8161: "ActiveMQ", 8443: "HTTPS-alt", 8500: "Consul",
    8686: "JMX", 8888: "HTTP-alt", 9000: "SonarQube / PHP-FPM",
    9001: "Supervisor", 9042: "Cassandra", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch cluster", 9443: "HTTPS-alt",
    10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ UI",
    27017: "MongoDB", 27018: "MongoDB shard", 50070: "Hadoop NameNode",
}

# Ports that should essentially never face the internet. Severity reflects how
# directly exposure leads to data access.
RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    23: (Severity.HIGH, "Telnet transmits credentials in cleartext"),
    69: (Severity.MEDIUM, "TFTP has no authentication at all"),
    79: (Severity.LOW, "Finger discloses local user accounts"),
    111: (Severity.MEDIUM, "rpcbind enumerates RPC services for an attacker"),
    135: (Severity.HIGH, "MSRPC exposed to the internet"),
    139: (Severity.HIGH, "NetBIOS exposed to the internet"),
    161: (Severity.HIGH, "SNMP often still answers on the default community string"),
    389: (Severity.MEDIUM, "LDAP exposed without TLS"),
    445: (Severity.CRITICAL, "SMB exposed to the internet"),
    512: (Severity.HIGH, "rexec is an unauthenticated remote execution service"),
    513: (Severity.HIGH, "rlogin trusts the client's claimed identity"),
    514: (Severity.MEDIUM, "syslog accepting remote input"),
    623: (Severity.HIGH, "IPMI gives out-of-band control of the hardware"),
    873: (Severity.MEDIUM, "rsync daemon often allows anonymous module listing"),
    1099: (Severity.HIGH, "Java RMI commonly permits remote class loading"),
    1433: (Severity.HIGH, "Microsoft SQL Server reachable from the internet"),
    1521: (Severity.HIGH, "Oracle database reachable from the internet"),
    2049: (Severity.HIGH, "NFS export reachable from the internet"),
    2181: (Severity.HIGH, "ZooKeeper has no authentication by default"),
    2375: (Severity.CRITICAL, "Unauthenticated Docker API is root on the host"),
    2376: (Severity.HIGH, "Docker API exposed (TLS)"),
    2379: (Severity.CRITICAL, "etcd holds cluster secrets and has no default auth"),
    3306: (Severity.HIGH, "MySQL reachable from the internet"),
    3389: (Severity.HIGH, "RDP exposed — a standing target for credential attacks"),
    4040: (Severity.MEDIUM, "Spark UI discloses jobs, configuration and data paths"),
    5432: (Severity.HIGH, "PostgreSQL reachable from the internet"),
    5601: (Severity.MEDIUM, "Kibana frequently ships without authentication"),
    5672: (Severity.MEDIUM, "AMQP broker reachable from the internet"),
    5900: (Severity.HIGH, "VNC exposed, often with no password"),
    5984: (Severity.HIGH, "CouchDB has historically shipped world-readable"),
    5985: (Severity.HIGH, "WinRM exposed — remote PowerShell"),
    6379: (Severity.CRITICAL, "Redis has no authentication by default"),
    6443: (Severity.HIGH, "Kubernetes API server reachable from the internet"),
    7001: (Severity.HIGH, "WebLogic has a long history of pre-auth RCE"),
    7474: (Severity.HIGH, "Neo4j browser reachable from the internet"),
    8009: (Severity.HIGH, "AJP connector — Ghostcat file read / RCE"),
    8086: (Severity.MEDIUM, "InfluxDB reachable from the internet"),
    8161: (Severity.MEDIUM, "ActiveMQ console reachable from the internet"),
    8500: (Severity.HIGH, "Consul exposes service configuration and KV data"),
    8686: (Severity.HIGH, "JMX allows remote code execution when unauthenticated"),
    9042: (Severity.HIGH, "Cassandra reachable from the internet"),
    9092: (Severity.HIGH, "Kafka broker reachable from the internet"),
    9200: (Severity.CRITICAL, "Elasticsearch has no authentication by default"),
    9300: (Severity.HIGH, "Elasticsearch transport port reachable"),
    10000: (Severity.HIGH, "Webmin runs as root and has had pre-auth RCE"),
    11211: (Severity.HIGH, "Memcached is unauthenticated and amplifies DDoS"),
    15672: (Severity.MEDIUM, "RabbitMQ console often keeps guest/guest"),
    27017: (Severity.CRITICAL, "MongoDB has historically bound with no auth"),
    27018: (Severity.HIGH, "MongoDB shard reachable from the internet"),
    50070: (Severity.HIGH, "Hadoop NameNode UI exposes the filesystem"),
}

# Banners worth grabbing. HTTP ports are handled by arjuna instead.
BANNER_PORTS = {
    21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379,
    9200, 11211, 27017, 1433, 5900, 873,
}


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "ports"
    ports = ctx.cfg.ports

    # One host per unique address, so a round-robin pool is not scanned
    # a dozen times for identical results.
    seen_ips: set[str] = set()
    targets: list[Subdomain] = []
    for entry in res.hosts_resolved():
        first_ip = entry.ips[0]
        if first_ip in seen_ips:
            continue
        seen_ips.add(first_ip)
        targets.append(entry)

    if not targets:
        ctx.progress.note(key, "no resolved hosts to scan")
        return

    max_hosts = 40 if not ctx.cfg.deep else 200
    if len(targets) > max_hosts:
        # Prefer hosts that answered HTTP — they are known to be alive.
        targets.sort(key=lambda e: (not e.alive, e.host))
        ctx.progress.note(
            key, f"scanning {max_hosts} of {len(targets)} unique hosts (--deep raises this)"
        )
        targets = targets[:max_hosts]

    total = len(targets) * len(ports)
    ctx.progress.task(key, f"Scanning {len(ports)} ports on {len(targets)} hosts", total=total)

    sem = asyncio.Semaphore(max(50, ctx.cfg.concurrency * 4))
    timeout = min(ctx.cfg.timeout, 3.0)
    open_map: dict[str, list[dict]] = {}

    async def scan(entry: Subdomain, port: int) -> None:
        if ctx.cancelled():
            ctx.progress.advance(key)
            return
        async with sem:
            is_open = await tcp_open(entry.host, port, timeout=timeout)
        ctx.progress.advance(key)
        if not is_open:
            return

        entry.ports.append(port)
        record = {"port": port, "service": SERVICES.get(port, "unknown"), "banner": ""}
        if port in BANNER_PORTS:
            record["banner"] = shuddhi.sanitize(
                await grab_banner(entry.host, port, timeout=timeout), max_len=160
            )
        open_map.setdefault(entry.host, []).append(record)
        label = f"{entry.host}:{port} ({record['service']})"
        ctx.progress.hit(key, label)

    await asyncio.gather(*(scan(e, p) for e in targets for p in ports))

    for entry in targets:
        entry.ports.sort()

    res.infra["open_ports"] = {h: sorted(v, key=lambda r: r["port"]) for h, v in open_map.items()}

    # Group risky findings by port so one finding covers every affected host.
    by_port: dict[int, list[str]] = {}
    for host, records in open_map.items():
        for record in records:
            by_port.setdefault(record["port"], []).append(host)

    for port, hosts in sorted(by_port.items()):
        if port not in RISKY_PORTS:
            continue
        severity, reason = RISKY_PORTS[port]
        service = SERVICES.get(port, "unknown")
        banners = [
            r["banner"] for h in hosts
            for r in open_map.get(h, []) if r["port"] == port and r["banner"]
        ]
        res.report(
            severity,
            f"{service} exposed on port {port}",
            asset=hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts",
            detail=f"{reason}. Port {port}/tcp accepted a connection on "
                   f"{len(hosts)} host(s): {', '.join(hosts[:10])}"
                   + (" and others." if len(hosts) > 10 else "."),
            evidence=(banners[0] if banners else f"TCP connect to {hosts[0]}:{port} succeeded"),
            chakra="ABHIMANYU",
            remediation="Restrict the port to the networks that need it, or put "
                        "it behind a VPN. Confirm authentication is enabled "
                        "regardless of network position.",
        )

    total_open = sum(len(v) for v in open_map.values())
    risky = sum(1 for p in by_port if p in RISKY_PORTS)
    ctx.progress.chakra_done(
        key, f"{total_open} open port(s) across {len(open_map)} host(s) · {risky} risky"
    )
