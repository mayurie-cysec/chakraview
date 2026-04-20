import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

CRITICAL_SUBS = [
    # Admin & Management
    "admin", "administrator", "admins", "adminpanel", "admin1", "admin2",
    "cpanel", "whm", "plesk", "directadmin", "webadmin", "sysadmin",
    "manager", "manage", "management", "control", "controlpanel",
    "dashboard", "panel", "portal", "console", "webpanel",

    # Development & Staging
    "dev", "dev1", "dev2", "dev3", "development", "develop",
    "staging", "stage", "stg", "stg1", "stg2",
    "test", "test1", "test2", "testing", "testenv",
    "beta", "beta1", "beta2", "alpha", "sandbox",
    "uat", "qa", "qat", "preprod", "pre-prod", "preview",
    "demo", "demo1", "demo2", "poc", "lab", "labs",

    # API & Services
    "api", "api1", "api2", "api3", "apiv1", "apiv2", "apiv3",
    "apis", "api-dev", "api-staging", "api-test", "api-prod",
    "rest", "graphql", "grpc", "soap", "ws", "websocket",
    "service", "services", "microservice", "gateway", "gw",

    # Authentication & Security
    "auth", "auth1", "auth2", "authentication", "authorize",
    "login", "logout", "signin", "signup", "register",
    "sso", "saml", "oauth", "openid", "identity", "idp",
    "2fa", "mfa", "otp", "password", "reset",
    "ldap", "ad", "activedirectory", "radius",

    # Infrastructure & Network
    "vpn", "vpn1", "vpn2", "vpn3", "ssl-vpn", "remote",
    "rdp", "citrix", "workspace", "horizon", "anyconnect",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "smtp", "smtps", "imap", "imaps", "pop", "pop3",
    "mail", "mail1", "mail2", "webmail", "email", "owa",
    "exchange", "autodiscover", "autoconfig",
    "proxy", "proxy1", "proxy2", "wpad", "pac",
    "fw", "firewall", "gateway", "router", "switch",
    "lb", "loadbalancer", "haproxy", "nginx", "f5",

    # DevOps & CI/CD
    "jenkins", "jenkins1", "jenkins2", "ci", "cd", "cicd",
    "gitlab", "git", "github", "gitea", "gogs", "bitbucket",
    "jira", "confluence", "wiki", "docs", "documentation",
    "sonar", "sonarqube", "nexus", "artifactory", "registry",
    "docker", "k8s", "kubernetes", "rancher", "portainer",
    "ansible", "puppet", "chef", "terraform", "vault",
    "grafana", "kibana", "elastic", "elasticsearch", "logstash",
    "prometheus", "alertmanager", "datadog", "splunk", "graylog",
    "zabbix", "nagios", "icinga", "prtg", "monitor", "monitoring",

    # Database
    "db", "db1", "db2", "db3", "database",
    "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "memcache", "memcached", "cassandra", "elastic",
    "mssql", "oracle", "mariadb", "phpmyadmin", "adminer",

    # Storage & Files
    "ftp", "ftp1", "ftp2", "sftp", "ftps",
    "files", "file", "upload", "uploads", "download", "downloads",
    "storage", "store", "backup", "backups", "bak",
    "media", "static", "assets", "cdn", "content",
    "s3", "blob", "bucket", "archive",

    # Internal & Corporate
    "internal", "intranet", "corp", "corporate", "office",
    "hr", "helpdesk", "support", "ticket", "tickets", "crm",
    "erp", "finance", "accounting", "billing", "invoice", "pay",
    "shop", "store", "ecommerce", "cart", "checkout",
    "app", "app1", "app2", "apps", "application", "web", "web1", "web2",
    "www", "www1", "www2", "www3", "m", "mobile", "wap",

    # Cloud & Hosting
    "aws", "azure", "gcp", "cloud", "cloud1", "cloud2",
    "heroku", "digitalocean", "linode", "vultr",
    "server", "server1", "server2", "server3", "host", "hosting",
    "vps", "dedicated", "shared",

    # Security Tools
    "waf", "ids", "ips", "siem", "soc",
    "pentest", "scan", "scanner", "security", "sec",
    "cert", "ssl", "tls", "ca", "pki",

    # Miscellaneous common ones
    "old", "new", "legacy", "v1", "v2", "v3",
    "test-api", "dev-api", "stage-api",
    "secret", "hidden", "private", "public",
    "status", "health", "ping", "heartbeat",
    "redirect", "link", "short", "url",
    "chat", "slack", "teams", "meet", "video",
    "news", "blog", "forum", "community",
    "partner", "vendor", "third-party", "integration",
]

def check_host(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        # Check HTTPS first, then HTTP
        https_up = False
        http_up  = False
        try:
            s = socket.create_connection((fqdn, 443), timeout=2)
            s.close()
            https_up = True
        except:
            pass
        if not https_up:
            try:
                s = socket.create_connection((fqdn, 80), timeout=2)
                s.close()
                http_up = True
            except:
                pass
        proto = "https" if https_up else ("http" if http_up else "dns-only")
        return {
            "host": fqdn,
            "ip": ip,
            "proto": proto,
            "url": f"{proto}://{fqdn}" if proto != "dns-only" else fqdn
        }
    except socket.gaierror:
        return None

def run(domain):
    found = []
    print(f"  [*] Probing {len(CRITICAL_SUBS)} subdomains with 50 threads...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, sub, domain): sub for sub in CRITICAL_SUBS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                # Print each found subdomain live as it's discovered
                print(f"    \033[38;5;208m⚔\033[0m  {result['host']}  [{result['proto'].upper()}]  → {result['ip']}")

    # Sort results: https first, then http, then dns-only
    found.sort(key=lambda x: (x['proto'] == 'dns-only', x['proto'] == 'http', x['host']))

    if found:
        return {
            "intelligence": f"CRITICAL: {len(found)} live subdomains detected out of {len(CRITICAL_SUBS)} probed.",
            "found": found
        }
    return {
        "intelligence": f"No subdomains found out of {len(CRITICAL_SUBS)} probed.",
        "found": []
    }
