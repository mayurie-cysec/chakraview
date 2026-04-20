import socket
import requests

def run(target):
    result = {"ip": "Unknown", "observation": "", "asn": "", "org": "", "cdn": False}
    
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip

        # Reverse DNS
        try:
            result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except:
            result["reverse_dns"] = "None"

        # ASN + Org lookup via ipinfo.io (free tier, no key needed)
        ipinfo = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8).json()
        result["org"] = ipinfo.get("org", "Unknown")
        result["city"] = ipinfo.get("city", "")
        result["country"] = ipinfo.get("country", "")

        # CDN/WAF detection — if org contains these, real IP is hidden
        cdn_providers = ["cloudflare", "akamai", "fastly", "incapsula", "sucuri"]
        org_lower = result["org"].lower()
        if any(c in org_lower for c in cdn_providers):
            result["cdn"] = True
            result["observation"] = (
                f"WARNING: Behind {result['org']}. "
                "Real IP hidden. Try: SecurityTrails, Shodan, old DNS records."
            )
        else:
            result["observation"] = f"Direct IP exposed. ASN: {result['org']}"

    except Exception as e:
        result["observation"] = f"DNS resolution failed: {e}"
    
    return result
