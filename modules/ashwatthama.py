import requests

JUICY_EXTENSIONS = ['.php', '.sql', '.env', '.json', '.xml', '.bak',
                    '.zip', '.log', '.key', '.pem', '.config', '.conf']
JUICY_PATHS = ['admin', 'api', 'login', 'wp-admin', 'phpmyadmin',
               'dashboard', 'upload', 'backup', 'config', 'secret']

def run(domain):
    base_domain = ".".join(domain.split('.')[-2:])
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url={base_domain}/*&output=json&collapse=urlkey"
        f"&fl=original,timestamp&limit=100"  # increased from 20
    )
    try:
        r = requests.get(url, timeout=20, headers={'User-Agent': 'ChakraView-Recon'})
        if r.status_code != 200:
            return {"found": False, "paths": [], "note": "Archive unreachable"}

        rows = r.json()
        if len(rows) <= 1:
            return {"found": False, "paths": [], "note": "No archive data"}

        hits = []
        for row in rows[1:]:
            original_url, timestamp = row[0], row[1]
            url_lower = original_url.lower()
            is_juicy_ext  = any(ext in url_lower for ext in JUICY_EXTENSIONS)
            is_juicy_path = any(p in url_lower for p in JUICY_PATHS)
            if is_juicy_ext or is_juicy_path:
                # Format timestamp: 20231104120000 → 2023-11-04
                ts = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
                hits.append(f"[{ts}] {original_url}")

        return {
            "found": bool(hits),
            "note": f"{len(hits)} high-value archived paths found",
            "paths": hits[:10]  # show top 10 in terminal
        }

    except Exception as e:
        return {"found": False, "paths": [], "note": str(e)}
