import requests
import os
from urllib.parse import quote, urlparse

API_HOST = "api.github.com"
API_ROOT = f"https://{API_HOST}"


def _api_get(url, headers, params=None, timeout=10):
    """GET a GitHub API URL, refusing to send the token off api.github.com.

    contributors_url is taken from a previous API response rather than built
    locally, so the host is checked before the Authorization header travels
    with it.
    """
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname != API_HOST:
        return None
    return requests.get(url, headers=headers, params=params, timeout=timeout)

def run(domain):
    org_name = domain.split('.')[0]
    
    token = os.environ.get('GITHUB_TOKEN', '')
    
    headers = {
        'User-Agent': 'ChakraView-Recon',
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f"token {token}"   # THIS LINE WAS COMMENTED OUT
    }

    results = {"count": 0, "names": [], "repos": [], "exposed_emails": []}
    
    # Safety check — warn if token is missing
    if not token:
        print("  [!] GITHUB_TOKEN not set. Run: export GITHUB_TOKEN=your_token")
        return {"count": "Error", "names": [], "repos": [], "error": "No token"}

    try:
        # 1. Org repos with contributor names
        org_res = _api_get(
            f"{API_ROOT}/orgs/{quote(org_name, safe='')}/repos",
            headers, params={"per_page": "50"}
        )
        if org_res is not None and org_res.status_code == 200:
            for repo in org_res.json():
                results["repos"].append(repo["full_name"])
                contrib_res = _api_get(repo["contributors_url"], headers, timeout=5)
                if contrib_res is not None and contrib_res.status_code == 200:
                    for c in contrib_res.json():
                        results["names"].append(c["login"])

        # 2. User search for domain keyword
        user_res = _api_get(
            f"{API_ROOT}/search/users",
            headers, params={"q": org_name, "per_page": "20"}
        )
        if user_res is not None and user_res.status_code == 200:
            for u in user_res.json().get("items", []):
                results["names"].append(u["login"])

        # 3. Code search for leaked configs and secrets
        code_res = _api_get(
            f"{API_ROOT}/search/code",
            headers, params={"q": f'"{domain}"', "per_page": "10"}
        )
        if code_res is not None and code_res.status_code == 200:
            for item in code_res.json().get("items", []):
                results["repos"].append(
                    f"[LEAK] {item['repository']['full_name']} → {item['name']}"
                )

        results["names"] = list(set(results["names"]))
        results["count"] = len(results["names"])
        return results

    except Exception as e:
        return {"count": "Error", "names": [], "repos": [], "error": str(e)}
