import requests
import os

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
        org_res = requests.get(
            f"https://api.github.com/orgs/{org_name}/repos?per_page=50",
            headers=headers, timeout=10
        )
        if org_res.status_code == 200:
            for repo in org_res.json():
                results["repos"].append(repo["full_name"])
                contrib_res = requests.get(repo["contributors_url"], headers=headers, timeout=5)
                if contrib_res.status_code == 200:
                    for c in contrib_res.json():
                        results["names"].append(c["login"])

        # 2. User search for domain keyword
        user_res = requests.get(
            f"https://api.github.com/search/users?q={org_name}&per_page=20",
            headers=headers, timeout=10
        )
        if user_res.status_code == 200:
            for u in user_res.json().get("items", []):
                results["names"].append(u["login"])

        # 3. Code search for leaked configs and secrets
        code_res = requests.get(
            f'https://api.github.com/search/code?q="{domain}"&per_page=10',
            headers=headers, timeout=10
        )
        if code_res.status_code == 200:
            for item in code_res.json().get("items", []):
                results["repos"].append(
                    f"[LEAK] {item['repository']['full_name']} → {item['name']}"
                )

        results["names"] = list(set(results["names"]))
        results["count"] = len(results["names"])
        return results

    except Exception as e:
        return {"count": "Error", "names": [], "repos": [], "error": str(e)}
