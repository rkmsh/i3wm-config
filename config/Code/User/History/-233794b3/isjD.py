import requests
import sys

def search_github_pocs(query):
    """Searches GitHub for public PoC repositories matching a CVE or software version."""
    print(f"[*] Searching GitHub for public PoCs: {query}...")
    url = f"https://api.github.com/search/repositories?q={query}+poc+exploit&sort=stars&order=desc"
    headers = {"Accept": "application/vnd.github.v3+json"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            results = response.json().get('items', [])[:5] # Top 5 star-rated repositories
            if results:
                for repo in results:
                    print(f"  [★ {repo['stargazers_count']}] {repo['html_url']} - {repo['description']}")
            else:
                print("  [-] No public GitHub exploit repositories found matching criteria.")
        else:
            print(f"  [-] GitHub API returned status code: {response.status_code}")
    except Exception as e:
        print(f"  [-] Error querying GitHub: {e}")

def search_nuclei_templates(cve_id):
    """Queries the centralized ProjectDiscovery Nuclei template data tree for specific CVE matchers."""
    if not cve_id.upper().startswith("CVE-"):
        return # Nuclei lookup works cleanly with structured CVE strings
        
    print(f"\n[*] Checking ProjectDiscovery Nuclei template registry for {cve_id}...")
    # Using GitHub API to search within the official nuclei-templates organization/repo
    url = f"https://api.github.com/search/code?q={cve_id}+repo:projectdiscovery/nuclei-templates"
    headers = {"Accept": "application/vnd.github.v3+json"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            items = response.json().get('items', [])
            if items:
                print(f"  [+] Match found in Nuclei Templates! You can execute this natively via:")
                print(f"      👉 nuclei -t {items[0]['path']}")
            else:
                print("  [-] No custom Nuclei template written for this specific entry yet.")
    except Exception as e:
        print(f"  [-] Error checking Nuclei registry: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 exploit_finder.py <CVE-ID or Software-Version>")
        print("Example: python3 exploit_finder.py CVE-2023-38606")
        print("Example: python3 exploit_finder.py 'Struts2 RCE'")
        sys.exit(1)

    search_target = " ".join(sys.argv[1:])
    
    print("=" * 60)
    print(f"🚀 EXPLOIT & PoC RECON ENGINE: {search_target}")
    print("=" * 60)

    # Trigger GitHub structural search
    search_github_pocs(search_target)
    
    # If the user passed a direct CVE string, drill down into Nuclei templates
    if "cve" in search_target.lower():
        # Sanitize string extract token (e.g. CVE-202X-XXXX)
        for token in search_target.split():
            if token.lower().startswith("cve-"):
                search_nuclei_templates(token.strip())

if __name__ == "__main__":
    main()