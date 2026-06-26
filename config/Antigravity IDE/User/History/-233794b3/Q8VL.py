#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADVANCED EXPLOIT FINDER - HTB Blood Hunting Tool
CVE PoC Hunter | GitHub | ExploitDB | Nuclei | NVD | Vulners | Sploitus

Usage:
    python exploit_finder.py CVE-2024-1234
    python exploit_finder.py "apache 2.4.49"
    python exploit_finder.py "log4shell"
    python exploit_finder.py CVE-2024-1234 --github-token ghp_xxxx
"""

import re
import sys
import os
import textwrap
import argparse
import threading
import time
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import io
import requests
try:
    import curl_cffi.requests as cf_requests
    _CF_BYPASS = True   # curl_cffi available — can impersonate Chrome TLS
except ImportError:
    _CF_BYPASS = False  # fall back to plain requests (may hit Cloudflare blocks)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.columns import Columns
from rich.rule import Rule
from rich.syntax import Syntax
from rich.live import Live
from rich.align import Align

# Force UTF-8 output on Windows to avoid charmap encoding errors
import sys
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console(highlight=False)

# ─────────────────────────── CONFIG ──────────────────────────────
TIMEOUT = 10
MAX_RESULTS = 10
GITHUB_API = "https://api.github.com"
NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"
PACKETSTORM_SEARCH = "https://packetstormsecurity.com/search/?q="
NUCLEI_TEMPLATES_REPO = "projectdiscovery/nuclei-templates"
SPLOITUS_API = "https://sploitus.com/search"
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

GITHUB_SEARCH_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "ExploitFinder/2.0"
}

# ANSI-style Rich color scheme
BANNER_COLOR   = "bold bright_red"
SECTION_COLOR  = "bold cyan"
SUCCESS_COLOR  = "bold green"
WARN_COLOR     = "bold yellow"
DIM_COLOR      = "dim white"
URL_COLOR      = "bright_blue underline"
STAR_COLOR     = "yellow"
SCORE_COLOR    = "bold magenta"

# ─────────────────────────── BANNER ──────────────────────────────
def print_banner():
    banner = r"""
  _____ __  __ _     ____ ___ _____   _____ ___ _   _ ____  _____ ____
 | ____|  \/  | |   / ___|_ _|_   _| |  ___|_ _| \ | |  _ \| ____|  _ \
 |  _| | |\/| | |  | |  _ | |  | |   | |_   | ||  \| | | | |  _| | |_) |
 | |___| |  | | |__| |_| || |  | |   |  _|  | || |\  | |_| | |___|  _ <
 |_____|_|  |_|_____\____|___| |_|   |_|   |___|_| \_|____/|_____|_| \_\
"""
    console.print(f"[bold red]{banner}[/bold red]")
    console.print(Panel(
        "[bold white]>>> HTB Blood Hunter | PoC & Exploit Aggregator <<<[/bold white]\n"
        "[dim]Sources: GitHub | ExploitDB | Nuclei Templates | NVD/NIST | Vulners | Sploitus[/dim]",
        border_style="red",
        padding=(0, 2)
    ))
    console.print()

# ─────────────────────── CVE EXTRACTION ──────────────────────────
def extract_cves(text: str) -> list[str]:
    """Extract CVE IDs from arbitrary text."""
    pattern = r"CVE-\d{4}-\d{4,7}"
    return list(set(re.findall(pattern, text.upper())))

def is_cve(query: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", query.strip().upper()))

def extract_software_name(query: str) -> str:
    """Strip trailing version numbers from a query like 'FreePBX 16.0.40.7' -> 'FreePBX'.
    Returns empty string if nothing was stripped (i.e. query had no version).
    """
    # Remove trailing version-like tokens: digits, dots, underscores after the first space
    stripped = re.sub(r"\s+[\d][\d._v\-]*.*$", "", query).strip()
    # Only return if we actually stripped something meaningful
    return stripped if stripped and stripped != query else ""

# ──────────────────────── CISA KEV ───────────────────────────────
_cisa_kev_cache: set = set()   # Set of CVE IDs that are in CISA KEV

def fetch_cisa_kev() -> set:
    """Download the CISA Known Exploited Vulnerabilities catalog and return
    a set of CVE IDs (upper-cased). Cached in module-level _cisa_kev_cache."""
    global _cisa_kev_cache
    if _cisa_kev_cache:
        return _cisa_kev_cache
    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=TIMEOUT + 5,
            headers={"User-Agent": "ExploitFinder/2.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            _cisa_kev_cache = {
                v.get("cveID", "").upper()
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            }
    except Exception:
        pass
    return _cisa_kev_cache

# ──────────────────────── NVD / NIST API ─────────────────────────
def fetch_nvd_details(cve_id: str) -> dict:
    """Fetch CVE metadata from NIST NVD API v2."""
    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id.upper()},
            timeout=TIMEOUT,
            headers={"User-Agent": "ExploitFinder/2.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                # Description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
                # CVSS Score
                metrics = cve_data.get("metrics", {})
                score = "N/A"
                severity = "N/A"
                vector = "N/A"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        cvss_data = m.get("cvssData", {})
                        score    = cvss_data.get("baseScore", "N/A")
                        severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
                        vector   = cvss_data.get("vectorString", "N/A")
                        break
                # Published date
                published = cve_data.get("published", "N/A")
                if published != "N/A":
                    published = published[:10]
                # References
                refs = [r["url"] for r in cve_data.get("references", [])[:3]]
                # Affected products
                configs = cve_data.get("configurations", [])
                affected = []
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe = match.get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) > 5:
                                vendor  = parts[3]
                                product = parts[4]
                                version = parts[5]
                                if vendor != "*":
                                    affected.append(f"{vendor}/{product} {version}".strip())
                return {
                    "description": desc,
                    "score": score,
                    "severity": severity,
                    "vector": vector,
                    "published": published,
                    "references": refs,
                    "affected": list(set(affected))[:5]
                }
    except Exception:
        pass
    return {}


def _parse_nvd_vuln(vuln: dict, kev_set: set) -> dict:
    """Extract a normalised result dict from a single NVD vulnerability object."""
    cve_data  = vuln.get("cve", {})
    cve_id    = cve_data.get("id", "N/A")
    published = cve_data.get("published", "")  # keep full ISO for sort

    descriptions = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")

    metrics  = cve_data.get("metrics", {})
    score    = "N/A"
    severity = "N/A"
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m         = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score     = cvss_data.get("baseScore", "N/A")
            severity  = m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
            break

    # Extract exploit-tagged references from NVD (curated by NIST)
    # Tags of interest: 'Exploit', 'Third Party Advisory', 'Patch'
    EXPLOIT_TAGS = {"Exploit", "Third Party Advisory", "Mitigation", "Patch"}
    exploit_refs = []
    for ref in cve_data.get("references", []):
        ref_tags = set(ref.get("tags", []))
        if "Exploit" in ref_tags or "Third Party Advisory" in ref_tags:
            exploit_refs.append({
                "url":   ref["url"],
                "tags":  list(ref_tags),
                "title": ref["url"].split("/")[-1] or ref["url"],
            })

    return {
        "cve_id":         cve_id,
        "score":          score,
        "severity":       severity,
        "published":      published[:10] if published else "N/A",
        "_published_iso": published,   # kept for sort, stripped before return
        "description":    desc,
        "url":            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source":         "NVD",
        "in_kev":         cve_id.upper() in kev_set,
        "exploit_refs":   exploit_refs,   # NVD-curated exploit/PoC links
    }


def search_nvd_by_keyword(keyword: str, exact: bool = False, limit: int = 20) -> list[dict]:
    """Search NVD CVE database by keyword, paginating through ALL results.

    The NVD v2 REST API returns entries in its own internal order (typically
    oldest-published first).  Without pagination we miss recent CVEs like
    CVE-2025-57819 when there are more total results than resultsPerPage.

    Strategy
    --------
    1. First request: get totalResults so we know how many pages to fetch.
    2. Fetch all pages in parallel (up to NVD_PAGE_SIZE records each).
    3. Sort client-side: CISA KEV entries first (sortOrder=2/KEV priority),
       then by published date descending (sortOrder=2, sortDirection=2 on
       NVD web UI).  Return the top `limit` entries.

    Args:
        keyword:  The search term, e.g. 'FreePBX'.
        exact:    If True, add keywordExactMatch for phrase search.
        limit:    Maximum number of CVEs to return.

    Returns a list of dicts with keys:
        cve_id, score, severity, published, description, url, in_kev
    """
    NVD_PAGE_SIZE = 2000   # NVD API v2 max per page
    kev_set = fetch_cisa_kev()
    results  = []
    seen_ids = set()

    base_params = {"keywordSearch": keyword}
    if exact:
        base_params["keywordExactMatch"] = ""

    try:
        # ── Page 0: discover totalResults ────────────────────────────────
        params0 = {**base_params, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": 0}
        resp0   = requests.get(
            NVD_API, params=params0,
            timeout=TIMEOUT + 10,
            headers={"User-Agent": "ExploitFinder/2.0"}
        )
        if resp0.status_code != 200:
            return results

        data0       = resp0.json()
        total       = data0.get("totalResults", 0)
        page_size   = data0.get("resultsPerPage", NVD_PAGE_SIZE)

        # Parse first page
        for vuln in data0.get("vulnerabilities", []):
            r = _parse_nvd_vuln(vuln, kev_set)
            if r["cve_id"] not in seen_ids:
                seen_ids.add(r["cve_id"])
                results.append(r)

        # ── Remaining pages (if any) ──────────────────────────────────────
        if total > page_size:
            remaining_starts = range(page_size, total, page_size)

            def _fetch_page(start_idx: int) -> list:
                try:
                    p = {**base_params, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": start_idx}
                    r = requests.get(
                        NVD_API, params=p,
                        timeout=TIMEOUT + 10,
                        headers={"User-Agent": "ExploitFinder/2.0"}
                    )
                    if r.status_code == 200:
                        return r.json().get("vulnerabilities", [])
                except Exception:
                    pass
                return []

            with ThreadPoolExecutor(max_workers=4) as pool:
                for page_vulns in pool.map(_fetch_page, remaining_starts):
                    for vuln in page_vulns:
                        r = _parse_nvd_vuln(vuln, kev_set)
                        if r["cve_id"] not in seen_ids:
                            seen_ids.add(r["cve_id"])
                            results.append(r)

    except Exception:
        pass

    # ── Sort: CISA KEV first (sortOrder=2 / KEV priority), then
    #         published date descending (sortDirection=2 = desc) ──────────
    # Tuple: (in_kev, published_iso)  sorted reverse=True
    #   → in_kev=True  sorts BEFORE in_kev=False  (KEV entries first)
    #   → within same KEV tier: newest published_iso first
    def _sort_key(r):
        pub = r.get("_published_iso", "") or ""
        return (r.get("in_kev", False), pub)

    results.sort(key=_sort_key, reverse=True)
    for r in results:
        r.pop("_published_iso", None)
    return results[:limit]


# ──────────────── CVE-DRIVEN EXPLOIT SEARCH ───────────────────────
def search_exploits_for_cves(
    cve_list:     list[str],
    token:        str = None,
    max_cves:     int = 5,
    vulners_key:  str = None,
) -> dict:
    """For each CVE in cve_list (up to max_cves), run targeted exploit
    searches on GitHub, ExploitDB, Vulners, and Sploitus in parallel.

    Returns a dict keyed by CVE ID, each value being a list of exploit dicts
    from all sources (deduplicated by URL).
    """
    cves = [c.upper() for c in cve_list[:max_cves] if is_cve(c)]
    if not cves:
        return {}

    per_cve: dict[str, list] = {c: [] for c in cves}
    seen_urls: dict[str, set] = {c: set() for c in cves}

    tasks = []  # (cve_id, source_label, callable, *args)
    for cve in cves:
        tasks.append((cve, "GitHub",      github_search_repos,     cve, token))
        tasks.append((cve, "ExploitDB",   search_exploitdb,        cve))
        tasks.append((cve, "Vulners",    search_packetstorm,      cve, vulners_key, False))
        tasks.append((cve, "Sploitus",    search_sploitus,         cve))
        tasks.append((cve, "Nuclei",      search_nuclei_templates, cve, token))

    def _run_task(task):
        cve_id, label, fn, *args = task
        try:
            hits = fn(*args)
            return cve_id, label, hits
        except Exception:
            return cve_id, label, []

    with ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as pool:
        for cve_id, label, hits in pool.map(_run_task, tasks):
            for hit in hits:
                url = hit.get("url", "")
                if url and url not in seen_urls[cve_id]:
                    seen_urls[cve_id].add(url)
                    hit["_cve_origin"] = cve_id  # tag for display
                    per_cve[cve_id].append(hit)

    return per_cve

# ────────────────────── GITHUB SEARCH ────────────────────────────
def github_search_repos(query: str, token: str = None) -> list[dict]:
    """Search GitHub repositories for exploit/PoC code.

    Strategy:
      1. Standard full-text queries (query + exploit/poc/vulnerability)
      2. Repo-name search using CVE id or bare software name (in:name)
         so that repos like 'watchTowr-vs-FreePBX-CVE-2025-57819' are
         found even when no description matches.
      3. GitHub code search for exploit files (.py/.rb/.sh/.go).
    """
    headers = dict(GITHUB_SEARCH_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    seen_urls = set()

    # ── Build a prioritised list of search expressions ──────────────
    search_exprs = []

    if is_cve(query):
        # Exact CVE string first, then keyword variants
        search_exprs.append(query)                        # "CVE-2025-57819"
        search_exprs.append(f"{query} in:name")          # repo name contains CVE
        search_exprs.append(f"{query} in:description")   # repo description contains CVE
        search_exprs.append(f"{query} exploit")
        search_exprs.append(f"{query} poc")
    else:
        # Software + version query: also search by bare software name
        software_name = extract_software_name(query)  # e.g. "FreePBX"
        search_exprs.append(f"{query} exploit")
        search_exprs.append(f"{query} poc")
        search_exprs.append(f"{query} vulnerability")
        if software_name:
            # Bare name searches — these catch repos named after the product
            search_exprs.append(f"{software_name} in:name exploit")
            search_exprs.append(f"{software_name} in:name poc")
            search_exprs.append(f"{software_name} in:name vulnerability")
            search_exprs.append(f"{software_name} exploit")

    for q in search_exprs:
        try:
            encoded = urllib.parse.quote(q)
            url = f"{GITHUB_API}/search/repositories?q={encoded}&sort=stars&order=desc&per_page=5"
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    if item["html_url"] not in seen_urls:
                        seen_urls.add(item["html_url"])
                        results.append({
                            "title": item["full_name"],
                            "url": item["html_url"],
                            "stars": item["stargazers_count"],
                            "description": item.get("description") or "",
                            "updated": item.get("updated_at", "")[:10],
                            "language": item.get("language") or "Unknown",
                            "topics": item.get("topics", []),
                            "source": "GitHub Repos"
                        })
            elif resp.status_code == 403:
                break  # Rate limited
        except Exception:
            continue
        time.sleep(0.3)  # be kind to GitHub API

    # ── GitHub code search for exploit script files ─────────────────
    try:
        code_query = urllib.parse.quote(f"{query} exploit")
        code_url = (
            f"{GITHUB_API}/search/code"
            f"?q={code_query}+filename:*.py+filename:*.rb+filename:*.sh+filename:*.go"
            f"&sort=indexed&per_page=5"
        )
        resp = requests.get(code_url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            for item in resp.json().get("items", []):
                # Use the REPOSITORY url, not the file blob url, to avoid confusion
                repo_url  = item.get("repository", {}).get("html_url", "")
                repo_name = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                if repo_url and repo_url not in seen_urls:
                    seen_urls.add(repo_url)
                    results.append({
                        "title": f"[Code] {item['name']} in {repo_name}",
                        "url": repo_url,        # ← repo root, never 404s
                        "file_path": file_path,  # informational
                        "stars": item.get("repository", {}).get("stargazers_count", 0),
                        "description": f"PoC file: {file_path}",
                        "updated": "",
                        "language": item.get("name", "").split(".")[-1].upper(),
                        "topics": [],
                        "source": "GitHub Code"
                    })
    except Exception:
        pass

    # Sort by stars descending, take top MAX_RESULTS
    results.sort(key=lambda x: x["stars"], reverse=True)
    return results[:MAX_RESULTS]

# ────────────────────── EXPLOITDB SEARCH ─────────────────────────
def search_exploitdb(query: str) -> list[dict]:
    """Search Exploit-DB via their web API."""
    results = []
    try:
        # ExploitDB search endpoint (used by their website)
        params = {
            "draw": 1,
            "columns[0][data]": "date_published",
            "order[0][column]": 0,
            "order[0][dir]": "desc",
            "search[value]": query,
            "start": 0,
            "length": 10,
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Referer": "https://www.exploit-db.com/",
            "X-Requested-With": "XMLHttpRequest"
        }
        resp = requests.get(EXPLOITDB_API, params=params, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", []):
                eid = item.get("id", "")
                title = item.get("description", "Unknown Exploit")
                date = item.get("date_published", "")[:10]
                edb_type = item.get("type", {})
                platform = item.get("platform", {})
                if isinstance(edb_type, dict):
                    edb_type = edb_type.get("name", "")
                if isinstance(platform, dict):
                    platform = platform.get("name", "")
                results.append({
                    "title": title,
                    "url": f"https://www.exploit-db.com/exploits/{eid}",
                    "edb_id": f"EDB-{eid}",
                    "date": date,
                    "type": edb_type,
                    "platform": platform,
                    "source": "ExploitDB"
                })
    except Exception:
        pass
    return results[:MAX_RESULTS]

# ───────────────── NUCLEI TEMPLATES SEARCH ───────────────────────
NUCLEI_RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
NUCLEI_BLOB_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main"
NUCLEI_CLOUD_BASE = "https://cloud.projectdiscovery.io/library"


def search_nuclei_templates(query: str, token: str = None) -> list[dict]:
    """Search ProjectDiscovery nuclei-templates for a CVE.

    Strategy (for CVE queries)
    --------------------------
    1. Direct path probe: try the predictable YAML locations
       (http/cves/YEAR/, network/cves/YEAR/, etc.) with a HEAD request.
       This works even when GitHub code-search is rate-limited or hasn't
       indexed a freshly-added template.
    2. ProjectDiscovery Cloud link: always include the PD cloud library URL
       for the CVE (cloud.projectdiscovery.io/library/CVE-XXXX-YYYY).
    3. GitHub code search fallback: used for non-CVE queries or when direct
       probing finds nothing.
    """
    headers = dict(GITHUB_SEARCH_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    seen_paths: set = set()

    cve_id = query.upper() if is_cve(query) else None

    # ── 1. Direct path probe for CVE IDs ────────────────────────────────
    if cve_id:
        year = cve_id.split("-")[1]   # e.g. "2025"
        slug = cve_id.lower()          # e.g. "cve-2025-57819"
        candidate_paths = [
            f"http/cves/{year}/{slug}.yaml",
            f"network/cves/{year}/{slug}.yaml",
            f"code/cves/{year}/{slug}.yaml",
            f"ssl/cves/{year}/{slug}.yaml",
            f"dns/cves/{year}/{slug}.yaml",
            # Some older templates live directly under cves/
            f"cves/{year}/{slug}.yaml",
        ]
        req_headers = {"User-Agent": "ExploitFinder/2.0"}
        for rel_path in candidate_paths:
            if rel_path in seen_paths:
                continue
            raw_url  = f"{NUCLEI_RAW_BASE}/{rel_path}"
            blob_url = f"{NUCLEI_BLOB_BASE}/{rel_path}"
            try:
                r = requests.head(raw_url, headers=req_headers, timeout=TIMEOUT,
                                  allow_redirects=True)
                if r.status_code == 200:
                    seen_paths.add(rel_path)
                    name = os.path.basename(rel_path).replace(".yaml", "").replace("-", " ").title()
                    results.append({
                        "title":      name,
                        "path":       rel_path,
                        "url":        blob_url,
                        "raw_url":    raw_url,
                        "nuclei_cmd": f"nuclei -t {rel_path} -u <TARGET>",
                        "source":     "Nuclei Templates",
                    })
            except Exception:
                pass

        # ── 2. ProjectDiscovery Cloud link (always for CVE queries) ───────
        cloud_url = f"{NUCLEI_CLOUD_BASE}/{cve_id}"
        try:
            r = requests.head(cloud_url, headers=req_headers, timeout=TIMEOUT,
                              allow_redirects=True)
            if r.status_code == 200:
                results.append({
                    "title":      f"{cve_id} (PD Cloud Library)",
                    "path":       "",
                    "url":        cloud_url,
                    "raw_url":    "",
                    "nuclei_cmd": f"nuclei -id {slug} -u <TARGET>",
                    "source":     "PD Cloud",
                })
        except Exception:
            pass

    # ── 3. GitHub code search fallback ───────────────────────────────
    # Run always so we catch templates in non-standard paths or non-CVE queries.
    try:
        encoded = urllib.parse.quote(f"{query} repo:{NUCLEI_TEMPLATES_REPO}")
        url = f"{GITHUB_API}/search/code?q={encoded}&per_page=10"
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            for item in resp.json().get("items", []):
                path = item.get("path", "")
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                file_url = item.get("html_url", "")
                raw_url  = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                name     = os.path.basename(path).replace(".yaml", "").replace("-", " ").title()
                results.append({
                    "title":      name,
                    "path":       path,
                    "url":        file_url,
                    "raw_url":    raw_url,
                    "nuclei_cmd": f"nuclei -t {path} -u <TARGET>",
                    "source":     "Nuclei Templates",
                })
    except Exception:
        pass

    return results[:10]


# ─────────────────── VULNERS SEARCH ──────────────────────────────
VULNERS_RSS_URL = "https://vulners.com/rss.xml"
# Note: Vulners API endpoint is handled internally by the `vulners` SDK.


def search_packetstorm(query: str, vulners_key: str = None, add_search_link: bool = False) -> list[dict]:
    """Search Vulners.com via the official Python SDK (aggregates PacketStorm,
    ExploitDB, Exploit-DB GitHub mirrors, and more).

    Two modes:
    1. **SDK mode** (VULNERS_API_KEY env var or --vulners-key set):
       Uses the official `vulners` Python SDK (pip install vulners).
       Calls `api.search.search_exploits()` which queries:
           bulletinFamily:exploit AND (query)
       This is the same query the Vulners website uses internally.
    2. **RSS fallback** (no key): Fetches the public RSS feed and filters
       locally. Coverage is limited to ~50 most recent items.

    Free API key at: https://vulners.com  (50 req/day on free tier)
    Set via: export VULNERS_API_KEY=your_key  OR  --vulners-key flag
    """
    import xml.etree.ElementTree as ET

    # Resolve API key: explicit arg > env var
    api_key = vulners_key or os.environ.get("VULNERS_API_KEY", "").strip()

    results     = []
    query_lower = query.lower()
    cve_upper   = query.upper() if is_cve(query) else None

    if api_key:
        # ── Mode 1: Official Vulners SDK ─────────────────────────────────
        try:
            import vulners as vulners_sdk
            vapi = vulners_sdk.VulnersApi(api_key=api_key, timeout=TIMEOUT)

            # search_exploits queries: bulletinFamily:exploit AND (query)
            # This is targeted at exploit entries including PacketStorm, EDB, etc.
            exploit_hits = vapi.search.search_exploits(query, limit=MAX_RESULTS)

            seen: set = set()
            for item in exploit_hits:
                href  = item.get("href", "") or item.get("sourceHref", "")
                title = item.get("title", "Unknown")
                bfam  = item.get("bulletinFamily", "")
                date  = (item.get("published", "") or "")[:10]
                if href and href not in seen:
                    seen.add(href)
                    results.append({
                        "title":  title,
                        "url":    href,
                        "date":   date,
                        "source": f"Vulners ({bfam})" if bfam else "Vulners",
                    })

            # If query is a CVE, also do a broader bulletin search
            # (may surface advisories, patches, blog posts with PoC links)
            if cve_upper and len(results) < 5:
                bulletin_hits = vapi.search.search_bulletins(
                    f'"{cve_upper}"', limit=10
                )
                for item in bulletin_hits:
                    href  = item.get("href", "") or item.get("sourceHref", "")
                    title = item.get("title", "Unknown")
                    bfam  = item.get("bulletinFamily", "")
                    date  = (item.get("published", "") or "")[:10]
                    if href and href not in seen:
                        seen.add(href)
                        results.append({
                            "title":  title,
                            "url":    href,
                            "date":   date,
                            "source": f"Vulners ({bfam})" if bfam else "Vulners",
                        })
        except Exception:
            pass
    else:
        # ── Mode 2: RSS fallback (no API key) ────────────────────────────
        try:
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            resp = requests.get(VULNERS_RSS_URL, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 200:
                root = ET.fromstring(resp.text)
                seen = set()
                for item in root.iter("item"):
                    title_el = item.find("title")
                    link_el  = item.find("link")
                    desc_el  = item.find("description")
                    if title_el is None or link_el is None:
                        continue
                    title    = (title_el.text or "").strip()
                    link     = (link_el.text  or "").strip()
                    desc     = (desc_el.text  or "") if desc_el is not None else ""
                    haystack = (title + " " + desc).lower()
                    if cve_upper and cve_upper.lower() in haystack:
                        match = True
                    elif not cve_upper and query_lower in haystack:
                        match = True
                    else:
                        match = False
                    if match and link not in seen:
                        seen.add(link)
                        results.append({
                            "title":  title,
                            "url":    link,
                            "source": "Vulners",
                        })
        except Exception:
            pass

    # Optionally append a direct Vulners search link (only for the main keyword
    # call, not per-CVE calls, to avoid cluttering results with one link per CVE).
    if add_search_link:
        vulners_url = f"https://vulners.com/search?query={urllib.parse.quote(query)}"
        results.append({
            "title":  f"Vulners search: {query}",
            "url":    vulners_url,
            "source": "Vulners",
        })

    return results[:MAX_RESULTS]


# ──────────────────── SPLOITUS SEARCH ────────────────────────────
def search_sploitus(query: str) -> list[dict]:
    """Search Sploitus - exploit aggregator.

    Root cause of empty results: Sploitus requires `"title": true` in the
    POST payload to enable the full response envelope `{"exploits": [...]}`.  
    Without it, the API returns a bare empty list `[]`.
    """
    results = []
    try:
        payload = {
            "type":   "exploits",
            "query":  query,
            "offset": 0,
            "sort":   "score",
            "title":  True,      # ← required; without this API returns []
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept":       "application/json, text/plain, */*",
            "Origin":       "https://sploitus.com",
            "Referer":      f"https://sploitus.com/?query={urllib.parse.quote(query)}#exploits",
        }
        if _CF_BYPASS:
            resp = cf_requests.post(
                SPLOITUS_API, json=payload, headers=headers,
                impersonate="chrome110", timeout=TIMEOUT
            )
        else:
            resp = requests.post(SPLOITUS_API, json=payload, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            # API returns {"exploits": [...], "exploits_total": N} with title:true
            items = data.get("exploits", []) if isinstance(data, dict) else []
            for item in items:
                title  = item.get("title", "Unknown")
                href   = item.get("href", "").strip()
                score  = item.get("score", 0)
                date   = item.get("published", "")[:10]
                # source field may contain the sploitus URL; extract real href first
                if not href:
                    src = item.get("source", "")
                    m = re.search(r'https?://\S+', src)
                    href = m.group(0) if m else ""
                if href:
                    results.append({
                        "title":  title,
                        "url":    href,
                        "score":  score,
                        "date":   date,
                        "source": "Sploitus"
                    })
    except Exception:
        pass
    return results[:MAX_RESULTS]


# ─────────────────── GITHUB ADVANCED SEARCH ──────────────────────
def github_topic_search(query: str, token: str = None) -> list[dict]:
    """Search GitHub topics for CVE/exploit-tagged repos."""
    headers = dict(GITHUB_SEARCH_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    cves = extract_cves(query)
    if not cves:
        return results

    for cve in cves[:2]:
        try:
            # Search by topic tag (many PoC authors tag their repos with CVE IDs)
            topic_slug = cve.lower()
            url = f"{GITHUB_API}/search/repositories?q=topic:{topic_slug}&sort=stars&order=desc&per_page=5"
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    results.append({
                        "title": f"[Topic] {item['full_name']}",
                        "url": item["html_url"],
                        "stars": item["stargazers_count"],
                        "description": item.get("description") or "",
                        "updated": item.get("updated_at", "")[:10],
                        "language": item.get("language") or "Unknown",
                        "topics": item.get("topics", []),
                        "source": "GitHub Topics"
                    })
        except Exception:
            continue

    results.sort(key=lambda x: x["stars"], reverse=True)
    return results[:5]

# ──────────────────── DISPLAY FUNCTIONS ──────────────────────────
def display_nvd_keyword_results(results: list[dict], keyword: str):
    """Display NVD CVEs returned by keyword search in a colour-coded table.

    Results are sorted newest-first (published date descending) with CISA KEV
    entries pinned to the top and flagged with a 🔥 KEV badge.
    """
    if not results:
        console.print("[dim]  No CVEs found on NVD for this keyword.[/dim]")
        return

    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
        "N/A":      "dim",
    }

    kev_count = sum(1 for r in results if r.get("in_kev"))
    title_extra = f" | [bold red]🔥 {kev_count} CISA KEV[/bold red]" if kev_count else ""

    # render_w is computed once here so it's consistent across the table
    # definition, textwrap, and the sub-console render.
    render_w = max(console.width, 80)

    table = Table(
        title=(
            f"[bold white]NVD results for keyword: [cyan]{keyword}[/cyan][/bold white]"
            f"{title_extra}\n"
            f"[dim]Sorted by: Published Date ↓  |  CISA KEV entries pinned first[/dim]"
        ),
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
        width=render_w,          # explicit width — Rich won't expand beyond this
    )
    table.add_column("KEV",       style="bold red", width=4,  no_wrap=True)
    table.add_column("CVE ID",    style="cyan",     width=18, no_wrap=True)
    table.add_column("CVSS",      style="white",    width=6,  justify="right", no_wrap=True)
    table.add_column("Severity",  style="white",    width=10, no_wrap=True)
    table.add_column("Published", style="dim",      width=12, no_wrap=True)
    # Description: no min_width — let Rich allocate whatever remains after
    # fixed columns.  We pre-wrap below so words never split mid-character.
    table.add_column("Description", style="white",  no_wrap=False)

    # Pre-wrap width: render_w minus column overhead.
    # Overhead = 7 borders (|) + 6 cols * 2 padding = 19 + fixed cols 4+18+6+10+12 = 50
    # Total overhead = 19 + 50 = 69 → description column content = render_w - 69
    # Subtract 2 more for a small safety margin so no word ever hits the border.
    desc_col_w = max(render_w - 71, 20)

    for r in results:
        sev       = str(r.get("severity", "N/A")).upper()
        color     = sev_colors.get(sev, "white")
        score_str = str(r.get("score", "N/A"))
        kev_badge = "[bold red]\U0001f525[/bold red]" if r.get("in_kev") else ""
        cve_style = "bold cyan" if r.get("in_kev") else "cyan"

        desc = textwrap.fill(
            r.get("description", ""),
            width=desc_col_w,
            break_long_words=False,   # never split a word mid-character
            break_on_hyphens=False,   # keep hyphenated terms intact
        )

        table.add_row(
            kev_badge,
            f"[{cve_style}]{r.get('cve_id', '')}[/{cve_style}]",
            f"[{color}]{score_str}[/{color}]",
            f"[{color}]{sev}[/{color}]",
            r.get("published", ""),
            desc
        )

    # Render into a StringIO buffer using a sub-console whose width equals
    # render_w.  Then write the raw ANSI bytes directly to sys.stdout so Rich
    # never re-processes (and potentially re-lays-out) the already-rendered text.
    import sys as _sys
    buf     = io.StringIO()
    tbl_con = Console(
        file=buf, width=render_w, highlight=False,
        force_terminal=True, color_system=console.color_system,
    )
    tbl_con.print(table)
    _sys.stdout.write(buf.getvalue())
    _sys.stdout.flush()
    console.print()
    console.print()

    # Full NVD URLs (never truncated); highlight KEV entries
    for i, r in enumerate(results, 1):
        kev_tag = " [bold red][CISA KEV][/bold red]" if r.get("in_kev") else ""
        console.print(f"  [{i:02d}] [bright_blue]{r['url']}[/bright_blue]{kev_tag}")

def display_nvd_info(cve_id: str, info: dict):
    if not info:
        return
    score    = info.get("score", "N/A")
    severity = info.get("severity", "N/A")
    published = info.get("published", "N/A")

    # Color code severity
    sev_color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green"
    }.get(str(severity).upper(), "white")

    desc_safe = (info.get('description', 'N/A') or 'N/A')[:300]
    affected_str = ", ".join(info.get("affected", [])[:3])
    vector_str = info.get('vector', '')

    lines = [
        f"[bold white]CVE:[/bold white] [cyan]{cve_id}[/cyan]  "
        f"[bold white]CVSS:[/bold white] [{sev_color}]{score} ({severity})[/{sev_color}]  "
        f"[bold white]Published:[/bold white] [dim]{published}[/dim]",
        "",
        f"[bold white]Description:[/bold white]",
        desc_safe,
    ]
    if affected_str:
        lines.append("")
        lines.append(f"[bold white]Affected:[/bold white] {affected_str}")
    if vector_str:
        lines.append(f"[bold white]Vector:[/bold white] [dim]{vector_str}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title="[bold red]>> NVD / NIST CVE Intelligence[/bold red]",
        border_style="red",
        padding=(1, 2)
    ))

def display_github_results(results: list[dict]):
    if not results:
        console.print("[dim]  No GitHub results found.[/dim]")
        return

    # Print URLs on separate lines so they are NEVER truncated by Rich's
    # table column wrapping (which was causing the '...' 404 issue).
    table = Table(
        title="",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        min_width=60
    )
    table.add_column("Stars", style="yellow", width=7, justify="right")
    table.add_column("Repository / File", style="white", min_width=38)
    table.add_column("Lang", style="magenta", width=8)
    table.add_column("Updated", style="dim", width=12)

    for r in results:
        stars = str(r.get("stars", 0))
        title = r.get("title", "")[:55]
        lang  = r.get("language", "")[:7]
        upd   = r.get("updated", "")
        table.add_row(stars, title, lang, upd)

    console.print(table)

    # Print full URLs below the table — guaranteed not truncated
    console.print()
    for i, r in enumerate(results, 1):
        url  = r.get("url", "")
        desc = r.get("description", "")
        fp   = r.get("file_path", "")
        label = f"  [{i:02d}] [bright_blue]{url}[/bright_blue]"
        if fp:
            label += f"  [dim](file: {fp})[/dim]"
        elif desc:
            label += f"  [dim]{desc[:80]}[/dim]"
        console.print(label)

def display_exploitdb_results(results: list[dict]):
    if not results:
        console.print("[dim]  No ExploitDB results found.[/dim]")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="green",
        header_style="bold green"
    )
    table.add_column("EDB-ID", style="green", width=10)
    table.add_column("Title", style="white", min_width=40)
    table.add_column("Type", style="yellow", width=15)
    table.add_column("Date", style="dim", width=12)

    for r in results:
        table.add_row(
            r.get("edb_id", ""),
            r.get("title", "")[:60],
            r.get("type", ""),
            r.get("date", "")
        )

    console.print(table)
    console.print()
    for i, r in enumerate(results, 1):
        console.print(f"  [{i:02d}] [bright_blue]{r.get('url', '')}[/bright_blue]")

def display_nuclei_results(results: list[dict]):
    if not results:
        console.print("[dim]  No Nuclei templates found.[/dim]")
        return

    for r in results:
        is_cloud = r.get("source") == "PD Cloud"
        badge    = "[bold cyan]☁ PD Cloud[/bold cyan]" if is_cloud else "[green][+][/green]"
        path_line = "" if is_cloud else f"     [dim]Path:[/dim] {r['path']}\n"
        console.print(
            f"  {badge} [bold white]{r['title']}[/bold white]\n"
            f"{path_line}"
            f"     [dim]URL:[/dim]  [bright_blue]{r['url']}[/bright_blue]\n"
            f"     [bold yellow]Run:[/bold yellow] [cyan]{r['nuclei_cmd']}[/cyan]\n"
        )

def display_packetstorm_results(results: list[dict]):
    if not results:
        console.print("[dim]  No Vulners results found.[/dim]")
        return

    for r in results:
        console.print(
            f"  [red]*[/red] [white]{r['title']}[/white]\n"
            f"     [bright_blue]{r['url']}[/bright_blue]\n"
        )

def display_sploitus_results(results: list[dict]):
    if not results:
        console.print("[dim]  No Sploitus results found.[/dim]")
        return

    table = Table(box=box.SIMPLE, border_style="magenta", header_style="bold magenta")
    table.add_column("Score", style="magenta", width=8)
    table.add_column("Title", style="white", min_width=50)
    table.add_column("Date", style="dim", width=12)

    for r in results:
        table.add_row(
            f"{r.get('score', 0):.2f}" if isinstance(r.get('score'), float) else str(r.get('score', '')),
            r.get("title", "")[:70],
            r.get("date", "")
        )
    console.print(table)
    console.print()
    for i, r in enumerate(results, 1):
        console.print(f"  [{i:02d}] [bright_blue]{r.get('url', '')}[/bright_blue]")

def display_summary(all_results: dict, query: str, elapsed: float):
    """Print a final consolidated summary with all URLs."""
    console.print()
    console.print(Rule("[bold red]CONSOLIDATED EXPLOIT SUMMARY[/bold red]", style="red"))
    console.print()

    total = 0
    rows  = []
    seen_summary_urls: set = set()

    # Skip internal-only keys that are subsets of already-merged keys
    skip_keys = {"GitHub Repos", "GitHub Topics"}  # replaced by merged "GitHub"

    for source, results in all_results.items():
        if source in skip_keys:
            continue
        for r in results:
            url = r.get("url", "")
            if url and url not in seen_summary_urls:
                seen_summary_urls.add(url)
                total += 1
                rows.append((source, r.get("title", ""), url))

    if rows:
        console.print(
            f"[bold white]>> Found {total} exploit leads for:[/bold white] [cyan]{query}[/cyan]"
        )
        console.print()
        for i, (source, title, url) in enumerate(rows[:50], 1):
            console.print(
                f"  [{i:02d}] [cyan]{source:<18}[/cyan] "
                f"[white]{title[:55]:<55}[/white]"
            )
            console.print(f"       [bright_blue]{url}[/bright_blue]")

    console.print()
    console.print(
        f"[dim]Completed in [bold]{elapsed:.2f}s[/bold] | "
        f"[bold]{total}[/bold] results | "
        f"Query: [cyan]{query}[/cyan][/dim]"
    )

# ──────────────────────── MAIN ENGINE ────────────────────────────
def run_search(query: str, token: str = None, no_nuclei: bool = False, vulners_key: str = None):
    start = time.time()
    all_results = {}

    print_banner()
    console.print(f"[bold white]>> Target Query:[/bold white] [cyan]{query}[/cyan]\n")

    cves = extract_cves(query)
    primary_cve = cves[0] if cves else None
    nvd_keyword_results: list[dict] = []   # populated in the else branch below

    # ── NVD Intelligence ──────────────────────────────────────────
    if primary_cve:
        # Known CVE: fetch full details
        console.print(Rule("[bold red]>> CVE Intelligence (NVD/NIST)[/bold red]", style="red"))
        with console.status("[bold red]Fetching CVE metadata from NIST NVD...[/bold red]"):
            nvd_info = fetch_nvd_details(primary_cve)
        display_nvd_info(primary_cve, nvd_info)
        console.print()
    else:
        # Software/keyword query: search NVD for related CVEs.
        # Run CISA KEV fetch + NVD search concurrently (both are HTTP calls).
        software_name = extract_software_name(query) or query
        console.print(Rule("[bold red]>> NVD CVE Keyword Search  +  CISA KEV[/bold red]", style="red"))

        def _kev_task():
            return fetch_cisa_kev()

        def _nvd_task():
            # Exact-match first, fall back to broad.
            # search_nvd_by_keyword now paginates through ALL results so
            # no CVE is ever missed regardless of total count.
            res = search_nvd_by_keyword(software_name, exact=True)
            if not res:
                res = search_nvd_by_keyword(software_name, exact=False)
            # If a version was appended, also try the full string and merge
            if software_name != query:
                extra = search_nvd_by_keyword(query, exact=False, limit=15)
                seen  = {r["cve_id"] for r in res}
                for r in extra:
                    if r["cve_id"] not in seen:
                        res.append(r)
                        seen.add(r["cve_id"])
                # Re-sort after merge
                def _mk(r):
                    pub = r.get("published", "") or ""
                    return (r.get("in_kev", False), pub)
                res.sort(key=_mk, reverse=True)
            return res

        with console.status(
            f"[bold red]Fetching CISA KEV + NIST NVD for '{software_name}' "
            f"(all pages, sorted: CISA KEV ↑  published date ↓)...[/bold red]"
        ):
            with ThreadPoolExecutor(max_workers=2) as pre_pool:
                f_kev = pre_pool.submit(_kev_task)
                f_nvd = pre_pool.submit(_nvd_task)
                kev_set            = f_kev.result()
                nvd_keyword_results = f_nvd.result()

        if kev_set:
            console.print(
                f"[dim green]  ✓ CISA KEV loaded — {len(kev_set):,} known-exploited CVEs[/dim green]"
            )

        display_nvd_keyword_results(nvd_keyword_results, software_name)

        # ── NVD Exploit References (curated by NIST) ─────────────────────
        # Each CVE fetched from NVD may carry references tagged "Exploit" or
        # "Third Party Advisory" — these include PoC repos, vendor advisories,
        # and exploit-database links that NIST has manually curated.
        nvd_exploit_refs = []
        seen_ref_urls: set = set()
        for r in nvd_keyword_results:
            for ref in r.get("exploit_refs", []):
                url = ref.get("url", "")
                if url and url not in seen_ref_urls:
                    seen_ref_urls.add(url)
                    nvd_exploit_refs.append((r["cve_id"], ref))
        if nvd_exploit_refs:
            console.print(Rule(
                "[bold red]>> NVD Exploit References (NIST-curated)[/bold red]",
                style="red"
            ))
            for cve_id, ref in nvd_exploit_refs:
                tags_str = ", ".join(ref.get("tags", []))
                console.print(
                    f"  [cyan]{cve_id}[/cyan]  [dim]{tags_str}[/dim]\n"
                    f"    [bright_blue]{ref['url']}[/bright_blue]"
                )
            console.print()
        console.print()

        # ── Auto-expand the highest-priority CVE (KEV first, then newest) ──
        if nvd_keyword_results:
            top = next(
                (r for r in nvd_keyword_results if r.get("in_kev")),
                nvd_keyword_results[0]
            )
            top_cve = top.get("cve_id", "")
            if top_cve and top_cve.startswith("CVE-"):
                kev_label = " [bold red][CISA KEV][/bold red]" if top.get("in_kev") else ""
                console.print(
                    f"[bold white]>> Full details for top hit:[/bold white] "
                    f"[cyan]{top_cve}[/cyan] "
                    f"(CVSS [bold]{top.get('score', 'N/A')}[/bold] {top.get('severity', '')})"
                    f"{kev_label}"
                )
                with console.status(f"[dim]Fetching full NVD record for {top_cve}...[/dim]"):
                    top_details = fetch_nvd_details(top_cve)
                display_nvd_info(top_cve, top_details)
                console.print()
                primary_cve = top_cve  # expose for Nuclei search

        # ── CVE-driven exploit search ─────────────────────────────────────
        # Take the top 5 CVEs (KEV-first, then newest) and hunt for PoCs
        # across all exploit sources alongside the keyword search.
        cve_targets = [
            r["cve_id"] for r in nvd_keyword_results
            if r.get("cve_id", "").startswith("CVE-")
        ][:5]

        # Store NVD results for the consolidated summary
        all_results["NVD"] = nvd_keyword_results if nvd_keyword_results else []

    # ── Parallel exploit search: keyword + CVE-specific combined ─────────
    # For keyword queries we run TWO sets of searches:
    #   A) keyword-based (existing behaviour)
    #   B) CVE-specific for each of the top discovered CVEs (new)
    # Both sets run in the same ThreadPoolExecutor to avoid doubling wall time.

    futures_map          = {}
    cve_exploit_future   = None          # always defined (set only in keyword mode)
    cve_exploit_results: dict[str, list] = {}  # always defined
    # cve_targets is defined in the else-branch above; empty for direct CVE queries
    _cve_targets  = locals().get("cve_targets", [])

    with ThreadPoolExecutor(max_workers=10) as executor:

        # ── A) Keyword-based searches (always run) ────────────────────────
        console.print(Rule("[bold cyan]>> GitHub Exploit Search[/bold cyan]", style="cyan"))
        f_github = executor.submit(github_search_repos, query, token)
        f_topics = executor.submit(github_topic_search, query, token)
        futures_map["GitHub Repos"]   = f_github
        futures_map["GitHub Topics"]  = f_topics

        console.print(Rule("[bold green]>> Exploit-DB[/bold green]", style="green"))
        f_edb = executor.submit(search_exploitdb, query)
        futures_map["ExploitDB"] = f_edb

        if not no_nuclei and primary_cve:
            console.print(Rule("[bold yellow]>> ProjectDiscovery Nuclei Templates[/bold yellow]", style="yellow"))
            f_nuclei = executor.submit(search_nuclei_templates, primary_cve, token)
            futures_map["Nuclei"] = f_nuclei

        console.print(Rule("[bold magenta]>> Vulners / PacketStorm[/bold magenta]", style="magenta"))
        f_ps = executor.submit(search_packetstorm, query, vulners_key)
        futures_map["Vulners"] = f_ps

        console.print(Rule("[bold blue]>> Sploitus (Exploit Aggregator)[/bold blue]", style="blue"))
        f_sploitus = executor.submit(search_sploitus, query)
        futures_map["Sploitus"] = f_sploitus

        # ── B) CVE-specific searches (keyword mode only) ──────────────────
        # Feed the top discovered CVEs into all exploit sources in parallel.
        # Results are collected separately and merged into the display later.
        cve_exploit_future = None
        if _cve_targets:
            cve_label = ", ".join(_cve_targets[:3]) + (" …" if len(_cve_targets) > 3 else "")
            console.print(
                f"[dim yellow]  ↳ Also searching exploits for discovered CVEs: "
                f"[cyan]{cve_label}[/cyan][/dim yellow]"
            )
            cve_exploit_future = executor.submit(
                search_exploits_for_cves, _cve_targets, token, 5, vulners_key
            )

        console.print()

        # Collect results as they complete
        with console.status("[bold white]Querying all sources in parallel...[/bold white]") as status:
            done_sources = set()
            pending = dict(futures_map)
            while pending:
                for name, fut in list(pending.items()):
                    if fut.done():
                        try:
                            result = fut.result()
                            all_results[name] = result
                        except Exception:
                            all_results[name] = []
                        done_sources.add(name)
                        del pending[name]
                        status.update(
                            f"[bold white]✓ {name} done — "
                            f"{len(done_sources)}/{len(futures_map)} sources[/bold white]"
                        )
                time.sleep(0.1)

        # Collect CVE-specific exploit results
        if cve_exploit_future:
            try:
                cve_exploit_results = cve_exploit_future.result()
            except Exception:
                cve_exploit_results = {}

    console.print()

    # ── Display Results ───────────────────────────────────────────
    gh_all = all_results.get("GitHub Repos", []) + all_results.get("GitHub Topics", [])

    # Merge CVE-specific GitHub results (deduplicate by URL)
    gh_seen_urls = {r.get("url") for r in gh_all}
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("source") in ("GitHub Repos", "GitHub Code", "GitHub Topics"):
                if h.get("url") not in gh_seen_urls:
                    gh_seen_urls.add(h.get("url"))
                    gh_all.append(h)
    gh_all.sort(key=lambda x: x.get("stars", 0), reverse=True)

    console.print(Rule("[bold cyan]>> GitHub Results[/bold cyan]", style="cyan"))
    display_github_results(gh_all)
    console.print()

    # ExploitDB: merge keyword + CVE-specific
    edb_all = list(all_results.get("ExploitDB", []))
    edb_seen = {r.get("url") for r in edb_all}
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("source") == "ExploitDB" and h.get("url") not in edb_seen:
                edb_seen.add(h.get("url"))
                edb_all.append(h)
    console.print(Rule("[bold green]>> Exploit-DB Results[/bold green]", style="green"))
    display_exploitdb_results(edb_all)
    console.print()

    # Nuclei: merge primary_cve results + CVE-specific hits from cve_exploit_results
    nuclei_all  = list(all_results.get("Nuclei", []))
    nuclei_seen = {r.get("url") for r in nuclei_all}
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("source") in ("Nuclei Templates", "PD Cloud") and h.get("url") not in nuclei_seen:
                nuclei_seen.add(h.get("url"))
                nuclei_all.append(h)
    if nuclei_all:
        console.print(Rule("[bold yellow]>> Nuclei Template Results[/bold yellow]", style="yellow"))
        display_nuclei_results(nuclei_all)
        console.print()

    # Vulners: merge keyword + CVE-specific
    ps_all  = list(all_results.get("Vulners", []))
    ps_seen = {r.get("url") for r in ps_all}
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("source") in ("Vulners", "PacketStorm") and h.get("url") not in ps_seen:
                ps_seen.add(h.get("url"))
                ps_all.append(h)
    console.print(Rule("[bold magenta]>> Vulners / PacketStorm[/bold magenta]", style="magenta"))
    display_packetstorm_results(ps_all)
    console.print()

    # Sploitus: merge keyword + CVE-specific
    sp_all  = list(all_results.get("Sploitus", []))
    sp_seen = {r.get("url") for r in sp_all}
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("source") == "Sploitus" and h.get("url") not in sp_seen:
                sp_seen.add(h.get("url"))
                sp_all.append(h)
    console.print(Rule("[bold blue]>> Sploitus Results[/bold blue]", style="blue"))
    display_sploitus_results(sp_all)
    console.print()

    # ── CVE-specific exploit section (if any new unique hits) ─────
    cve_only_hits = []
    all_displayed_urls = (
        {r.get("url") for r in gh_all}
        | {r.get("url") for r in edb_all}
        | {r.get("url") for r in ps_all}
        | {r.get("url") for r in sp_all}
    )
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            if h.get("url") and h.get("url") not in all_displayed_urls:
                all_displayed_urls.add(h.get("url"))
                h["_cve_label"] = cve_id
                cve_only_hits.append(h)

    if cve_only_hits:
        console.print(Rule("[bold red]>> CVE-Specific Exploit Hits (additional)[/bold red]", style="red"))
        for h in cve_only_hits:
            cve_lbl = h.get("_cve_label", "")
            src     = h.get("source", "")
            title   = h.get("title", "")[:70]
            url     = h.get("url", "")
            console.print(
                f"  [cyan]{cve_lbl}[/cyan]  [dim]{src}[/dim]  {title}\n"
                f"    [bright_blue]{url}[/bright_blue]"
            )
        console.print()

    elapsed = time.time() - start

    # Build a complete picture for the summary: merge all displayed lists
    # back into all_results so display_summary sees every result.
    all_results["GitHub"]     = gh_all
    all_results["ExploitDB"]  = edb_all
    all_results["Nuclei"]     = nuclei_all
    all_results["Vulners"]    = ps_all
    all_results["Sploitus"]   = sp_all
    # Flatten CVE-specific hits that weren't already merged above
    cve_extra = []
    for cve_id, hits in cve_exploit_results.items():
        for h in hits:
            src = h.get("source", "")
            if src not in ("GitHub Repos", "GitHub Code", "GitHub Topics",
                           "ExploitDB", "Vulners", "Sploitus",
                           "Nuclei Templates", "PD Cloud"):
                cve_extra.append(h)
    if cve_extra:
        all_results["CVE-Specific"] = cve_extra

    display_summary(all_results, query, elapsed)

# ─────────────────────────── CLI ─────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="🩸 Advanced Exploit Finder — HTB Blood Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python exploit_finder.py CVE-2024-1234
  python exploit_finder.py "apache 2.4.49"
  python exploit_finder.py "log4shell rce"
  python exploit_finder.py CVE-2023-44487 --github-token ghp_xxxx
  python exploit_finder.py "openssh 9.1" --no-nuclei
        """
    )
    parser.add_argument(
        "query",
        nargs="+",
        help="CVE ID or software/version string to search"
    )
    parser.add_argument(
        "--github-token", "-t",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub API token (or set GITHUB_TOKEN env var) — removes rate limiting"
    )
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="Skip Nuclei template search"
    )
    parser.add_argument(
        "--vulners-key", "-vk",
        default=os.environ.get("VULNERS_API_KEY"),
        help="Vulners API key for full search (or set VULNERS_API_KEY env var). "
             "Free key at https://vulners.com (50 req/day)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Save results to JSON file"
    )

    args = parser.parse_args()
    query = " ".join(args.query)

    if not args.github_token:
        console.print(
            "[dim yellow][!] No GitHub token set. You may hit rate limits. "
            "Set GITHUB_TOKEN env var or use --github-token for full results.[/dim yellow]\n"
        )

    vulners_key = getattr(args, "vulners_key", None)
    if not vulners_key:
        console.print(
            "[dim yellow][!] No Vulners API key. Using RSS fallback (limited coverage). "
            "Get a free key at https://vulners.com and set VULNERS_API_KEY env var.[/dim yellow]\n"
        )

    run_search(
        query=query,
        token=args.github_token,
        no_nuclei=args.no_nuclei,
        vulners_key=vulners_key,
    )

if __name__ == "__main__":
    main()