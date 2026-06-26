#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADVANCED EXPLOIT FINDER - HTB Blood Hunting Tool
CVE PoC Hunter | GitHub | ExploitDB | Nuclei | NVD | PacketStorm | Sploitus

Usage:
    python exploit_finder.py CVE-2024-1234
    python exploit_finder.py "apache 2.4.49"
    python exploit_finder.py "log4shell"
    python exploit_finder.py CVE-2024-1234 --github-token ghp_xxxx
"""

import re
import sys
import os
import argparse
import threading
import time
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import io
import requests
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
        "[dim]Sources: GitHub | ExploitDB | Nuclei Templates | NVD/NIST | PacketStorm | Sploitus[/dim]",
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

# ────────────────────── GITHUB SEARCH ────────────────────────────
def github_search_repos(query: str, token: str = None) -> list[dict]:
    """Search GitHub repositories for exploit/PoC code."""
    headers = dict(GITHUB_SEARCH_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    # Multiple targeted query strategies
    queries = [
        f"{query} exploit",
        f"{query} poc",
        f"{query} vulnerability",
    ]
    if is_cve(query):
        queries.insert(0, query)  # Exact CVE first

    seen_urls = set()
    for q in queries:
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

    # Also search GitHub code for PoC files
    try:
        code_query = urllib.parse.quote(f"{query} exploit")
        code_url = f"{GITHUB_API}/search/code?q={code_query}+filename:*.py+filename:*.rb+filename:*.sh+filename:*.go&sort=indexed&per_page=5"
        resp = requests.get(code_url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            for item in resp.json().get("items", []):
                repo_url = item.get("repository", {}).get("html_url", "")
                file_url = item.get("html_url", "")
                if file_url not in seen_urls:
                    seen_urls.add(file_url)
                    results.append({
                        "title": f"[Code] {item['name']} in {item.get('repository', {}).get('full_name', '')}",
                        "url": file_url,
                        "stars": item.get("repository", {}).get("stargazers_count", 0),
                        "description": f"PoC file: {item.get('path', '')}",
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
def search_nuclei_templates(query: str, token: str = None) -> list[dict]:
    """Search ProjectDiscovery nuclei-templates repository."""
    headers = dict(GITHUB_SEARCH_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    try:
        encoded = urllib.parse.quote(f"{query} repo:{NUCLEI_TEMPLATES_REPO}")
        url = f"{GITHUB_API}/search/code?q={encoded}&per_page=10"
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            for item in resp.json().get("items", []):
                path = item.get("path", "")
                file_url = item.get("html_url", "")
                raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                name = os.path.basename(path).replace(".yaml", "").replace("-", " ").title()
                results.append({
                    "title": name,
                    "path": path,
                    "url": file_url,
                    "raw_url": raw_url,
                    "nuclei_cmd": f"nuclei -t {path} -u <TARGET>",
                    "source": "Nuclei Templates"
                })
    except Exception:
        pass
    return results[:5]

# ─────────────────── PACKETSTORM SEARCH ──────────────────────────
def search_packetstorm(query: str) -> list[dict]:
    """Search PacketStorm Security for exploits."""
    results = []
    try:
        encoded = urllib.parse.quote(query)
        url = f"{PACKETSTORM_SEARCH}{encoded}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html"
        }
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            # Parse the HTML response for exploit listings
            html = resp.text
            # PacketStorm listing pattern: <a href="/files/NNNNN/title.html">Title</a>
            pattern = r'<a href="(/files/\d+/[^"]+\.html)"[^>]*>([^<]+)</a>'
            matches = re.findall(pattern, html)
            seen = set()
            for path, title in matches:
                if path in seen:
                    continue
                seen.add(path)
                clean_title = re.sub(r'\s+', ' ', title).strip()
                if len(clean_title) > 5:  # Filter noise
                    results.append({
                        "title": clean_title,
                        "url": f"https://packetstormsecurity.com{path}",
                        "source": "PacketStorm"
                    })
    except Exception:
        pass
    return results[:MAX_RESULTS]

# ──────────────────── SPLOITUS SEARCH ────────────────────────────
def search_sploitus(query: str) -> list[dict]:
    """Search Sploitus - exploit aggregator."""
    results = []
    try:
        payload = {
            "type": "exploits",
            "query": query,
            "offset": 0,
            "sort": "score"
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        }
        resp = requests.post(SPLOITUS_API, json=payload, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("exploits", []):
                title = item.get("title", "Unknown")
                href  = item.get("href", "") or item.get("source", "")
                score = item.get("score", 0)
                date  = item.get("published", "")[:10]
                results.append({
                    "title": title,
                    "url": href,
                    "score": score,
                    "date": date,
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

    table = Table(
        title="",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        min_width=80
    )
    table.add_column("⭐ Stars", style="yellow", width=8, justify="right")
    table.add_column("Repository / File", style="white", min_width=35)
    table.add_column("Language", style="magenta", width=12)
    table.add_column("Updated", style="dim", width=12)
    table.add_column("URL", style="bright_blue", min_width=40)

    for r in results:
        stars = str(r.get("stars", 0))
        title = r.get("title", "")[:50]
        lang  = r.get("language", "")[:10]
        upd   = r.get("updated", "")
        url   = r.get("url", "")
        table.add_row(stars, title, lang, upd, url)

    console.print(table)

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
    table.add_column("URL", style="bright_blue", min_width=40)

    for r in results:
        table.add_row(
            r.get("edb_id", ""),
            r.get("title", "")[:60],
            r.get("type", ""),
            r.get("date", ""),
            r.get("url", "")
        )

    console.print(table)

def display_nuclei_results(results: list[dict]):
    if not results:
        console.print("[dim]  No Nuclei templates found.[/dim]")
        return

    for r in results:
        console.print(
            f"  [green][+][/green] [bold white]{r['title']}[/bold white]\n"
            f"     [dim]Path:[/dim] {r['path']}\n"
            f"     [dim]URL:[/dim]  [bright_blue]{r['url']}[/bright_blue]\n"
            f"     [bold yellow]Run:[/bold yellow] [cyan]{r['nuclei_cmd']}[/cyan]\n"
        )

def display_packetstorm_results(results: list[dict]):
    if not results:
        console.print("[dim]  No PacketStorm results found.[/dim]")
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
    table.add_column("Title", style="white", min_width=45)
    table.add_column("Date", style="dim", width=12)
    table.add_column("URL", style="bright_blue", min_width=40)

    for r in results:
        table.add_row(
            f"{r.get('score', 0):.2f}" if isinstance(r.get('score'), float) else str(r.get('score', '')),
            r.get("title", "")[:65],
            r.get("date", ""),
            r.get("url", "")
        )
    console.print(table)

def display_summary(all_results: dict, query: str, elapsed: float):
    """Print a final consolidated summary with all URLs."""
    console.print()
    console.print(Rule("[bold red]CONSOLIDATED EXPLOIT SUMMARY[/bold red]", style="red"))
    console.print()

    total = 0
    rows = []
    for source, results in all_results.items():
        for r in results:
            if r.get("url"):
                total += 1
                rows.append((source, r.get("title", ""), r.get("url", "")))

    if rows:
        table = Table(
            title=f"[bold white]>> Found {total} exploit leads for: [cyan]{query}[/cyan][/bold white]",
            box=box.DOUBLE_EDGE,
            border_style="red",
            header_style="bold white",
            show_lines=True
        )
        table.add_column("Source", style="cyan", width=18)
        table.add_column("Title", style="white", min_width=40)
        table.add_column("URL", style="bright_blue underline", min_width=50)

        for source, title, url in rows[:25]:  # cap at 25 for readability
            table.add_row(source, title[:65], url)

        console.print(table)

    console.print()
    console.print(
        f"[dim]Completed in [bold]{elapsed:.2f}s[/bold] | "
        f"[bold]{total}[/bold] results | "
        f"Query: [cyan]{query}[/cyan][/dim]"
    )

# ──────────────────────── MAIN ENGINE ────────────────────────────
def run_search(query: str, token: str = None, no_nuclei: bool = False):
    start = time.time()
    all_results = {}

    print_banner()
    console.print(f"[bold white]>> Target Query:[/bold white] [cyan]{query}[/cyan]\n")

    cves = extract_cves(query)
    primary_cve = cves[0] if cves else None

    # ── NVD Intelligence ──────────────────────────────────────────
    if primary_cve:
        console.print(Rule("[bold red]>> CVE Intelligence (NVD/NIST)[/bold red]", style="red"))
        with console.status("[bold red]Fetching CVE metadata from NIST NVD...[/bold red]"):
            nvd_info = fetch_nvd_details(primary_cve)
        display_nvd_info(primary_cve, nvd_info)
        console.print()

    # Use concurrent futures for speed
    futures_map = {}
    with ThreadPoolExecutor(max_workers=6) as executor:

        # GitHub Repos + Code
        console.print(Rule("[bold cyan]>> GitHub Exploit Search[/bold cyan]", style="cyan"))
        f_github = executor.submit(github_search_repos, query, token)
        f_topics = executor.submit(github_topic_search, query, token)
        futures_map["GitHub Repos"] = f_github
        futures_map["GitHub Topics"] = f_topics

        # ExploitDB
        console.print(Rule("[bold green]>> Exploit-DB[/bold green]", style="green"))
        f_edb = executor.submit(search_exploitdb, query)
        futures_map["ExploitDB"] = f_edb

        # Nuclei Templates
        if not no_nuclei and primary_cve:
            console.print(Rule("[bold yellow]>> ProjectDiscovery Nuclei Templates[/bold yellow]", style="yellow"))
            f_nuclei = executor.submit(search_nuclei_templates, primary_cve, token)
            futures_map["Nuclei"] = f_nuclei

        # PacketStorm
        console.print(Rule("[bold magenta]>> PacketStorm Security[/bold magenta]", style="magenta"))
        f_ps = executor.submit(search_packetstorm, query)
        futures_map["PacketStorm"] = f_ps

        # Sploitus
        console.print(Rule("[bold blue]>> Sploitus (Exploit Aggregator)[/bold blue]", style="blue"))
        f_sploitus = executor.submit(search_sploitus, query)
        futures_map["Sploitus"] = f_sploitus

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
                        status.update(f"[bold white]✓ {name} done — {len(done_sources)}/{len(futures_map)} sources[/bold white]")
                time.sleep(0.1)

    console.print()

    # ── Display Results ───────────────────────────────────────────
    gh_all = all_results.get("GitHub Repos", []) + all_results.get("GitHub Topics", [])
    gh_all.sort(key=lambda x: x.get("stars", 0), reverse=True)

    console.print(Rule("[bold cyan]>> GitHub Results[/bold cyan]", style="cyan"))
    display_github_results(gh_all)
    console.print()

    console.print(Rule("[bold green]>> Exploit-DB Results[/bold green]", style="green"))
    display_exploitdb_results(all_results.get("ExploitDB", []))
    console.print()

    if "Nuclei" in all_results:
        console.print(Rule("[bold yellow]>> Nuclei Template Results[/bold yellow]", style="yellow"))
        display_nuclei_results(all_results.get("Nuclei", []))
        console.print()

    console.print(Rule("[bold magenta]>> PacketStorm Results[/bold magenta]", style="magenta"))
    display_packetstorm_results(all_results.get("PacketStorm", []))
    console.print()

    console.print(Rule("[bold blue]>> Sploitus Results[/bold blue]", style="blue"))
    display_sploitus_results(all_results.get("Sploitus", []))
    console.print()

    elapsed = time.time() - start
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

    run_search(
        query=query,
        token=args.github_token,
        no_nuclei=args.no_nuclei
    )

if __name__ == "__main__":
    main()