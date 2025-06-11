# modules/auth_enum.py

import os
import shutil
import re
from core.helpers import run_command, save_loot
from core.colors import blue, green, yellow, red

def enum_users(session, save=False):
    print(blue("[*] Extracting domain users via SMB (nxc)..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc smb {session.target_ip} -u \"{session.username}\""
    if session.hash:
        cmd += f" -p :{session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    else:
        cmd += " -k --no-pass"
    cmd += " --users"

    out, err = run_command(cmd)
    if not out:
        print(red("[!] No output returned. Check credentials or target."))
        return

    users = []
    found_header = False

    for line in out.splitlines():
        # Wait until the listing header appears
        if "-Username-" in line and "-Last PW Set-" in line:
            found_header = True
            continue

        if found_header:
            parts = line.split()
            if len(parts) >= 2:
                user = parts[4] if len(parts) >= 5 else parts[0]
                if user.lower() not in ["administrator", "guest", "krbtgt"]:  # optional
                    users.append(user)

    unique_users = sorted(set(users), key=lambda x: x.lower())
    if unique_users:
        for u in unique_users:
            print(green(f"[+] User: {u}"))
        if save:
            with open("loot/valid_users.txt", "w") as f:
                f.writelines([u + "\n" for u in unique_users])
            print(yellow("[+] Saved to loot/valid_users.txt"))
    else:
        print(red("[-] No usernames extracted."))
        if err:
            print(yellow(err.strip()))


def enum_shares(session, save=False):
    print(blue("[*] Enumerating SMB shares via nxc..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc smb {session.target_ip} --shares"
    if session.hash:
        cmd += f" -u {session.username} -p :{session.hash}"
    elif session.password:
        cmd += f" -u {session.username} -p '{session.password}'"
    else:
        cmd += f" -u {session.username} -k"

    out, err = run_command(cmd)
    print(out.strip() or err.strip())

    if save:
        save_loot(f"smb_shares_{session.target_ip}.txt", out or err)


def enum_bloodhound(session, save=False):
    print(blue("[*] Running BloodHound LDAP collection via nxc..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc ldap {session.dc_ip} -u \"{session.username}\""
    if session.hash:
        cmd += f" -p :{session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    else:
        cmd += " -k"

    cmd += f" --dns-server {session.dc_ip} --bloodhound --collection All"

    out, err = run_command(cmd)
    combined = out + "\n" + err
    print(combined.strip())

    for line in combined.splitlines():
        if ".zip" in line and "bloodhound" in line.lower():
            print(green(f"[+] BloodHound file: {line.strip()}"))
