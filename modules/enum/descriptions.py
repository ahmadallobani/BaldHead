# modules/enum/descriptions.py

import re
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

PASSWORD_PATTERNS = [r"pass", r"pwd", r"password", r"secret", r"cred", r"key", r"token"]


def enum_descriptions(session, save=False):
    print(blue("[*] Scraping AD object descriptions for credentials..."))
    try:
        if session.hash:
            cred = f"-H {session.hash}"
        elif session.password:
            cred = f"-p '{session.password}'"
        else:
            print(red("[-] No credentials in session."))
            return

        cmd = (
            f"nxc ldap {session.dc_ip} -u {session.username} "
            f"{cred} -d {session.domain} "
            f"--query '(description=*)' description sAMAccountName"
        )
        out, err = run_command(cmd)
        combined = out + err

        hits = [
            line for line in combined.splitlines()
            if any(re.search(p, line, re.IGNORECASE) for p in PASSWORD_PATTERNS)
        ]

        if hits:
            print(green(f"[+] Found {len(hits)} suspicious descriptions:"))
            for h in hits:
                print(green(f"  {h}"))
            if save:
                save_loot("suspicious_descriptions.txt", "\n".join(hits))
        else:
            print(yellow("[*] No suspicious descriptions found."))
            if save and combined.strip():
                save_loot("all_descriptions.txt", combined)
    except Exception as e:
        print(red(f"[!] Description enumeration failed: {e}"))
