# modules/enum/unconstrained.py

from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow


def enum_unconstrained(session, save=False):
    print(blue("[*] Enumerating computers with unconstrained delegation (excluding DCs)..."))
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
            f"--trusted-for-delegation"
        )
        out, err = run_command(cmd)
        combined = out + err
        print(combined)
        if save:
            save_loot("unconstrained_delegation.txt", combined)
    except Exception as e:
        print(red(f"[!] Unconstrained delegation enumeration failed: {e}"))
