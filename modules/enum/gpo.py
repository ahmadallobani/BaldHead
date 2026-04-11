# modules/enum/gpo.py

from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow


def enum_gpo(session, save=False):
    print(blue("[*] Enumerating Group Policy Objects via LDAP..."))
    try:
        base_dn = "DC=" + session.domain.replace(".", ",DC=")
        if session.hash:
            auth = f"-hashes :{session.hash}"
        elif session.password:
            auth = f"-p '{session.password}'"
        else:
            print(red("[-] No credentials in session."))
            return

        cmd = (
            f"ldapsearch -x -H ldap://{session.dc_ip} "
            f"-D '{session.username}@{session.domain}' "
            f"-w '{session.password or ''}' "
            f"-b '{base_dn}' "
            f"'(objectClass=groupPolicyContainer)' displayName gPCFileSysPath"
        )
        out, err = run_command(cmd)
        combined = out + err

        if out.strip():
            print(green(out))
            if save:
                save_loot("gpo_enum.txt", out)
        else:
            print(yellow("[*] No GPO results returned."))
            if err:
                print(red(f"[-] {err}"))
    except Exception as e:
        print(red(f"[!] GPO enumeration failed: {e}"))
