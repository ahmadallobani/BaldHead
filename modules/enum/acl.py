# modules/enum/acl.py

from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

INTERESTING_RIGHTS = [
    "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
    "AllExtendedRights", "ForceChangePassword", "Self",
]


def enum_acl(session, target=None, save=False):
    if not target:
        target = input("[?] Enter target object (user/group/computer name or DN): ").strip()
    if not target:
        print(red("[-] No target specified."))
        return

    print(blue(f"[*] Enumerating ACLs on '{target}'..."))
    try:
        if session.hash:
            auth = f"-p :{session.hash}"
        elif session.password:
            auth = f"-p '{session.password}'"
        else:
            print(red("[-] No credentials in session."))
            return

        cmd = (
            f"bloodyAD --host {session.dc_ip} -d {session.domain} "
            f"-u {session.username} {auth} "
            f"get object '{target}' --attr ntSecurityDescriptor"
        )
        out, err = run_command(cmd)
        combined = out + err

        hits = [l for l in combined.splitlines() if any(r in l for r in INTERESTING_RIGHTS)]
        if hits:
            print(green(f"[+] Interesting ACL entries found on '{target}':"))
            for h in hits:
                print(green(f"  {h}"))
            if save:
                save_loot(f"acl_{target}.txt", "\n".join(hits))
        else:
            print(combined if combined.strip() else yellow("[*] No interesting ACLs found."))
    except Exception as e:
        print(red(f"[!] ACL enumeration failed: {e}"))
