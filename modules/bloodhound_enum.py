# modules/bloodhound_enum.py

import subprocess
import os
import shutil
from core.colors import red, green, blue, yellow
from core.helpers import run_command, save_loot

def run_bloodhound(session):
    print(blue("[*] Running BloodHound-python enumeration..."))

    if session.hash:
        auth = f"-u {session.username} -p :{session.hash}"
    elif session.password:
        auth = f"-u {session.username} -p {session.password}"

    cmd = (
        f"bloodhound-python {auth} "
        f"-d {session.domain} -ns {session.dc_ip} "
        f"-c all --zip"
    )

    print(blue(f"[*] Executing as {session.username}@{session.domain} on {session.dc_hostname}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    # === Save log
    save_loot("bloodhound_enum.log", combined)

    # === Find .zip
    zip_files = [f for f in os.listdir(".") if f.endswith(".zip") and "bloodhound" in f.lower()]
    if zip_files:
        zip_name = zip_files[0]
        loot_zip = os.path.join("loot", zip_name)
        shutil.move(zip_name, loot_zip)
        print(green(f"[+] BloodHound data saved to: {loot_zip}"))
        print(yellow("[*] You can now import it into Neo4j."))
    else:
        print(red("[-] No BloodHound .zip file found."))
        print(yellow("[!] Check log for errors: loot/bloodhound_enum.log"))
