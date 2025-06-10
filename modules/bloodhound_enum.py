# modules/bloodhound_enum.py

import subprocess
import os
from core.colors import red, green, blue

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def run_bloodhound(session):
    print(blue("[*] Running BloodHound-python enumeration..."))

    if not session.dc_hostname:
        print(red("[-] No DC hostname found. Use 'setdchost <fqdn>' to fix."))
        return

    if session.hash:
        auth = f"-u {session.username} -p :{session.hash}"
    elif session.password:
        auth = f"-u {session.username} -p {session.password}"
    else:
        auth = f"-u {session.username} -k --no-pass"

    cmd = (
        f"bloodhound-python {auth} "
        f"-d {session.domain} -dc {session.dc_hostname} -ns {session.dc_ip} "
        f"-c all --zip"
    )

    out, err = run_command(cmd)

    zip_files = [f for f in os.listdir(".") if f.endswith(".zip") and "bloodhound" in f.lower()]
    if zip_files:
        zip_name = zip_files[0]
        print(green(f"[+] BloodHound collection completed. Output saved as: {zip_name}"))
    else:
        print(red("[-] BloodHound may have failed:"))
        if out:
            print(out)
        if err:
            print(err)

