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
    else:
        print(red(f"[-] Unknown connect method: {cmd}"))
        print_usage()

def connect_smb(session):
    if not shutil.which("smbclient"):
        print(red("[-] 'smbclient' not found in PATH. Please install smbclient (samba-client)."))
        return

    # === Build base connection info ===
    ip = session.target_ip
    user = session.username
    domain = session.domain

    if session.hash:
        print(red("[-] SMB connection via hash not supported with native smbclient. Use password or Kerberos."))
        return

    if not session.password:
        print(red("[-] No password provided for smbclient."))
        return

    # === List shares
    print(blue(f"[*] Listing available shares on {ip}..."))
    list_cmd = f"smbclient -L \\\\{ip} -U {user}%{session.password}"
    out, err = run_command(list_cmd)
    combined = out + "\n" + err

    if "NT_STATUS_LOGON_FAILURE" in combined:
        print(red("[-] Authentication failed. Check username or password."))
        return
    elif "Anonymous login successful" in combined:
        print(yellow("[!] Warning: logged in anonymously."))

    # === Extract shares
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

    # === Prompt user to select
    shares.append("exit")
    share = select_from_list(shares, "[*] Select share to open (or type 'exit'):")

    if share.lower() == "exit":
        print(yellow("[*] Exiting SMB connect menu."))
        return


    # === Launch interactive session
    connect_cmd = f"smbclient \\\\\\\\{ip}\\\\{share} -U {user}%{session.password}"
    print(blue(f"[*] Connecting to share: {share}"))
    print(yellow("[*] Type 'exit' to leave SMB shell.\n"))
    os.system(connect_cmd)


def connect_winrm(session):
    cmd = f"evil-winrm -i {session.target_ip} -u {session.username}"
    if session.password:
        cmd += f" -p '{session.password}'"
    elif session.hash:
        print(red("[-] WinRM does not support NTLM hash auth in this client. Use password."))
        return
    else:
        print(red("[-] Missing password for WinRM connection."))
        return
    os.system(cmd)

def connect_rdp(session):
 
    if session.password:
        cmd = f"xfreerdp3 /u:{session.username} /p:{session.password} /v:{session.target_ip} +dynamic-resolution /clipboard:direction-to:all,files-to:all"
    elif session.hash:
        cmd = f"xfreerdp3 /v:{session.target_ip} /u:{session.username} /pth:{session.hash} +dynamic-resolution /clipboard:direction-to:all,files-to:all"
    else:
        print(red("[-] RDP requires a plaintext password."))
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

    print(blue(f"[*] Launching: {cmd}"))
    os.system(cmd)


def connect_ftp(session):
    print(blue(f"[*] Trying FTP on {session.target_ip}..."))

    # Try anonymous first
    anon_cmd = f"echo open {session.target_ip} 21\\nuser anonymous\\nquit | ftp -n"
    out, err = run_command(anon_cmd)
    if "230" in (out + err):
        print(green("[+] FTP allows anonymous login."))
        return

    # Try user credentials
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
            "SQL .*?master\\)>",
            pexpect.EOF,
            pexpect.TIMEOUT
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


def print_usage():
    print(blue("Usage:"))
    print("  connect smb       - Open SMB shell (impacket-smbclient)")
    print("  connect winrm     - Launch Evil-WinRM shell")
    print("  connect rdp       - Launch RDP client (xfreerdp)")
    print("  connect psexec    - Run remote shell via impacket-psexec")
    print("  connect ftp       - Try FTP login (anonymous or user)")
    print("  connect mssql     - Connect to MSSQL via impacket-mssqlclient")
