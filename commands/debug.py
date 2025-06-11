# commands/debug.py

import shutil
import os
from core.colors import red, green, yellow, blue

REQUIRED_TOOLS = [
    "impacket-smbclient",
    "impacket-psexec",
    "evil-winrm",
    "xfreerdp",
    "nxc",
    "enum4linux-ng",
    "certipy-ad"
]

REQUIRED_DIRS = ["loot", "core", "modules", "commands"]

def handle_debug(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    if cmd == "check-paths":
        check_paths()
    elif cmd == "check-structure":
        check_structure()
    elif cmd == "whoami":
        show_current_session(session_mgr)
    else:
        print(red(f"[-] Unknown debug subcommand: {cmd}"))
        print_usage()


def print_usage():
    print(blue("Usage: debug <check-paths|check-structure|whoami>"))
    print("  check-paths       - Check if tools are in PATH")
    print("  check-structure   - Check required folders exist")
    print("  whoami            - Show current session info (debug)")


def check_paths():
    print(blue("[*] Checking external tools in PATH...\n"))
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            print(green(f"[+] {tool} found"))
        else:
            print(red(f"[-] {tool} NOT found"))
    print()


def check_structure():
    print(blue("[*] Checking folder structure...\n"))
    for folder in REQUIRED_DIRS:
        if os.path.isdir(folder):
            print(green(f"[+] {folder}/ exists"))
        else:
            print(red(f"[-] {folder}/ is missing"))
    print()


def show_current_session(session_mgr):
    session = session_mgr.get_current()
    if not session:
        print(red("[-] No active session"))
        return

    print(blue("[*] Current session info:"))
    print(f"  Username  : {session.username}")
    print(f"  Domain    : {session.domain}")
    print(f"  Target IP : {session.target_ip}")
    print(f"  DC IP     : {session.dc_ip}")
    print(f"  Password  : {bool(session.password)}")
    print(f"  Hash      : {bool(session.hash)}")
    print(f"  Hostname  : {session.dc_hostname or 'N/A'}")
