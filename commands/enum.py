# commands/enum.py

from core.colors import red, green, yellow, blue
import traceback

# Authenticated enum
from modules import auth_enum

# Anonymous enum
from modules import anon_enum

def handle_enum(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    try:
        if cmd == "users":
            auth_enum.enum_users(session_mgr.get_current(), save="save" in args)

        elif cmd == "shares":
            auth_enum.enum_shares(session_mgr.get_current(), save="save" in args)


        elif cmd == "bloodhound":
            auth_enum.enum_bloodhound(session_mgr.get_current(), save="save" in args)

        elif cmd == "anon":
            anon_args = args[1:]
            anon_enum.main(anon_args)

        else:
            print(red(f"[-] Unknown enum module: {cmd}"))
            print_usage()

    except KeyboardInterrupt:
        print(yellow("\n[!] Enumeration interrupted by user."))
    except Exception as e:
        print(red(f"[!] Enumeration failed: {e}"))
        print(traceback.format_exc())


def print_usage():
    print(blue("Usage: enum <module> [save]"))
    print("  users           - Enum users via nxc")
    print("  shares          - Enum SMB shares via nxc")
    print("  bloodhound      - BloodHound (nxc LDAP All)")
    print("  anon <target>   - Anonymous enum4linux + ftp/smb/nmap")
