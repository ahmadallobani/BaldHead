import traceback
import argparse
from core.colors import red, green, yellow, blue

# Authenticated enum
from modules import auth_enum, bloodhound_enum, enum_mssql
# Anonymous enum
from modules import anon_enum

ENUM_MODULES = {
    "users": auth_enum.enum_users,
    "groups": auth_enum.enum_groups,
    "computers": auth_enum.enum_computers,
    "dcs": auth_enum.enum_dcs,
    "sid": auth_enum.enum_sid,
    "active": auth_enum.enum_active_users,
    "delegation": auth_enum.enum_find_delegation,
    "trusted": auth_enum.enum_trusted_for_delegation,
    "passnotreq": auth_enum.enum_password_not_required,
    "admincount": auth_enum.enum_admincount,
    "gmsa": auth_enum.enum_gmsa,
    "asrep": auth_enum.enum_asreproast,
    "kerberoast": auth_enum.enum_kerberoast,
    "shares": auth_enum.enum_shares,
    "deletedusers": auth_enum.enum_deleted_users,
    "bloodhound": bloodhound_enum.run_bloodhound,
    # DO NOT PUT "mssql" HERE – it's handled separately!
}

def handle_enum(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    try:
        if cmd == "all":
            enum_all(args[1:], session_mgr)

        elif cmd == "anon":
            anon_args = args[1:]
            anon_enum.main(anon_args)

        elif cmd == "mssql":
            if len(args) < 2:
                print(red("[-] Missing action. Use: enum mssql <action> [db] [table] [save]"))
                return

            action = args[1].lower()
            db = args[2] if len(args) > 2 and args[2].lower() != "save" else None
            table = args[3] if len(args) > 3 and args[3].lower() != "save" else None
            save_flag = "save" in args

            enum_mssql.enum_mssql(session_mgr.get_current(), action=action, db=db, table=table, save=save_flag)

        elif cmd in ENUM_MODULES:
            if cmd == "bloodhound":
                ENUM_MODULES[cmd](session_mgr.get_current())
            else:
                ENUM_MODULES[cmd](session_mgr.get_current(), save="save" in args)

        else:
            print(red(f"[-] Unknown enum module: {cmd}"))
            print_usage()

    except KeyboardInterrupt:
        print(yellow("\n[!] Enumeration interrupted by user."))
    except Exception as e:
        print(red(f"[!] Enumeration failed: {e}"))
        print(traceback.format_exc())


def enum_all(raw_args, session_mgr):
    parser = argparse.ArgumentParser(prog="enum all", add_help=False)
    parser.add_argument("module")
    parser.add_argument("--env")
    parser.add_argument("--domain")
    parser.add_argument("--ip")
    parser.add_argument("--username")
    parser.add_argument("--save", action="store_true")

    try:
        args = parser.parse_args(raw_args)
    except SystemExit:
        print(red("[-] Invalid syntax for enum all. Usage: enum all <module> [--env X] [--domain X] [--ip X]"))
        return

    filters = {}
    if args.domain: filters["domain"] = args.domain
    if args.username: filters["username"] = args.username
    if args.env: filters["env"] = args.env
    if args.ip: filters["ip"] = args.ip

    if args.module not in ENUM_MODULES:
        print(red(f"[-] Unknown enum module: {args.module}"))
        print_usage()
        return

    all_sessions = session_mgr.list(raw=True, filters=filters)
    if not all_sessions:
        print(red("[-] No matching sessions found."))
        return

    print(blue(f"[*] Running '{args.module}' enumeration on {len(all_sessions)} sessions...\n"))
    for sess in all_sessions:
        print(yellow(f"[>] Enumerating {args.module} on {sess.name} ({sess.username}@{sess.domain}) [{sess.target_ip}]"))
        try:
            ENUM_MODULES[args.module](sess, save=args.save)
        except Exception as e:
            print(red(f"[-] Failed on {sess.name}: {e}"))
        print()

def print_usage():
    print(blue("Usage: enum <module> [save]"))
    print("       enum  <module> [--env ENV] [--domain X] [--ip X] [--save]")
    print("\nModules:")
    print("  users           - Enum users via nxc")
    print("  groups          - Enum groups via nxc")
    print("  computers       - Enum computer objects via nxc")
    print("  dcs             - Domain Controllers")
    print("  sid             - Domain SID")
    print("  active          - Active accounts")
    print("  delegation      - Delegation relationships")
    print("  trusted         - Trusted-for-delegation")
    print("  passnotreq      - Users without password requirement")
    print("  admincount      - Users with adminCount=1")
    print("  gmsa            - Enumerate GMSA accounts")
    print("  asrep           - AS-REP roastable users")
    print("  kerberoast      - Kerberoastable users")
    print("  shares          - SMB shares via nxc")
    print("  deletedUsers    - Enumerate Deleted Users")
    print("  anon <target>   - Anonymous enum4linux + ftp/smb/nmap")
    print("  bloodhound      - Bloodhound graph")
    print("  mssql <action> [db] [table] [save] - MSSQL enumeration module")
