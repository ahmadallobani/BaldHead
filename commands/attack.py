from core.colors import red, green, yellow, blue
from core.helpers import run_command
import traceback
import argparse

# === Module Imports ===
from modules import (
    addself, writeowner, genericall, dcsync, shadow, dump_secrets,
    writespn, forcechangepw, kerberoast, asrep, bloodhound_enum, readgmsa, gettgt,
    enableuser, password_spray, forge_silver, extrasid, writedacl, convert_ticket,attack_rbcd,
)

# === Modules that require a session ===
ATTACK_MODULES = {
    "dcsync": dcsync.attack_dcsync,
    "writeowner": writeowner.attack_write_owner,
    "genericall": genericall.attack_genericall,
    "addself": addself.attack_addself,
    "shadow": shadow.attack_shadow,
    "writespn": writespn.attack_writespn,
    "password_spray": password_spray.attack_password_spray,
    "localdump": dump_secrets.dump_all,
    "asrep": asrep.attack_asrep,
    "bloodhound": bloodhound_enum.run_bloodhound,
    "readgmsa": readgmsa.attack_readgmsa,
    "forcechangepw": forcechangepw.attack_force_change,
    "kerberoast": kerberoast.attack_kerberoast,
    "gettgt": gettgt.get_tgt,
    "enableuser": enableuser.attack_enableuser,
    "forge_silver": forge_silver.forge_silver_ticket,
    "extrasid": extrasid.run,
    "writedacl": writedacl.attack_writedacl,
    "addmember": addself.attack_addself,
    "genericwrite": writedacl.attack_writedacl,
    "kirbi2ccache": convert_ticket.convert_ticket,
    "rbcd": attack_rbcd.attack_rbcd,
    }

# === Aliases for convenience ===
ATTACK_ALIASES = {
    "addmember": "addself",
    "genericwrite": "writedacl",
    "fcpass": "forcechangepw",
    "changepw": "forcechangepw",
    "enable": "enableuser",
    "silver": "forge_silver",
    "dacl": "writedacl",
    "ccache": "kirbi2ccache",
    "spray": "password_spray",
}

# === Session-Optional modules ===
SESSION_OPTIONAL_MODULES = {"help", "asrep", "password_spray"}

# === Main Command Entry ===
def handle_attack(args, session_mgr):
    if not args:
        print_usage()
        return

    if args[0].lower() == "all":
        attack_all(args[1:], session_mgr)
        return

    cmd = args[0].lower()
    cmd = ATTACK_ALIASES.get(cmd, cmd)

    if cmd not in ATTACK_MODULES:
        print(red(f"[-] Unknown attack module: {cmd}"))
        print_usage()
        return

    if cmd in SESSION_OPTIONAL_MODULES:
        try:
            ATTACK_MODULES[cmd](None, *args[1:])
        except Exception as e:
            print(red(f"[!] {cmd} failed: {e}"))
            print(traceback.format_exc())
        return

    session = session_mgr.get_current()
    if not session:
        print(red("[-] No active session. Use 'session use <name>' first."))
        return

    run_attack([cmd] + args[1:], session, session_mgr)

# === Per-Session Attack Runner ===
def run_attack(args, session, session_mgr):
    cmd = args[0].lower()
    cmd = ATTACK_ALIASES.get(cmd, cmd)
    try:
        if cmd not in ATTACK_MODULES:
            print(red(f"[-] Unknown attack module: {cmd}"))
            print_usage()
            return

        if cmd == "addself" and len(args) >= 3:
            ATTACK_MODULES[cmd](session, args[1], args[2])
        elif cmd == "shadow":
            if len(args) >= 2:
                ATTACK_MODULES[cmd](session, [args[1]])
            else:
                ATTACK_MODULES[cmd](session, [], session_mgr=session_mgr)
        elif cmd == "enableuser":
            ATTACK_MODULES[cmd](session, args[1] if len(args) > 1 else None)
        elif cmd == "readgmsa":
            ATTACK_MODULES[cmd](session, *args[1:])
        elif cmd == "forcechangepw":
            ATTACK_MODULES[cmd](session, *args[1:], session_mgr=session_mgr)
        else:
            ATTACK_MODULES[cmd](session)

    except KeyboardInterrupt:
        print(yellow("\n[!] Attack interrupted by user."))
    except Exception as e:
        print(red(f"[!] Attack failed: {e}"))
        print(traceback.format_exc())

# === Run on all matching sessions ===
def attack_all(raw_args, session_mgr):
    parser = argparse.ArgumentParser(prog="attack all", add_help=False)
    parser.add_argument("module")
    parser.add_argument("--env")
    parser.add_argument("--domain")
    parser.add_argument("--ip")
    parser.add_argument("--username")
    args, unknown_args = parser.parse_known_args(raw_args)

    filters = {}
    if args.domain: filters["domain"] = args.domain
    if args.username: filters["username"] = args.username
    if args.env: filters["env"] = args.env
    if args.ip: filters["ip"] = args.ip

    all_sessions = session_mgr.list(raw=True, filters=filters)
    if not all_sessions:
        print(red("[-] No matching sessions found."))
        return

    print(blue(f"[*] Executing '{args.module}' on {len(all_sessions)} sessions...\n"))
    for sess in all_sessions:
        print(yellow(f"[>] Running on {sess.name} ({sess.username}@{sess.domain}) [{sess.target_ip}]"))
        try:
            run_attack([args.module] + unknown_args, sess, session_mgr)
        except Exception as e:
            print(red(f"[-] Failed on {sess.name}: {e}"))
        print()

# === Help Output ===
def print_usage():
    print(blue("Usage: attack <module> [args]"))
    print("       attack <module> [--env dev] [--domain X] [--ip 1.2.3.4]")
    print("\nAvailable modules:")
    for m in sorted(ATTACK_MODULES):
        aliases = [k for k, v in ATTACK_ALIASES.items() if v == m]
        if aliases:
            print(f" - {m} (aliases: {', '.join(aliases)})")
        else:
            print(f" - {m}")
