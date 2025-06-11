# commands/attack.py

from core.colors import red, green, yellow, blue
from core.helpers import run_command
import traceback

# === Module Imports ===
from modules import (
    addself, writeowner, genericall, dcsync, shadow, dump_secrets,
    writespn, forcechangepw, kerberoast, asrep, bloodhound_enum, readgmsa, gettgt, enableuser,password_spray
)

def handle_attack(args, session_mgr):
    if not args:
        print_usage()
        return

    session = session_mgr.get_current()
    if not session:
        print(red("[-] No active session. Use 'session use <name>' first."))
        return

    cmd = args[0].lower()
    try:
        if cmd == "dcsync":
            dcsync.attack_dcsync(session)
        elif cmd == "writeowner":
            writeowner.attack_write_owner(session, *args[1:])
        elif cmd == "genericall":
            genericall.attack_genericall(session, *args[1:])
        elif cmd == "addself":
            if len(args) < 3:
                print(red("Usage: attack addself <group> <user>"))
                return
            addself.attack_addself(session, args[1], args[2])
        elif cmd == "shadow":
            if len(args) < 2:
                print(red("Usage: attack shadow <user>"))
                return
            shadow.attack_shadow(session, [args[1]])
        elif cmd == "writespn":
            writespn.attack_writespn(session)
        elif cmd == "password_spray":
            password_spray.attack_password_spray(session)
        elif cmd == "localdump":
            dump_secrets.dump_all(session)
        elif cmd == "asrep":
            asrep.attack_asrep(session)
        elif cmd == "bloodhound":
            bloodhound_enum.run_bloodhound(session)
        elif cmd == "readgmsa":
            readgmsa.attack_readgmsa(session, *args[1:])        
        elif cmd == "forcechangepw":
            forcechangepw.attack_force_change(session, *args[1:], session_mgr=session_mgr)
        elif cmd == "kerberoast":
            kerberoast.attack_kerberoast(session)
        elif cmd == "gettgt":
            gettgt.get_tgt(session)
        elif cmd == "enableuser":
            enableuser.attack_enableuser(session, args[1] if len(args) > 1 else None)



        else:
            print(red(f"[-] Unknown attack module: {cmd}"))
            print_usage()

    except KeyboardInterrupt:
        print(yellow("\n[!] Attack interrupted by user."))
    except Exception as e:
        print(red(f"[!] Attack failed: {e}"))
        print(traceback.format_exc())


def print_usage():
    print(blue("Usage: attack <module> [args]"))
    print("  dcsync")
    print("  writeowner <target_dn> <new_owner>")
    print("  genericall <target_dn> [principal]")
    print("  addself <group> <user>")
    print("  shadow <user>")
    print("  writespn")
    print("  localdump")
    print("  forcechangepw <user>")
    print("  kerberoast       - Extract SPN hashes for offline cracking")
    print("  asrep            - Extract AS-REP hashes for cracking")
    print("  bloodhound       - Run BloodHound-python LDAP collection")
    print("  readgmsa         - Extract gMSA password for specified account")
    print("  gettgt           - Request a TGT and store it as a .ccache file")
    print("  password_spray     - SMB password spray via nxc using valid_users.txt")