import os
import argparse
import socket
from core.colors import red, green, blue, yellow, bold
from scripts import session_io
from core.helpers import select_from_list
import shutil
from core.helpers import run_command
def handle_session(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()
    cmd = SESSION_ALIASES.get(cmd, cmd)

    if cmd == "add":
        add_session(args[1:], session_mgr)
    elif cmd == "use":
        use_session(args[1:], session_mgr)
    elif cmd == "list":
        list_sessions(args[1:], session_mgr)
    elif cmd == "check":
        check_session(session_mgr.get_current())

    elif cmd == "clear":
        session_mgr.clear()
        print(green("[+] All sessions cleared."))
    elif cmd == "import":
        path = args[1] if len(args) > 1 else "sessions.json"
        session_mgr.import_sessions(path)

    elif cmd == "export":
        path = args[1] if len(args) > 1 else "sessions.json"
        session_mgr.export_sessions(path)
    elif cmd == "delete":
        delete_session(session_mgr)


    else:
        print(red(f"[-] Unknown session subcommand: {cmd}"))
        print_usage()

SESSION_ALIASES = {
    "ls": "list",
    "show": "list",
    "u": "use",
    "a": "add",
    "rm": "clear",
    "chk": "check",
    "imp": "import",
    "exp": "export",
    "del": "delete",
}

def print_usage():
    print(blue("Usage:"))
    print("  session add (a) <name> <user> <pass_or_hash> [domain] [ip1,ip2,...] [dc_ip] [--env ENV] [--tags tag1,tag2] [--notes \"text\"]")
    print("  session use (u) <name>")
    print("  session list (ls, show) [--domain X] [--env Y] [--username U] [--ip Z]")
    print("  session clear (rm)")
    print("  session check (chk)      - Validate current session credentials using nxc")
    print("  session import (imp) [file] - Import sessions from JSON")
    print("  session export (exp) [file] - Export sessions to JSON")
    print("  session delete (del)     - Remove a specific session")


def add_session(raw_args, session_mgr):
    parser = argparse.ArgumentParser(prog="session add", add_help=False)
    parser.add_argument("name")
    parser.add_argument("username")
    parser.add_argument("secret")
    parser.add_argument("domain", nargs="?")
    parser.add_argument("target_ips", nargs="?")
    parser.add_argument("dc_ip", nargs="?")
    parser.add_argument("--env", default="default")
    parser.add_argument("--tags", default="")
    parser.add_argument("--notes", default="")

    try:
        args = parser.parse_args(raw_args)
    except SystemExit:
        print_usage()
        return

    tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    # Try to resolve DC hostname safely here
    dc_hostname = None
    dc_ip = args.dc_ip or args.target_ips or session_mgr.default_dc_ip

    session_mgr.add(
        name=args.name,
        username=args.username,
        secret=args.secret,
        domain=args.domain,
        target_ips=args.target_ips,
        dc_ip=dc_ip,
        env=args.env,
        tags=tags,
        notes=args.notes
    )

    session = session_mgr.get(args.name)
    if session:
        session.dc_hostname = dc_hostname

    print(green(f"[+] Session '{args.name}' added."))
    try:
        os.makedirs("loot", exist_ok=True)
        with open("loot/creds.txt", "a") as f:
            line = f"{args.username}|{args.secret}|{args.domain or 'UNKNOWN'}|{args.target_ips or 'UNKNOWN'}\n"
            f.write(line)
    except Exception as e:
        print(red(f"[!] Failed to write to creds.txt: {e}"))

def use_session(args, session_mgr):
    sessions = session_mgr.list(raw=True)
    if not sessions:
        print(red("[-] No sessions available."))
        return

    if args:
        name = args[0]
    else:
        print(blue("[*] Available sessions:\n"))
        for i, sess in enumerate(sessions):
            line = f"{sess.name} | {sess.username} | {sess.domain} | {', '.join(sess.target_ips)} | {sess.env}"
            prefix = green("  *") if sess == session_mgr.get_current() else yellow("   ")
            print(f"{prefix} [{i}] {line}")
        print()

        try:
            choice = int(input("Select session index: ").strip())
            name = sessions[choice].name
        except (ValueError, IndexError):
            print(red("[-] Invalid selection."))
            return

    if session_mgr.use(name):
        print(green(f"[+] Switched to session '{name}'"))
    else:
        print(red(f"[-] Failed to switch to session '{name}'"))



def list_sessions(raw_args, session_mgr):
    parser = argparse.ArgumentParser(prog="session list", add_help=False)
    parser.add_argument("--domain")
    parser.add_argument("--username")
    parser.add_argument("--env")
    parser.add_argument("--ip")

    try:
        args = parser.parse_args(raw_args)
    except SystemExit:
        print_usage()
        return

    filters = {}
    if args.domain: filters["domain"] = args.domain
    if args.username: filters["username"] = args.username
    if args.env: filters["env"] = args.env
    if args.ip: filters["ip"] = args.ip

    rows = session_mgr.list(filters=filters)
    if not rows:
        print(red("[-] No sessions found."))
        return

    print(blue("\n[+] Active Sessions:"))
    for r in rows:
        is_active = r[-1] == "(active)"
        formatted = " | ".join(str(x) for x in r[:-1])
        if is_active:
            print(green("  * " + bold(formatted + " [ACTIVE]")))
        else:
            print(yellow("    " + formatted))

def check_session(session):
    if not session:
        print(red("[-] No active session selected. Use 'session use <name>' first."))
        return

    print(blue(f"[*] Checking credentials for session '{session.name}'..."))

    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    auth_args = f"-u \"{session.username}\""
    if session.hash:
        auth_args += f" -H {session.hash}"
    elif session.password:
        auth_args += f" -p '{session.password}'"
    else:
        print(red("[-] No valid secret found for session."))
        return

    ip = session.target_ips[0] if session.target_ips else session.dc_ip

    try:
        for proto in ["smb", "winrm", "ldap"]:
            print(yellow(f"[*] Trying {proto.upper()}..."))
            cmd = f"nxc {proto} {ip} {auth_args} -d {session.domain}"
            out, err = run_command(cmd)
            output = out.strip() or err.strip()
            print(output)

            if "STATUS_SUCCESS" in output or "successfully" in output.lower():
                print(green(f"[+] Credentials valid via {proto.upper()}"))
                return

        print(red("[-] All checks failed. Credentials may be invalid."))

    except KeyboardInterrupt:
        print(red("\n[!] Check interrupted by user."))

def delete_session(session_mgr):
    sessions = session_mgr.list(raw=True)
    if not sessions:
        print(red("[-] No sessions available to delete."))
        return

    print(blue("[*] Available sessions:\n"))
    for i, sess in enumerate(sessions):
        current = session_mgr.get_current()
        marker = green("*") if sess == current else " "
        print(f"  {marker} [{i}] {sess.name} | {sess.username} | {sess.domain} | {', '.join(sess.target_ips)} | {sess.env}")
    print()

    try:
        choice = int(input("Select session index to delete: ").strip())
        sess = sessions[choice]
    except (ValueError, IndexError):
        print(red("[-] Invalid selection."))
        return

    name = sess.name
    confirm = input(yellow(f"[?] Confirm delete session '{name}'? (y/N): ")).strip().lower()
    if confirm == "y":
        session_mgr.remove(name)
        print(green(f"[+] Session '{name}' deleted."))
    else:
        print(yellow("[!] Deletion cancelled."))
