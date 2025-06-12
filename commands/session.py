import os
import argparse
import socket
from core.colors import red, green, blue, yellow, bold
from scripts import session_io
from core.helpers import select_from_list

def handle_session(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    if cmd == "add":
        add_session(args[1:], session_mgr)
    elif cmd == "use":
        use_session(args[1:], session_mgr)
    elif cmd == "list":
        list_sessions(args[1:], session_mgr)
    elif cmd == "clear":
        session_mgr.clear()
        print(green("[+] All sessions cleared."))
    elif cmd == "import":
        path = args[1] if len(args) > 1 else "sessions.json"
        session_mgr.import_sessions(path)

    elif cmd == "export":
        path = args[1] if len(args) > 1 else "sessions.json"
        session_mgr.export_sessions(path)

    else:
        print(red(f"[-] Unknown session subcommand: {cmd}"))
        print_usage()

def print_usage():
    print(blue("Usage:"))
    print("  session add <name> <user> <pass_or_hash> [domain] [ip1,ip2,...] [dc_ip] [--env ENV] [--tags tag1,tag2] [--notes \"text\"]")
    print("  session use <name>")
    print("  session list [--domain X] [--env Y] [--username U] [--ip Z]")
    print("  session clear")
    print("  import [file]      - Import sessions from JSON (default: sessions.json)")
    print("  export [file]      - Export sessions to JSON (default: sessions.json)")

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
    if not args:
        print(red("[-] Missing session name."))
        return
    name = args[0]
    if session_mgr.use(name):
        print(green(f"[+] Switched to session '{name}'"))

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
