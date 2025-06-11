import os
from core.colors import red, green, yellow, blue
from scripts import session_io
from core.helpers import run_command, get_auth_args, select_from_list

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
        list_sessions(session_mgr)
    elif cmd == "clear":
        clear_sessions(session_mgr)
    elif cmd == "addkerb":
        add_kerberos_sessions(session_mgr)
    elif cmd == "export":
        path = args[1] if len(args) > 1 else "sessions.txt"
        session_io.export_sessions(session_mgr, path)
    elif cmd == "import":
        path = args[1] if len(args) > 1 else "sessions.txt"
        domain = args[2] if len(args) > 2 else None
        ip = args[3] if len(args) > 3 else None
        dc_ip = args[4] if len(args) > 4 else None
        session_io.import_sessions(session_mgr, filepath=path, domain=domain, ip=ip, dc_ip=dc_ip)
    elif cmd == "reuse":
        if len(args) == 2:
            reuse_index = args[1]
            reuse_credential(reuse_index, session_mgr)
        else:
            list_reuse_candidates()
    else:
        print(red(f"[-] Unknown session subcommand: {cmd}"))
        print_usage()


def print_usage():
    print(blue("Usage:"))
    print("  session add <name> <user> <pass_or_hash> [domain] [ip] [dc_ip]")
    print("  session use <name>")
    print("  session list")
    print("  session clear")
    print("  session addkerb                       - Load .ccache tickets from loot/")
    print("  session export [file]                - Export sessions to file")
    print("  session import [file] [domain ip dc] - Import sessions from file")
    print("  session reuse                        - Show vault")
    print("  session reuse <index>                - Reuse saved credentials")


def add_session(args, session_mgr):
    if len(args) < 3:
        print(red("[-] Missing arguments."))
        print_usage()
        return

    name, user, secret = args[:3]
    domain = args[3] if len(args) > 3 else None
    ip = args[4] if len(args) > 4 else None
    dc_ip = args[5] if len(args) > 5 else None

    session_mgr.add(name, user, secret, domain=domain, target_ip=ip, dc_ip=dc_ip)
    print(green(f"[+] Session '{name}' added."))

    # === Auto-save to creds.txt ===
    cred_path = "loot/creds.txt"
    try:
        os.makedirs("loot", exist_ok=True)
        with open(cred_path, "a") as f:
            line = f"{user}|{secret}|{domain or session_mgr.default_domain or 'UNKNOWN'}|{ip or session_mgr.default_dc_ip or 'UNKNOWN'}\n"
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
    else:
        print(red(f"[-] Session not found: {name}"))


def list_sessions(session_mgr):
    sessions = session_mgr.list()
    for name, user, domain, ip, active in sessions:
        print(blue(f" - {name}: {user}@{domain} ({ip}) {active}"))


def clear_sessions(session_mgr):
    confirm = input(yellow("[?] Are you sure you want to clear all sessions? [y/N]: ")).strip().lower()
    if confirm != "y":
        print(yellow("[*] Session clear aborted."))
        return

    session_mgr.default_domain = None
    session_mgr.default_dc_ip = None
    session_mgr.sessions.clear()
    session_mgr.current = None
    print(green("[+] All sessions cleared."))


def add_kerberos_sessions(session_mgr):
    import glob
    import re
    from subprocess import run, PIPE

    print(blue("[*] Scanning loot/ for Kerberos ticket cache files..."))

    loot_dir = "loot"
    krb_files = glob.glob(os.path.join(loot_dir, "*.ccache"))
    if not krb_files:
        print(red("[-] No Kerberos ccache files found in loot/."))
        return

    dc_ip = session_mgr.default_dc_ip or input("[?] Enter DC IP: ").strip()
    target_ip = dc_ip

    added = 0
    for path in krb_files:
        print(yellow(f"[*] Checking {path}..."))
        result = run(["klist", "-c", path], stdout=PIPE, stderr=PIPE, text=True)
        output = result.stdout

        match = re.search(r"Default principal:\s+([^\s@]+)@([^\s]+)", output)
        if not match:
            print(red("[-] Could not extract principal. Skipping."))
            continue

        username, domain = match.groups()
        domain = domain.lower()
        session_name = f"{username}_kerb"

        if added == 0:
            os.environ["KRB5CCNAME"] = path
            print(green(f"[+] Loaded default ticket into env: KRB5CCNAME={path}"))

        session_mgr.add(session_name, username, "", domain, target_ip=target_ip, dc_ip=dc_ip)
        print(green(f"[+] Kerberos session added: {session_name} ({username}@{domain})"))
        added += 1

    if added == 0:
        print(red("[-] No valid Kerberos sessions loaded."))
    else:
        print(blue(f"[*] Total sessions loaded: {added}"))


def list_reuse_candidates():
    cred_path = "loot/creds.txt"
    if not os.path.exists(cred_path):
        print(red("[-] No creds.txt found. Run attacks first."))
        return

    print(blue("[*] Saved credentials:"))
    with open(cred_path, "r") as f:
        lines = [line.strip() for line in f if "|" in line]
        for idx, line in enumerate(lines):
            user, secret, domain, ip = line.split("|")
            print(f"  {idx}) {green(user)} | {secret[:8]}... | {domain} | {ip}")


def reuse_credential(index, session_mgr):
    cred_path = "loot/creds.txt"
    if not os.path.exists(cred_path):
        print(red("[-] creds.txt not found"))
        return

    with open(cred_path, "r") as f:
        lines = [line.strip() for line in f if "|" in line]

    try:
        index = int(index)
        line = lines[index]
    except (ValueError, IndexError):
        print(red(f"[-] Invalid index: {index}"))
        return

    user, secret, domain, ip = line.split("|")
    name = f"{user}_reused{index}"
    session_mgr.add(name, user, secret, domain, ip, ip)
    print(green(f"[+] Session '{name}' added from vault."))
