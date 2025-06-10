# scripts/session_io.py

from core.session_manager import SessionManager

def export_sessions(session_mgr, filepath="sessions.txt"):
    sessions = session_mgr.list(raw=True)
    with open(filepath, "w") as f:
        for s in sessions:
            secret = s.hash or s.password or ""
            f.write(f"{s.username}:{secret}\n")
    print(f"[+] Exported {len(sessions)} sessions to {filepath}")

def import_sessions(session_mgr, filepath="sessions.txt", domain=None, ip=None, dc_ip=None):
    count = 0
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                username, secret = line.split(":", 1)
                session_name = f"imported_{username.lower()}"
                session_mgr.add(session_name, username, secret, domain=domain, target_ip=ip, dc_ip=dc_ip)
                count += 1
        print(f"[+] Imported {count} sessions from {filepath}")
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")

