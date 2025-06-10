# core/helpers.py

import os
from datetime import datetime
import subprocess

def get_auth_args(session):
    """Return formatted auth string for net rpc / nxc / fallback tools."""
    if session.hash:
        return f"-U \"{session.domain}/{session.username}%:{session.hash}\""
    elif session.password:
        return f"-U \"{session.domain}/{session.username}%{session.password}\""
    else:
        return f"-U \"{session.domain}/{session.username}\" -k --no-pass"

def get_bloodyad_auth(session):
    """Return BloodyAD-compatible authentication part."""
    if session.hash:
        return f"-p :{session.hash}"
    elif session.password:
        return f"-p '{session.password}'"
    else:
        return "-k --no-pass"

def save_loot(filename, content, binary=False):
    os.makedirs("loot", exist_ok=True)
    path = os.path.join("loot", filename)
    if binary:
        with open(path, "wb") as f:
            f.write(content)
    else:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n### {datetime.now().isoformat()} ###\n")
            f.write(content.strip() + "\n")
    print(f"[+] Loot saved to: {path}")

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)


def select_from_list(items, prompt="Select an item"):
    print()
    for i, item in enumerate(items, 1):
        print(f"  [{i}] {item}")
    print()

    while True:
        try:
            choice = int(input(f"{prompt} [1-{len(items)}]: "))
            if 1 <= choice <= len(items):
                return items[choice - 1]
        except ValueError:
            pass
        print("Invalid selection. Try again.")

