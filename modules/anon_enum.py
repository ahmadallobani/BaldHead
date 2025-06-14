import subprocess, argparse, os, re
from datetime import datetime
from core.colors import green, yellow, blue, red
from core.helpers import run_command, save_loot

def section(title):
    print(f"\n{blue('[*]')} {yellow(title)}")

def extract_group_blocks(text, marker):
    pattern = rf"\|\s+{re.escape(marker)}\s+.*?\|"
    results = []
    in_section = False
    block = []
    for line in text.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            if block:
                results.append("\n".join(block).strip())
                block = []
            in_section = True
            block.append(line)
        elif in_section and line.strip().startswith("[+]"):
            block.append(line)
        elif in_section and line.strip() == "":
            if block:
                results.append("\n".join(block).strip())
                block = []
            in_section = False
        elif in_section:
            block.append(line)
    if block:
        results.append("\n".join(block).strip())
    return results

def check_ftp(target):
    section("FTP Anonymous Access Check")
    cmd = f"echo 'quit' | ftp -n {target}"
    out, err = run_command(cmd)
    combined = out + "\n" + err
    if "230" in combined:
        print(green("[+] FTP allows anonymous login."))
    elif "530" in combined:
        print(red("[-] FTP anonymous access denied."))
    else:
        print(yellow("[!] FTP response unclear."))
        print(combined)

def check_smb(target):
    section("SMB Anonymous Access Check")
    cmd = f"smbclient -L \\{target} -N"
    out, err = run_command(cmd)
    combined = out + "\n" + err
    if "NT_STATUS_ACCESS_DENIED" in combined:
        print(red("[-] SMB anonymous access denied."))
    elif "Sharename" in combined:
        print(green("[+] SMB anonymous access allowed."))
        print(combined)
    else:
        print(yellow("[!] SMB response unclear."))
        print(combined)

def run_nmap(target):
    section("Running Nmap Fast Top Ports Scan")
    cmd = f"nmap -sS -sV -T4 -Pn -n --top-ports 100 {target}"
    out, err = run_command(cmd)
    combined = out + "\n" + err
    print(combined)
    return combined

def enum(args):
    target = args.target
    timestamp = datetime.utcnow().isoformat()

    section("Running enum4linux-ng")
    cmd = f"enum4linux-ng -A {target}"
    out, err = run_command(cmd)
    combined = out + "\n" + err

    if not combined.strip():
        print(red("[-] No output from enum4linux-ng"))
        return

    if args.save:
        save_loot(f"enum4linux_{target}.txt", combined)

    targets = {
        "1": "Users",
        "2": "Groups",
        "3": "Shares",
        "4": "Policies",
        "5": "RID",
        "6": ["Users", "Groups", "Shares", "Policies", "RID"],
        "7": "FTP",
        "8": "SMB",
        "9": "NMAP"
    }

    while True:
        print(blue("[?] What do you want to extract?"))
        print("  1) Users")
        print("  2) Groups")
        print("  3) Shares")
        print("  4) Password Policies")
        print("  5) RID cycling")
        print("  6) All enum4linux-ng sections")
        print("  7) Check FTP Anonymous Access")
        print("  8) Check SMB Anonymous Access")
        print("  9) Run Nmap Fast Scan (top 100 ports)")
        print("  0) Exit")
        choice = input("[Choice] > ").strip()

        if choice == "0":
            print(yellow("[!] Exiting enumeration menu."))
            break

        elif choice == "7":
            check_ftp(target)

        elif choice == "8":
            check_smb(target)

        elif choice == "9":
            out = run_nmap(target)
            if args.save:
                save_loot(f"nmap_{target}.txt", out)

        elif choice in targets:
            selected = targets[choice]
            if isinstance(selected, list):
                for section_name in selected:
                    section(section_name)
                    for block in extract_group_blocks(combined, section_name):
                        print(block)
            else:
                section(f"Extracted {selected}")
                for block in extract_group_blocks(combined, selected):
                    print(block)
        else:
            print(yellow("[!] Invalid selection. Nothing parsed."))

def main(argv):
    if not argv:
        print(red("[-] Error: Target is required.\nUsage: e anon <target> [--save]"))
        return

    parser = argparse.ArgumentParser(description="Anonymous SMB Enumeration via enum4linux-ng + FTP/SMB/Nmap", add_help=False)
    parser.add_argument("target", nargs="?", help="Target IP")
    parser.add_argument("--save", action='store_true', help="Save raw output to loot")

    try:
        args = parser.parse_args(argv)
        if not args.target:
            print(red("[-] Error: Target is required.\nUsage: e anon <target> [--save]"))
            return
        enum(args)
    except SystemExit:
        # Suppress argparse crash on invalid/missing args
        print(red("[-] Invalid arguments. Usage: e anon <target> [--save]"))
