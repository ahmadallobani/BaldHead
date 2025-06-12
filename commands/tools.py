# Enhanced tools.py functionality (implementation)
import os
import subprocess
import shutil
import re
from core.colors import red, green, yellow, blue
from core.helpers import save_loot

LOOT_DIR = "loot"

def handle_tools(args, session_mgr):
    if not args:
        return run_interactive()

    cmd = args[0].lower()

    if cmd == "custom":
        run_custom(args[1:])
    elif cmd == "loot":
        show_loot(args[1:])
    elif cmd == "showmodules":
        show_modules()
    elif cmd == "parsehashes":
        parse_hashes()
    elif cmd == "checktickets":
        check_tickets()
    elif cmd == "extract-creds":
        extract_creds()
    elif cmd == "open":
        open_loot_file(args[1:])
    elif cmd == "grepusers":
        grep_users(args[1:])
    elif cmd == "removeloot":
        remove_loot(args[1:])
    else:
        print(red(f"[-] Unknown tools subcommand: {cmd}"))
        run_interactive()

def print_usage():
    print(blue("Usage: tools <custom|loot|showmodules|convert_ticket|parsehashes|checktickets|extract-creds|open|grepusers|removeloot>"))

# === Base commands ===
def run_custom(args):
    if not args:
        print(red("[-] Usage: tools custom <shell_command>"))
        return
    cmd = " ".join(args)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(red(result.stderr.strip()))
    except Exception as e:
        print(red(f"[!] Error executing command: {e}"))

def show_loot(args):
    if not os.path.exists(LOOT_DIR):
        print(red("[-] 'loot/' directory not found."))
        return
    files = os.listdir(LOOT_DIR)
    if not files:
        print(yellow("[*] No loot files found."))
        return
    if not args:
        print(blue("[*] Available loot files:"))
        for f in sorted(files):
            print(f" - {f}")
        return
    if args[0] == "grep":
        if len(args) < 2:
            print(red("[-] Usage: tools loot grep <keyword>"))
            return
        search_term = args[1].lower()
        print(blue(f"[*] Searching loot files for: {search_term}"))
        for filename in sorted(files):
            path = os.path.join(LOOT_DIR, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f.readlines()):
                        if search_term in line.lower():
                            print(green(f"[{filename}] Line {i+1}: ") + line.strip())
            except Exception as e:
                print(red(f"[!] Could not read {filename}: {e}"))
        return
    file_path = os.path.join(LOOT_DIR, args[0])
    if not os.path.exists(file_path):
        print(red(f"[-] File not found: {file_path}"))
        return
    print(blue(f"[*] Showing contents of: {args[0]}"))
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                print(line.strip())
    except Exception as e:
        print(red(f"[!] Error reading file: {e}"))

def show_modules():
    print(blue("[*] Core Attack Modules:"))
    for cmd in sorted([
        "addself", "readgmsa", "forcechangepw", "writeowner", "genericall",
        "extrasid", "dumpsecrets", "dcsync", "gettgt", "shadow",
        "authenum", "writespn", "shell", "bloodhound"
    ]):
        print(f"  - {cmd}")
    print(blue("\n[*] ADCS Modules:"))
    for esc in sorted(["enum", "esc1", "esc2", "esc3", "esc9", "esc10", "pfx2hash"]):
        print(f"  - {esc}")

# === New Utilities ===
def parse_hashes():
    print(blue("[*] Parsing hashes in loot/ directory..."))
    if not os.path.exists(LOOT_DIR): return
    ntlm, asrep, tgs = [], [], []
    for fname in os.listdir(LOOT_DIR):
        fpath = os.path.join(LOOT_DIR, fname)
        with open(fpath, "r", errors="ignore") as f:
            for line in f:
                if "$krb5asrep$" in line:
                    asrep.append(line.strip())
                elif "$krb5tgs$" in line:
                    tgs.append(line.strip())
                elif ":::" in line:
                    parts = line.split(":")
                    if len(parts) >= 4 and all(len(p) == 32 for p in parts[2:4]):
                        ntlm.append(line.strip())
    if ntlm:
        save_loot("parsed_ntlm_hashes.txt", "\n".join(ntlm))
        print(green(f"[+] Found {len(ntlm)} NTLM hashes."))
    if asrep:
        save_loot("parsed_asrep_hashes.txt", "\n".join(asrep))
        print(green(f"[+] Found {len(asrep)} AS-REP hashes."))
    if tgs:
        save_loot("parsed_tgs_hashes.txt", "\n".join(tgs))
        print(green(f"[+] Found {len(tgs)} TGS hashes."))
    if not (ntlm or asrep or tgs):
        print(yellow("[*] No hashes found."))

def check_tickets():
    print(blue("[*] Checking Kerberos tickets in loot/"))
    for f in os.listdir(LOOT_DIR):
        if f.endswith(".ccache") or f.endswith(".kirbi"):
            print(green(f"[+] Ticket: {f}"))

def extract_creds():
    print(blue("[*] Extracting credential-like strings from loot/"))
    pattern = re.compile(r"[\\/\w.-]+[:][^\s:]{3,}")
    for f in os.listdir(LOOT_DIR):
        with open(os.path.join(LOOT_DIR, f), "r", errors="ignore") as file:
            for line in file:
                if pattern.search(line):
                    print(green(f"[{f}] ") + line.strip())

def open_loot_file(args):
    if not args:
        print(red("[-] Usage: tools open <filename>"))
        return
    fname = args[0]
    path = os.path.join(LOOT_DIR, fname)
    if not os.path.exists(path):
        print(red(f"[-] File not found: {fname}"))
        return
    os.system(f"less {path}" if shutil.which("less") else f"cat {path}")

def grep_users(args):
    if not args:
        print(red("[-] Usage: tools grepusers <term>"))
        return
    term = args[0].lower()
    for f in os.listdir(LOOT_DIR):
        if "user" in f.lower():
            path = os.path.join(LOOT_DIR, f)
            with open(path, "r", errors="ignore") as file:
                for line in file:
                    if term in line.lower():
                        print(green(f"[{f}] ") + line.strip())

def remove_loot(args):
    if not args:
        print(red("[-] Usage: tools removeloot <filename|all>"))
        return
    if args[0] == "all":
        confirm = input(yellow("[?] Are you sure you want to delete ALL loot? (y/N): ")).strip().lower()
        if confirm == "y":
            for f in os.listdir(LOOT_DIR):
                try:
                    os.remove(os.path.join(LOOT_DIR, f))
                except: pass
            print(green("[+] All loot deleted."))
        else:
            print(yellow("[*] Cancelled."))
    else:
        f = os.path.join(LOOT_DIR, args[0])
        if os.path.exists(f):
            os.remove(f)
            print(green(f"[+] Deleted loot file: {args[0]}"))
        else:
            print(red(f"[-] File not found: {args[0]}"))

def run_interactive():
    print(blue("\n[*] Tools Menu:"))
    print("  1) Show loot files")
    print("  2) Parse hashes")
    print("  3) Check tickets")
    print("  4) Extract credentials")
    print("  5) Open loot file")
    print("  6) Grep users")
    print("  7) Remove loot file")
    print("  8) Exit")
    choice = input("Select > ").strip()
    if choice == "1": show_loot([])
    elif choice == "2": parse_hashes()
    elif choice == "3": check_tickets()
    elif choice == "4": extract_creds()
    elif choice == "5": open_loot_file([input("Filename > ").strip()])
    elif choice == "6": grep_users([input("Search term > ").strip()])
    elif choice == "7": remove_loot([input("Filename or all > ").strip()])
    else: print(yellow("[*] Exiting tools menu."))