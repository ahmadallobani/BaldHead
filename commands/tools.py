# commands/tools.py

import os
import subprocess
from core.colors import red, green, yellow, blue

def handle_tools(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()
    if cmd == "custom":
        run_custom(args[1:])
    elif cmd == "loot":
        show_loot(args[1:])
    elif cmd == "showmodules":
        show_modules()
    else:
        print(red(f"[-] Unknown tools subcommand: {cmd}"))
        print_usage()


def print_usage():
    print(blue("Usage: tools <custom|loot|showmodules>"))
    print("  custom <cmd>        - Run a shell command")
    print("  loot                - list loot files or view one")
    print("  showmodules         - Show supported attack modules")
    print("  loot [filename]     - Show loot file contents")
    print("  loot grep <term>    - Search all loot for keyword")



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
    loot_dir = "loot"
    if not os.path.exists(loot_dir):
        print(red("[-] 'loot/' directory not found."))
        return

    files = os.listdir(loot_dir)
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
            path = os.path.join(loot_dir, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if search_term in line.lower():
                            print(green(f"[{filename}] Line {i+1}: ") + line.strip())
            except Exception as e:
                print(red(f"[!] Could not read {filename}: {e}"))
        return

    # Show a single file
    file_path = os.path.join(loot_dir, args[0])
    if not os.path.exists(file_path):
        print(red(f"[-] File not found: {file_path}"))
        return

    print(blue(f"[*] Showing contents of: {args[0]}"))
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "###" in line:
                    print(yellow(line.strip()))
                else:
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

