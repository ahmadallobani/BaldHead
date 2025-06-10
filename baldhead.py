# main.py

import cmd
import os
from core.helpers import run_command
import subprocess
from subprocess import run, PIPE
import traceback
import atexit
import re
import readline
from core.session_manager import SessionManager
from core.colors import red, green, yellow, blue
from core.helptext import HELP_TEXT
from modules import (
    addself,
    readgmsa,
    forcechangepw,
    writeowner,
    genericall,
    bloodhound_enum,
    dump_secrets,
    shell,
    dcsync,
    gettgt,
    auth_enum,
    shadow,
    password_spray,
    extrasid,
    writespn
)
from modules.adcs import enum as adcs_enum, esc1, esc2, esc3, esc9, esc10, pfx2hash
from scripts import session_io
from startup_check import run_checks

readline.set_history_length(1000)
try:
    readline.read_history_file(".baldhead_history")
except FileNotFoundError:
    pass
atexit.register(readline.write_history_file, ".baldhead_history")


class BaldHead(cmd.Cmd):
    intro = r"""

  ____        _     _   _   _                _
 | __ )  __ _| | __| | | | | | ___  __ _  __| |
 |  _ \ / _` | |/ _` | | |_| |/ _ \/ _` |/ _` |
 | |_) | (_| | | (_| | |  _  |  __/ (_| | (_| |
 |____/ \__,_|_|\__,_| |_| |_|\___|\__,_|\__,_|

by FakeLaw

Type help or ? to list commands.
"""
    run_checks()
    prompt = 'baldhead> '

    def __init__(self):
        super().__init__()
        self.session_mgr = SessionManager()

    def preloop(self):
        self._update_prompt()

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def _update_prompt(self):
        session = self.session_mgr.get_current()
        if session:
            self.prompt = f"baldhead 💀 {green(session.username)}@{blue(session.domain)} > "
        else:
            self.prompt = "baldhead> "

    # ------------------------
    # Aliases
    # ------------------------
    def do_add(self, line): self.do_addsession(line)
    def do_use(self, line): self.do_usesession(line)
    def do_list(self, line): self.do_listsessions(line)
    def do_quit(self, line): return self.do_exit(line)
    def do_ls(self, line): self.do_loot(line)
    def do_defaults(self, line): self.do_setdefaults(line)
    def do_dcfqdn(self, line): self.do_setdchost(line)
    def do_sess(self, line): self.do_session(line)
    def do_mods(self, line): self.do_showmodules(line)
    def do_adcs(self, line): self.do_adcs(line)
    def do_custom(self, line): self.do_custom(line)

    # ------------------------
    # Help
    # ------------------------
    def do_help(self, arg):
        topic = arg.strip().lower()
        if not topic:
            print(HELP_TEXT["general"])
        elif topic in HELP_TEXT:
            print(HELP_TEXT[topic])
        else:
            print(f"No help available for '{topic}'. Try one of:")
            for k in sorted(HELP_TEXT.keys()):
                print(f"  - {k}")

    # ------------------------
    # Session Management
    # ------------------------
    def do_addsession(self, line):
        parts = line.strip().split()
        if len(parts) < 3:
            print("Usage: addsession <name> <user> <pass_or_hash> [domain] [ip] [dc_ip]")
            return
        name, user, secret = parts[:3]
        domain = parts[3] if len(parts) > 3 else None
        ip = parts[4] if len(parts) > 4 else None
        dc_ip = parts[5] if len(parts) > 5 else None
        self.session_mgr.add(name, user, secret, domain=domain, target_ip=ip, dc_ip=dc_ip)
        if self.session_mgr.get_current():
            print(green(f"[+] Session '{name}' added and set active"))

    def do_listsessions(self, _):
        sessions = self.session_mgr.list()
        for name, user, domain, ip, active in sessions:
            print(blue(f" - {name}: {user}@{domain} ({ip}) {active}"))

    def do_usesession(self, line):
        if self.session_mgr.use(line.strip()):
            print(green(f"[+] Switched to session '{line.strip()}'"))
        else:
            print(red(f"[-] No such session: {line.strip()}"))

    def do_session(self, _):
        s = self.session_mgr.get_current()
        if not s:
            print(red("[-] No session selected."))
        else:
            print(green(f"[+] Active session: {s.name} — {s.username}@{s.domain} ({s.target_ip})"))

    def do_setdefaults(self, line):
        parts = line.strip().split()
        if len(parts) < 2:
            print("Usage: setdefaults <domain> <dc_ip>")
            return

        domain, dc_ip = parts[:2]
        self.session_mgr.set_defaults(domain=domain, dc_ip=dc_ip)
        print(green(f"[+] Default domain set to '{domain}', DC IP set to '{dc_ip}'"))

        # --- Step 1: Add to /etc/hosts if not present ---
        try:
            with open("/etc/hosts", "r") as f:
                hosts = f.read()
            if domain not in hosts:
                with open("/etc/hosts", "a") as f:
                    f.write(f"\n{dc_ip}\t{domain}\n")
                print(green(f"[+] Added {dc_ip} {domain} to /etc/hosts"))
            else:
                print(yellow(f"[*] {domain} already in /etc/hosts"))
        except Exception as e:
            print(red(f"[!] Failed to update /etc/hosts: {e}"))

        # --- Step 2: Sync time with DC ---
        try:
            print(blue(f"[*] Syncing system time with DC {dc_ip}..."))
            out, err = run_command(f"ntpdate -u {dc_ip}")
            print(green(out.strip()) if out else yellow("[*] No output from ntpdate"))
            if err:
                print(red(err.strip()))
        except Exception as e:
            print(red(f"[!] Failed to sync time: {e}"))

    def do_setdchost(self, line):
        if not line.strip():
            print("Usage: setdchost <dc_fqdn>")
            return
        self.session_mgr.set_dc_hostname(line.strip())

    # ------------------------
    # Utility Commands
    # ------------------------
    def do_loot(self, line):
        if not os.path.exists("loot"):
            print(red("[-] 'loot' directory does not exist."))
            return
        files = os.listdir("loot")
        if not files:
            print(yellow("[*] No loot files found."))
            return
        if not line.strip():
            print(blue("[*] Loot files:"))
            for f in files:
                print(f" - {f}")
        else:
            path = os.path.join("loot", line.strip())
            if not os.path.exists(path):
                print(red(f"[-] File not found: {path}"))
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                print(f.read())
    

    def do_export(self, line):
        path = line.strip() or "sessions.txt"
        session_io.export_sessions(self.session_mgr, path)

    def do_import(self, line):
        parts = line.strip().split()
        path = parts[0] if parts else "sessions.txt"
        domain = parts[1] if len(parts) > 1 else None
        ip = parts[2] if len(parts) > 2 else None
        dc_ip = parts[3] if len(parts) > 3 else None
        session_io.import_sessions(self.session_mgr, filepath=path, domain=domain, ip=ip, dc_ip=dc_ip)

    def do_clear(self, line):
        os.system("clear" if os.name != "nt" else "cls")

    def do_clearsessions(self, line):
        confirm = input(yellow("[?] Are you sure you want to clear all sessions? [y/N]: ")).strip().lower()
        if confirm != "y":
            print(yellow("[*] Session clear aborted."))
            return
        self.session_mgr.default_domain = None
        self.session_mgr.default_dc_ip = None
        print(yellow("[*] Defaults also cleared."))


        self.session_mgr.sessions.clear()
        self.session_mgr.current = None
        print(green("[+] All sessions cleared."))


    def do_showmodules(self, _):
        print(blue("[*] Attack Modules:"))
        for cmd in sorted([
            "addself", "readgmsa", "forcechangepw", "writeowner", "genericall",
            "extrasid", "dumpsecrets", "dcsync", "gettgt", "shadow",
            "authenum", "writespn", "shell", "bloodhound", "adcs_enum"
        ]):
            print(f"  - {cmd}")
        print("\n" + blue("[*] ADCS Modules:"))
        for esc in sorted(["enum", "esc1", "esc2", "esc3", "esc9", "esc10", "pfx2hash"]):
            print(f"  - {esc}")

    def _confirm_action(self, message):
        resp = input(f"{yellow(message)} [y/N]: ").strip().lower()
        return resp == 'y'

    # ------------------------
    # Attack Handler
    # ------------------------
    def do_attack(self, line):
        parts = line.strip().split()
        if not parts:
            print(HELP_TEXT["attack"])
            return
        cmd, *args = parts
        session = self.session_mgr.get_current()
        if not session or not session.is_ready():
            print(red("[-] No active session. Use `usesession` or `addsession` first."))
            return

        try:
            if cmd in ["forcechangepw", "writeowner"]:
                if not self._confirm_action(f"[!] Are you sure you want to run '{cmd}'?"):
                    print(yellow("[!] Action cancelled."))
                    return

            # Attack dispatch map with argument validation
            attack_map = {
                "addself": (lambda: addself.attack_addself(session, *args), 2, "attack addself <group> <user>"),
                "readgmsa": (lambda: readgmsa.attack_read_gmsa(session, *args), 1, "attack readgmsa <account>"),
                "forcechangepw": (lambda: forcechangepw.attack_force_change(session, args[0], self.session_mgr), 1, "attack forcechangepw <target_user>"),
                "writeowner": (lambda: writeowner.attack_write_owner(session, *args), 2, "attack writeowner <target_dn> <new_owner>"),
                "genericall": (lambda: genericall.attack_genericall(session, *args), 1, "attack genericall <target_DN> [principal]"),
                "extrasid": (lambda: extrasid.run(session), 0, None),
                "dumpsecrets": (lambda: dump_secrets.dump_all(session), 0, None),
                "shell": (lambda: shell.run_shell(session), 0, None),
                "dcsync": (lambda: dcsync.attack_dcsync(session), 0, None),
                "bloodhound": (lambda: bloodhound_enum.run_bloodhound(session), 0, None),
                "gettgt": (lambda: gettgt.get_tgt(session), 0, None),
                "writespn": (lambda: writespn.attack_writespn(session), 0, None),
                "shadow": (lambda: shadow.attack_shadow(session, args), 1, "attack shadow <user>"),
                "authenum": (lambda: self._handle_authenum(session, args), 1, "attack authenum <users|shares|asrep|kerberoast|bloodhound> [save]"),
                "adcs_enum": (lambda: adcs_enum.enumerate_adcs(session, save=("save" in args)), 0, None),
                "spray": (lambda: password_spray.attack_password_spray(session), 0, None)
            }

            if cmd not in attack_map:
                print(red(f"[!] Unknown attack module: {cmd}"))
                print(HELP_TEXT["attack"])
                return

            func, min_args, usage = attack_map[cmd]
            if len(args) < min_args:
                if usage:
                    print(red(f"[-] Usage: {usage}"))
                else:
                    print(red(f"[-] Too many arguments or unexpected input for '{cmd}'."))
                return

            func()

        except KeyboardInterrupt:
            print(yellow("\n[!] Attack interrupted by user. Returning to prompt."))
        except Exception as e:
            print(red(f"[!] Attack failed:\n{e}"))
            print(red(traceback.format_exc()))

    def _handle_authenum(self, session, args):
        if not args:
            print("Usage: attack authenum <users|shares|asrep|kerberoast|bloodhound> [save]")
            return
        subcmd = args[0]
        save = (len(args) > 1 and args[1] == "save")
        auth_funcs = {
            "users": auth_enum.enum_users,
            "shares": auth_enum.enum_shares,
            "asrep": auth_enum.enum_asrep,
            "kerberoast": auth_enum.enum_kerberoast,
            "bloodhound": auth_enum.enum_bloodhound
        }
        if subcmd in auth_funcs:
            auth_funcs[subcmd](session, save=save)
        else:
            print(red(f"[!] Invalid authenum subcommand: {subcmd}"))

    def do_adcs(self, line):
        parts = line.strip().split()
        if not parts:
            print(HELP_TEXT["adcs"])
            return

        subcmd = parts[0].lower()
        session = self.session_mgr.get_current()
        if not session:
            print(red("[-] No session selected."))
            return

        try:
            esc_map = {
                "enum": lambda: adcs_enum.enumerate_adcs(session, save=("save" in parts)),
                "esc1": lambda: self._abuse_template(session, esc1.abuse_esc1, "ESC1"),
                "esc2": lambda: self._abuse_template(session, lambda s, t: esc2.abuse_esc2(s, t, save=True), "ESC2"),
                "esc3": lambda: self._abuse_template(session, esc3.abuse_esc3, "ESC3"),
                "esc9": lambda: self._abuse_template(session, esc9.abuse_esc9, "ESC9"),
                "esc10": lambda: self._abuse_template(session, esc10.abuse_esc10, "ESC10"),
                "pfx2hash": lambda: pfx2hash.abuse_pfx2hash(session)
            }

            if subcmd in esc_map:
                esc_map[subcmd]()
            else:
                print(red(f"[!] Unknown ADCS subcommand: {subcmd}"))
                print(HELP_TEXT["adcs"])

        except Exception as e:
            print(red(f"[!] Exception during adcs {subcmd}: {e}"))
            traceback.print_exc()

    def _abuse_template(self, session, func, esc_label):
        templates = session.adcs_metadata.get("templates", [])
        matching = [t["name"] for t in templates if esc_label in t["vulns"]]
        if not matching:
            print(red(f"[-] No {esc_label} templates found in session metadata."))
            return
        print(blue(f"[*] Available {esc_label} templates:"))
        for t in matching:
            print(f"  - {t}")
        chosen = input("[?] Enter template name to abuse: ").strip()
        func(session, chosen)

    def _select_pfx_file(self):
        files = pfx2hash.list_pfx_files()
        if not files:
            print(red("[-] No PFX files found in loot/certs"))
            return None
        print(blue("[*] Available PFX files:"))
        for f in files:
            print(f" - {f}")
        selected = input("[?] Enter PFX filename to use: ").strip()
        if selected not in files:
            print(red("[-] Invalid PFX file selected."))
            return None
        return selected


    def do_exit(self, _):
        print("Bye!")
        return True
    
    def do_addkerb(self, line):
        import os
        import re
        import glob
        from subprocess import run, PIPE
        from core.colors import green, yellow, red, blue

        print(blue("[*] Scanning loot/ for Kerberos tickets..."))

        loot_dir = "loot"
        krb_files = glob.glob(os.path.join(loot_dir, "*.ccache"))
        if not krb_files:
            print(red("[-] No krb5cc_* files found in loot/."))
            return

        dc_ip = self.session_mgr.default_dc_ip or input("[?] Enter DC IP: ").strip()
        target_ip = self.session_mgr.default_dc_ip or dc_ip

        added = 0
        for path in krb_files:
            print(yellow(f"[*] Checking {path}..."))
            result = run(["klist", "-c", path], stdout=PIPE, stderr=PIPE, text=True)
            output = result.stdout

            if "Default principal" not in output:
                print(red(f"[-] No valid ticket in {path}"))
                continue

            match = re.search(r"Default principal:\s+([^\s@]+)@([^\s]+)", output)
            if not match:
                print(red(f"[-] Could not parse principal from {path}"))
                continue

            username, domain = match.groups()
            domain = domain.lower()
            session_name = f"{username}_kerb"

            # Avoid duplicate sessions
            if session_name in self.session_mgr.sessions:
                session_name += f"_{added}"

            # Set env if first one
            if added == 0:
                os.environ["KRB5CCNAME"] = path
                print(green(f"[+] Set default ticket: KRB5CCNAME={path}"))

            self.session_mgr.add(
                name=session_name,
                username=username,
                secret="",
                domain=domain,
                target_ip=target_ip,
                dc_ip=dc_ip
            )

            print(green(f"[+] Kerberos session added: '{session_name}' for {username}@{domain}"))
            added += 1

        if added == 0:
            print(red("[-] No valid Kerberos tickets were loaded."))
        else:
            print(blue(f"[*] Total loaded Kerberos sessions: {added}"))



if __name__ == '__main__':
    BaldHead().cmdloop()
