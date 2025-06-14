# baldhead.py

import cmd
import shlex
import readline
import atexit
import re
from core.colors import red, green, blue
from core.session_manager import SessionManager
from scripts.startup_check import run_checks
from core.helptext import HELP_TEXT
# === Load Command Modules ===
from commands import setup, session, connect, attack, enum, adcs, tools, debug

readline.set_history_length(1000)
try:
    readline.read_history_file(".baldhead_history")
except FileNotFoundError:
    pass
atexit.register(readline.write_history_file, ".baldhead_history")

def ansi_wrap(color_func, text):
    """
    Properly wrap ANSI color codes for readline to avoid prompt glitching.
    """
    # Get colored text like '\033[91mtext\033[0m'
    colored = color_func(text)

    # Use regex to extract start and end escape sequences
    start_match = re.match(r'(\033\[[0-9;]+m)', colored)
    end_match = re.search(r'(\033\[0m)$', colored)

    if not start_match or not end_match:
        return text  # fallback: no wrapping

    start_code = start_match.group(1)
    end_code = end_match.group(1)

    return f"\001{start_code}\002{text}\001{end_code}\002"


class BaldHead(cmd.Cmd):
    prompt = green("baldhead> ")

    def __init__(self):
        super().__init__()
        self.session_mgr = SessionManager()

    def preloop(self):
        self._update_prompt()

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def _update_prompt(self):
        s = self.session_mgr.get_current()
        if s:
            self.prompt = (
                ansi_wrap(green, "baldhead") +
                " 💀 " +
                ansi_wrap(red, s.username) +
                "@" +
                ansi_wrap(blue, s.domain) +
                " > "
            )
        else:
            self.prompt = ansi_wrap(green, "baldhead> ")




    def startup_banner(self):
        from rich import print
        print(r"""
  ____        _     _   _   _                _
 | __ )  __ _| | __| | | | | | ___  __ _  __| |
 |  _ \ / _` | |/ _` | | |_| |/ _ \/ _` |/ _` |
 | |_) | (_| | | (_| | |  _  |  __/ (_| | (_| |
 |____/ \__,_|_|\__,_| |_| |_|\___|\__,_|\__,_|

[bold blue]by FakeLaw[/bold blue]
""")
        run_checks()

    # ---------- DISPATCHER FOR COMMAND GROUPS ----------
    def do_setup(self, line):
        setup.handle_setup(shlex.split(line), self.session_mgr)

    def do_session(self, line):
        session.handle_session(shlex.split(line), self.session_mgr)

    def do_connect(self, line):
        connect.handle_connect(shlex.split(line), self.session_mgr)

    def do_attack(self, line):
        attack.handle_attack(shlex.split(line), self.session_mgr)

    def do_enum(self, line):
        enum.handle_enum(shlex.split(line), self.session_mgr)

    def do_adcs(self, line):
        adcs.handle_adcs(shlex.split(line), self.session_mgr)

    def do_tools(self, line):
        tools.handle_tools(shlex.split(line), self.session_mgr)
    def do_debug(self, line):
        debug.handle_debug(shlex.split(line), self.session_mgr)
    def do_help(self, line):
            topic = line.strip().lower() or "general"
            if topic in HELP_TEXT:
                print(HELP_TEXT[topic])
            else:
                print(f"[!] Unknown help topic: {topic}\n")
                print(HELP_TEXT["general"])


    def do_exit(self, _):
        print("Bye!")
        return True

    def do_clear(self, _):
        import os
        os.system("clear" if os.name != "nt" else "cls")

    do_s = do_session
    do_a = do_attack
    do_c = do_connect
    do_e = do_enum
    do_t = do_tools
    do_ad = do_adcs
    do_d = do_debug
    do_st = do_setup
    do_set = do_setup
    do_h = do_help


if __name__ == "__main__":
    BaldHead().startup_banner()
    BaldHead().cmdloop()
