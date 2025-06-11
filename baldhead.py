# baldhead.py

import cmd
import shlex
import readline
import atexit
from core.colors import red, green, blue
from core.session_manager import SessionManager
from scripts.startup_check import run_checks

# === Load Command Modules ===
from commands import setup, session, connect, attack, enum, adcs, tools, debug

readline.set_history_length(1000)
try:
    readline.read_history_file(".baldhead_history")
except FileNotFoundError:
    pass
atexit.register(readline.write_history_file, ".baldhead_history")


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
            self.prompt = f"{red('baldhead')} 💀 {green(s.username)}@{blue(s.domain)} > "
        else:
            self.prompt = green("baldhead> ")

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


    def do_exit(self, _):
        print("Bye!")
        return True

    def do_clear(self, _):
        import os
        os.system("clear" if os.name != "nt" else "cls")


if __name__ == "__main__":
    BaldHead().startup_banner()
    BaldHead().cmdloop()
