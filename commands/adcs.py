# commands/adcs.py

from core.colors import red, green, yellow, blue
from core.helpers import select_from_list
import traceback

# === Import ADCS modules ===
from modules.adcs import enum as adcs_enum
from modules.adcs import esc1, esc2, esc3, esc9,esc4, pfx2hash,esc6

def handle_adcs(args, session_mgr):
    if not args:
        print_usage()
        return

    session = session_mgr.get_current()
    if not session:
        print(red("[-] No active session. Use 'session use <name>' first."))
        return

    cmd = args[0].lower()
    try:
        if cmd == "enum":
            adcs_enum.enumerate_adcs(session, save="save" in args)

        elif cmd == "esc1":
            _use_template(session, esc1.abuse_esc1, "ESC1")

        elif cmd == "esc2":
            _use_template(session, lambda s, t: esc2.abuse_esc2(s, t, save=True), "ESC2")

        elif cmd == "esc3":
            _use_template(session, esc3.abuse_esc3, "ESC3")
        elif cmd == "esc4":
            _use_template(session, esc4.abuse_esc4, "ESC4")


        elif cmd == "esc6":
            _use_template(session, esc6.abuse_esc6, "ESC6")

        elif cmd == "esc9":
            _use_template(session, esc9.abuse_esc9, "ESC9")


        elif cmd == "pfx2hash":
            pfx2hash.abuse_pfx2hash(session)
        elif cmd == "show":
            show_adcs_metadata(session)

        else:
            print(red(f"[-] Unknown ADCS subcommand: {cmd}"))
            print_usage()

    except KeyboardInterrupt:
        print(yellow("\n[!] ADCS action interrupted by user."))
    except Exception as e:
        print(red(f"[!] ADCS command failed: {e}"))
        print(traceback.format_exc())


def print_usage():
    print(blue("Usage: adcs <enum|esc1|esc2|esc3|esc9|esc10|pfx2hash>"))
    print("  enum [save]      - Enumerate CAs, templates, and ESCs")
    print("  esc1             - Abuse vulnerable ESC1 template")
    print("  esc2             - Abuse vulnerable ESC2 template")
    print("  esc3             - Use enrollment agent impersonation")
    print("  esc9             - Abuse UPN mapping ESC9")
    print("  esc10            - Abuse registry misconfig for UPN shadow")
    print("  pfx2hash         - Extract NT hash from .pfx certificate")


def _use_template(session, func, esc_label):
    templates = session.adcs_metadata.get("templates", [])
    matching = [t["name"] for t in templates if esc_label in t["vulns"]]

    if not matching:
        print(red(f"[-] No {esc_label} templates found in session metadata."))
        return

    print(blue(f"[*] Found vulnerable templates for {esc_label}:"))
    selected = select_from_list(matching, f"Select {esc_label} template")
    if selected:
        func(session, selected)

def show_adcs_metadata(session):
    metadata = session.adcs_metadata or {}
    cas = metadata.get("cas", [])
    escs = metadata.get("esc_vulns", [])
    templates = metadata.get("templates", [])

    if not (cas or escs or templates):
        print(yellow("[*] No ADCS metadata found. Run 'adcs enum' first."))
        return

    print(blue("[*] Stored ADCS Metadata:\n"))

    if cas:
        for ca in cas:
            print(green("[CA] ") + ca["name"])
            print(f"     {yellow('DNS')} : {ca['dns']}")
            print(f"     {yellow('Subject')} : {ca['subject']}")
        print()

    if escs:
        print(red("[!] Vulnerabilities:"))
        for e in escs:
            print(f"  {e['id']} → {e['desc']}")
        print()

    if templates:
        print("[*] Templates with ESCs:")
        for t in templates:
            print(f"  {t['name']} — {', '.join(t['vulns'])}")
        print()

