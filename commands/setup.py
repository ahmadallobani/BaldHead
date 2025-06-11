# commands/setup.py

from core.colors import red, green, yellow, blue
from core.helpers import run_command

def handle_setup(args, session_mgr):
    if not args:
        print_usage()
        return

    cmd = args[0].lower()

    if cmd == "domain" and len(args) > 1:
        session_mgr.default_domain = args[1]
        print(green(f"[+] Default domain set to: {args[1]}"))

    elif cmd == "ip" and len(args) > 1:
        session_mgr.default_dc_ip = args[1]
        print(green(f"[+] Default target/DC IP set to: {args[1]}"))

    elif cmd == "dc" and len(args) > 1:
        fqdn = args[1]
        if session_mgr.get_current():
            session_mgr.set_dc_hostname(fqdn)
        else:
            print(yellow("[*] No active session, setting will apply to next one added."))
        print(green(f"[+] DC hostname set to: {fqdn}"))

    elif cmd == "sync-time":
        dc_ip = session_mgr.default_dc_ip
        if not dc_ip:
            print(red("[-] No DC IP set. Use 'setup ip <ip>' first."))
            return
        print(blue(f"[*] Syncing time with DC {dc_ip}..."))
        out, err = run_command(f"ntpdate -u {dc_ip}")
        if out:
            print(green(out.strip()))
        if err:
            print(red(err.strip()))

    elif cmd == "defaults" and len(args) >= 3:
        domain, dc_ip = args[1], args[2]
        session_mgr.set_defaults(domain=domain, dc_ip=dc_ip)
        print(green(f"[+] Default domain set to '{domain}', DC IP set to '{dc_ip}'"))

        # Auto-add /etc/hosts entry
        try:
            with open("/etc/hosts", "r") as f:
                if domain not in f.read():
                    with open("/etc/hosts", "a") as f_append:
                        f_append.write(f"\n{dc_ip}\t{domain}\n")
                    print(green(f"[+] Added {dc_ip} {domain} to /etc/hosts"))
                else:
                    print(yellow(f"[*] {domain} already exists in /etc/hosts"))
        except Exception as e:
            print(red(f"[!] Failed to update /etc/hosts: {e}"))

        # Sync time
        print(blue(f"[*] Syncing system time with DC {dc_ip}..."))
        out, err = run_command(f"ntpdate -u {dc_ip}")
        if out:
            print(green(out.strip()))
        if err:
            print(red(err.strip()))
    else:
        print_usage()


def print_usage():
    print(blue("Usage:"))
    print("  setup domain <domain>")
    print("  setup ip <target_ip>")
    print("  setup dc <fqdn>")
    print("  setup sync-time")
    print("  setup defaults <domain> <dc_ip>")

