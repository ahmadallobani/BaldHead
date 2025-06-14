import os
import re
from datetime import datetime
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def enumerate_adcs(session, save=False, verbose=True):
    print(blue(f"[*] Enumerating ADCS with certipy-ad (stdout mode) for {session.username}@{session.domain}..."))

    cmd = f"certipy-ad find -target {session.domain} -dc-ip {session.dc_ip} -vulnerable -stdout"
    if session.hash:
        cmd += f" -u {session.username} -hashes :{session.hash}"
    elif session.password:
        cmd += f" -u {session.username} -p '{session.password}'"

    out, err = run_command(cmd)
    if not out:
        print(red("[-] No output from Certipy."))
        if err:
            print(yellow("[!] stderr:\n") + err)
        return

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    save_loot(f"{timestamp}_certipy_stdout.txt", out, binary=False)

    # === Parse Certificate Authorities
    cas = []
    esc_vulns = []
    current_ca = {}
    inside_ca = False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("CA Name"):
            current_ca["name"] = line.split(":", 1)[1].strip()
            inside_ca = True
        elif line.startswith("DNS Name"):
            current_ca["dns"] = line.split(":", 1)[1].strip()
        elif line.startswith("Certificate Subject"):
            current_ca["subject"] = line.split(":", 1)[1].strip()
        elif re.match(r"^ESC\d+\s*:", line) and inside_ca:
            match = re.match(r"^(ESC\d+)", line)
            if match:
                esc_vulns.append({"id": match.group(1), "desc": line})
        elif line == "" and current_ca:
            cas.append(current_ca)
            current_ca = {}
            inside_ca = False
    if "name" in current_ca:
        cas.append(current_ca)

    # === Parse Certificate Templates
    templates = []
    current_tpl = {}
    in_template = False
    for line in out.splitlines():
        line = line.strip()

        if line.startswith("Template Name"):
            if current_tpl and current_tpl.get("vulns"):
                templates.append(current_tpl)
            current_tpl = {"name": line.split(":", 1)[1].strip(), "vulns": []}
            in_template = True
        elif line.startswith("[!] Vulnerabilities") and in_template:
            continue
        elif re.match(r"^ESC\d+\s*:", line) and in_template:
            match = re.match(r"^(ESC\d+)", line)
            if match:
                current_tpl["vulns"].append(match.group(1))
        elif line.startswith("[*] Remarks") or line == "":
            if current_tpl and current_tpl.get("vulns"):
                templates.append(current_tpl)
            current_tpl = {}
            in_template = False

    if current_tpl and current_tpl.get("vulns"):
        templates.append(current_tpl)

    # === Fallback for no CA
    if not cas:
        print(yellow("[!] No CA block found. Adding fallback..."))
        cas.append({
            "name": "UNKNOWN-CA",
            "dns": session.dc_ip,
            "subject": f"CN=UNKNOWN, DC={session.domain.replace('.', ',DC=')}"
        })

    session.adcs_metadata = {
        "cas": cas,
        "esc_vulns": esc_vulns,
        "templates": templates
    }

    if verbose:
        print(green("[+] ADCS Enumeration Output:\n"))

        for ca in cas:
            print(green("[CA] ") + ca.get("name", "Unknown"))
            print(f"     {yellow('DNS')} : {ca.get('dns', '')}")
            print(f"     {yellow('Subject')} : {ca.get('subject', '')}")
        print()

        if esc_vulns:
            print(red("[!] CA-Level Vulnerabilities:"))
            for v in esc_vulns:
                print(f"  {v['id']} → {v['desc']}")
            print()
            esc_ca_template_map = {}
            for esc in esc_vulns:
                esc_id = esc["id"]
                if esc_id not in esc_ca_template_map:
                    esc_ca_template_map[esc_id] = {
                        "name": f"CA-Level-{esc_id}",
                        "vulns": [esc_id]
                    }

            # Add virtual templates for CA-level ESCs if not already in templates
            for esc_tpl in esc_ca_template_map.values():
                if esc_tpl["name"] not in [t["name"] for t in templates]:
                    templates.append(esc_tpl)
        if templates:
            print("[*] Templates:")
            for t in templates:
                print(f"  [Template] {t['name']} — Vuln: {', '.join(t['vulns'])}")
        else:
            print(yellow("[-] No vulnerable templates found."))
