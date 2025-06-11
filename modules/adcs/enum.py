import os
import re
import json
import glob
from datetime import datetime
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def matches_client_auth(eku_list):
    return any("Client Authentication" in e for e in eku_list)

def enumerate_adcs(session, save=False, verbose=True):
    print(blue(f"[*] Enumerating ADCS with certipy-ad (JSON mode) for {session.username}@{session.domain}..."))

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    base_name = f"{timestamp}"
    expected_json = f"{base_name}_Certipy.json"

    cmd = f"certipy-ad find -target {session.domain} -dc-ip {session.dc_ip} -json -output {base_name}"
    if session.hash:
        cmd += f" -u {session.username} -hashes :{session.hash}"
    elif session.password:
        cmd += f" -u {session.username} -p '{session.password}'"
    else:
        cmd += f" -u {session.username} -k --no-pass"

    _, err = run_command(cmd)

    possible_files = glob.glob(f"{base_name}*_Certipy.json")
    if not possible_files:
        print(red("[-] Certipy did not produce expected JSON output."))
        if err:
            print(yellow("[!] Certipy stderr:\n") + err)
        return

    json_file = possible_files[0]

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(red(f"[-] Failed to parse Certipy JSON output: {e}"))
        return

    save_loot(os.path.basename(json_file), json.dumps(data, indent=2), binary=False)

    cas, esc_vulns, templates = [], [], []

    # === Parse Certificate Authorities
    for _, ca in data.get("Certificate Authorities", {}).items():
        cas.append({
            "name": ca.get("CA Name"),
            "dns": ca.get("DNS Name"),
            "subject": ca.get("Certificate Subject")
        })

        for esc_id, esc_desc in ca.get("[!] Vulnerabilities", {}).items():
            if re.fullmatch(r'ESC\d+', esc_id):
                esc_vulns.append({
                    "id": esc_id,
                    "desc": esc_desc
                })

    # === Parse Templates with Derived ESCs
    for _, tpl in data.get("Certificate Templates", {}).items():
        tpl_name = tpl.get("Template Name", "Unknown")
        tpl_vulns = tpl.get("[!] Vulnerabilities", {})
        escs = [k for k in tpl_vulns if re.fullmatch(r'ESC\d+', k)]

        # Derive ESCs from properties
        if tpl.get("Enrollment Agent", False):
            escs.append("ESC3")

        if tpl.get("Enrollee Supplies Subject", False):
            escs.append("ESC1")

        if tpl.get("Schema Version") == 1:
            escs.append("ESC13")

        if matches_client_auth(tpl.get("Extended Key Usage", [])):
            if tpl.get("Enrollee Supplies Subject"):
                escs.append("ESC1")
            if tpl.get("[+] User Enrollable Principals"):
                escs.append("ESC6")

        escs = sorted(set([e for e in escs if re.fullmatch(r'ESC\d+', e)]))
        if escs:
            templates.append({
                "name": tpl_name,
                "vulns": escs
            })

    # === Save to session
    session.adcs_metadata = {
        "cas": cas,
        "esc_vulns": esc_vulns,
        "templates": templates
    }

    # === Output
    if verbose:
        print(green("[+] ADCS Enumeration Output:\n"))

        for ca in cas:
            print(green("[CA] ") + ca["name"])
            print(f"     {yellow('DNS')} : {ca['dns']}")
            print(f"     {yellow('Subject')} : {ca['subject']}")
        print()

        if esc_vulns:
            print(red("[!] Potential Vulnerabilities:"))
            for vuln in esc_vulns:
                print(f"  {vuln['id']} → {vuln['desc']}")
            print()

        if templates:
            print("[*] Templates:")
            for t in templates:
                print(f"  [Template] {t['name']} — Vuln: {', '.join(sorted(set(t['vulns'])))}")
            print()
