import re
from core.helpers import run_command, save_loot
from core.colors import red, green, yellow, blue

def enumerate_adcs(session, save=False, verbose=True):
    print(blue(f"[*] Enumerating ADCS with certipy-ad for {session.username}@{session.domain}..."))

    base_cmd = f"certipy-ad find -target {session.domain} -dc-ip {session.dc_ip} -stdout"

    if session.hash:
        base_cmd += f" -u {session.username} -p :{session.hash}"
    elif session.password:
        base_cmd += f" -u {session.username} -p {session.password}"
    else:
        base_cmd += f" -u {session.username} -k --no-pass"

    output, err = run_command(base_cmd)
    full_output = output + "\n" + err

    if "Certificate Authorities" not in full_output and "Certificate Templates" not in full_output:
        print(red("[-] No certificate authorities or templates found."))
        if err:
            print(err)
        return

    cas = []
    esc_vulns = []
    templates = []

    # Parse CAs
    ca_blocks = re.findall(r'Certificate Authorities(.*?)Certificate Templates', full_output, re.DOTALL)
    for ca_block in ca_blocks:
        ca_name = re.search(r'CA Name\s+: (.*)', ca_block)
        dns_name = re.search(r'DNS Name\s+: (.*)', ca_block)
        subj = re.search(r'Certificate Subject\s+: (.*)', ca_block)

        ca_info = {
            "name": ca_name.group(1).strip() if ca_name else "N/A",
            "dns": dns_name.group(1).strip() if dns_name else "N/A",
            "subject": subj.group(1).strip() if subj else "N/A"
        }
        cas.append(ca_info)

    # Parse global ESC vulnerabilities
    for line in full_output.splitlines():
        match = re.search(r'(ESC\d{1,2})\s*[:→\-]+\s*(.*)', line)
        if match:
            esc_vulns.append({
                "id": match.group(1),
                "desc": match.group(2).strip()
            })

    # Parse templates and ESCs from Certificate Templates section
    template_section_match = re.search(r'Certificate Templates(.*?)(Certipy v\d|\Z)', full_output, re.DOTALL)
    if template_section_match:
        template_section = template_section_match.group(1)
        template_blocks = re.split(r'\n\s*\d+\n', template_section)

        for block in template_blocks:
            name_match = re.search(r'Template Name\s+:\s+(.*)', block)
            if not name_match:
                continue

            name = name_match.group(1).strip()
            escs = re.findall(r'ESC\d{1,2}', block)
            if escs:
                templates.append({
                    "name": name,
                    "vulns": sorted(set(escs))
                })

    # Save to session (only vulnerable templates)
    session.adcs_metadata = {
        "cas": cas,
        "esc_vulns": esc_vulns,
        "templates": templates
    }

    # Output
    if verbose:
        print(green("[+] ADCS Enumeration Output:\n"))

        if cas:
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
                escs = ", ".join(t["vulns"])
                print(f"  [Template] {t['name']} — Vuln: {escs}")
            print()

    if save:
        save_loot("certipy_adcs_output.txt", full_output)