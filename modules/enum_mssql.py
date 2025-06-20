import os
import ast
from core.colors import blue, green, red, yellow
from core.helpers import run_command

def enum_mssql(session, action, db=None, table=None, save=False):
    if not action or action.lower() == "help":
        print_mssql_enum_usage()
        return

    print(blue(f"[*] Running MSSQL enumeration: {action}"))

    is_windows_auth = bool(session.domain and session.domain.lower() not in ['.', 'local', ''])

    if is_windows_auth:
        full_user = f"{session.domain}/{session.username}"
        print(blue(f"[*] Using Windows Auth as {full_user}"))
        run_with_windows_auth(session, full_user, action, db, table)
    else:
        print(blue(f"[*] Using SQL Auth as {session.username}"))
        run_with_sql_auth(session, action, db, table)

def print_mssql_enum_usage():
    print(blue("Usage: enum mssql <action> [db] [table]"))
    print("Available Actions:")
    print("  help                            - Show this help message")
    print("  privs                           - Show current user and sysadmin status")
    print("  dbs                             - List all databases")
    print("  tables <db>                     - List tables in a specific database")
    print("  logins                          - Enumerate SQL server logins")
    print("  users                           - List database users")
    print("  roles                           - List database roles and members")
    print("  spns                            - List SPNs in sys.dm_exec_sessions (safe fallback)")
    print("  trusts                          - List linked servers")
    print("  linked_pivotable                - Check for pivotable linked servers")
    print("  execas_usable                   - Check EXECUTE AS usability")
    print("  lsa_dump_check                  - Check login/SID alignment for abuse")
    print("  xp_status                       - Check if xp_cmdshell is enabled")
    print("  dump_table <db> <table>         - Dump contents of a table")
    print("  linked                          - List all linked servers")
    print("  linked:<srv>:<action> [db]      - Run any above action on a linked server")

def run_with_windows_auth(session, full_user, action, db, table):
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

        return clean(out), err

    if action == "linked":
        query = "EXEC sp_linkedservers"
    elif action == "spns":
        query = "SELECT host_name, program_name, client_interface_name FROM sys.dm_exec_sessions"
    elif action == "xp_status":
        query = "EXEC sp_configure 'show advanced options'; RECONFIGURE; EXEC sp_configure 'xp_cmdshell'"
    elif action.startswith("linked:"):
        parts = action.split(":")
        if len(parts) != 3:
            print(red("[-] Format: linked:<linked_server>:<action>"))
            return
        linked_server, linked_action = parts[1], parts[2]
        query = build_linked_query(linked_server, linked_action, db, table)
        if not query:
            print(red(f"[-] Unsupported or incomplete linked action: {linked_action}"))
            return
    else:
        query = build_local_query(action, db, table)
        if not query:
            print(red(f"[-] Unsupported or incomplete action: {action}"))
            return

    cleaned_output, err = exec_sql(query)

    if not cleaned_output:
        print(red(f"[-] No data returned.\n{err.strip()}"))
        return

    print(green("\n[+] Enumeration Output:\n"))
    parse_and_print_output("\n".join(cleaned_output), action)



def parse_and_print_output(raw_out, action):
    lines = raw_out.strip().splitlines()

    cleaned_lines = []
    skip_prefixes = ("[*]", "[-]", "Impacket", "ACK: Result")
    for line in lines:
        line = line.strip()
        if any(line.startswith(prefix) for prefix in skip_prefixes):
            continue
        if line.lower().startswith("sql>"):
            continue
        cleaned_lines.append(line)

    headers = []
    rows = []
    parsing = False
    for line in cleaned_lines:
        if not parsing and any(c.isalpha() for c in line) and ("   " in line or "\t" in line):
            headers = [col.strip() for col in line.split() if col.strip()]
            parsing = True
            continue
        if parsing and set(line) <= set("- "):
            continue
        if parsing and line:
            parts = [col.strip() for col in line.split() if col.strip()]
            rows.append(parts)

    cleaned_rows = [r for r in rows if len(r) == len(headers)]
    if headers and cleaned_rows:
        print_table(headers, cleaned_rows)
        return

    parsed_rows = []
    for line in cleaned_lines:
        if line.startswith("[") and line.endswith("]"):
            try:
                parsed = ast.literal_eval(line)
                if isinstance(parsed, list):
                    row = ["" if str(x).upper() == "NULL" else str(x).replace("'", "").strip() for x in parsed]
                    parsed_rows.append(row)
            except Exception:
                continue

    if parsed_rows:
        max_len = max(len(r) for r in parsed_rows)
        if action == "linked":
            if max_len == 6:
                headers = ["SRV_NAME", "PROVIDER", "PRODUCT", "DATASOURCE", "PROVIDER_STRING", "LOCATION"]
            elif max_len == 7:
                headers = ["SRV_NAME", "PROVIDER", "PRODUCT", "DATASOURCE", "PROVIDER_STRING", "LOCATION", "CATEGORY"]
            elif max_len == 8:
                headers = ["SRV_NAME", "PROVIDER", "PRODUCT", "DETAIL", "DATASOURCE", "PROVIDER_STRING", "LOCATION", "CATEGORY"]
            else:
                headers = [f"Col{i+1}" for i in range(max_len)]
        else:
            headers = [f"Col{i+1}" for i in range(max_len)]

        print_table(headers, parsed_rows)
        return

    print_table(["Result"], [[line.strip()] for line in cleaned_lines if line.strip()])

def run_with_sql_auth(session, action, db, table):
    import pymssql
    try:
        conn = pymssql.connect(
            server=session.dc_ip,
            user=session.username,
            password=session.password,
            database=db or "master",
            login_timeout=5,
            timeout=5,
            appname="baldhead",
            charset='UTF-8',
            autocommit=True
        )
        cursor = conn.cursor()

        if action == "linked":
            cursor.execute("EXEC sp_linkedservers")
        elif action.startswith("linked:"):
            parts = action.split(":")
            if len(parts) != 3:
                print(red("[-] Format: linked:<linked_server>:<action>"))
                return
            linked_server, linked_action = parts[1], parts[2]
            query = build_linked_query(linked_server, linked_action, db, table)
            if not query:
                print(red(f"[-] Unsupported or incomplete linked action: {linked_action}"))
                return
            cursor.execute(query)
        else:
            query = build_local_query(action, db, table)
            if not query:
                print(red(f"[-] Unsupported or incomplete action: {action}"))
                return
            cursor.execute(query)

        rows = cursor.fetchall()
        headers = [desc[0] for desc in cursor.description]
        print(green("\n[+] Enumeration Output:"))
        print_table(headers, rows)
        cursor.close()
        conn.close()

    except Exception as e:
        print(red(f"[-] Error: {e}"))

def build_linked_query(linked, action, db=None, table=None):
    db = db or "master"
    table = table or ""

    queries = {
        "privs": (
            f"SELECT * FROM OPENQUERY({linked}, "
            f"'SELECT SYSTEM_USER AS SystemUser, USER_NAME() AS UserName, "
            f"SUSER_NAME() AS SUserName, ORIGINAL_LOGIN() AS OriginalLogin, "
            f"IS_SRVROLEMEMBER(''sysadmin'') AS IsSysadmin')"
        ),
        "whoami": f"SELECT * FROM OPENQUERY({linked}, 'SELECT SYSTEM_USER AS SystemUser, SUSER_SNAME() AS SUserName')",
        "sysadmin_check": f"SELECT * FROM OPENQUERY({linked}, 'SELECT IS_SRVROLEMEMBER(''sysadmin'') AS IsSysadmin')",
        "dbs": f"SELECT * FROM OPENQUERY({linked}, 'SELECT name AS DatabaseName FROM sys.databases')",
        "tables": (
            f"SELECT * FROM OPENQUERY({linked}, "
            f"'SELECT TABLE_SCHEMA AS Schema, TABLE_NAME AS TableName FROM {db}.INFORMATION_SCHEMA.TABLES')"
            if db else None
        ),
        "logins": f"SELECT * FROM OPENQUERY({linked}, 'SELECT name, type_desc, is_disabled FROM sys.server_principals')",
        "users": f"SELECT * FROM OPENQUERY({linked}, 'SELECT name, type_desc FROM sys.database_principals WHERE type IN (''S'',''U'',''G'')')",
        "roles": (
            f"SELECT * FROM OPENQUERY({linked}, "
            f"'SELECT dp.name AS RoleName, mp.name AS MemberName "
            f"FROM sys.database_role_members rm "
            f"JOIN sys.database_principals dp ON rm.role_principal_id = dp.principal_id "
            f"JOIN sys.database_principals mp ON rm.member_principal_id = mp.principal_id')"
        ),
        "execas_check": (
            f"SELECT * FROM OPENQUERY({linked}, "
            f"'SELECT name AS PrincipalName, type_desc AS Type "
            f"FROM sys.database_principals WHERE authentication_type_desc = ''INSTANCE''')"
        ),
        "lsa_dump_check": (
            f"SELECT * FROM OPENQUERY({linked}, "
            f"'SELECT s.name AS UserName, l.name AS LoginName "
            f"FROM sys.sql_logins l JOIN sys.sysusers s ON s.sid = l.sid')"
        ),
        "xp_status": (
            f"EXEC ('IF EXISTS (SELECT * FROM sys.configurations "
            f"WHERE name = ''xp_cmdshell'' AND value_in_use = 1) "
            f"SELECT ''ENABLED'' AS status ELSE SELECT ''DISABLED'' AS status') AT {linked}"
        ),
        "linked_nested": f"SELECT * FROM OPENQUERY({linked}, 'EXEC sp_linkedservers')",
        "dump_table": (
            f"SELECT * FROM OPENQUERY({linked}, 'SELECT * FROM {db}.dbo.{table}')"
            if db and table else None
        ),
    }

    return queries.get(action)

def build_local_query(action, db, table):
    return {
        "privs": (
            "SELECT SYSTEM_USER AS SystemUser, USER_NAME() AS UserName, "
            "SUSER_NAME() AS SUserName, ORIGINAL_LOGIN() AS OriginalLogin, "
            "IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin"
        ),
        "dbs": "SELECT name AS DatabaseName FROM sys.databases",
        "tables": f"SELECT TABLE_SCHEMA, TABLE_NAME FROM {db}.INFORMATION_SCHEMA.TABLES" if db else None,
        "logins": "SELECT name, type_desc, is_disabled FROM sys.server_principals",
        "users": "SELECT name, type_desc FROM sys.database_principals WHERE type IN ('S','U','G')",
        "roles": (
            "SELECT dp.name AS RoleName, mp.name AS MemberName "
            "FROM sys.database_role_members rm "
            "JOIN sys.database_principals dp ON rm.role_principal_id = dp.principal_id "
            "JOIN sys.database_principals mp ON rm.member_principal_id = mp.principal_id"
        ),
        "spns": "SELECT DISTINCT service_principal_name FROM sys.dm_exec_connections WHERE service_principal_name IS NOT NULL",
        "trusts": "EXEC sp_linkedservers",
        "linked_pivotable": "SELECT * FROM sys.servers WHERE is_linked = 1",
        "xp_status": "EXEC sp_configure 'xp_cmdshell'",
        "execas_usable": (
            "SELECT name, type_desc, principal_id "
            "FROM sys.database_principals WHERE authentication_type_desc = 'INSTANCE'"
        ),
        "lsa_dump_check": (
            "SELECT s.name, l.name "
            "FROM sys.sql_logins l JOIN sys.sysusers s ON s.sid = l.sid"
        ),
        "dump_table": f"SELECT * FROM {db}.dbo.{table}" if db and table else None,
    }.get(action)

def print_table(headers, rows):
    if not headers or not rows:
        print(red("[-] No data to display."))
        return

    valid_rows = [r for r in rows if len(r) == len(headers)]
    if not valid_rows:
        print_table(["Output"], [[str(row)] for row in rows])
        return

    col_widths = [len(h) for h in headers]
    for row in valid_rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    header_row = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(green("  " + header_row))
    print(green("  " + "-+-".join("-" * w for w in col_widths)))
    for row in valid_rows:
        print("  " + " | ".join(str(col).ljust(col_widths[i]) for i, col in enumerate(row)))
