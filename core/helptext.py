HELP_TEXT = {
    "general": """
BaldHead - Active Directory Attack Toolkit

Available commands:
  addsession        - Add a new session
  listsessions      - List all sessions
  usesession        - Switch to an existing session
  session           - Show current session info
  setdefaults       - Set default domain and DC IP
  setdchost         - Set FQDN for DC (used by BloodHound)
  export/import     - Export or import sessions
  attack            - Run an attack module
  adcs              - Run ADCS-specific modules (enum, esc1–esc10, etc.)
  showadcs          - Display stored ADCS metadata
  custom            - Run a custom command with placeholder replacement
  help <command>    - Show help for specific command
  exit              - Quit the tool
""",

    "addsession": """
addsession <name> <user> <pass_or_hash> [domain] [target_ip] [dc_ip]

Creates a session that stores credentials and context. Password or NT hash can be used.
Examples:
  addsession admin1 administrator 'P@ssw0rd!' auth.lab 10.0.0.5
  addsession hash1 administrator 8846f7eaee8fb117ad06bdd830b7586c auth.lab 10.0.0.5
""",

    "setdefaults": """
setdefaults <domain> <dc_ip>

Set default domain and domain controller IP to use when not explicitly provided.
""",

    "setdchost": """
setdchost <fqdn>

Set the FQDN (hostname) of the DC (needed for BloodHound Python).
""",

    "listsessions": """
Lists all available sessions. Shows active session.
""",

    "usesession": """
usesession <session_name>

Switch to a specific session by name.
""",

    "session": """
Show the currently active session.
""",

    "attack": """
attack <module> [args...]

Available modules:
  addself           <group> <user>              — Add user to group (BloodHound edge)
  readgmsa          <account>                   — Dump gMSA password
  forcechangepw     <user>                      — Force password reset
  writeowner        <target_dn> <new_owner>    — Change object owner (WriteOwner)
  genericall        <target_dn> [principal]    — Abuse GenericAll (FullControl)
  extrasid                                    — Priv. esc from child → parent domain
  dumpsecrets                                — Dump LSA, SAM, DPAPI with `nxc`
  dcsync                                     — Perform DCSync attack (secretsdump)
  gettgt                                     — Request TGT and load in memory
  shell                                      — Open WinRM/PsExec shell
  writespn                                   — Kerberoast using SPN write
  bloodhound                                 — BloodHound collection (Python)
  shadow             <user>                    — Shadow credentials hash extraction
  authenum           <subcmd> [save]           — Enum: users, shares, asrep, kerberoast, bloodhound
  adcs_enum         [save]                    — Enumerate ADCS CAs and templates
""",

    "adcs": """
adcs <enum|esc1|esc2|esc3|esc9|esc10|pfx2hash>

ADCS enumeration and template-specific exploitation.

  enum [save]        — Enumerate CAs, templates, vulnerabilities
  esc1               — Abuse ESC1 with vulnerable template
  esc2               — Abuse ESC2 to enroll as Administrator
  esc3               — Use Enrollment Agent template to impersonate others
  esc9               — Exploit insecure UPN mapping
  esc10              — Exploit registry misconfigs to impersonate users
  pfx2hash           — Convert .pfx file into usable NTLM hash
""",

    "showadcs": """
Show stored ADCS enumeration results: CA info, vulnerable templates, ESC vulnerabilities.
""",

    "custom": """
custom <command>

Run arbitrary command with placeholders auto-replaced.
Supported placeholders:
  {domain} {user} {pass} {hash} {dc_ip} {target_ip} {auth}
Example:
  custom nxc ldap {target_ip} --users -u {user} -p {pass}
""",

    "exit": """
Exit the BaldHead CLI.
""",

    "import": """
importsessions [file] [domain] [ip] [dc_ip]

Import session data from a file (e.g., sessions.txt)
""",

    "export": """
exportsessions [file]

Export current sessions to file for backup/reuse.
"""
}

