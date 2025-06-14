# core/helptext.py — full enhanced help menu for BaldHead CLI

# core/helptext.py — final corrected and complete help menu for BaldHead CLI

HELP_TEXT = {
    "general": """
BaldHead - Active Directory Attack Toolkit

Command Categories:
  setup       - Configure default domain, DC IP, and sync time
  session     - Manage authentication sessions and contexts
  connect     - Open SMB, WinRM, RDP, FTP, or PsExec connections
  enum        - Run enumeration modules (anonymous, authenticated, BloodHound)
  attack      - Launch post-exploitation attack modules
  adcs        - Abuse Active Directory Certificate Services (ESCx)
  tools       - Utilities for parsing loot, hashes, tickets, and running modules
  debug       - Validate tool paths, directory structure, and show session info

Type 'help <command>' to view usage details.
""",

    "setup": """
setup <option>

  domain <domain>             - Set the default domain (e.g. auth.lab)
  ip <ip_address>             - Set the default target or DC IP
  dc <fqdn>                   - Set the FQDN of the Domain Controller
  defaults <domain> <ip>      - Set domain + IP together and sync time
  sync-time                   - Sync system time with Domain Controller
""",

    "session": """
session <subcommand>

  add <name> <user> <secret> [domain] [ip] [dc_ip] [--env ENV] [--tags ...]
                                - Add a new session
  use <name>                   - Switch to an existing session
  list [--domain ...]          - List sessions (with optional filters)
  export [file]                - Export sessions to a file
  import [file] [domain] [ip]  - Import sessions from file
  addkerb                     - Add session using current Kerberos TGT #soon
  check <name>                - Validate session's credentials
  delete <name>               - Delete a specific session
  clear                       - Clear all sessions from memory
""",

    "connect": """
connect <type>

  smb                         - Open an interactive SMB client shell
  winrm                       - Connect using evil-winrm (Kerberos/hash/pass)
  rdp                         - Launch xfreerdp connection
  psexec                      - Execute command over SMB via PsExec
  ftp                         - Connect to FTP service
""",

   "enum": """
enum <module>

  Modules:
    users           - Enumerate users via LDAP
    groups          - Enumerate groups via LDAP
    computers       - Enumerate computers via LDAP
    dcs             - List Domain Controllers
    sid             - Get domain SID
    active          - List enabled user accounts
    delegation      - Identify delegation settings
    trusted         - Find 'Trusted for Delegation' users
    passnotreq      - Users with 'Password Not Required' flag
    admincount      - Users with adminCount=1
    gmsa            - Enumerate GMSA accounts
    asrep           - Find AS-REP roastable users
    kerberoast      - Find SPN-enabled users (Kerberoast)
    shares          - Enumerate SMB shares via nxc
    deletedusers    - Enumerate deleted users
    anon <target>   - Run anonymous SMB/FTP/Nmap enum
  """,

  "attack": """
attack <module>

  asrep                      - Extract AS-REP roastable users
  kerberoast                 - Extract SPN tickets for offline cracking
  extrasid                   - Use forged TGT with ExtraSID to escalate
  enableuser                 - Enable a disabled user account
  forcechangepw              - Force user to change password at next login
  genericall                 - Abuse GenericAll to take object control
  writedacl                  - Set FullControl DACL on a target object
  writespn                   - Write SPN and request TGS (Kerberoast)
  writeowner                 - Change ownership of target object
  addself                    - Add current user to target ACL
  dcsync                     - Perform DCSync to dump password hashes
  shadow                     - Abuse shadow credentials (ESC10, ESC11, ESC16)
  rbcd                       - Perform full RBCD attack chain
  gettgt                     - Request new TGT from KDC
  forge_silver               - Create and use forged Silver Ticket
  dump_secrets               - Dump SAM, LSA, and DPAPI secrets
  password_spray             - Spray password across users
  readgmsa                   - Dump GMSA passwords from AD
""",

    "adcs": """
adcs <module>

  enum                      - Enumerate CA, templates, and ADCS vulnerabilities
  esc1                      - ESC1: Enrollable template with client auth EKU
  esc2                      - ESC2: Misconfigured enrollment permissions
  esc3                      - ESC3: Dangerous CT_FLAGS
  esc4                      - ESC4: Enrollment agent abuse
  esc5                      - ESC5: SubCA manual approval request abuse
  esc6                      - ESC6: Misconfigured CT_FLAGS and EKU abuse
  esc7                      - ESC7: No manager approval required for client auth
  esc8                      - NTLM relay to ADCS HTTP endpoint
  esc9                      - ESC9: Misconfigured certificate name constraints
  esc10                     - ESC10: Misconfigured registry-based auth mapping
  esc11                     - ESC11: Vulnerable template issuance chain
  esc16                     - ESC16: Shadow credentials + cert authentication
  showadcs                  - Show CA name, DNS, and loaded metadata
""",

"tools": """
tools <option>

  loot                      - List all stored loot files
  showmodules               - Show available attack/enum modules
  parsehashes               - Extract NTLM hashes from output files
  checktickets              - Analyze .kirbi or .ccache Kerberos tickets
  extract-creds             - Parse credentials from all loot
  open <filename>           - Open and display a loot file
  grepusers <filename>      - Extract usernames from logs/tickets
  removeloot <filename>     - Delete a specific loot file
  custom <command>          - Run any custom shell command
  run                       - Launch tools menu in interactive mode
"""
,

    "debug": """
 debug <option>

  check_paths               - Verify that required tools are in PATH
  check_structure           - Ensure BaldHead folders and loot paths exist
  whoami            - Show current session info (debug)
"""
}

def get_help(topic="general"):
    topic = topic.lower().strip()
    return HELP_TEXT.get(topic, HELP_TEXT["general"])
