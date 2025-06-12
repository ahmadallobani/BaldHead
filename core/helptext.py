# core/helptext.py — full detailed help menu for BaldHead CLI

HELP_TEXT = {
    "general": """
BaldHead - Active Directory Attack Toolkit

Available command groups:
  setup           - Set defaults and synchronize time
  session         - Manage sessions (add, use, list, import, export)
  connect         - Connect to targets (SMB, WinRM, RDP, PsExec, FTP)
  attack          - Run post-exploitation modules
  enum            - Run enumeration modules (authenticated and anonymous)
  adcs            - Run AD Certificate Services enumeration and attacks
  tools           - Utilities for loot, hashes, tickets, etc.
  debug           - Debug project paths, structure, and session state

Run 'help <command>' for more details on any group.
""",

    "setup": """
setup <option>

  domain <domain>       - Set default domain
  ip <target_ip>        - Set default target IP / DC IP
  dc <fqdn>             - Set FQDN of Domain Controller
  defaults <domain> <dc_ip> - Set both domain and IP, update /etc/hosts, sync time
  sync-time             - Sync system time with DC (required for Kerberos)
""",

    "session": """
session <subcommand>

  add <name> <user> <pass_or_hash> [domain] [ip] [dc_ip] [--env ENV] [--tags tag1,tag2] [--notes \"msg\"]
      Add a session. Example:
        session add admin1 Administrator 'P@ssw0rd' auth.lab 10.0.0.5

  use <name>            - Switch to session by name
  list [filters]        - List all sessions. Optional: --domain, --ip, --env, --username
  export [file]         - Save current sessions to a file
  import [file]         - Load sessions from a file
  clear                 - Delete all sessions
""",

    "connect": """
connect <method>

  smb           - Interactive smbclient session to share
  winrm         - Launch Evil-WinRM with password
  rdp           - Launch xfreerdp with password or hash
  psexec        - Remote shell via impacket-psexec
  ftp           - Try anonymous or credentialed FTP login
""",

    "attack": """
attack <module> [args]

Modules:
  dcsync                              - secretsdump against domain controller
  shadow <user>                       - extract NT hash via certificate shadow
  writedacl                           - write FullControl DACL on object
  genericall                          - abuse GenericAll to escalate
  writeowner                          - change object owner
  addself                             - add yourself to group
  addmember                           - add user to group 
  forcechangepw                       - force password reset
  enableuser <user>                   - remove ACCOUNTDISABLE flag
  localdump                           - LSA/SAM/DPAPI via nxc
  kerberoast                          - SPN request + hashcat format
  asrep                               - AS-REP roastable users
  gettgt                              - request a TGT and store .ccache
  readgmsa <account>                  - dump gMSA password
  forge_silver                        - generate Silver Ticket (.ccache)
  extrasid                            - forge TGT with ExtraSID to access parent domain
  genericwrite                        - write FullControl DACL on object
  bloodhound                          - run bloodhound-python with auth

Use 'attack <module> [--env DEV] [--domain X] ...' to run across multiple sessions.
""",

    "enum": """
enum <module> [save]

Authenticated:
  users           - LDAP user listing
  groups          - Group listing
  computers       - Computers in domain
  dcs             - Domain Controllers
  sid             - Get domain SID
  active          - Active user accounts
  delegation      - Accounts with delegation rights
  trusted         - Trusted-for-delegation accounts
  passnotreq      - Users with PASSWD_NOTREQD
  admincount      - Accounts with adminCount=1
  gmsa            - Group Managed Service Accounts
  asrep           - Roastable AS-REP accounts
  kerberoast      - Roastable SPN users
  bloodhound      - LDAP collection for BloodHound

Anonymous:
  anon <target>   - enum4linux-ng + ftp/smb/nmap
""",

    "adcs": """
adcs <subcommand>

  enum [save]      - Discover CAs, templates, ESCx vulns
  esc1             - abuse ESC1 templates (supply subject)
  esc2             - abuse ESC2 to enroll as admin
  esc3             - use enrollment agent to request on-behalf
  esc4             - abuse ESC4 via SAN + UPN override
  esc6             - abuse ESC6 for impersonation
  esc9             - abuse ESC9 (UPN change)
  esc10            - abuse ESC10 (registry config)
  pfx2hash         - extract NT hash from .pfx cert
  show             - display stored ADCS metadata
""",

    "tools": """
tools <subcommand>

  custom <cmd>         - Run shell command (env vars like {user}, {pass} substituted)
  loot                 - List loot files
  loot <file>          - Show content of a specific loot file
  loot grep <keyword>  - Search all loot files for keyword
  convert_ticket       - Convert Kerberos tickets (describe .ccache/.kirbi)
  showmodules          - List supported attack modules
  parsehashes          - Extract and classify NTLM/ASREP/TGS hashes from loot
  checktickets         - List and show all tickets in loot (ccache, kirbi)
  extract-creds        - Pull all user:pass and user:hash from loot
  open <filename>      - View loot file interactively
  grepusers <term>     - Search for user-like values in loot
  (no args)            - Launch interactive tools menu
""",

    "debug": """
debug <subcommand>

  check-paths     - Ensure required tools exist in PATH
  check-structure - Ensure folder structure is valid
  whoami          - Print current session info
"""
}


def get_help(topic="general"):
    topic = topic.lower().strip()
    return HELP_TEXT.get(topic, HELP_TEXT["general"])
