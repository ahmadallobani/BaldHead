# 🧠 BaldHead v1

**BaldHead** is an interactive, modular Active Directory (AD) attack framework designed for red teamers and penetration testers. It automates and streamlines the enumeration and exploitation of common AD misconfigurations using Python and familiar tools like `Impacket`, `nxc`,`bloodyAD` and `Certipy`.

---

## ✨ Features

- 🎯 Session management system with full environment and domain/IP tracking
- 🔐 Authenticated AD enumeration using `nxc`, `ldapsearch`, `impacket`
- 📦 Modular attack system: `GenericAll`, `WriteOwner`, `DCSync`, `ReadGMSAPassword`, and more
- 🧾 Session import/export via structured JSON
- 🪪 Supports NTLM, plaintext
- 🖥️ Interactive shell interface
- 💥 WinRM and PsExec integration with auto-fallback
- 🔑 AD CS enumeration + ESCx abuse modules (e.g., ESC1, ESC5, ESC8, ESC10, ESC16)
- 🗂 Environment-aware, taggable sessions for large infrastructure support

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ahmadallobani/BaldHead.git
cd BaldHead
```

### 2. Install dependencies (recommended via pipx)

Install `pipx` if you haven't:
```bash
sudo apt install pipx
```

Then install the tools:
```bash
pipx install impacket
pipx install certipy-ad
sudo apt install bloodyad
pipx ensurepath

```

For legacy tools:
```bash
sudo apt install smbclient ldap-utils
```

Or clone Impacket manually for bleeding-edge modules:
```bash
git clone https://github.com/fortra/impacket.git
cd impacket && pipx install .
```

### 3. Launch BaldHead

```bash
python3 baldhead.py
```

---

## 🧠 Session Management

```
session <subcommand>

  add <name> <user> <pass_or_hash> [domain] [ip] [dc_ip] [--env ENV] [--tags tag1,tag2] [--notes "msg"]
      Add a session. Example:
        session add admin1 Administrator 'P@ssw0rd' auth.lab 10.0.0.5

  use <name>            - Switch to session by name
  list [filters]        - List all sessions. Optional: --domain, --ip, --env, --username
  export [file]         - Save current sessions to a file
  import [file]         - Load sessions from a file
  clear                 - Delete all sessions

```
---

## 🔐 Active Directory Certificate Services (ADCS)

BaldHead supports full AD CS enumeration and exploitation automation using Certipy.

### Enumeration

```bash
adcs enum
```

This will run `certipy find` and automatically parse:

- CA Name / DNS / Template
- ESC1–ESC16 vulnerabilities
- Enrollment permissions and authentication flags

### AD CS Exploitation Modules

```bash
adcs esc1
adcs esc5
adcs esc8
adcs esc6
adcs esc2
adcs pfx2hash
```

Each `escX` module automates the exploit logic for that misconfiguration. If manual intervention is needed (e.g., for approval in ESC5), the tool will instruct you how to proceed.

---

## 🛠 Supported Commands

### Enumeration

```bash
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


```

### Attacks

```bash
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
```

### Kerberos Handling

```bash
addkerb <ccache file>   #soon
usekerb                 #soon --no-pass for Kerberos
```

---

## 🔥 Connect Shell

Launch an interactive shell via WinRM or PsExec:

```bash
connect <method>
  smb           - Interactive smbclient session to share
  winrm         - Launch Evil-WinRM with password
  rdp           - Launch xfreerdp with password or hash
  psexec        - Remote shell via impacket-psexec
  ftp           - Try anonymous or credentialed FTP login

```

Supports fallback chaining — if WinRM fails, PsExec will be attempted (or vice versa).

---

## 📁 Loot & Output

- Looted credentials, certs, and dumps are stored in: `loot/`
- Each module outputs summary to terminal
- Session-aware logging planned in future versions

---

## 💡 Tips

- Use `session notes` and `session tags` to organize large engagements
- Import previously cracked sessions for reuse

---


## 📌 Version

**BaldHead v1**  
Initial release — session management, core modules, and command interface fully operational.

---

## 🧩 Roadmap (v2+ Ideas)

- BloodHound collection integration
- Interactive graph navigation of AD objects
- Custom report generation
- Remote agent support (SOCKS, pivoting)

---

## 🧙 Author

- FakeLaw — [@ahmadallobani](https://github.com/ahmadallobani) 

---

## 🔗 References

- [Impacket](https://github.com/fortra/impacket)
- [Certipy](https://github.com/ly4k/Certipy)
- [nxc](https://github.com/AlboSecurity/nxc)
- [Active Directory Attacks Cheatsheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
