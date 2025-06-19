# BaldHead v1.0

**BaldHead** is a modular and interactive Active Directory (AD) attack framework built for red teamers and security testers. It automates enumeration and exploitation of AD misconfigurations using tools like `Impacket`, `nxc`, `Certipy`, and `BloodyAD`.

---

## Features

- Full session management with tagging, environment grouping
- Authenticated and anonymous AD enumeration (users, groups, GMSA, trusts, etc.)
- Post-exploitation modules: GenericAll, DCSync, WriteSPN, ExtraSID, Silver Tickets, and more
- Session import/export in JSON format
- auth support for plaintext, NTLM hash
- AD Certificate Services (AD CS) enumeration and ESC1–ESC16 exploitation
- Interactive shell with custom command aliases and auto-prompt formatting
- Tools for loot parsing, ticket inspection, hash extraction, and more

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ahmadallobani/BaldHead.git
cd BaldHead
```

### 2. Install Dependencies

#### Core Tools (via `pipx` recommended)

```bash
sudo apt install pipx
pipx install impacket
pipx install certipy-ad
pipx ensurepath
```

#### BloodyAD

```bash
sudo apt install bloodyad
```

#### Useful Extras

```bash
sudo apt install smbclient ldap-utils nmap ftp xfreerdp3
```

---

## Usage

### Launch BaldHead:

```bash
python3 baldhead.py
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

### View Help:

```bash
help                # General help
help session        # Session commands
help attack         # All attacks
help adcs           # AD CS exploitation
help enum           # Enumeration modules
help setup          # setup the Environment
help tools          # Loot & utility tools
```

### Add a Session:

```bash
session add s1 administrator 'Pass123!' auth.lab 192.168.56.10
session list
session use
session del
```

### Launch Attacks:

```bash
attack kerberoast
attack dcsync
attack shadow
attack rbcd
attack mssql <action>
```

### Enumerate Environment:

```bash
enum users
enum delegation
enum mssql <action> [db] [table]
enum anon 192.168.56.10
```

### Exploit AD CS:

```bash
adcs enum
adcs esc1
adcs esc16
```

---

## Command Groups

| Command  | Description |
|----------|-------------|
| `setup`  | Set defaults for domain, IP, and DC |
| `session`| Manage sessions, Kerberos tickets, tags |
| `connect`| SMB, WinRM, RDP, PsExec, FTP |
| `attack` | All supported AD privilege escalation and abuse modules |
| `enum`   | LDAP and network enumeration |
| `adcs`   | Enumerate and abuse vulnerable certificate templates and CAs |
| `tools`  | Loot inspection, hash parsing, ticket conversion |
| `debug`  | Diagnose paths, config, DNS, and session issues |

---

## Module Examples

### Enumeration

- `users`, `groups`, `computers`, `delegation`, `trusted`, `kerberoast`, `gmsa`, etc.
- `anon <target>` — enum4linux-style check with SMB, FTP, and Nmap

### Attacks

- `kerberoast`, `asrep`, `dcsync`, `shadow`, `rbcd`, `writespn`, `forge_silver`, `enableuser`, etc.

### AD CS

- `enum` (CA and templates)
- `esc1` to `esc16` for exploiting misconfigured templates, cert relaying, and shadow credentials

---

## Tools

- `loot` — list loot files
- `parsehashes` — extract hashes from logs
- `checktickets` — inspect Kerberos tickets
- `convert_ticket` — convert kirbi/ccache
- `open <file>` — view loot file
- `grepusers <file>` — extract usernames

---

## Directory Structure

```
baldhead/
│
├── core/           # Session, helpers, color, helptext
├── commands/       # Command handlers for each group
├── modules/        # All attack and enum modules
├── loot/           # Captured output and artifacts
├── baldhead.py     # Main entrypoint
├── README.md
```

---

## 🧙 Author

- Ahmad Allobani — [@ahmadallobani](https://www.linkedin.com/in/ahmad-allobani-50a952257/)

---
## Credits

- Built using [Impacket](https://github.com/fortra/impacket)
- Certificate abuse via [Certipy](https://github.com/ly4k/Certipy)
- LDAP/SMB via [nxc](https://github.com/Acceis/nxc)
- Red team abuse via [BloodyAD](https://github.com/CravateRouge/bloodyAD)

---

## Version

**BaldHead v1.0**  
Initial release — session management, core modules, and command interface fully operational.

---
