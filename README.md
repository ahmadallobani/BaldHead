# 🧠 BaldHead v1

**BaldHead** is an interactive, modular Active Directory (AD) attack framework designed for red teamers and penetration testers. It automates and streamlines the enumeration and exploitation of common AD misconfigurations using Python and familiar tools like `Impacket`, `nxc`,`bloodyAD` and `Certipy`.

---

## ✨ Features

- 🎯 Session management system with full environment and domain/IP tracking
- 🔐 Authenticated AD enumeration using `nxc`, `ldapsearch`, `impacket`
- 📦 Modular attack system: `GenericAll`, `WriteOwner`, `DCSync`, `ReadGMSAPassword`, and more
- 🧾 Session import/export via structured JSON
- 🪪 Supports NTLM, plaintext, Kerberos (`--no-pass`, TGT, and `.ccache`)
- 🖥️ Interactive shell interface
- 💥 WinRM and PsExec integration with auto-fallback
- 🔑 AD CS enumeration + ESCx abuse modules (e.g., ESC1, ESC5, ESC8, ESC10, ESC16)
- 🧠 Memory-persisted TGT/SSO support (`addkerb`, `usekerb`)
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
python3 main.py
```

---

## 🧠 Session Management

### Add a session

```bash
session add <name> <username> <password|hash> <domain> <ip>
```

Example:
```bash
session add dc-admin Administrator 'Password123!' corp.local 192.168.1.10
```

### Use a session

```bash
session use <name>
```

### List sessions

```bash
session list
```

### Export/Import sessions

```bash
session export [filename.json]
session import [filename.json]
```

---

## 🔐 Active Directory Certificate Services (ADCS)

BaldHead supports full AD CS enumeration and exploitation automation using Certipy.

### Enumeration

```bash
enum certs
```

This will run `certipy find` and automatically parse:

- CA Name / DNS / Template
- ESC1–ESC16 vulnerabilities
- Enrollment permissions and authentication flags

### Exploitation Modules

```bash
attack esc1
attack esc5
attack esc8
attack esc10
attack esc16
```

Each `escX` module automates the exploit logic for that misconfiguration. If manual intervention is needed (e.g., for approval in ESC5), the tool will instruct you how to proceed.

---

## 🛠 Supported Commands

### Enumeration

```bash
enum users
enum shares
enum smb
enum domain
enum certs
```

### Attacks

```bash
attack genericall
attack writeowner
attack writedacl
attack writespn
attack readgmsa
attack dcsync
attack localdump
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
connect winrm
connect psexec
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
- Combine with `kerbrute`/`GetNPUsers.py` for unauthenticated enumeration
- Import previously cracked sessions for reuse

---

## 🛡️ Legal Disclaimer

This tool is for **authorized security assessments** only. Do not use it against systems you do not own or have permission to test.

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

- Ahmad Allobani — [@ahmadallobani](https://github.com/ahmadallobani)

---

## 🔗 References

- [Impacket](https://github.com/fortra/impacket)
- [Certipy](https://github.com/ly4k/Certipy)
- [nxc](https://github.com/AlboSecurity/nxc)
- [Active Directory Attacks Cheatsheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)