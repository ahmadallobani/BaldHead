
# 🧑‍🦲 BaldHead

**BaldHead** is a professional, modular, and fully interactive command-line Red Teaming tool for Active Directory attacks. Built for adversary simulation, it automates and streamlines enumeration, privilege escalation, and misconfiguration abuse using modern Python tooling.

---

## 🎯 Features

- Interactive command-line interface
- Modular attack architecture
- Native support for:
  - Kerberos (TGT/TGS management)
  - DACL abuse: `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`
  - AD CS exploitation (ESC1–ESC11 detection and attack modules)
  - Credential dumping (LSA, SAM, DPAPI via NXC)
  - Shell launcher: Evil-WinRM/PsExec fallback chain
- AD-aware session memory (contextual state, ticket reuse)
- Beautiful CLI output powered by `rich`

---

## 🧰 Tooling Dependencies

To make full use of `BaldHead`, the following tools are required:

| Tool        | Install via pipx                                 | Purpose                              |
|-------------|--------------------------------------------------|--------------------------------------|
| `impacket`  | `pipx install git+https://github.com/fortra/impacket` | Kerberos, SMB, DACL, etc. attacks    |
| `bloodyAD`  | `pipx install git+https://github.com/CravateRouge/bloodyAD` | DACL abuse, privilege escalation     |
| `certipy-ad`| `pipx install certipy-ad`                        | AD CS enumeration and ESC exploitation |

---

## 🛠 Installation (Best Practice via `pipx`)

### 📦 Step 1: Install pipx

```bash
sudo pipx ensurepath
```

Restart your shell or run:

```bash
source ~/.bashrc  # or ~/.zshrc
```

---

### 🚀 Step 2: Install Required Tools

```bash
# Install BaldHead
git clone https://github.com/ahmadallobani/BaldHead.git

# External tools
sudo pipx install impacket
sudo apt install bloodyad
sudo pipx install certipy-ad
```

> All tools will be globally available in your `PATH` and isolated in their own virtual environments.

---

## 📂 Project Layout

```
baldhead/
├── main.py
├── modules/
│   ├── adcs/
│   ├── dacl/
│   ├── enum/
│   └── shell/
├── core/
│   ├── session.py
│   ├── protocol.py
│   └── utils.py
├── data/
├── requirements.txt
└── README.md
```

---

## 🧪 Usage

After installing via `pipx`, just run:

```bash
sudo python3 baldhead.py
```

Then use commands like:

- `gettgt`
- `dcsync`
- `dump`
- `shell`
- `adcs_enum`
- `showadcs`
- `getspn`
- `help`

> Use `help` inside the shell to see available modules and usage patterns.

---
