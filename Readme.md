
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
| `baldhead`  | `pipx install git+https://github.com/YOUR-USERNAME/baldhead.git` | Main command-line interface          |

---

## 🛠 Installation (Best Practice via `pipx`)

### 📦 Step 1: Install pipx

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

Restart your shell or run:

```bash
source ~/.bashrc  # or ~/.zshrc
```

---

### 🚀 Step 2: Install Required Tools

```bash
# Install BaldHead
pipx install git+https://github.com/YOUR-USERNAME/baldhead.git

# External tools
pipx install git+https://github.com/fortra/impacket
pipx install git+https://github.com/CravateRouge/bloodyAD
pipx install certipy-ad
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
baldhead
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

## 🔐 Requirements

- Linux/macOS (or WSL)
- Python 3.9+
- `pipx` installed
- Access to an Active Directory environment for testing

---

## ⚠️ Legal Disclaimer

> This software is intended for authorized penetration testing and research purposes only. Unauthorized use against systems without permission is illegal.

---

## 📄 License

MIT License — see [LICENSE](./LICENSE)

---

## 🤝 Contributing

Pull requests are welcome. Please open an issue first to discuss what you would like to change or improve.

