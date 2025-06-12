import socket
from collections import defaultdict
from core.session import Session
import json
from core.colors import red, green, yellow, blue

class SessionManager:
    def __init__(self):
        self.sessions = {}  # key: name, value: Session
        self.environments = defaultdict(list)  # key: env name, value: list of session names
        self.current = None
        self.default_domain = None
        self.default_dc_ip = None

    def set_defaults(self, domain=None, dc_ip=None):
        if domain:
            self.default_domain = domain
        if dc_ip:
            self.default_dc_ip = dc_ip

    def add(self, name, username, secret, domain=None, target_ips=None, dc_ip=None, env="default", tags=None, notes=None):
        domain = domain or self.default_domain
        dc_ip = dc_ip or self.default_dc_ip
        
        if isinstance(target_ips, str):
            target_ips = [ip.strip() for ip in target_ips.split(",") if ip.strip()]
        elif target_ips is None:
            target_ips = [self.default_dc_ip] if self.default_dc_ip else []

        if not domain or not target_ips:
            print("[-] Error: 'domain' and 'target_ips' are required (explicitly or via defaults).")
            return

        if secret:
            is_hash = len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret)
            hash_value = secret if is_hash else None
            password = None if is_hash else secret
        else:
            is_hash = False
            hash_value = None
            password = None

        hash_value = secret if is_hash else None
        password = None if is_hash else secret

        for ip in target_ips:
            session_id = f"{name}-{ip}"
            session = Session(session_id, username, password, domain, ip, dc_ip, hash=hash_value)

            session.adcs_metadata = {}
            session.env = env
            session.tags = tags or []
            session.notes = notes or ""

            self.sessions[session_id] = session
            self.environments[env].append(session_id)
            self.current = session  # last added is current

    def set_dc_hostname(self, fqdn):
        if self.current:
            self.current.dc_hostname = fqdn
            print(f"[+] DC hostname set to '{fqdn}' for session '{self.current.name}'")
        else:
            print("[-] No active session to set hostname for.")

    def use(self, name):
        if name in self.sessions:
            self.current = self.sessions[name]
            return True
        print(f"[-] Session '{name}' not found.")
        return False

    def list(self, raw=False, filters=None):
        sessions = list(self.sessions.values())
        
        if filters:
            if "domain" in filters:
                sessions = [s for s in sessions if s.domain == filters["domain"]]
            if "ip" in filters:
                sessions = [s for s in sessions if s.target_ip == filters["ip"]]
            if "username" in filters:
                sessions = [s for s in sessions if s.username == filters["username"]]
            if "env" in filters:
                sessions = [s for s in sessions if getattr(s, "env", "default") == filters["env"]]

        if raw:
            return sessions

        return [
            (s.name, s.username, s.domain, s.target_ip, getattr(s, "env", "default"), "(active)" if s == self.current else "")
            for s in sessions
        ]

    def get_current(self):
        return self.current

    def get(self, name=None, ip=None, domain=None):
        for s in self.sessions.values():
            if name and s.name == name:
                return s
            if ip and s.target_ip == ip:
                return s
            if domain and s.domain == domain:
                return s
        return None

    def store_adcs_metadata(self, ca_name, dns, subject):
        if self.current:
            self.current.adcs_metadata = {
                "ca_name": ca_name,
                "dns": dns,
                "subject": subject
            }

    def get_adcs_metadata(self):
        if self.current:
            return getattr(self.current, "adcs_metadata", None)
        return None

    def clear(self):
        self.sessions.clear()
        self.environments.clear()
        self.current = None

    def export_sessions(self, filepath="sessions.json"):
        try:
            data = {}
            for name, session in self.sessions.items():
                exportable = vars(session).copy()
                # Remove internal or duplicate keys not supported by __init__
                for key in ["password", "target_ip"]:
                    exportable.pop(key, None)
                data[name] = exportable
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            print(green(f"[+] Exported {len(data)} sessions to {filepath}"))
        except Exception as e:
            print(red(f"[-] Failed to export sessions: {e}"))



    def import_sessions(self, filepath="sessions.json"):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            for name, session_data in data.items():
                s = Session(**session_data)
                self.sessions[name] = s
                env = getattr(s, "env", "default")
                self.environments[env].append(name)
            print(green(f"[+] Imported {len(data)} sessions from {filepath}"))
        except Exception as e:
            print(red(f"[-] Failed to import sessions: {e}"))
