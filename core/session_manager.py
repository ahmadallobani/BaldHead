import socket
from core.session import Session

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.current = None
        self.default_domain = None
        self.default_dc_ip = None

    def set_defaults(self, domain=None, dc_ip=None):
        if domain:
            self.default_domain = domain
        if dc_ip:
            self.default_dc_ip = dc_ip

    def add(self, name, username, secret, domain=None, target_ip=None, dc_ip=None):
        domain = domain or self.default_domain
        target_ip = target_ip or self.default_dc_ip
        dc_ip = dc_ip or self.default_dc_ip or target_ip

        if not domain or not target_ip:
            print("[-] Error: 'domain' and 'target_ip' are required (explicitly or via defaults).")
            return

        is_hash = len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret)
        hash_value = secret if is_hash else None
        password = None if is_hash else secret

        session = Session(name, username, password, domain, target_ip, dc_ip, nt_hash=hash_value)

        try:
            fqdn = socket.gethostbyaddr(dc_ip)[0]
            session.dc_hostname = fqdn
        except Exception:
            session.dc_hostname = None
            print(f"[!] Could not resolve hostname for DC IP {dc_ip}. Use 'setdchost' to set manually.")

        session.adcs_metadata = {}  # ensure the attribute always exists

        self.sessions[name] = session
        self.current = session

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
        return False

    def list(self, raw=False):
        if raw:
            return self.sessions.values()
        return [
            (s.name, s.username, s.domain, s.target_ip, "(active)" if s == self.current else "")
            for s in self.sessions.values()
        ]

    def get_current(self):
        return self.current

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

