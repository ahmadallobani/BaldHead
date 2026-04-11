from datetime import datetime

class Session:
        def __init__(self, name, username, secret, domain, target_ips=None,
                 dc_ip=None, hash=None, ccache=None, kerberos=False,
                 dc_hostname=None, notes="", tags=None, env="default",
                 adcs_metadata=None, created_at=None, last_used=None):

            self.name = name
            self.username = username
            self.password = secret
            self.secret = secret
            self.hash = hash
            self.domain = domain
            self.target_ips = target_ips if isinstance(target_ips, list) else [target_ips]
            self.dc_ip = dc_ip
            self.ccache = ccache
            self.kerberos = kerberos
            self.dc_hostname = dc_hostname
            self.notes = notes or ""
            self.tags = tags or []
            self.env = env or "default"
            self.adcs_metadata = adcs_metadata or {}
            self.created_at = created_at or datetime.now().isoformat()
            self.last_used = last_used

        @property
        def target_ip(self):
            return self.target_ips[0] if self.target_ips else None

        def __repr__(self):
            return f"<Session {self.name} {self.username}@{self.domain} ({self.target_ip})>"
