class Session:
        def __init__(self, name, username, secret, domain, target_ips=None,
                 dc_ip=None, hash=None, ccache=None, kerberos=False,
                 dc_hostname=None, notes="", tags=None, env="default",
                 adcs_metadata=None):

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
            self.notes = ""
            self.tags = tags or []
            self.env = "default"
            self.adcs_metadata = {}
        def __getattr__(self, attr):
            if attr == "target_ip":
                return self.target_ips[0] if self.target_ips else None
            raise AttributeError(f"'Session' object has no attribute '{attr}'")

        def __repr__(self):
            return f"<Session {self.name} {self.username}@{self.domain} ({self.target_ip})>"
