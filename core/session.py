class Session:
    def __init__(self, name, username, password, domain, target_ip, dc_ip, nt_hash=None):
        self.name = name
        self.username = username
        self.password = password
        self.hash = nt_hash
        self.domain = domain
        self.target_ip = target_ip
        self.dc_ip = dc_ip
        self.dc_hostname = None

        # ADCS-specific fields
        self.adcs_ca_name = None
        self.adcs_ca_dns = None
        self.adcs_vulns = []

    def is_ready(self):
        return all([self.domain, self.username, self.target_ip])

