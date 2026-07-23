import csv
from pathlib import Path

class Scope:
    def __init__(self, csv_path):
        self.allowed = {}   # {port: True} for IN endpoints
        self.denied = {}    # {port: True} for OUT endpoints (just for clarity)
        self._load(csv_path)

    def _load(self, csv_path):
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)  # uses the header row
            for row in reader:
                asset = row['asset'].strip()
                scope_flag = row['scope'].strip()
                
                # Ignore CIDR entries like 0.0.0.0/0 – we handle loopback logic directly
                if '/' in asset:
                    continue
                
                # Parse "127.0.0.1:18231"
                if ':' in asset:
                    host, port_str = asset.split(':')
                    port = int(port_str)
                    
                    # We only care about loopback (as per the brief)
                    if host in ('127.0.0.1', 'localhost'):
                        if scope_flag == 'IN':
                            self.allowed[port] = True
                        elif scope_flag == 'OUT':
                            self.denied[port] = True

    def is_allowed(self, host, port):
        # Rule 1: Host MUST be loopback (127.0.0.1)
        if host not in ('127.0.0.1', 'localhost'):
            return False

        # Rule 2: Port must be EXPLICITLY marked IN
        if port in self.allowed:
            return True

        # Rule 3: Everything else (including OUT and unknown ports) is denied
        return False

    def get_allowed_ports(self):
        return list(self.allowed.keys())
