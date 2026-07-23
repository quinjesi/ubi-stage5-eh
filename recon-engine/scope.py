import csv
from pathlib import Path

class Scope:
    def __init__(self, csv_path):
        self.allowed = {}
        self.denied = {}
        self._load(csv_path)

    def _load(self, csv_path):
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                asset = row['asset'].strip()
                scope_flag = row['scope'].strip()

                if '/' in asset:
                    continue

                if ':' in asset:
                    host, port_str = asset.split(':')
                    port = int(port_str)

                    if host in ('127.0.0.1', 'localhost'):
                        if scope_flag == 'IN':
                            self.allowed[port] = True
                        elif scope_flag == 'OUT':
                            self.denied[port] = True

    def is_allowed(self, host, port):
        if host not in ('127.0.0.1', 'localhost'):
            return False

        if port in self.denied:
            return False

        return True

    def get_allowed_ports(self):
        return list(self.allowed.keys())
