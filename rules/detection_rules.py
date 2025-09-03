import re
from datetime import datetime


class RuleEngine:
    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self):
        return [
            {
                'id': 'R001',
                'name': 'Multiple Failed Logins',
                'description': 'Detect multiple failed login attempts from same source',
                'condition': self.check_failed_logins,
                'severity': 'high'
            },
            {
                'id': 'R002',
                'name': 'Port Scan Detection',
                'description': 'Detect multiple connection attempts to different ports',
                'condition': self.check_port_scan,
                'severity': 'medium'
            },
            {
                'id': 'R003',
                'name': 'Suspicious Process',
                'description': 'Detect execution of suspicious processes',
                'condition': self.check_suspicious_process,
                'severity': 'high'
            },
            {
                'id': 'R004',
                'name': 'Firewall Rule Change',
                'description': 'Detect changes to firewall rules',
                'condition': self.check_firewall_change,
                'severity': 'medium'
            },
            {
                'id': 'R005',
                'name': 'IDS Alert',
                'description': 'Detect IDS/IPS alerts',
                'condition': self.check_ids_alert,
                'severity': 'high'
            },
            {
                'id': 'R006',
                'name': 'Unknown Listening Port',
                'description': 'Detect unusual listening ports',
                'condition': self.check_listening_ports,
                'severity': 'medium'
            },
            {
                'id': 'R007',
                'name': 'Suspicious Network Connection',
                'description': 'Detect connections to known malicious IPs',
                'condition': self.check_malicious_ips,
                'severity': 'high'
            },
            {
                'id': 'R008',
                'name': 'Unusual Process Behavior',
                'description': 'Detect processes with suspicious characteristics',
                'condition': self.check_unusual_process_behavior,
                'severity': 'high'
            }
        ]

    def apply_rules(self, log):
        alerts = []
        for rule in self.rules:
            try:
                if rule['condition'](log):
                    alert = {
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'timestamp': datetime.now().isoformat(),
                        'description': rule['description']
                    }
                    alerts.append(alert)
            except Exception as e:
                print(f"Error applying rule {rule['id']}: {e}")
        return alerts

    def check_failed_logins(self, log):
        if log.get('source') == 'windows' and log.get('EventID') == 4625:
            return True
        elif 'authentication failure' in log.get('message', '').lower():
            return True
        return False

    def check_port_scan(self, log):
        if log.get('source') == 'firewall' and log.get('action') == 'DROP':
            dst_port = log.get('dst_port', 0)
            if dst_port > 1024 and dst_port < 10000:
                return True
        return False

    def check_suspicious_process(self, log):
        suspicious_processes = [
            'nc', 'netcat', 'ncat', 'wget', 'curl', 'powershell',
            'cmd', 'bash', 'ssh', 'telnet', 'ftp'
        ]

        if log.get('source') == 'windows' and log.get('EventID') == 4688:
            process_name = log.get('ProcessName', '').lower()
            return any(sp in process_name for sp in suspicious_processes)
        return False

    def check_firewall_change(self, log):
        if log.get('source') == 'windows' and log.get('EventID') in [4946, 4947]:
            return True
        return False

    def check_ids_alert(self, log):
        if log.get('source') == 'ids' and log.get('severity') == 'high':
            return True
        return False

    def check_listening_ports(self, log):
        if log.get('source') == 'network' and log.get('status') == 'LISTEN':
            port = log.get('local_address', ':').split(':')[-1]
            if port and int(port) > 1024 and int(port) not in [8000, 8080, 3000]:  # Common dev ports
                return True
        return False

    def check_malicious_ips(self, log):
        malicious_ips = [
            '185.220.101.', '193.218.118.', '45.133.1.', '91.92.109.',
            '95.214.24.', '80.94.92.'  # Example threat IP ranges
        ]

        remote_ip = log.get('remote_address', '').split(':')[0] if log.get('remote_address') else None
        if remote_ip:
            return any(remote_ip.startswith(ip_range) for ip_range in malicious_ips)
        return False

    def check_unusual_process_behavior(self, log):
        # Check for processes with no parent or unusual characteristics
        if log.get('source') == 'process':
            process_name = log.get('name', '').lower()
            cmdline = log.get('cmdline', '').lower()

            # Suspicious patterns
            suspicious_patterns = [
                'http://', 'https://',  # Downloading content
                'base64', 'encoded',  # Obfuscated commands
                'powershell -enc',  # Encoded PowerShell
                'certutil -urlcache',  # Certificate utility abuse
                'bitsadmin',  # Background Intelligent Transfer Service
            ]

            # Check for suspicious patterns in command line
            if any(pattern in cmdline for pattern in suspicious_patterns):
                return True

            # Check for processes running from unusual locations
            unusual_paths = [
                'temp\\', 'tmp\\', 'appdata\\', 'local\\temp\\',
                '/tmp/', '/var/tmp/', '/dev/shm/'
            ]

            if any(path in cmdline for path in unusual_paths):
                return True

        return False
