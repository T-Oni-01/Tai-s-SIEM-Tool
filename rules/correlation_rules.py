from datetime import datetime, timedelta


class CorrelationEngine:
    def __init__(self):
        self.correlation_rules = self.load_rules()
        self.event_buffer = []

    def load_rules(self):
        return [
            {
                'id': 'C001',
                'name': 'Multiple Failed Logins followed by Success',
                'description': 'Detect brute force attack pattern',
                'condition': self.check_brute_force
            },
            {
                'id': 'C002',
                'name': 'Port Scan followed by Exploit Attempt',
                'description': 'Detect reconnaissance followed by attack',
                'condition': self.check_scan_and_exploit
            }
        ]

    def correlate_events(self, events):
        correlated_alerts = []
        self.event_buffer.extend(events)

        # Keep only events from last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        self.event_buffer = [e for e in self.event_buffer
                             if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > one_hour_ago]

        for rule in self.correlation_rules:
            try:
                alert = rule['condition'](self.event_buffer)
                if alert:
                    correlated_alerts.append(alert)
            except Exception as e:
                print(f"Error applying correlation rule {rule['id']}: {e}")

        return correlated_alerts

    def check_brute_force(self, events):
        # Look for multiple failed logins followed by a successful login
        failed_logins = []
        success_logins = []

        for event in events:
            if event.get('alerts'):
                for alert in event['alerts']:
                    if alert.get('rule_id') == 'R001':  # Multiple Failed Logins
                        failed_logins.append(event)

            # Check for successful login
            if (event.get('source') == 'windows' and event.get('EventID') == 4624) or \
                    (event.get('source') == 'system' and 'Accepted password' in event.get('raw_log', {}).get('message',
                                                                                                             '')):
                success_logins.append(event)

        if len(failed_logins) >= 3 and success_logins:
            # Check if success login happened after failed logins
            last_failed = max(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in failed_logins)
            first_success = min(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in success_logins)

            if first_success > last_failed and (first_success - last_failed) < timedelta(minutes=10):
                return {
                    'rule_id': 'C001',
                    'name': 'Brute Force Attack Detected',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Multiple failed logins followed by successful login from same source'
                }

        return None

    def check_scan_and_exploit(self, events):
        # Look for port scanning followed by exploit attempts
        port_scans = []
        exploit_attempts = []

        for event in events:
            if event.get('alerts'):
                for alert in event['alerts']:
                    if alert.get('rule_id') == 'R002':  # Port Scan Detection
                        port_scans.append(event)
                    elif alert.get('rule_id') == 'R005':  # IDS Alert
                        exploit_attempts.append(event)

        if port_scans and exploit_attempts:
            # Check if exploit attempt happened after port scan
            last_scan = max(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in port_scans)
            first_exploit = min(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in exploit_attempts)

            if first_exploit > last_scan and (first_exploit - last_scan) < timedelta(minutes=30):
                return {
                    'rule_id': 'C002',
                    'name': 'Scan and Exploit Attempt Detected',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Port scanning activity followed by exploit attempts'
                }

        return None