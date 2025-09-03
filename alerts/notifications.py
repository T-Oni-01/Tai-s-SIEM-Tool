import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import json


class AlertNotifier:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        # This would load from a config file
        return {
            'email': {
                'enabled': False,  # Disabled by default for safety
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'username': 'alerts@example.com',
                'password': 'password',
                'from_addr': 'alerts@example.com',
                'to_addrs': ['admin@example.com']
            },
            'slack': {
                'enabled': False,  # Disabled by default for safety
                'webhook_url': ''
            },
            'console': {
                'enabled': True  # Always log to console
            }
        }

    def send_alert(self, alert, log):
        if self.config['email']['enabled']:
            self.send_email_alert(alert, log)

        if self.config['slack']['enabled']:
            self.send_slack_alert(alert, log)

        if self.config['console']['enabled']:
            self.send_console_alert(alert, log)

    def send_email_alert(self, alert, log):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['from_addr']
            msg['To'] = ', '.join(self.config['email']['to_addrs'])
            msg[
                'Subject'] = f"SIEM Alert: {alert.get('rule_name', 'Unknown')} - {alert.get('severity', 'unknown').upper()}"

            body = f"""
            SIEM Alert Notification

            Rule: {alert.get('rule_name', 'Unknown')}
            Severity: {alert.get('severity', 'unknown')}
            Timestamp: {alert.get('timestamp', 'Unknown')}
            Description: {alert.get('description', 'No description')}

            Log Details:
            {json.dumps(log, indent=2)}
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], self.config['email']['password'])
            server.send_message(msg)
            server.quit()

        except Exception as e:
            print(f"Failed to send email alert: {e}")

    def send_slack_alert(self, alert, log):
        if not self.config['slack']['webhook_url']:
            return

        try:
            message = {
                "text": f"SIEM Alert: {alert.get('rule_name', 'Unknown')}",
                "attachments": [
                    {
                        "color": "danger" if alert.get('severity') == 'high' else "warning",
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.get('severity', 'unknown'),
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": alert.get('timestamp', 'Unknown'),
                                "short": True
                            },
                            {
                                "title": "Description",
                                "value": alert.get('description', 'No description')
                            }
                        ]
                    }
                ]
            }

            requests.post(self.config['slack']['webhook_url'],
                          json=message,
                          headers={'Content-Type': 'application/json'})

        except Exception as e:
            print(f"Failed to send Slack alert: {e}")

    def send_console_alert(self, alert, log):
        print(f"ALERT: {alert.get('rule_name', 'Unknown')} - {alert.get('severity', 'unknown')}")
        print(f"Time: {alert.get('timestamp', 'Unknown')}")
        print(f"Description: {alert.get('description', 'No description')}")
        print(f"Log: {json.dumps(log, indent=2)}")
        print("-" * 50)