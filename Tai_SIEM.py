from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
from elasticsearch import Elasticsearch
import logging
from logging.handlers import RotatingFileHandler
import numpy as np
import psutil

# Import custom modules
from rules.detection_rules import RuleEngine
from rules.correlation_rules import CorrelationEngine
from ml.anomaly_detector import AnomalyDetector
from alerts.notifications import AlertNotifier

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Initialize components
es = Elasticsearch([app.config['ELASTICSEARCH_URL']]) if app.config['USE_ELASTICSEARCH'] else None
rule_engine = RuleEngine()
correlation_engine = CorrelationEngine()
anomaly_detector = AnomalyDetector()
alert_notifier = AlertNotifier()

# Global variables for dashboard data
dashboard_data = {
    'alerts': [],
    'stats': {},
    'events': []
}


class SIEMCore:
    def __init__(self):
        self.loggers = {}
        self.setup_logging()
        self.running = False
        self.start_time = datetime.now()

    def setup_logging(self):
        handler = RotatingFileHandler('siem.log', maxBytes=10000000, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger = logging.getLogger('SIEMCore')
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def start_collectors(self):
        """Start all log collectors in separate threads"""
        self.running = True

        # Real collectors
        t = threading.Thread(target=self.collect_windows_logs)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.collect_firewall_logs)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.monitor_network_traffic)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.monitor_processes)
        t.daemon = True
        t.start()

        # Start correlation engine
        t = threading.Thread(target=self.run_correlation_engine)
        t.daemon = True
        t.start()

        self.logger.info("All collectors started")

    def collect_windows_logs(self):
        """Collect real Windows Event Logs"""
        while self.running:
            try:
                # Method 1: Using PowerShell commands (simple approach)
                import subprocess

                # Get security events from the last 5 minutes
                ps_command = [
                    "powershell",
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddMinutes(-5)} | "
                    "Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json"
                ]

                result = subprocess.run(ps_command, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    events = json.loads(result.stdout)
                    for event in events:
                        log_entry = {
                            'EventID': event['Id'],
                            'Source': event['ProviderName'],
                            'Message': event['Message'],
                            'TimeCreated': event['TimeCreated'],
                            'raw_event': event
                        }
                        self.process_log(log_entry, 'windows')

                time.sleep(app.config['WINDOWS_LOG_INTERVAL'])

            except Exception as e:
                self.logger.error(f"Error collecting Windows logs: {e}")
                time.sleep(60)  # Wait longer on error

    def collect_firewall_logs(self):
        """Collect real Windows Firewall logs"""
        while self.running:
            try:
                import subprocess

                # Read Windows Firewall logs
                log_path = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
                ps_command = [
                    "powershell",
                    f"Get-Content '{log_path}' -Tail 20 | ConvertFrom-Csv -Delimiter ' ' -Header "
                    "'Date', 'Time', 'Action', 'Protocol', 'Src-IP', 'Dst-IP', 'Src-Port', 'Dst-Port', 'Size', 'TCPFlags', 'TCPSyn', 'TCPAck', 'TCPWin', 'ICMPType', 'ICMPCode', 'Info', 'Path'"
                ]

                result = subprocess.run(ps_command, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            fields = line.split(' ')
                            if len(fields) >= 8:
                                log_entry = {
                                    'action': fields[2],
                                    'protocol': fields[3],
                                    'src_ip': fields[4],
                                    'dst_ip': fields[5],
                                    'src_port': fields[6],
                                    'dst_port': fields[7],
                                    'timestamp': f"{fields[0]} {fields[1]}"
                                }
                                self.process_log(log_entry, 'firewall')

                time.sleep(app.config['FIREWALL_LOG_INTERVAL'])

            except Exception as e:
                self.logger.error(f"Error collecting firewall logs: {e}")
                time.sleep(60)


    def collect_ids_logs(self):
        """Collect IDS/IPS alerts"""
        while self.running:
            try:
                # Simulate IDS logs
                simulated_logs = [
                    {
                        'signature': 'ET WEB_SERVER Possible CVE-2021-44228 Exploit M1',
                        'category': 'Attempted Administrator Privilege Gain',
                        'src_ip': '203.0.113.5',
                        'dst_ip': '192.168.1.100',
                        'severity': 'high'
                    },
                    {
                        'signature': 'ET POLICY curl User Agent',
                        'category': 'Potential Corporate Privacy Violation',
                        'src_ip': '192.168.1.50',
                        'dst_ip': 'external.com',
                        'severity': 'medium'
                    }
                ]

                for log in simulated_logs:
                    self.process_log(log, 'ids')

                time.sleep(app.config['IDS_LOG_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Error collecting IDS logs: {e}")

    def collect_system_logs(self):
        """Collect real system logs (Linux)"""
        while self.running:
            try:
                # Auth logs (for SSH, login attempts)
                auth_log_path = "/var/log/auth.log"

                try:
                    with open(auth_log_path, 'r') as f:
                        # Read last 100 lines
                        lines = f.readlines()[-100:]
                        for line in lines:
                            if 'Failed password' in line or 'Accepted password' in line:
                                log_entry = {
                                    'message': line.strip(),
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.process_log(log_entry, 'system')
                except FileNotFoundError:
                    # Try different log paths for different distros
                    pass

                time.sleep(app.config['SYSTEM_LOG_INTERVAL'])

            except Exception as e:
                self.logger.error(f"Error collecting system logs: {e}")
                time.sleep(60)

    def monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            try:
                import psutil

                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                    try:
                        log_entry = {
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'username': proc.info['username'],
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.process_log(log_entry, 'process')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                time.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Error monitoring processes: {e}")
                time.sleep(60)

    def monitor_network_traffic(self):
        """Monitor network traffic in real-time"""
        while self.running:
            try:
                import psutil
                import socket

                # Get current network connections
                connections = psutil.net_connections()

                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        log_entry = {
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'pid': conn.pid,
                            'status': conn.status,
                            'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                        }
                        self.process_log(log_entry, 'network')

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                self.logger.error(f"Error monitoring network: {e}")
                time.sleep(30)


    def process_log(self, log, source):
        """Process a single log entry"""
        # Add metadata
        log['@timestamp'] = datetime.now().isoformat()
        log['source'] = source

        # Rule-based detection
        alerts = rule_engine.apply_rules(log)

        # Anomaly detection
        anomalies = anomaly_detector.detect_anomalies(log)

        # Store in Elasticsearch if enabled
        if es:
            try:
                es.index(index='siem-logs', body=log)
            except Exception as e:
                self.logger.error(f"Error storing log in Elasticsearch: {e}")

        # Add to dashboard data
        if alerts or anomalies:
            event_data = {
                'timestamp': log['@timestamp'],
                'source': source,
                'alerts': alerts,
                'anomalies': anomalies,
                'raw_log': log
            }

            # Update dashboard data (keep only last 1000 events)
            dashboard_data['events'].append(event_data)
            if len(dashboard_data['events']) > 1000:
                dashboard_data['events'] = dashboard_data['events'][-1000:]

            # Send alerts if any
            if alerts:
                for alert in alerts:
                    alert_notifier.send_alert(alert, log)

    def run_correlation_engine(self):
        """Run correlation rules on collected events"""
        while self.running:
            try:
                if dashboard_data['events']:
                    correlated_alerts = correlation_engine.correlate_events(dashboard_data['events'])
                    for alert in correlated_alerts:
                        alert_notifier.send_alert(alert, {'correlated': True})
            except Exception as e:
                self.logger.error(f"Error in correlation engine: {e}")
            time.sleep(app.config['CORRELATION_INTERVAL'])


# Initialize SIEM core
siem_core = SIEMCore()


# Flask routes
@app.route('/')
def dashboard():
    # Get the last 20 events for display
    recent_events = dashboard_data['events'][-20:] if dashboard_data['events'] else []

    # Calculate basic statistics
    stats = {
        'total_events': len(dashboard_data['events']),
        'alerts_last_hour': len([e for e in dashboard_data['events']
                                 if e.get('alerts') and
                                 datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) >
                                 datetime.now() - timedelta(hours=1)]),
        'alerts_today': len([e for e in dashboard_data['events']
                             if e.get('alerts') and
                             datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')).date() ==
                             datetime.now().date()]),
        'unique_sources': len(set(e['source'] for e in dashboard_data['events'] if 'source' in e)),
        'connected_sources': f"{len(set(e['source'] for e in dashboard_data['events'] if 'source' in e))}/5",
        'system_uptime': str(datetime.now() - siem_core.start_time).split('.')[0] if hasattr(siem_core,
                                                                                             'start_time') else "0:00:00"
    }

    return render_template('dashboard.html',
                           events=recent_events,
                           stats=stats,
                           sources=list(set(e['source'] for e in dashboard_data['events'] if 'source' in e)))


@app.route('/api/events')
def get_events():
    limit = int(request.args.get('limit', 100))
    source = request.args.get('source', None)

    events = dashboard_data['events']
    if source:
        events = [e for e in events if e['source'] == source]

    return jsonify(events[-limit:])


@app.route('/api/alerts')
def get_alerts():
    alerts = []
    for event in dashboard_data['events']:
        if event['alerts']:
            for alert in event['alerts']:
                alerts.append({
                    'timestamp': event['timestamp'],
                    'source': event['source'],
                    'alert': alert,
                    'raw_log': event['raw_log']
                })
    return jsonify(alerts)


@app.route('/api/stats')
def get_stats():
    # Calculate various statistics
    now = datetime.now()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    recent_events = [e for e in dashboard_data['events']
                     if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > hour_ago]

    stats = {
        'total_events': len(dashboard_data['events']),
        'alerts_last_hour': len([e for e in recent_events if e['alerts']]),
        'alerts_today': len([e for e in dashboard_data['events'] if e.get('alerts') and datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')).date() == datetime.now().date()]),
        'unique_sources': len(set(e['source'] for e in dashboard_data['events'] if 'source' in e)),
        'top_sources': pd.Series([e['source'] for e in recent_events]).value_counts().to_dict(),
        'alert_types': {}
    }

    # Count alert types
    for event in recent_events:
        if event['alerts']:
            for alert in event['alerts']:
                alert_type = alert.get('rule_name', 'unknown')
                stats['alert_types'][alert_type] = stats['alert_types'].get(alert_type, 0) + 1

    return jsonify(stats)


@app.route('/start')
def start_siem():
    siem_core.start_collectors()
    return jsonify({'status': 'started'})


@app.route('/stop')
def stop_siem():
    siem_core.running = False
    return jsonify({'status': 'stopped'})

@app.route('/api/system-status')
def get_system_status():
    """Get current system status"""
    try:
        # Get disk usage
        disk_usage = psutil.disk_usage('/').percent

        # Get memory usage
        memory_usage = psutil.virtual_memory().percent

        # Count active collector threads
        active_collectors = sum(1 for thread in threading.enumerate()
                                if 'collect' in thread.name.lower() or 'monitor' in thread.name.lower())

        # Calculate events per second (simplified)
        if dashboard_data['events']:
            # Count events from last 10 seconds
            recent_events = [e for e in dashboard_data['events']
                             if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) >
                             datetime.now() - timedelta(seconds=10)]
            eps = len(recent_events) / 10
        else:
            eps = 0

        status = {
            'disk_usage': round(disk_usage, 1),
            'memory_usage': round(memory_usage, 1),
            'connected_sources': f"{active_collectors}/5",
            'system_uptime': str(datetime.now() - siem_core.start_time).split('.')[0],
            'eps': round(eps, 1),
            'process_time': 45  # Fixed value for demo
        }
        return jsonify(status)
    except Exception as e:
        print(f"Error getting system status: {e}")
        return jsonify({
            'disk_usage': 0,
            'memory_usage': 0,
            'connected_sources': "0/0",
            'system_uptime': "0:00:00",
            'eps': 0,
            'process_time': 0
        })


@app.route('/api/top-threats')
def get_top_threats():
    """Get top threats from alerts"""
    try:
        # Extract top threats from alerts
        threat_counts = {}
        for event in dashboard_data['events']:
            if event.get('alerts'):
                for alert in event['alerts']:
                    rule_name = alert.get('rule_name', 'Unknown')
                    threat_counts[rule_name] = threat_counts.get(rule_name, 0) + 1

        # Convert to list of objects
        top_threats = [{'name': name, 'count': count} for name, count in threat_counts.items()]
        top_threats.sort(key=lambda x: x['count'], reverse=True)

        return jsonify(top_threats[:5])  # Return top 5
    except Exception as e:
        print(f"Error getting top threats: {e}")
        return jsonify([])


@app.route('/api/geo-data')
def get_geo_data():
    """Get geographic distribution data"""
    # This is a simplified version - in a real implementation, you'd extract IPs and geolocate them
    try:
        # Count events by source as a proxy for geographic distribution
        source_counts = {}
        for event in dashboard_data['events']:
            source = event.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1

        # Convert to format expected by the chart
        countries = list(source_counts.keys())
        counts = list(source_counts.values())

        # Find top country
        top_country = max(source_counts.items(), key=lambda x: x[1]) if source_counts else ('None', 0)

        return jsonify({
            'countries': countries,
            'counts': counts,
            'top_country': {'name': top_country[0], 'count': top_country[1]},
            'unique_countries': len(countries)
        })
    except Exception as e:
        print(f"Error getting geo data: {e}")
        return jsonify({
            'countries': [],
            'counts': [],
            'top_country': {'name': 'None', 'count': 0},
            'unique_countries': 0
        })


@app.route('/api/timeline-data')
def get_timeline_data():
    """Get timeline data for charts"""
    try:
        # Group events by hour
        events_by_hour = {}
        alerts_by_hour = {}

        for event in dashboard_data['events']:
            # Extract hour from timestamp
            try:
                event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                hour_key = event_time.strftime('%Y-%m-%d %H:00')

                # Count events
                events_by_hour[hour_key] = events_by_hour.get(hour_key, 0) + 1

                # Count alerts
                if event.get('alerts'):
                    alerts_by_hour[hour_key] = alerts_by_hour.get(hour_key, 0) + len(event['alerts'])
            except:
                continue

        # Convert to arrays for chart
        timeline_events = [{'x': hour, 'y': count} for hour, count in events_by_hour.items()]
        timeline_alerts = [{'x': hour, 'y': count} for hour, count in alerts_by_hour.items()]

        return jsonify({
            'events': timeline_events,
            'alerts': timeline_alerts
        })
    except Exception as e:
        print(f"Error getting timeline data: {e}")
        return jsonify({
            'events': [],
            'alerts': []
        })


# Add these debug routes to your Tai_SIEM.py

@app.route('/debug/events')
def debug_events():
    """Debug endpoint to check events data"""
    return jsonify({
        'total_events': len(dashboard_data['events']),
        'events': dashboard_data['events'][-5:] if dashboard_data['events'] else [],
        'event_sources': list(set(e['source'] for e in dashboard_data['events'] if 'source' in e))
    })


@app.route('/debug/system')
def debug_system():
    """Debug endpoint to check system data"""
    return jsonify({
        'siem_running': siem_core.running,
        'collector_threads': [t.name for t in threading.enumerate() if 'collect' in t.name or 'monitor' in t.name],
        'dashboard_data_keys': list(dashboard_data.keys())
    })


@app.route('/debug/test-alert')
def test_alert():
    """Create a test alert to verify the system is working"""
    test_log = {
        'source': 'test',
        'message': 'This is a test alert',
        'timestamp': datetime.now().isoformat(),
        'EventID': 9999
    }

    # Process the test log
    siem_core.process_log(test_log, 'test')

    return jsonify({
        'status': 'Test alert created',
        'total_events': len(dashboard_data['events'])
    })

@app.route('/api/status')
def get_status_alias():
    return get_system_status()

if __name__ == '__main__':
    siem_core.start_collectors()
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])