# SIEM Configuration
DEBUG = True
HOST = '0.0.0.0'
PORT = 5000

# Data Collection Settings
COLLECT_WINDOWS_LOGS = True
COLLECT_FIREWALL_LOGS = True
COLLECT_IDS_LOGS = True
COLLECT_SYSTEM_LOGS = True

# Collection Intervals (seconds)
WINDOWS_LOG_INTERVAL = 30
FIREWALL_LOG_INTERVAL = 30
IDS_LOG_INTERVAL = 30
SYSTEM_LOG_INTERVAL = 30
CORRELATION_INTERVAL = 60

# Elasticsearch Settings
USE_ELASTICSEARCH = False
ELASTICSEARCH_URL = 'http://localhost:9200'

# Alerting Settings
EMAIL_ALERTS = False  # Set to True and configure if you want email alerts
EMAIL_RECIPIENTS = ['admin@example.com']
SLACK_ALERTS = False  # Set to True and configure if you want Slack alerts
SLACK_WEBHOOK = ''

# ML Settings
ML_ENABLED = True
ML_TRAINING_INTERVAL = 3600  # 1 hour

# Log Retention
LOG_RETENTION_DAYS = 30