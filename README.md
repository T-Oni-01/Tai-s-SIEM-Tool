# Tai-s-SIEM-Tool
Hello, this is a custom-built Security Information and Event Management (SIEM) platform designed for real-time log collection, correlation, and intelligent alerting. I use it mainly to monitor the processes running in the background on my personal Laptop. It combines rule-based detection, machine learning anomaly detection, and correlation rules to give a modern take on SIEM functionality.

***Key Features***
Log Collection & Monitoring
Windows Event Logs & Firewall logs
Linux system logs (auth, SSH, etc.)
IDS/IPS alerts (simulated for testing)
Process monitoring & network traffic tracking

***Detection & Analysis***
Rule-based engine for known attack patterns
ML anomaly detector for adaptive, data-driven insights
Correlation engine to link multi-source events into higher-confidence alerts

***Alerting & Visualization***
Real-time alerts with customizable notification system
Web-based Flask dashboard with:

***Event timelines***
Top threats & geo distribution
System health metrics (EPS, uptime, memory/disk usage)
RESTful APIs for integration with external tools

***Data Handling***
Elasticsearch integration for log storage & querying
Rotating log files for efficient local logging
Config-driven intervals for collection & analysis

***Use Cases***
Detect brute-force login attempts across systems
Monitor network connections for suspicious activity
Correlate multiple low-level alerts into high-confidence threats
Provide visibility into insider threats, malware, and privilege misuse


<img width="959" height="449" alt="First Test Run of SIEM_Simulated" src="https://github.com/user-attachments/assets/f5bfb6e4-2531-477d-9cf9-5ea0596dde0d" />

<img width="957" height="539" alt="Running Code" src="https://github.com/user-attachments/assets/8c467df5-974f-4c8c-a029-665a15bb1368" />
