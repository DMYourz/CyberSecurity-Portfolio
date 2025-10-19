\# Lab Screenshots



This directory contains screenshots documenting the Splunk Security Operations Lab setup and functionality.



\## Screenshot Index



\### Data Collection and Analysis



\#### 01-data-sources.png.png

Overview of all data sources being collected and indexed. Shows 350,000+ events across multiple sourcetypes and demonstrates successful data collection from Kali Linux VM.



\#### 02-failed-logins.png.png

Failed authentication detection showing 76 failed login attempts identified. Demonstrates security monitoring capability.



\#### 03-sudo-activity.png.png

Privilege escalation monitoring, tracking sudo commands and privileged access. Shows administrative activity analysis.



\#### 04-timeline.png.png

Timeline visualization of security events. Pattern analysis over time demonstrating temporal analysis capabilities.



\#### 05-sample-logs.png.png

Raw log data examples showing authentication events and system activity. Displays actual security data being analyzed.



\### Infrastructure Configuration



\#### 06-forwarder-status.png.png

Splunk Universal Forwarder running status. Confirms forwarder is operational on Kali Linux VM and shows successful service deployment.



\#### 07-outputs-config.png.png

Forwarder output configuration showing connection to Splunk Enterprise indexer. Demonstrates proper data forwarding setup on port 9997.



\#### 08-inputs-config.png.png

Forwarder input configuration listing all monitored log files and directories. Shows data collection sources including /var/log/auth.log, syslog, and more.



\## Data Volume



| Metric | Value |

|--------|-------|

| Total Events Indexed | 350,000+ |

| Primary Source | linux\_journal (333,406 events) |

| Additional Sources | linux\_logs, apache\_access, apache\_error, linux\_boot |



\## Lab Components



| Component | Details |

|-----------|---------|

| Splunk Enterprise | Windows 11 VM |

| Universal Forwarder | Kali Linux VM |

| Network | Bridged adapter configuration |

| Data Flow | Kali → Port 9997 → Splunk Enterprise |



\## Skills Demonstrated



\*\*Technical Skills:\*\*

\- SIEM deployment and configuration

\- Data collection and forwarding setup

\- Security event analysis

\- SPL (Search Processing Language) queries

\- Timeline and pattern analysis



\*\*Security Operations:\*\*

\- Failed authentication monitoring

\- Privilege escalation tracking

\- Log analysis and correlation

\- Infrastructure monitoring



\*\*System Administration:\*\*

\- Linux system configuration

\- Network connectivity setup

\- Service deployment and management

\- Configuration file management



