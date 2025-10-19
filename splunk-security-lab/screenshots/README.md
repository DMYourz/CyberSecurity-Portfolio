\# Lab Screenshots



This directory contains screenshots documenting the Splunk Security Operations Lab setup and functionality.



---



\## Screenshot Index



\### Data Collection and Analysis



\*\*01-data-sources.png.png\*\*

\- Overview of all data sources being collected and indexed

\- Shows 350,000+ events across multiple sourcetypes

\- Demonstrates successful data collection from Kali Linux VM



\*\*02-failed-logins.png.png\*\*

\- Failed authentication detection

\- 76 failed login attempts identified

\- Demonstrates security monitoring capability



\*\*03-sudo-activity.png.png\*\*

\- Privilege escalation monitoring

\- Tracking sudo commands and privileged access

\- Shows administrative activity analysis



\*\*04-timeline.png.png\*\*

\- Timeline visualization of security events

\- Pattern analysis over time

\- Demonstrates temporal analysis capabilities



\*\*05-sample-logs.png.png\*\*

\- Raw log data examples

\- Authentication events and system activity

\- Shows actual security data being analyzed



---



\### Infrastructure Configuration



\*\*06-forwarder-status.png.png\*\*

\- Splunk Universal Forwarder running status

\- Confirms forwarder is operational on Kali Linux VM

\- Shows successful service deployment



\*\*07-outputs-config.png.png\*\*

\- Forwarder output configuration

\- Shows connection to Splunk Enterprise indexer

\- Demonstrates proper data forwarding setup (port 9997)



\*\*08-inputs-config.png.png\*\*

\- Forwarder input configuration

\- Lists all monitored log files and directories

\- Shows data collection sources (/var/log/auth.log, syslog, etc.)



---



\## Screenshot Details



\### Data Volume

\- \*\*Total Events Indexed:\*\* 350,000+

\- \*\*Primary Source:\*\* linux\_journal (333,406 events)

\- \*\*Additional Sources:\*\* linux\_logs, apache\_access, apache\_error, linux\_boot



\### Lab Components

\- \*\*Splunk Enterprise:\*\* Windows 11 VM

\- \*\*Universal Forwarder:\*\* Kali Linux VM

\- \*\*Network:\*\* Bridged adapter configuration

\- \*\*Data Flow:\*\* Kali → Port 9997 → Splunk Enterprise



---



\## How These Screenshots Demonstrate Skills



\### Technical Skills

\- ✅ SIEM deployment and configuration

\- ✅ Data collection and forwarding setup

\- ✅ Security event analysis

\- ✅ SPL (Search Processing Language) queries

\- ✅ Timeline and pattern analysis



\### Security Operations

\- ✅ Failed authentication monitoring

\- ✅ Privilege escalation tracking

\- ✅ Log analysis and correlation

\- ✅ Infrastructure monitoring



\### System Administration

\- ✅ Linux system configuration

\- ✅ Network connectivity setup

\- ✅ Service deployment and management

\- ✅ Configuration file management



---



\## Screenshot Specifications



\- \*\*Format:\*\* PNG

\- \*\*Source:\*\* VirtualBox VMs (Windows 11 + Kali Linux)

\- \*\*Tools Used:\*\* Windows Snipping Tool, Linux screenshot utilities

\- \*\*Resolution:\*\* High-resolution for clarity



