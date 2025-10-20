# Splunk SPL Search Reference

A collection of useful Splunk Search Processing Language (SPL) queries for security operations, threat hunting, and incident investigation.

---

## Table of Contents

1. [Authentication & Access](#authentication--access)
2. [Privilege Escalation](#privilege-escalation)
3. [Malware & Threats](#malware--threats)
4. [Network Analysis](#network-analysis)
5. [Web Server Security](#web-server-security)
6. [Cloud Security (AWS)](#cloud-security-aws)
7. [System Monitoring](#system-monitoring)
8. [Correlation Searches](#correlation-searches)
9. [Dashboard Queries](#dashboard-queries)
10. [Threat Hunting](#threat-hunting)

---

## Authentication & Access

### Failed Login Attempts
```spl
index=main sourcetype=linux_journal "Failed password"
| table _time, user, src_ip, _raw
| sort -_time
```

### Failed Login Count by User
```spl
index=main sourcetype=linux_journal "Failed password"
| rex field=_raw "invalid user (?<username>\w+)"
| stats count by username
| sort -count
```

### Brute Force Detection (5+ failures)
```spl
index=main sourcetype=linux_journal "Failed password"
| rex field=_raw "invalid user (?<username>\w+) from (?<src_ip>[\w\.:]+)"
| stats count by username, src_ip
| where count > 5
| sort -count
```

### Successful Logins After Failed Attempts
```spl
index=main sourcetype=linux_journal (user=* OR username=*)
| transaction user maxspan=10m
| search "Failed password" AND "Accepted password"
| table _time, user, src_ip
```

### Login Timeline
```spl
index=main sourcetype=linux_journal (failed OR accepted) password
| timechart count by status
```

### SSH Login Sources
```spl
index=main sourcetype=linux_journal "Accepted password"
| rex field=_raw "from (?<src_ip>[\d\.]+)"
| stats count by src_ip
| sort -count
```

---

## Privilege Escalation

### All Sudo Commands
```spl
index=main sourcetype=linux_journal sudo
| rex field=_raw "COMMAND=(?<command>.*)"
| table _time, user, command
| sort -_time
```

### Sudo Command Frequency
```spl
index=main sourcetype=linux_journal sudo
| rex field=_raw "COMMAND=(?<command>.*)"
| stats count by command
| sort -count
```

### Unauthorized Sudo Attempts
```spl
index=main sourcetype=linux_journal sudo (failed OR denied OR "not in sudoers")
| table _time, user, _raw
```

### Root Access Events
```spl
index=main sourcetype=linux_journal (su OR "root shell" OR "UID=0")
| table _time, user, _raw
```

### Sensitive File Access
```spl
index=main sourcetype=linux_journal (/etc/shadow OR /etc/passwd OR /root)
| table _time, user, command, _raw
```

---

## Malware & Threats

### Ransomware Indicators
```spl
index=* (ransomware OR cerber OR locky OR wannacry OR cryptolocker OR encrypted OR decrypt OR ransom OR bitcoin)
| table _time, host, sourcetype, _raw
| sort -_time
```

### Cerber C2 Communication
```spl
index=botsv3 cerber.brewertalk.com
| table _time, src_ip, query, answer, host
| sort _time
```

### Malware File Extensions
```spl
index=* (*.cerber OR *.encrypted OR *.locked OR *.crypto)
| stats count by filename
```

### Windows Defender Status
```spl
index=* "Windows Defender" (stopped OR disabled OR "not running")
| table _time, host, State, Status, _raw
```

### Suspicious Process Execution
```spl
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search (powershell OR cmd.exe OR wscript OR cscript)
| table _time, Computer, Image, CommandLine, ParentImage
```

### Known Malicious Domains
```spl
index=* sourcetype=stream:dns
| search (malware OR botnet OR c2 OR command-and-control)
| stats count by query, answer
| sort -count
```

---

## Network Analysis

### Top Destination IPs
```spl
index=* sourcetype=stream:*
| stats count by dest_ip
| sort -count
| head 20
```

### Unusual Port Activity
```spl
index=* sourcetype=stream:*
| stats count by dest_port
| where dest_port > 1024 AND dest_port < 65535
| sort -count
```

### External Connections
```spl
index=* sourcetype=stream:*
| search NOT (dest_ip=10.* OR dest_ip=172.16.* OR dest_ip=192.168.*)
| stats count by src_ip, dest_ip, dest_port
| sort -count
```

### DNS Query Analysis
```spl
index=* sourcetype=stream:dns
| stats count by query
| sort -count
| head 50
```

### Failed DNS Queries (NXDOMAIN)
```spl
index=* sourcetype=stream:dns NXDOMAIN
| stats count by query
| sort -count
```

### Large Data Transfers
```spl
index=* sourcetype=stream:http
| where bytes_out > 10000000
| table _time, src_ip, dest_ip, uri, bytes_out
| sort -bytes_out
```

---

## Web Server Security

### HTTP Status Codes
```spl
index=main sourcetype=apache_access
| rex field=_raw "\s(?<status>\d{3})\s"
| stats count by status
| sort -count
```

### Top Accessed URLs
```spl
index=main sourcetype=apache_access
| rex field=_raw "\"(?<method>\w+)\s(?<uri>[^\s]+)"
| stats count by uri
| sort -count
| head 20
```

### Failed Requests (4xx, 5xx)
```spl
index=main sourcetype=apache_access
| rex field=_raw "\s(?<status>[45]\d{2})\s"
| stats count by status, uri
| sort -count
```

### Potential Web Attacks
```spl
index=main sourcetype=apache_access ("../" OR "etc/passwd" OR "admin" OR "sql" OR "script" OR "exec" OR "union" OR "select")
| table _time, clientip, uri, status
```

### SQL Injection Attempts
```spl
index=main sourcetype=apache_access (union OR select OR insert OR update OR delete OR drop OR "1=1" OR "' OR")
| table _time, clientip, uri
```

### Directory Traversal Attempts
```spl
index=main sourcetype=apache_access ("../" OR "..\\" OR "/etc/" OR "/root/")
| table _time, clientip, uri
```

### Top Client IPs
```spl
index=main sourcetype=apache_access
| rex field=_raw "^(?<clientip>[\d\.]+)"
| stats count by clientip
| sort -count
| head 20
```

---

## Cloud Security (AWS)

### AWS GuardDuty Alerts
```spl
index=botsv3 sourcetype=aws:cloudwatch:guardduty
| table _time, severity, type, _raw
| sort -_time
```

### VPC Flow Log Analysis
```spl
index=botsv3 sourcetype=aws:cloudwatchlogs:vpcflow
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<src_ip>[\d\.]+)\s+(?<dest_ip>[\d\.]+)\s+\d+\s+(?<dest_port>\d+)"
| stats count by dest_ip, dest_port
| sort -count
```

### AWS CloudWatch Errors
```spl
index=botsv3 sourcetype=aws:cloudwatchlogs (error OR ERROR OR failed OR FAILED)
| table _time, _raw
| sort -_time
```

### RDS Database Activity
```spl
index=botsv3 sourcetype=aws:rds:audit
| stats count by command, user
| sort -count
```

### Lambda Function Errors
```spl
index=botsv3 sourcetype=aws:cloudwatchlogs (lambda OR Lambda) (error OR ERROR)
| table _time, _raw
```

### Unusual AWS API Calls
```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats count by eventName, userIdentity.userName
| sort -count
```

---

## System Monitoring

### System Errors
```spl
index=main (error OR ERROR OR critical OR CRITICAL OR fatal OR FATAL)
| stats count by sourcetype, host
| sort -count
```

### Service Status Changes
```spl
index=main (started OR stopped OR failed OR restarted) service
| table _time, host, service, status, _raw
```

### Disk Space Monitoring
```spl
index=main sourcetype=syslog (disk OR filesystem OR "no space")
| table _time, host, _raw
```

### Package Installation
```spl
index=main sourcetype=linux_packages
| rex field=_raw "(?<action>install|remove|upgrade)\s+(?<package>\S+)"
| stats count by action, package
| sort -count
```

### System Reboots
```spl
index=main (reboot OR shutdown OR "system boot")
| table _time, host, _raw
```

---

## Correlation Searches

### Failed Login Followed by Successful Login
```spl
index=main sourcetype=linux_journal
| transaction src_ip maxspan=10m
| search "Failed password" AND "Accepted password"
| table _time, src_ip, user
```

### Privilege Escalation After Login
```spl
index=main sourcetype=linux_journal
| transaction user maxspan=30m
| search "Accepted password" AND sudo
| table _time, user, src_ip
```

### Security Service Disruption
```spl
index=* ("Windows Defender" OR firewall OR antivirus) (stopped OR disabled OR "not running")
| table _time, host, service, status
```

### Suspicious Activity Timeline
```spl
index=main (failed OR sudo OR nmap OR scan OR exploit OR attack)
| timechart count by sourcetype
```

### Multi-Source Threat Correlation
```spl
index=* earliest=-1h
| search (failed OR malware OR attack OR suspicious OR denied)
| stats count by _time, host, sourcetype
| sort _time
```

---

## Dashboard Queries

### Security Operations Dashboard

**Panel 1: Failed Logins Over Time**
```spl
index=main sourcetype=linux_journal "Failed password"
| timechart count
```

**Panel 2: Top Targeted Usernames**
```spl
index=main sourcetype=linux_journal "Failed password"
| rex field=_raw "invalid user (?<username>\w+)"
| top limit=10 username
```

**Panel 3: Sudo Command Activity**
```spl
index=main sourcetype=linux_journal sudo
| rex field=_raw "COMMAND=(?<command>.*)"
| top limit=10 command
```

**Panel 4: Web Traffic by Status**
```spl
index=main sourcetype=apache_access
| rex field=_raw "\s(?<status>\d{3})\s"
| stats count by status
```

**Panel 5: Recent Security Events**
```spl
index=main (failed OR error OR denied OR attack)
| head 20
| table _time, host, sourcetype, _raw
```

---

## Threat Hunting

### Anomalous Login Times
```spl
index=main sourcetype=linux_journal "Accepted password"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, user, src_ip
```

### Rare Commands Executed
```spl
index=main sourcetype=linux_journal sudo
| rex field=_raw "COMMAND=(?<command>.*)"
| rare command
```

### New User Accounts
```spl
index=main (useradd OR "new user" OR "user created")
| table _time, user, _raw
```

### Unusual Network Destinations
```spl
index=* sourcetype=stream:*
| stats count by dest_ip
| where count < 5
| sort count
```

### Suspicious File Downloads
```spl
index=main sourcetype=stream:http (.exe OR .zip OR .rar OR .bat OR .ps1)
| table _time, src_ip, uri, method
```

### Lateral Movement Detection
```spl
index=* (psexec OR wmi OR "remote desktop" OR ssh)
| stats dc(dest_ip) as unique_targets by src_ip
| where unique_targets > 5
```

### Data Exfiltration Detection
```spl
index=* sourcetype=stream:http method=POST
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 100000000
| sort -total_bytes
```

---

## Alert Queries

### Brute Force Alert
```spl
index=main sourcetype=linux_journal "Failed password"
| stats count by src_ip
| where count > 5
```
**Trigger:** Run every 5 minutes, alert if results > 0

### Privilege Escalation Alert
```spl
index=main sourcetype=linux_journal sudo (root OR shadow OR passwd)
| table _time, user, command
```
**Trigger:** Real-time, alert on any result

### Malware C2 Alert
```spl
index=* (cerber OR malware OR botnet OR c2)
| table _time, host, src_ip, dest_ip
```
**Trigger:** Real-time, alert on any result

### Security Service Disruption Alert
```spl
index=* ("Windows Defender" OR firewall OR antivirus) (stopped OR disabled)
| table _time, host, service
```
**Trigger:** Real-time, alert on any result

### Unusual Port Activity Alert
```spl
index=* sourcetype=stream:*
| where dest_port IN (4444, 5555, 6666, 7777, 8888, 31337)
| table _time, src_ip, dest_ip, dest_port
```
**Trigger:** Run every 5 minutes, alert if results > 0

---

## Tips & Best Practices

### Performance Optimization
1. **Use time ranges:** Always specify `earliest` and `latest` when possible
2. **Filter early:** Put most restrictive filters first
3. **Limit results:** Use `head` or `tail` to limit output
4. **Use indexed fields:** Prefer indexed fields over `rex` extraction

### Search Efficiency
```spl
# Good - filters early
index=main sourcetype=apache_access status=404
| stats count by uri

# Bad - processes all data first
index=main
| search sourcetype=apache_access
| where status=404
| stats count by uri
```

### Field Extraction
```spl
# Extract IP address
| rex field=_raw "(?<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# Extract username
| rex field=_raw "user[=:](?<username>\w+)"

# Extract email
| rex field=_raw "(?<email>[\w\.-]+@[\w\.-]+\.\w+)"
```

### Time Formatting
```spl
# Convert epoch to readable time
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")

# Extract hour of day
| eval hour=strftime(_time, "%H")

# Extract day of week
| eval day=strftime(_time, "%A")
```

---

## Quick Reference

### Common SPL Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Filter events | `search error` |
| `stats` | Calculate statistics | `stats count by host` |
| `table` | Display fields | `table _time, user, action` |
| `timechart` | Time-based chart | `timechart count by sourcetype` |
| `top` | Most common values | `top limit=10 user` |
| `rare` | Least common values | `rare command` |
| `rex` | Extract fields | `rex field=_raw "user=(?<user>\w+)"` |
| `eval` | Calculate/create fields | `eval status=if(code=200,"OK","ERROR")` |
| `where` | Filter results | `where count > 100` |
| `sort` | Sort results | `sort -_time` |
| `head` | First N results | `head 20` |
| `tail` | Last N results | `tail 20` |
| `dedup` | Remove duplicates | `dedup user` |
| `transaction` | Group related events | `transaction user maxspan=10m` |

---

**Pro Tip:** Save frequently used searches as reports or alerts for quick access and automated monitoring!

