# Cerber Ransomware Investigation

## Executive Summary

This document details the investigation of a Cerber ransomware incident using the Boss of the SOC (BOTS) v3 dataset. The investigation analyzed 1.9+ million security events across multiple data sources to identify the attack timeline, affected systems, and indicators of compromise.

---

## Incident Overview

**Incident Type:** Ransomware Attack  
**Malware Family:** Cerber  
**Dataset:** BOTS v3 (~1,944,092 events)  
**Investigation Date:** October 18, 2025  
**Investigator:** [Your Name]  

---

## Attack Timeline

### Phase 1: Initial Compromise
**Time:** ~04:00 AM - 05:08 AM (August 20, 2018)

**Activity:**
- Initial infection vector (under investigation)
- Attacker gained administrative access
- Preparation for security service disruption

### Phase 2: Defense Evasion
**Time:** 05:08:28 AM (August 20, 2018)

**Critical Event:** Windows Defender Antivirus Service Stopped

**Evidence:**
```
Type=Service
Name="WinDefend"
DisplayName="Windows Defender Antivirus Service"
Description="Helps protect users from malware and other potentially unwanted software"
Path="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.1806.18062-0\\MsMpEng.exe"
ServiceType="Own Process"
StartMode="Manual"
Started=false
State="Stopped"
Status="OK"
ProcessId=0
```

**Analysis:**
- Windows Defender was disabled by attacker
- StartMode changed to "Manual" (should be "Automatic")
- Service state: "Stopped"
- This is a classic ransomware tactic to evade detection

**SPL Search Used:**
```spl
index=botsv3 "Windows Defender" (stopped OR disabled)
| table _time, host, _raw
| sort _time
```

### Phase 3: Command & Control Communication
**Time:** 11:02:33 AM (August 20, 2018)

**Critical Event:** Cerber C2 DNS Query

**Evidence:**
```
cerber.brewertalk.com A NXDOMAIN UDP NRT53 13.124.132.145
```

**Analysis:**
- DNS query for Cerber C2 domain: `cerber.brewertalk.com`
- Query type: A record (looking for IP address)
- Result: NXDOMAIN (domain doesn't exist or is blocked)
- Source IP: 13.124.132.145
- **Significance:** Ransomware attempting to contact command & control server for encryption keys

**SPL Search Used:**
```spl
index=botsv3 cerber.brewertalk.com
| table _time, src_ip, query, answer
| sort _time
```

### Phase 4: Encryption & Impact
**Time:** ~11:02 AM onwards (August 20, 2018)

**Expected Activity:**
- File encryption with .cerber extension
- Ransom note deployment
- System impact and data loss

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Value | Description |
|------|-------|-------------|
| Domain | cerber.brewertalk.com | Cerber C2 domain |
| IP Address | 13.124.132.145 | Associated C2 infrastructure |
| Protocol | DNS (UDP/53) | C2 communication method |

### Host Indicators

| Type | Value | Description |
|------|-------|-------------|
| Service | Windows Defender | Stopped/Disabled |
| Process | WinDefend | Service disruption |
| File Extension | .cerber | Encrypted file indicator |
| Malware Family | Cerber | Ransomware-as-a-Service |

### Affected Systems

| Hostname | Domain | Type | Status |
|----------|--------|------|--------|
| PCERF-L | froth.ly | Windows Endpoint | Compromised |
| serverless | AWS | Cloud Infrastructure | Compromised |

---

## Investigation Methodology

### Step 1: Initial Discovery

**Objective:** Identify security anomalies

**Search:**
```spl
index=botsv3 (ransomware OR cerber OR locky OR wannacry OR malware)
| stats count by sourcetype
```

**Findings:**
- Multiple references to "cerber" in DNS logs
- Windows service disruption events

### Step 2: Timeline Analysis

**Objective:** Establish attack timeline

**Search:**
```spl
index=botsv3 (cerber OR "Windows Defender" stopped)
| timechart count
| sort _time
```

**Findings:**
- Windows Defender stopped at 05:08:28 AM
- C2 communication at 11:02:33 AM
- 6-hour gap between defense evasion and C2 contact

### Step 3: Affected System Identification

**Objective:** Identify compromised hosts

**Search:**
```spl
index=botsv3 "Windows Defender" stopped
| stats values(host) as affected_hosts, values(ComputerName) as computer_names
```

**Findings:**
- Windows host: PCERF-L.froth.ly
- AWS infrastructure: serverless

### Step 4: C2 Communication Analysis

**Objective:** Identify command & control infrastructure

**Search:**
```spl
index=botsv3 cerber.brewertalk.com
| table _time, src_ip, query, answer, host
| sort _time
```

**Findings:**
- C2 domain: cerber.brewertalk.com
- DNS query returned NXDOMAIN (blocked or unavailable)
- Multiple query attempts from compromised systems

### Step 5: Data Source Correlation

**Objective:** Correlate events across multiple log sources

**Data Sources Analyzed:**
- Windows Event Logs (WinEventLog:Security)
- AWS CloudWatch Logs
- AWS VPC Flow Logs
- DNS query logs (stream:dns)
- AWS GuardDuty alerts

**Correlation Search:**
```spl
index=botsv3 earliest="08/20/2018:05:00:00" latest="08/20/2018:12:00:00"
| search (cerber OR "Windows Defender" OR stopped)
| stats count by _time, sourcetype, host
| sort _time
```

---

## Key Findings

### 1. Defense Evasion Tactic
**MITRE ATT&CK:** T1562.001 - Impair Defenses: Disable or Modify Tools

The attacker disabled Windows Defender before deploying ransomware, demonstrating:
- Administrative access to target system
- Knowledge of security controls
- Deliberate evasion of endpoint protection

### 2. Command & Control Infrastructure
**MITRE ATT&CK:** T1071.004 - Application Layer Protocol: DNS

Cerber ransomware used DNS queries to contact C2 infrastructure:
- Domain: cerber.brewertalk.com
- Purpose: Retrieve encryption keys and instructions
- Result: Blocked (NXDOMAIN)

### 3. Multi-Environment Compromise

The attack affected both:
- **On-premises Windows endpoints** (PCERF-L.froth.ly)
- **AWS cloud infrastructure** (serverless)

This indicates:
- Sophisticated attack spanning multiple environments
- Potential lateral movement or separate infection vectors
- Need for comprehensive monitoring across hybrid infrastructure

### 4. Ransomware-as-a-Service (RaaS)

Cerber is a known RaaS platform, indicating:
- Commercially available malware
- Affiliate-based distribution model
- Professional-grade encryption and C2 infrastructure

---

## SPL Searches Used

### Failed Authentication Detection
```spl
index=main sourcetype=linux_journal "Failed password"
| rex field=_raw "invalid user (?<username>\w+) from (?<src_ip>[\w\.:]+)"
| stats count by username, src_ip
| where count > 5
| sort -count
```

### Privilege Escalation Monitoring
```spl
index=main sourcetype=linux_journal sudo
| rex field=_raw "COMMAND=(?<command>.*)"
| stats count by user, command
| sort -count
```

### Ransomware C2 Detection
```spl
index=botsv3 (cerber OR locky OR wannacry OR ransomware)
sourcetype!=aws:cloudtrail
| table _time, host, sourcetype, _raw
| sort _time
```

### Windows Defender Status Check
```spl
index=botsv3 "Windows Defender"
| table _time, host, State, Status, Started
| sort _time
```

### DNS Query Analysis
```spl
index=botsv3 sourcetype=stream:dns cerber
| stats count by query, answer, src_ip
| sort -count
```

### AWS CloudWatch Investigation
```spl
index=botsv3 host=serverless sourcetype=aws:cloudwatchlogs
earliest="08/20/2018:11:00:00" latest="08/20/2018:11:05:00"
| stats count by sourcetype
```

### VPC Flow Log Analysis
```spl
index=botsv3 host=serverless sourcetype=aws:cloudwatchlogs:vpcflow
earliest="08/20/2018:11:00:00" latest="08/20/2018:11:05:00"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<src_ip>[\d\.]+)\s+(?<dest_ip>[\d\.]+)\s+\d+\s+(?<dest_port>\d+)"
| stats count by dest_ip, dest_port
| sort -count
```

---

## Recommendations

### Immediate Actions

1. **Isolate Affected Systems**
   - Disconnect PCERF-L.froth.ly from network
   - Quarantine compromised AWS resources
   - Prevent lateral movement

2. **Block IOCs**
   - Add cerber.brewertalk.com to DNS blocklist
   - Block IP 13.124.132.145 at firewall
   - Update IDS/IPS signatures

3. **Restore from Backup**
   - Verify backup integrity before restoration
   - Restore from pre-infection backup (before 05:08 AM, Aug 20)
   - Do NOT pay ransom

4. **Enable Tamper Protection**
   - Re-enable Windows Defender
   - Enable tamper protection to prevent future disabling
   - Verify security services are running

### Short-Term Actions

5. **Threat Hunting**
   - Search for additional compromised systems
   - Look for similar IOCs across environment
   - Check for lateral movement indicators

6. **Forensic Analysis**
   - Preserve evidence (disk images, memory dumps)
   - Analyze initial infection vector
   - Identify patient zero

7. **Alert Creation**
   - Create alert for Windows Defender service disruption
   - Alert on Cerber IOCs
   - Monitor for similar ransomware families

### Long-Term Actions

8. **Security Hardening**
   - Implement application whitelisting
   - Enable controlled folder access
   - Deploy EDR solution (e.g., CrowdStrike)

9. **User Training**
   - Security awareness training
   - Phishing simulation exercises
   - Incident reporting procedures

10. **Backup Strategy**
    - Implement 3-2-1 backup rule
    - Test backup restoration regularly
    - Store backups offline/air-gapped

11. **Monitoring Enhancement**
    - Expand Splunk data sources
    - Create additional correlation searches
    - Implement UEBA for anomaly detection

---

## Lessons Learned

### What Went Well
✅ Splunk SIEM captured critical security events  
✅ Multiple data sources enabled correlation  
✅ DNS filtering prevented C2 communication (NXDOMAIN)  
✅ Comprehensive logging facilitated investigation  

### Areas for Improvement
⚠️ Windows Defender was disabled without alerting  
⚠️ Delay between defense evasion and detection  
⚠️ Initial infection vector not fully identified  
⚠️ Limited endpoint visibility (Sysmon not fully deployed)  

### Key Takeaways
1. **Defense in Depth:** Multiple security layers are critical
2. **Tamper Protection:** Security services must be protected from disabling
3. **Rapid Detection:** Faster detection reduces impact window
4. **Comprehensive Logging:** Multiple data sources enable effective investigation
5. **Cloud Visibility:** Hybrid environments require monitoring across all platforms

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Observed |
|--------|-----------|----------|
| Defense Evasion | T1562.001 - Disable or Modify Tools | ✅ Windows Defender stopped |
| Command and Control | T1071.004 - Application Layer Protocol: DNS | ✅ DNS queries to C2 |
| Impact | T1486 - Data Encrypted for Impact | ⚠️ Expected (not fully observed) |
| Execution | T1204.002 - User Execution: Malicious File | 🔍 Under investigation |
| Persistence | T1547 - Boot or Logon Autostart Execution | 🔍 Under investigation |

---

## References

- **Cerber Ransomware Analysis:** https://www.malwarebytes.com/blog/news/2016/03/cerber-ransomware
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **BOTS v3 Dataset:** https://github.com/splunk/botsv3
- **Splunk Documentation:** https://docs.splunk.com/

---

## Appendix: Investigation Timeline

| Time | Activity | Evidence |
|------|----------|----------|
| ~04:00 AM | Initial compromise | Under investigation |
| 05:08:28 AM | Windows Defender stopped | WinEventLog:Security |
| 05:08 - 11:02 AM | Ransomware deployment | Expected activity |
| 11:02:33 AM | C2 communication attempt | DNS query logs |
| 11:02:33 AM | C2 blocked (NXDOMAIN) | DNS response |
| 11:02+ AM | Encryption activity | Expected impact |

---

**Investigation Status:** Ongoing  
**Next Steps:** Identify initial infection vector, complete forensic analysis, implement recommendations

---

*This investigation demonstrates practical application of SIEM analysis, threat hunting, and incident response methodologies in a realistic security operations environment.*

