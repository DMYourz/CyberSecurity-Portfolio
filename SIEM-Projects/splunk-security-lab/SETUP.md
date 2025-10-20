# Lab Setup Guide

Complete step-by-step instructions for building the Splunk Security Operations Lab.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [VM Configuration](#vm-configuration)
3. [Splunk Enterprise Installation](#splunk-enterprise-installation)
4. [Universal Forwarder Installation](#universal-forwarder-installation)
5. [Network Configuration](#network-configuration)
6. [Data Input Configuration](#data-input-configuration)
7. [BOTS Dataset Installation](#bots-dataset-installation)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Software Requirements
- **VirtualBox** 7.0 or later
- **Windows 11 ISO** (for Splunk Enterprise)
- **Kali Linux ISO** (for Universal Forwarder)
- **Splunk Enterprise** (free license, 500MB/day)
- **Splunk Universal Forwarder** for Linux
- **BOTS v3 Dataset** (optional, ~12GB)

### Hardware Requirements
- **CPU**: 4+ cores recommended
- **RAM**: 16GB minimum (8GB for Windows VM, 4GB for Kali VM)
- **Storage**: 100GB+ free space
- **Network**: Bridged adapter capability

---

## VM Configuration

### Windows 11 VM (Splunk Enterprise)

**VirtualBox Settings:**
```
Name: Win11-Splunk
Type: Microsoft Windows
Version: Windows 11 (64-bit)
Memory: 8192 MB
Processors: 2-4 cores
Storage: 60 GB (dynamic)
Network: Bridged Adapter
```

**Installation Steps:**
1. Create new VM in VirtualBox
2. Attach Windows 11 ISO
3. Install Windows 11
4. Install VirtualBox Guest Additions
5. Configure network adapter to Bridged mode
6. Note the IP address (e.g., 192.168.1.203)

### Kali Linux VM (Universal Forwarder)

**VirtualBox Settings:**
```
Name: Kali-Forwarder
Type: Linux
Version: Debian (64-bit)
Memory: 4096 MB
Processors: 2 cores
Storage: 40 GB (dynamic)
Network: Bridged Adapter
```

**Installation Steps:**
1. Create new VM in VirtualBox
2. Attach Kali Linux ISO
3. Install Kali Linux
4. Install VirtualBox Guest Additions:
   ```bash
   sudo apt update
   sudo apt install -y virtualbox-guest-x11
   ```
5. Configure network adapter to Bridged mode
6. Note the IP address (e.g., 192.168.1.93)

---

## Splunk Enterprise Installation

### On Windows 11 VM

**Step 1: Download Splunk Enterprise**
1. Go to https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Download Windows 64-bit installer
3. Create free Splunk account if needed

**Step 2: Install Splunk**
1. Run the installer as Administrator
2. Accept license agreement
3. Choose installation directory: `C:\Program Files\Splunk`
4. Create admin username and password (remember these!)
5. Complete installation

**Step 3: Start Splunk**
1. Splunk should start automatically
2. Access web interface: http://127.0.0.1:8000
3. Log in with admin credentials

**Step 4: Configure Receiving Port**
1. Go to **Settings** → **Forwarding and receiving**
2. Click **Configure receiving**
3. Click **New Receiving Port**
4. Enter port: `9997`
5. Click **Save**

**Step 5: Configure Windows Firewall**
1. Open **Windows Defender Firewall with Advanced Security**
2. Click **Inbound Rules** → **New Rule**
3. Select **Port** → **Next**
4. Select **TCP**, enter port `9997` → **Next**
5. Select **Allow the connection** → **Next**
6. Check all profiles (Domain, Private, Public) → **Next**
7. Name: "Splunk Receiving Port 9997" → **Finish**

---

## Universal Forwarder Installation

### On Kali Linux VM

**Step 1: Download Universal Forwarder**
```bash
cd ~/Downloads
wget -O splunkforwarder.tgz 'https://download.splunk.com/products/universalforwarder/releases/9.1.0/linux/splunkforwarder-9.1.0-linux-2.6-amd64.tgz'
```

**Step 2: Extract and Install**
```bash
sudo tar xvzf splunkforwarder.tgz -C /opt
```

**Step 3: Start Forwarder and Accept License**
```bash
cd /opt/splunkforwarder/bin
sudo ./splunk start --accept-license
```

**Step 4: Create Admin User**
- Enter admin username (e.g., admin)
- Enter password (remember this!)

**Step 5: Enable Boot Start**
```bash
sudo /opt/splunkforwarder/bin/splunk enable boot-start
```

---

## Network Configuration

### Verify Connectivity

**On Windows VM:**
```cmd
ipconfig
```
Note the IPv4 Address (e.g., 192.168.1.203)

**On Kali VM:**
```bash
ip addr show
```
Note the IP address (e.g., 192.168.1.93)

**Test connectivity from Kali to Windows:**
```bash
ping 192.168.1.203
telnet 192.168.1.203 9997
```

If telnet connects, you're ready to proceed!

---

## Data Input Configuration

### Configure outputs.conf (Kali)

**Tell the forwarder WHERE to send data:**

```bash
sudo nano /opt/splunkforwarder/etc/system/local/outputs.conf
```

**Add this configuration (replace with your Windows IP):**
```ini
[tcpout]
defaultGroup = my_indexers

[tcpout:my_indexers]
server = 192.168.1.203:9997
```

Save and exit (Ctrl+X, Y, Enter)

### Configure inputs.conf (Kali)

**Tell the forwarder WHAT data to send:**

```bash
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

**Add this configuration:**
```ini
[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///var/log/syslog]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/dpkg.log]
disabled = false
index = main
sourcetype = linux_packages

[monitor:///var/log/apache2/access.log]
disabled = false
index = main
sourcetype = apache_access

[monitor:///var/log/apache2/error.log]
disabled = false
index = main
sourcetype = apache_error
```

Save and exit

### Export Systemd Journal Logs

**Create export script:**
```bash
sudo mkdir -p /var/log/splunk_export
sudo nano /usr/local/bin/export_journal.sh
```

**Add this content:**
```bash
#!/bin/bash
journalctl --since "5 minutes ago" -o short-iso >> /var/log/splunk_export/journal.log
```

Save and exit

**Make executable:**
```bash
sudo chmod +x /usr/local/bin/export_journal.sh
```

**Add to inputs.conf:**
```bash
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

**Append:**
```ini
[monitor:///var/log/splunk_export/journal.log]
disabled = false
index = main
sourcetype = linux_journal
```

**Set up cron job for automatic export:**
```bash
sudo crontab -e
```

**Add this line:**
```
*/5 * * * * /usr/local/bin/export_journal.sh
```

### Restart Universal Forwarder

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

---

## BOTS Dataset Installation

### Download BOTS v3

**Option 1: Direct Download**
1. Go to https://github.com/splunk/botsv3
2. Download the dataset (botsv3_data_set.tgz)
3. Extract on Windows VM

**Option 2: Git Clone**
```bash
git clone https://github.com/splunk/botsv3.git
```

### Install BOTS App

**On Windows VM:**

**Step 1: Stop Splunk**
```cmd
cd "C:\Program Files\Splunk\bin"
splunk.exe stop
```

**Step 2: Copy BOTS folder**
```cmd
xcopy "C:\Users\[username]\Downloads\botsv3_data_set\botsv3_data_set" "C:\Program Files\Splunk\etc\apps\botsv3_data_set" /E /I /H
```

**Step 3: Copy data to index location**
```cmd
xcopy "C:\Program Files\Splunk\etc\apps\botsv3_data_set\var\lib\splunk\botsv3" "C:\Program Files\Splunk\var\lib\splunk\botsv3" /E /I /H
```

**Step 4: Start Splunk**
```cmd
splunk.exe start
```

### Verify BOTS Data

**Search in Splunk:**
```spl
index=botsv3
| stats count
```

You should see ~1.9 million events!

---

## Verification

### Test Data Flow from Kali

**Generate test events on Kali:**
```bash
logger "TEST EVENT - $(date)"
sudo /usr/local/bin/export_journal.sh
```

**Search in Splunk (wait 1-2 minutes):**
```spl
index=main sourcetype=linux_journal "TEST EVENT"
```

### Generate Security Events

**Failed login attempts:**
```bash
ssh fakeuser@localhost
ssh admin@localhost
ssh root@localhost
sudo /usr/local/bin/export_journal.sh
```

**Search in Splunk:**
```spl
index=main sourcetype=linux_journal "Failed password"
| stats count by user
```

### Check Forwarder Status

**On Kali:**
```bash
sudo /opt/splunkforwarder/bin/splunk status
```

**Check connection in Splunk:**
```spl
index=_internal source=*metrics.log group=tcpin_connections
| stats count by hostname
```

---

## Troubleshooting

### No Data Appearing in Splunk

**Check 1: Forwarder is running**
```bash
sudo /opt/splunkforwarder/bin/splunk status
```

**Check 2: Network connectivity**
```bash
telnet 192.168.1.203 9997
```

**Check 3: Forwarder logs**
```bash
sudo tail -50 /opt/splunkforwarder/var/log/splunk/splunkd.log
```

**Check 4: Receiving port enabled**
- Splunk Web → Settings → Forwarding and receiving → Configure receiving
- Verify port 9997 is listed

**Check 5: Windows Firewall**
```cmd
netstat -an | findstr 9997
```
Should show `LISTENING` on port 9997

### Permission Denied Errors

**Fix forwarder permissions:**
```bash
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder
```

### Configuration File Errors

**Verify outputs.conf:**
```bash
cat /opt/splunkforwarder/etc/system/local/outputs.conf
```

Should show proper format with IP and port.

**Verify inputs.conf:**
```bash
cat /opt/splunkforwarder/etc/system/local/inputs.conf
```

Should show monitor stanzas with proper paths.

### Journal Export Not Working

**Test export script:**
```bash
sudo /usr/local/bin/export_journal.sh
cat /var/log/splunk_export/journal.log
```

**Check cron job:**
```bash
sudo crontab -l
```

---

## Next Steps

Once your lab is set up and verified:

1. **[Practice Security Investigations](INVESTIGATION.md)**
2. **[Learn SPL Searches](SEARCHES.md)**
3. **Create Dashboards and Alerts**
4. **Generate More Security Events**
5. **Practice Incident Response**

---

## Quick Reference

### Important Paths

**Windows (Splunk Enterprise):**
- Installation: `C:\Program Files\Splunk`
- Apps: `C:\Program Files\Splunk\etc\apps`
- Indexes: `C:\Program Files\Splunk\var\lib\splunk`
- Web UI: http://127.0.0.1:8000

**Kali (Universal Forwarder):**
- Installation: `/opt/splunkforwarder`
- Config: `/opt/splunkforwarder/etc/system/local`
- Logs: `/opt/splunkforwarder/var/log/splunk`

### Important Commands

**Splunk Enterprise (Windows):**
```cmd
cd "C:\Program Files\Splunk\bin"
splunk.exe start
splunk.exe stop
splunk.exe restart
splunk.exe status
```

**Universal Forwarder (Kali):**
```bash
sudo /opt/splunkforwarder/bin/splunk start
sudo /opt/splunkforwarder/bin/splunk stop
sudo /opt/splunkforwarder/bin/splunk restart
sudo /opt/splunkforwarder/bin/splunk status
```

---

**Setup complete! You now have a fully functional Splunk Security Operations Lab.**

