# Quick Start Guide

Get your Splunk Security Lab up and running in under 30 minutes!

## Prerequisites Checklist

- [ ] VirtualBox installed
- [ ] Windows 11 ISO downloaded
- [ ] Kali Linux ISO downloaded
- [ ] 16GB+ RAM available
- [ ] 100GB+ disk space free

## Quick Setup (30 minutes)

### Step 1: Create VMs (10 minutes)

**Windows 11 VM:**
- 8GB RAM, 2-4 cores, 60GB disk
- Network: Bridged Adapter

**Kali Linux VM:**
- 4GB RAM, 2 cores, 40GB disk
- Network: Bridged Adapter

### Step 2: Install Splunk Enterprise (10 minutes)

**On Windows VM:**
1. Download Splunk Enterprise from splunk.com
2. Run installer, create admin account
3. Access http://127.0.0.1:8000
4. Configure receiving port 9997
5. Add firewall rule for port 9997

### Step 3: Install Universal Forwarder (5 minutes)

**On Kali VM:**
```bash
# Download and extract
wget -O splunkforwarder.tgz 'https://download.splunk.com/products/universalforwarder/releases/9.1.0/linux/splunkforwarder-9.1.0-linux-2.6-amd64.tgz'
sudo tar xvzf splunkforwarder.tgz -C /opt

# Start and configure
cd /opt/splunkforwarder/bin
sudo ./splunk start --accept-license
sudo ./splunk enable boot-start
```

### Step 4: Configure Data Flow (5 minutes)

**Create outputs.conf:**
```bash
sudo nano /opt/splunkforwarder/etc/system/local/outputs.conf
```

Add (replace IP with your Windows VM IP):
```ini
[tcpout]
defaultGroup = my_indexers

[tcpout:my_indexers]
server = 192.168.1.203:9997
```

**Create inputs.conf:**
```bash
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

Add:
```ini
[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure
```

**Restart forwarder:**
```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

### Step 5: Verify (2 minutes)

**In Splunk Web, search:**
```spl
index=main sourcetype=linux_secure
```

You should see events! 🎉

## Next Steps

1. **[Complete Setup Guide](SETUP.md)** - Full detailed instructions
2. **[Practice Searches](SEARCHES.md)** - Learn SPL queries
3. **[BOTS Investigation](INVESTIGATION.md)** - Analyze ransomware
4. **[Take Screenshots](SCREENSHOTS.md)** - Document your work

## Troubleshooting

**No data appearing?**
- Check forwarder status: `sudo /opt/splunkforwarder/bin/splunk status`
- Test connectivity: `telnet <windows-ip> 9997`
- Check firewall on Windows

**Can't connect to Splunk Web?**
- Verify Splunk is running: `splunk status`
- Check if port 8000 is listening: `netstat -an | findstr 8000`

**Need help?**
See full [SETUP.md](SETUP.md) for detailed troubleshooting.

