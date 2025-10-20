# Splunk Security Operations Lab

> A hands-on lab for learning and practicing security monitoring, threat hunting, and incident response with Splunk.

[![Splunk](https://img.shields.io/badge/Splunk-Enterprise-000000?style=flat&logo=splunk )](https://www.splunk.com/ )
[![Platform](https://img.shields.io/badge/Platform-VirtualBox-blue )](https://www.virtualbox.org/ )
[![License](https://img.shields.io/badge/License-MIT-green )](LICENSE)

---

## 📖 Project Overview

This project is a fully functional Splunk lab environment designed for security professionals, students, and enthusiasts to develop practical skills in security operations. The lab is built to simulate a realistic enterprise environment, providing hands-on experience with SIEM configuration, data analysis, and threat detection.

The primary goal of this lab is to serve as an educational resource. It provides a platform to:

*   Learn and practice with Splunk for security monitoring.
*   Analyze real-world security data and threat scenarios.
*   Develop and test custom detection rules and alerts.
*   Conduct in-depth incident investigations from start to finish.

This repository includes the necessary configurations, documentation, and sample data to replicate the lab and explore various security use cases.

---

## 🏗️ Lab Architecture

### Infrastructure Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Splunk Enterprise                        │
│                    (Windows 11 VM)                           │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Indexer    │  │  Search Head │  │   Forwarder  │     │
│  │   Port 9997  │  │   Port 8000  │  │   Management │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         ▲                                                    │
│         │ TCP 9997                                          │
│         │                                                    │
└─────────┼────────────────────────────────────────────────────┘
          │
          │ Encrypted Data Stream
          │
┌─────────┼────────────────────────────────────────────────────┐
│         │        Universal Forwarder                         │
│         │          (Kali Linux VM)                           │
│         │                                                    │
│  ┌──────▼──────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Forwarder  │  │  Data Inputs │  │  Log Sources │      │
│  │   Service   │  │  Management  │  │  Monitoring  │      │
│  └─────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
│  Data Sources:                                              │
│  • Authentication logs (SSH, sudo)                          │
│  • System logs (syslog, kernel)                            │
│  • Web server logs (Apache)                                │
│  • Security events (failed logins, privilege escalation)   │
└─────────────────────────────────────────────────────────────┘

Additional Dataset:
┌─────────────────────────────────────────────────────────────┐
│              BOTS v3 Security Dataset                        │
│             (1,944,092 Events)                               │
│                                                              │
│  • Windows Event Logs (Security, Sysmon)                    │
│  • AWS CloudWatch & VPC Flow Logs                           │
│  • Network Traffic (DNS, HTTP, IDS)                         │
│  • Real Cerber Ransomware Attack Data                       │
└─────────────────────────────────────────────────────────────┘
```


### Technical Specifications

| Component | Specification | Purpose |
|-----------|--------------|---------|
| **Splunk Enterprise** | v9.x, Windows 11 | Central indexing and search |
| **Universal Forwarder** | v9.x, Kali Linux | Log collection and forwarding |
| **Data Volume** | 350,000+ events indexed | Real-world scale dataset |
| **Network** | Bridged adapter, isolated lab | Secure testing environment |
| **Storage** | 100GB+ allocated | Index storage and retention |

---

## ✨ Lab Highlights

### Data Collection

The lab successfully collects and indexes security data from multiple sources:

![Data Sources](screenshots/01-data-sources.png.png)

**Data Sources:**
- **333,406 events** from linux_journal (authentication, sudo, system logs)
- **17,514 events** from linux_logs
- Apache web server access and error logs
- System boot logs

### Security Monitoring

The lab demonstrates real security monitoring capabilities:

![Failed Login Detection](screenshots/02-failed-logins.png.png)

**Failed Authentication Detection:** 76 failed login attempts detected and analyzed.

![Sudo Activity](screenshots/03-sudo-activity.png.png)

**Privilege Escalation Monitoring:** Tracking sudo commands and privileged access.

### Timeline Analysis

![Activity Timeline](screenshots/04-timeline.png.png)

Visual analysis of security events over time, enabling pattern recognition and anomaly detection.

### Log Analysis

![Sample Logs](screenshots/05-sample-logs.png.png)

Raw log data showing authentication events, system activity, and security-relevant information.

---

## 🔧 Forwarder Configuration

### Universal Forwarder Setup

![Forwarder Status](screenshots/06-forwarder-status.png.png)

The Splunk Universal Forwarder is configured and running on the Kali Linux VM.

### Output Configuration

![Outputs Config](screenshots/07-outputs-config.png.png)

Configured to forward data to the Splunk Enterprise indexer on port 9997.

### Input Configuration

![Inputs Config](screenshots/08-inputs-config.png.png)

Monitoring multiple log sources including authentication logs, system logs, and web server logs.

---

## 🚀 Getting Started

To get started with this lab, you will need:

*   VirtualBox or another hypervisor
*   A Windows 11 VM
*   A Kali Linux VM
*   A Splunk Enterprise license (a free trial license is sufficient)

Follow the [Setup Guide](SETUP.md) for detailed instructions on how to configure the lab environment.

For a quick setup, see the [Quick Start Guide](QUICKSTART.md).

---

## 📂 Repository Structure

```
├── README.md                  # This file
├── SETUP.md                   # Detailed setup guide
├── INVESTIGATION.md           # Security investigation walkthrough
├── SEARCHES.md                # Collection of useful SPL queries
├── SCREENSHOTS.md             # Screenshot documentation guide
├── QUICKSTART.md              # Quick setup guide
├── screenshots/               # Lab screenshots
│   ├── 01-data-sources.png.png
│   ├── 02-failed-logins.png.png
│   ├── 03-sudo-activity.png.png
│   ├── 04-timeline.png.png
│   ├── 05-sample-logs.png.png
│   ├── 06-forwarder-status.png.png
│   ├── 07-outputs-config.png.png
│   └── 08-inputs-config.png.png
├── configs/                   # Configuration files
│   ├── inputs.conf           # Example forwarder inputs
│   ├── outputs.conf          # Example forwarder outputs
│   └── alert-examples.txt    # Sample alert configurations
├── LICENSE                    # MIT License
└── .gitignore                # Git ignore rules
```

*   **README.md:** This file, providing an overview of the project.
*   **SETUP.md:** A detailed guide to setting up the lab environment.
*   **INVESTIGATION.md:** A step-by-step walkthrough of the Cerber ransomware investigation.
*   **SEARCHES.md:** A collection of useful SPL queries.
*   **SCREENSHOTS.md:** Screenshots of dashboards and investigation steps.
*   **configs/:** Example configuration files for the Splunk Universal Forwarder.
*   **LICENSE:** The project's license.
*   **.gitignore:** A list of files and directories to ignore in the repository.


---

## 📚 Documentation

*   **[SETUP.md](SETUP.md)** - Complete step-by-step setup instructions
*   **[INVESTIGATION.md](INVESTIGATION.md)** - Detailed security investigation walkthrough
*   **[SEARCHES.md](SEARCHES.md)** - 50+ useful SPL queries for security operations
*   **[QUICKSTART.md](QUICKSTART.md)** - Get up and running in 30 minutes

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
