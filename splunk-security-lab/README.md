# Splunk Security Operations Lab

> A hands-on lab for learning and practicing security monitoring, threat hunting, and incident response with Splunk.

[![Splunk](https://img.shields.io/badge/Splunk-Enterprise-000000?style=flat&logo=splunk)](https://www.splunk.com/)
[![Platform](https://img.shields.io/badge/Platform-VirtualBox-blue)](https://www.virtualbox.org/)
[![Dataset](https://img.shields.io/badge/Dataset-BOTS%20v3-orange)](https://github.com/splunk/botsv3)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

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
| **Data Volume** | 1.9M+ events indexed | Real-world scale dataset |
| **Network** | Bridged adapter, isolated lab | Secure testing environment |
| **Storage** | 100GB+ allocated | Index storage and retention |

---

## ✨ Key Features

*   **Realistic Lab Environment:** A multi-VM setup that mirrors a typical corporate network, with data flowing from a Linux host to a Splunk instance on Windows.
*   **Real-World Dataset:** Utilizes the Splunk Boss of the SOC (BOTS) v3 dataset, which contains over 1.9 million events from a variety of sources, including a real Cerber ransomware attack.
*   **Hands-On Investigation:** A detailed walkthrough of a ransomware investigation, from initial indicators to identifying the full attack chain.
*   **Practical SPL Queries:** A collection of over 50 SPL queries for threat hunting, reporting, and dashboarding.
*   **Custom Alerts:** Examples of custom alerts for detecting common security threats.

---

## 🔍 Investigation Highlight: Cerber Ransomware

This lab includes a detailed investigation of a Cerber ransomware attack, based on the BOTSv3 dataset. The investigation demonstrates how to use Splunk to:

*   Identify indicators of compromise (IOCs).
*   Trace the attacker's steps across multiple systems.
*   Build a timeline of the attack.
*   Develop queries to detect similar threats in the future.

See the full [Investigation Walkthrough](INVESTIGATION.md) for a step-by-step analysis of the attack.

---

## 🚀 Getting Started

To get started with this lab, you will need:

*   VirtualBox or another hypervisor
*   A Windows 11 VM
*   A Kali Linux VM
*   A Splunk Enterprise license (a free trial license is sufficient)

Follow the [Setup Guide](SETUP.md) for detailed instructions on how to configure the lab environment.

---

## 📂 Repository Structure

```
├── README.md
├── SETUP.md
├── INVESTIGATION.md
├── SEARCHES.md
├── SCREENSHOTS.md
├── configs
│   ├── inputs.conf
│   └── outputs.conf
├── LICENSE
└── .gitignore
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

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

