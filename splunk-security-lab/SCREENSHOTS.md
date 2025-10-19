# Lab Screenshots

This document provides a reference for key screenshots to capture for documenting the Splunk Security Lab setup and findings.

---

## Recommended Screenshots

### 1. Lab Architecture Diagram
**What to capture:**
- A diagram showing the network relationship between the Windows 11 VM (Splunk Enterprise) and the Kali Linux VM (Universal Forwarder).

**Purpose:** Visually explains the lab's infrastructure.

### 2. Splunk Enterprise Web Interface
**What to capture:**
- The main dashboard of the Splunk Enterprise instance.

**Purpose:** Confirms that the Splunk server is running and accessible.

### 3. Data Receiving Configuration
**What to capture:**
- The Splunk settings page for TCP data inputs, showing port 9997 is enabled and listening.

**Purpose:** Shows the configuration for receiving data from the forwarder.

### 4. Universal Forwarder Configuration Files
**What to capture:**
- The contents of `outputs.conf` and `inputs.conf` on the Kali Linux VM.

**Purpose:** Documents how the forwarder is configured to send data.

### 5. Data Flow Verification
**What to capture:**
- A Splunk search showing events received from the Kali Linux host (e.g., `index=main host=kali-forwarder`).

**Purpose:** Verifies that data is successfully being forwarded and indexed.

### 6. Security Event Example
**What to capture:**
- Search results for a specific security event, such as failed SSH logins.

**Purpose:** Demonstrates the lab's ability to capture and display security-relevant data.

### 7. BOTS Dataset Event Count
**What to capture:**
- The result of the search `index=botsv3 | stats count`.

**Purpose:** Confirms that the BOTS v3 dataset is successfully loaded and indexed.

### 8. Cerber Ransomware Investigation Search
**What to capture:**
- The Splunk search results for the Cerber C2 domain `cerber.brewertalk.com`.

**Purpose:** Highlights a key finding from the ransomware investigation.

### 9. Defense Evasion Event
**What to capture:**
- The search results showing the event where Windows Defender was stopped.

**Purpose:** Shows a critical indicator of compromise identified during the investigation.

### 10. Custom Security Dashboard
**What to capture:**
- A custom-built dashboard that visualizes security data, such as failed logins, sudo commands, and network traffic.

**Purpose:** Demonstrates how to create a simple dashboard for monitoring security events.

---

## Screenshot Tips

*   **Clarity:** Use a high resolution and ensure text is clear and readable.
*   **Format:** Save images in PNG format for better quality.
*   **Cropping:** Crop out unnecessary parts of the screen to focus on the relevant information.
*   **Annotation:** Use arrows or boxes to highlight important details in the screenshots.
*   **Organization:** Store all screenshots in a dedicated `/screenshots` directory for easy access.

