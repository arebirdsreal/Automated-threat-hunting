#  Automated Linux Threat Hunting & Live Intelligence Pipeline

An end-to-end security orchestration and detection engineering pipeline built from scratch in Kali Linux. This system captures low-level Linux kernel telemetry (`auditd`), processes multi-line event logs through a custom Python analytical engine, maps behaviors directly to the **MITRE ATT&CK®** framework, and streams live threat intelligence to a zero-refresh web dashboard.

---

##  Project Overview & Motivation

Modern Security Operations Centers (SOCs) rely heavily on telemetry pipelines to turn raw, noisy operating system events into actionable security alerts. Rather than relying on black-box enterprise SIEMs, this project builds the entire detection stack from the ground up to demonstrate:
* **Kernel-Level Visibility:** Monitoring system calls (`execve`) and file integrity (`wa` attributes) directly at the OS level.
* **Log Correlation & Noise Reduction:** Parsing multi-line audit logs by unique transaction IDs while filtering out benign system utilities (`sysstat`).
* **Real-Time Threat Visualization:** Decoupling data ingestion from the frontend UI using background cron automation, JSON normalization, and asynchronous JavaScript (AJAX) polling.

---

##  System Architecture

```text
+--------------------+      +-----------------------+      +-------------------------+

| Adversary Activity | ---> | Linux Kernel (Auditd) | ---> | /var/log/audit/audit.log|
+--------------------+      +-----------------------+      +-------------------------+
                                                                        |
                                                       (Automated via Root Cronjob)
                                                                        v
+--------------------+      +-----------------------+      +-------------------------+

| Live Web Dashboard | <--- |   Flask API Server    | <--- |  kali_hunter.py Parser  |
| (AJAX Auto-Poll)   |      |     (/api/alerts)     |      | (Deduplicates & Maps)   |
+--------------------+      +-----------------------+      +-------------------------+
```

---

##  MITRE ATT&CK® Detection Matrix

The detection engine (`kali_hunter.py`) currently monitors for four distinct adversarial behaviors mapped to enterprise tactics and techniques:

| Alert Type | Trigger / Indicator | MITRE Tactic | Technique ID |
| :--- | :--- | :--- | :--- |
| **Unix Shell Discovery** | Execution of `ip address` or enumeration of `/etc/passwd` | Discovery / Execution | **T1059.004** |
| **Network Reconnaissance** | Execution of `nmap`, `ss`, `netstat`, or `lsof` | Discovery | **T1049 / T1046** |
| **File Integrity Modification** | Unauthorized writes or permission changes (`chmod`) to `/etc/passwd` or `/etc/shadow` | Defense Evasion / Persistence | **T1222** |
| **Impair Defenses (Log Tampering)** | Attempts to query, stop, or disable logging services (`auditctl`, `auditd`) | Defense Evasion | **T1562.001** |

---

##  Engineering Challenges Solved

Building a reliable detection pipeline required solving several real-world telemetry hurdles:
1. **Multi-Line Log Correlation:** Linux `auditd` splits command executions across separate `SYSCALL` (containing the rule key) and `EXECVE` (containing the command arguments) lines. The parser groups lines dynamically using unique cryptographic audit transaction IDs (`audit(epoch:serial)`).
2. **Accurate Chronological Timestamps:** Instead of stamping alerts with the time the Python script executed, the parser extracts and converts the raw Unix epoch float embedded in the kernel event ID to preserve the exact second the attack occurred.
3. **False Positive Tuning:** Built explicit exclusion logic to filter out benign background Linux performance utilities (such as `debian-sa1` and `sysstat`) that share string patterns with network reconnaissance commands.

---

##  Installation & Deployment Guide

### Prerequisites
* Debian/Ubuntu or Kali Linux environment
* Python 3.8+
* Root (`sudo`) privileges for kernel auditing

### Step 1: Configure Linux Audit Daemon (`auditd`)
Install the auditing framework and enable the background service:
```bash
sudo apt update && sudo apt install auditd audispd-plugins -y
sudo systemctl enable --now auditd
```

Open `/etc/audit/rules.d/audit.rules` and append the custom kernel hooks at the bottom:
```text
-a always,exit -F arch=b64 -S execve -k mitre_t1059
-w /etc/passwd -p wa -k mitre_t1222
-w /etc/shadow -p wa -k mitre_t1078
```

Restart the service to load the rules into the kernel:
```bash
sudo systemctl restart auditd
```

### Step 2: Clone the Repository & Install Dependencies
```bash
git clone https://github.com/arebirdsreal/Automated-threat-hunting
cd automated-linux-threat-hunting
pip install flask --break-system-packages
```

### Step 3: Automate Threat Hunting via Root Cron
Schedule `kali_hunter.py` to run every minute in the background as root:
```bash
sudo crontab -e
```
Add the following line (replace `/path/to/repo` with your actual directory path):
```text
cd /path/to/repo && /usr/bin/python3 kali_hunter.py
```

### Step 4: Launch the Live Dashboard
Start the Flask web server:
```bash
python3 app.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`**. The UI polls `/api/alerts` every 3 seconds and updates automatically without requiring manual page refreshes.

---

##  Adversary Emulation (Testing the Pipeline)

To test the detection rules safely in your lab environment, run the following simulated attack commands in a separate terminal:

```bash
# 1. Trigger Network Reconnaissance (T1049 / T1046)
nmap 127.0.0.1

# 2. Trigger Host & Account Discovery (T1059.004)
ip address show && cat /etc/passwd | grep home

# 3. Trigger File Integrity Modification (T1222)
sudo chmod 644 /etc/passwd

# 4. Trigger Defense Evasion / Log Tampering (T1562.001)
sudo auditctl -s
```
---

##  Project Structure
```text
├── kali_hunter.py    # Core log parser, noise filter, and MITRE mapping engine
├── app.py            # Flask web server and AJAX-enabled frontend dashboard
├── .gitignore        # Excludes local alerts.json and Python cache files
└── README.md         # Project documentation and deployment guide
```
