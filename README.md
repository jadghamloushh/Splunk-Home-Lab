```markdown
# Security Monitoring Home Lab with Splunk

This project is a walkthrough of how I built a home SIEM lab using Splunk to monitor Windows security events, detect attacks, and set up automated alerts.

---

## What This Lab Covers

- Installing and configuring Splunk
- Forwarding Windows Security logs using Splunk Universal Forwarder
- Writing SPL queries to detect suspicious activity
- Setting up scheduled alerts
- Understanding key Windows Event IDs
- Simulating real attack scenarios
- Investigating alerts
- Adding Sysmon for deeper visibility

---

## Part 1 — Installing Splunk

### Splunk Enterprise

Download Splunk Enterprise and install it with default settings.

After installation, open:

```

[http://localhost:8000](http://localhost:8000)

```

Log in with your admin credentials.

---

### Splunk Universal Forwarder

Install the Universal Forwarder to send logs to Splunk.

Set receiving indexer:

```

localhost:9997

```

---

## Part 2 — Setting Up Log Ingestion

### Create the Index

Go to:
Settings → Indexes → New Index

- Name: `wineventlog`

---

### Enable Receiving Port

Go to:
Settings → Forwarding and Receiving

- Add port: `9997`

---

### Configure the Forwarder

Edit:

```

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf

````

Add:

```ini
[WinEventLog://Security]
disabled = 0
index = wineventlog

[WinEventLog://System]
disabled = 0
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = wineventlog
````

---

### Restart Forwarder

```bash
splunk restart
```

---

### Verify Logs

```spl
index=wineventlog
```

---

## Part 3 — Adding Sysmon (Endpoint Visibility)

Sysmon provides detailed logs about process execution and system activity.

### What Sysmon adds

* Process execution (Event ID 1)
* Command-line visibility
* Parent-child process tracking

This allows detection of:

* PowerShell attacks
* Suspicious process chains
* Recon activity

---

## Part 4 — Simulating Attacks

### Brute Force

* Lock your PC
* Enter wrong password multiple times
* Then log in correctly

---

### Account Persistence

```bash
net user testattacker Password123! /add
net localgroup administrators testattacker /add
```

---

### Recon Commands

```bash
whoami
net user
net localgroup administrators
systeminfo
ipconfig /all
```

---

## Part 5 — Detection Queries

### Brute Force Detection

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name
| where count > 5
```

#### What it detects

Multiple failed login attempts.

#### False Positives

* User mistyping password
* Service using wrong credentials

#### MITRE

* T1110 (Brute Force)

---

### Encoded PowerShell Detection

```spl
index=wineventlog EventCode=1
Image="*\\powershell.exe"
CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
```

#### What it detects

Hidden PowerShell execution.

#### False Positives

* Admin scripts
* Automation tools

#### MITRE

* T1059.001 (PowerShell)

---

### Suspicious Parent-Child Process

```spl
EventCode=1
ParentImage="*\\WINWORD.EXE"
Image="*\\powershell.exe"
```

#### What it detects

Word spawning PowerShell (possible macro attack).

#### False Positives

* Rare but possible admin scripts

#### MITRE

* T1059 (Command Execution)

---

### Recon Activity Detection

```spl
EventCode=1
CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

#### What it detects

System discovery commands.

#### False Positives

* IT troubleshooting
* Admin activity

#### MITRE

* Discovery techniques

---

## Part 6 — Multi-Stage Detection (Attack Chain)

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624 OR EventCode=4672)
| eval account=coalesce(Account_Name, TargetUserName, SubjectUserName)
| stats count(eval(EventCode=4625)) as failed
        count(eval(EventCode=4624)) as success
        count(eval(EventCode=4672)) as privileged
        by account
| where failed > 3 AND success > 0 AND privileged > 0
```

### What it detects

A full attack flow:

1. Multiple failed logins
2. Successful login
3. Privileged access

### Why it matters

This shows attacker behavior, not just single events.

---

## Part 7 — Investigation Workflow

When an alert triggers:

1. Identify affected account
2. Check login history
3. Check source activity
4. Check privilege changes
5. Look for suspicious commands

---

## Part 8 — Sigma Rule Example

```yaml
title: Suspicious PowerShell Encoded Command
logsource:
  product: windows
  category: process_creation

detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection

level: high
```

---

## Part 9 — Key Event IDs

### Authentication

* 4624 → Successful login
* 4625 → Failed login
* 4672 → Admin privileges

### Account Activity

* 4720 → Account created
* 4732 → Added to admin group

### Sysmon

* 1 → Process creation

---

## Final Notes

This lab focuses on:

* Detecting attacker behavior
* Simulating real attack scenarios
* Understanding logs and alerts
* Thinking about false positives
* Connecting events into attack chains

---

## Key Takeaway

This is not just about writing queries.

It is about:

* understanding attacker behavior
* detecting it
* and investigating it

```

---

# ✅ What I did for you

- Kept your structure  
- Added:
  - Sysmon  
  - Multi-stage detection  
  - False positives  
  - MITRE  
  - Investigation logic  
- Kept language **simple and clean** (no overcomplication)

---

# 🚀 Next step

If you want, I can:

👉 Make your **GitHub look like a top-tier project (badges, visuals, screenshots layout)**  
👉 Or update your **CV perfectly based on this final version**  
👉 Or simulate **interview questions from this exact project**

Just tell me 👍
```
