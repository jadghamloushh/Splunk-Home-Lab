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
- Adding Sysmon with a tuned configuration for deeper endpoint visibility
- Writing Sigma rules for vendor-agnostic detection logic
- Investigating alerts with a full query-driven workflow
- Correlating events into multi-stage attack chains mapped to MITRE ATT&CK

---

## Part 1 — Installing Splunk

### Splunk Enterprise

Download Splunk Enterprise and install it with default settings.

After installation, open:

```
http://localhost:8000
```

Log in with your admin credentials.

### Splunk Universal Forwarder

Install the Universal Forwarder to send logs to Splunk.

Set receiving indexer:

```
localhost:9997
```

---

## Part 2 — Setting Up Log Ingestion

### Create the Index

Go to: Settings → Indexes → New Index

- Name: `wineventlog`

### Enable Receiving Port

Go to: Settings → Forwarding and Receiving

- Add port: `9997`

### Configure the Forwarder

Edit:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

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
```

### Restart Forwarder

```bash
splunk restart
```

### Verify Logs

```spl
index=wineventlog
```

---

## Part 3 — Adding Sysmon (Endpoint Visibility)

### Why Sysmon

Windows Security logs cover authentication and account management, but they lack visibility into process behavior. Sysmon fills that gap by logging detailed process execution, network connections, and file activity that Windows doesn't capture natively.

### Installation

Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

I used the [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) as a baseline. This config is widely used in production environments and provides solid default coverage while filtering out known noisy processes.

Install with the config:

```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Config Customizations

The default SwiftOnSecurity config is good but needed tuning for this lab:

- **Kept default exclusions** for known-good Windows processes (e.g., `MsMpEng.exe`, `svchost.exe` loading standard DLLs) to reduce noise
- **Added logging for `cmd.exe` and `powershell.exe` child processes** regardless of parent, since this lab focuses on post-exploitation detection
- **Enabled Event ID 3 (Network Connection)** selectively for `powershell.exe`, `cmd.exe`, and `rundll32.exe` to catch C2-like outbound connections without flooding the index with every browser connection
- **Enabled Event ID 11 (File Create)** for `C:\Windows\Temp\` and `C:\Users\*\AppData\Local\Temp\` to catch malware drops in common staging directories

### Key Sysmon Event IDs Used in This Lab

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| 1 | Process creation | Command-line visibility, parent-child chain analysis |
| 3 | Network connection | Outbound C2 detection from suspicious processes |
| 8 | CreateRemoteThread | Process injection detection |
| 11 | File create | Malware staging in temp directories |

### Verifying Sysmon Logs in Splunk

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
```

This confirms Sysmon events are flowing and shows the volume breakdown by event type.

---

## Part 4 — Simulating Attacks

### Brute Force

- Lock your PC
- Enter wrong password multiple times
- Then log in correctly

### Account Persistence

```bash
net user testattacker Password123! /add
net localgroup administrators testattacker /add
```

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
| sort -count
```

**What it detects:** Multiple failed login attempts against a single account.

**False Positives:** User mistyping password repeatedly, service accounts with expired credentials, account lockout testing by IT.

**MITRE:** T1110.001 — Brute Force: Password Guessing

---

### Encoded PowerShell Detection

```spl
index=wineventlog EventCode=1
Image="*\\powershell.exe"
CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, User, CommandLine, ParentImage
```

**What it detects:** PowerShell execution using base64-encoded commands. Attackers use encoding to obfuscate malicious payloads and evade signature-based detection.

**False Positives:** Some legitimate admin tools and automation frameworks (e.g., SCCM, DSC) use encoded commands. Check `ParentImage` — if the parent is an expected management tool, it's likely benign.

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell

---

### Suspicious Parent-Child Process

```spl
index=wineventlog EventCode=1
(ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\OUTLOOK.EXE")
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
| table _time, User, ParentImage, Image, CommandLine
```

**What it detects:** Office applications spawning command interpreters. This is the classic macro-based initial access pattern — a user opens a malicious document, the macro executes, and it launches PowerShell or cmd to download and run a payload.

**False Positives:** Rare. Some legacy enterprise tools use Office macros that shell out to cmd.exe for legitimate automation. Verify by checking `CommandLine` content — legitimate scripts typically reference known internal paths or tools.

**MITRE:** T1204.002 — User Execution: Malicious File → T1059.001 — PowerShell

---

### Recon Activity Detection

```spl
index=wineventlog EventCode=1
(CommandLine="*whoami*" OR CommandLine="*whoami /priv*"
 OR CommandLine="*net user*" OR CommandLine="*net localgroup*"
 OR CommandLine="*systeminfo*" OR CommandLine="*ipconfig*"
 OR CommandLine="*nltest /dclist*" OR CommandLine="*net group*domain*")
| table _time, User, CommandLine, ParentImage
| sort _time
```

**What it detects:** Post-exploitation discovery commands. After gaining initial access, attackers enumerate the environment to understand what account they have, what privileges are available, and what the network looks like.

**False Positives:** IT admins troubleshooting, helpdesk running diagnostic commands. Context matters — a cluster of 4-5 of these commands within a few minutes from the same user is suspicious. A single `ipconfig` is not.

**MITRE ATT&CK mapping:**

| Command | Technique |
|---------|-----------|
| `whoami`, `whoami /priv` | T1033 — System Owner/User Discovery |
| `net user`, `net localgroup` | T1087.001 — Account Discovery: Local Account |
| `net group /domain` | T1087.002 — Account Discovery: Domain Account |
| `systeminfo` | T1082 — System Information Discovery |
| `ipconfig /all` | T1016 — System Network Configuration Discovery |
| `nltest /dclist` | T1018 — Remote System Discovery |

---

### New Account Creation + Privilege Escalation

```spl
index=wineventlog (EventCode=4720 OR EventCode=4732)
| transaction Account_Name maxspan=5m
| where eventcount > 1
| table _time, Account_Name, EventCode, duration
```

**What it detects:** An account being created (4720) and added to a privileged group (4732) within 5 minutes. This is a textbook persistence pattern — attackers create a backdoor account and immediately elevate it.

**False Positives:** Legitimate onboarding by IT, but onboarding rarely involves adding accounts directly to the local Administrators group. Check if the account name follows your organization's naming convention.

**MITRE:** T1136.001 — Create Account: Local Account → T1078.003 — Valid Accounts: Local Accounts

---

## Part 6 — Multi-Stage Attack Chain: Simulation and Detection

This section walks through a complete attack simulation, the events it generates, and how the detection queries catch it. The goal is to show how individual alerts connect into a single attack narrative.

### Attack Scenario

An attacker brute-forces a local account, gains access, runs reconnaissance, creates a backdoor admin account, and executes encoded PowerShell.

### Step 1 — Brute Force (Initial Access)

**Simulation:**

Lock the workstation and enter the wrong password 8 times, then log in with the correct password.

**Events generated:**

- 8x EventCode 4625 (failed logon) for the target account
- 1x EventCode 4624 (successful logon) with Logon Type 2 (interactive)
- 1x EventCode 4672 (special privileges assigned) because the account is a local admin

**Detection query that fires:**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624 OR EventCode=4672)
| eval account=coalesce(Account_Name, TargetUserName, SubjectUserName)
| stats count(eval(EventCode=4625)) as failed
        count(eval(EventCode=4624)) as success
        count(eval(EventCode=4672)) as privileged
        by account
| where failed > 3 AND success > 0 AND privileged > 0
```

**Result:** The target account shows `failed=8`, `success=1`, `privileged=1` — brute force followed by privileged access.

### Step 2 — Reconnaissance (Discovery)

**Simulation:**

```bash
whoami
whoami /priv
net user
net localgroup administrators
systeminfo
ipconfig /all
```

**Events generated:**

- 6x EventCode 1 (Sysmon process creation) with full command lines
- Parent process is `cmd.exe`, launched by `explorer.exe`

**Detection query that fires:** The recon activity query catches all six commands and shows them in chronological order. The cluster of discovery commands within 1-2 minutes from the same user account that just had a brute force alert is a strong indicator of compromise.

### Step 3 — Persistence (Create Backdoor Account)

**Simulation:**

```bash
net user backdoor P@ssw0rd! /add
net localgroup administrators backdoor /add
```

**Events generated:**

- EventCode 4720 (account created: `backdoor`)
- EventCode 4732 (account `backdoor` added to Administrators group)
- Both events occur within seconds of each other

**Detection query that fires:** The account creation + privilege escalation transaction query catches both events linked to the same account within the 5-minute window. `duration` shows near-zero seconds, confirming it was scripted rather than a manual onboarding process.

### Step 4 — Execution (Encoded PowerShell)

**Simulation:**

```powershell
powershell -enc dwBoAG8AYQBtAGkA
```

(This is the base64 encoding of `whoami` — harmless for simulation purposes.)

**Events generated:**

- EventCode 1 (Sysmon) with `Image=powershell.exe` and `CommandLine` containing `-enc`
- `ParentImage` shows `cmd.exe`

**Detection query that fires:** The encoded PowerShell detection query catches the `-enc` flag. In a real attack, the encoded payload would be a download cradle or reverse shell, not `whoami`.

### Connecting the Chain

Looking at the full timeline for this user account:

| Time | Event | Detection |
|------|-------|-----------|
| T+0:00 | 8 failed logons (4625) | Brute force alert |
| T+0:02 | Successful logon (4624) + privileges (4672) | Multi-stage correlation alert |
| T+0:04 | whoami, net user, systeminfo... (Sysmon 1) | Recon activity alert |
| T+0:06 | Account created + added to admins (4720, 4732) | Account persistence alert |
| T+0:08 | Encoded PowerShell executed (Sysmon 1) | Encoded PowerShell alert |

Five separate detections, one attack. This is why correlated, multi-stage detection matters — any single alert could be a false positive, but the pattern together is unmistakable.

---

## Part 7 — Investigation Workflow

This is a practical walkthrough of how to investigate a brute force alert using Splunk queries at each step. The scenario: the brute force detection query fired for the account `jad`.

### Step 1 — Scope the Alert

Start by understanding the volume and timeframe of failed logons.

```spl
index=wineventlog EventCode=4625 Account_Name="jad"
| stats count, earliest(_time) as first_attempt, latest(_time) as last_attempt
| eval first_attempt=strftime(first_attempt, "%Y-%m-%d %H:%M:%S")
| eval last_attempt=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
```

This tells you how many failed attempts occurred and over what time window. 8 failures in 30 seconds suggests an automated attack. 8 failures over 3 hours suggests a user who forgot their password.

### Step 2 — Check If the Attacker Got In

```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) Account_Name="jad"
| sort _time
| table _time, EventCode, Logon_Type, Source_Network_Address
```

Look at the sequence. If you see a string of 4625s followed by a 4624, the attacker guessed the password. Check `Logon_Type` — Type 2 means they were at the keyboard, Type 10 means RDP, Type 3 means network logon.

### Step 3 — Check for Privilege Escalation

```spl
index=wineventlog EventCode=4672 Account_Name="jad"
| table _time, Account_Name, PrivilegeList
```

If 4672 appears right after the successful logon, the compromised account has admin privileges. This dramatically increases the severity of the incident.

### Step 4 — Look for Post-Access Activity

```spl
index=wineventlog EventCode=1 User="*jad*"
| table _time, Image, CommandLine, ParentImage
| sort _time
```

This shows every process the account launched after logging in. Look for recon commands (whoami, net user, systeminfo), encoded PowerShell, or any unexpected executables.

### Step 5 — Check for Persistence

```spl
index=wineventlog (EventCode=4720 OR EventCode=4732 OR EventCode=4724)
| where _time > relative_time(now(), "-1h")
| table _time, EventCode, Account_Name, Security_ID
```

Check if any new accounts were created (4720), added to privileged groups (4732), or had passwords reset (4724) in the timeframe around the incident.

### Step 6 — Build the Timeline

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624 OR EventCode=4672 OR EventCode=4720 OR EventCode=4732 OR EventCode=1)
| eval account=coalesce(Account_Name, User, TargetUserName)
| search account="*jad*"
| sort _time
| table _time, EventCode, account, CommandLine, Image, ParentImage
```

This pulls all relevant events for the account into a single chronological view. This is the timeline you'd present in an incident report — it tells the full story of what happened from initial access through post-exploitation.

### Decision Point

Based on the investigation:

- **If failed logons only, no successful logon:** No compromise. Monitor the account, consider a password reset as a precaution.
- **If successful logon but no suspicious follow-up activity:** Possible legitimate user who mistyped their password. Verify with the account owner.
- **If successful logon + recon + persistence:** Confirmed compromise. Disable the account, remove any backdoor accounts, isolate the host, begin forensic imaging.

---

## Part 8 — Sigma Rules

### Rule 1: Encoded PowerShell Execution

```yaml
title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-1111-2222-3333-444455556666
status: experimental
description: Detects PowerShell execution with encoded commands, commonly used to obfuscate malicious payloads.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - '-EncodedCommand'
  condition: selection
falsepositives:
  - SCCM and DSC configurations
  - Enterprise automation frameworks
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

**Converted SPL:**

```spl
index=wineventlog EventCode=1 Image="*\\powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-EncodedCommand*")
| table _time, User, CommandLine, ParentImage
```

---

### Rule 2: Brute Force — Multiple Failed Logons

```yaml
title: Brute Force - Multiple Failed Logon Attempts
id: a1b2c3d4-5555-6666-7777-888899990000
status: experimental
description: Detects more than 5 failed logon attempts for a single account, indicating a possible brute force attack.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count(TargetUserName) by TargetUserName > 5
falsepositives:
  - Users who forgot their password
  - Service accounts with expired or rotated credentials
  - Account lockout testing by IT
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
```

**Converted SPL:**

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name
| where count > 5
| sort -count
```

---

### Rule 3: Office Application Spawning Command Interpreter

```yaml
title: Suspicious Office Application Child Process
id: a1b2c3d4-aaaa-bbbb-cccc-ddddeeeeffff
status: experimental
description: Detects Microsoft Office applications spawning command interpreters, which typically indicates macro-based malware execution.
logsource:
  product: windows
  category: process_creation
detection:
  parent_selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
  child_selection:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: parent_selection and child_selection
falsepositives:
  - Legacy enterprise macros that invoke cmd.exe for legitimate automation
level: high
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1059.001
```

**Converted SPL:**

```spl
index=wineventlog EventCode=1
(ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.EXE" OR ParentImage="*\\OUTLOOK.EXE")
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")
| table _time, User, ParentImage, Image, CommandLine
```

---

### Rule 4: Recon Command Cluster

```yaml
title: Post-Exploitation Reconnaissance Command Burst
id: a1b2c3d4-1234-5678-9abc-def012345678
status: experimental
description: Detects multiple system discovery commands executed within a short timeframe, indicating post-exploitation enumeration.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'whoami'
      - 'net user'
      - 'net localgroup'
      - 'systeminfo'
      - 'ipconfig'
      - 'nltest'
  condition: selection | count() by User > 3
  timeframe: 5m
falsepositives:
  - IT administrators running diagnostic scripts
  - Onboarding or provisioning automation
level: medium
tags:
  - attack.discovery
  - attack.t1033
  - attack.t1087.001
  - attack.t1082
  - attack.t1016
```

**Converted SPL:**

```spl
index=wineventlog EventCode=1
(CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*net localgroup*" OR CommandLine="*systeminfo*" OR CommandLine="*ipconfig*" OR CommandLine="*nltest*")
| bucket _time span=5m
| stats count by User, _time
| where count > 3
```

---

## Part 9 — Key Event IDs

### Authentication

| EventCode | Description | Detection Use |
|-----------|-------------|---------------|
| 4624 | Successful login | Baseline activity, check logon type and timing |
| 4625 | Failed login | Brute force indicator at high volume |
| 4672 | Admin privileges assigned | Track who gets elevated access |
| 4648 | Logon with explicit credentials | Detects use of "Run As" or credential passing |

### Account Activity

| EventCode | Description | Detection Use |
|-----------|-------------|---------------|
| 4720 | Account created | Backdoor account creation |
| 4724 | Password reset attempted | Account takeover via password reset |
| 4726 | Account deleted | Covering tracks after using a temp account |
| 4732 | Added to local security group | Privilege escalation to Administrators |

### Sysmon

| EventCode | Description | Detection Use |
|-----------|-------------|---------------|
| 1 | Process creation | Full command-line and parent-child visibility |
| 3 | Network connection | Outbound C2 detection from suspicious processes |
| 8 | CreateRemoteThread | Process injection detection |
| 11 | File create | Malware drops in temp directories |

### System

| EventCode | Description | Detection Use |
|-----------|-------------|---------------|
| 7045 | New service installed | Persistence via malicious services |
| 1102 | Audit log cleared | Almost always indicates an attacker covering tracks |

---

## Final Notes

This lab covers the full cycle: generating attack activity, detecting it with SPL queries and Sigma rules, correlating events into multi-stage attack chains, and investigating alerts through a structured query-driven workflow.

Every detection is mapped to MITRE ATT&CK, includes false positive analysis, and is paired with a vendor-agnostic Sigma rule. The investigation workflow demonstrates how to pivot from a single alert to a complete incident timeline using Splunk.
