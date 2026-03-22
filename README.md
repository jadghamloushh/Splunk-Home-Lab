# Building a Security Monitoring Home Lab with Splunk

This is a walkthrough of how I built a home SIEM lab using Splunk to monitor Windows security events, detect attacks, and set up automated alerts. The goal was to simulate what a real SOC analyst does day-to-day — ingest logs, write detections, and respond to threats.

Everything here runs on a single Windows machine. No cloud, no paid tools, no VMs required.

---

## What This Lab Covers

- Installing and configuring Splunk Enterprise (free version)
- Forwarding Windows Security logs using Splunk Universal Forwarder
- Writing SPL queries to detect brute force, privilege escalation, and suspicious activity
- Setting up scheduled alerts that fire automatically
- Understanding key Windows Event IDs for security monitoring

---

## Part 1 — Installing Splunk

### Splunk Enterprise

1. Go to [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html) and download Splunk Enterprise (the free license lets you ingest up to 500MB/day, which is plenty for a home lab).

2. Run the installer, leave everything as default. During setup you'll create an admin username and password — remember these, you'll use them to log into the web interface.

3. Once installed, Splunk runs as a service. Open your browser and go to:

```
http://localhost:8000
```

4. Log in with the credentials you just created. You should see the Splunk home screen.

### Splunk Universal Forwarder

The Universal Forwarder is a lightweight agent that sits on your machine and sends logs to Splunk. This is how it works in real enterprise environments — forwarders on endpoints, Splunk on a central server.

1. Download the Universal Forwarder from [splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html).

2. Run the installer. When it asks for a receiving indexer, enter:

```
localhost:9997
```

3. Finish the install with default settings.

---

## Part 2 — Setting Up Log Ingestion

### Create the Index

Before Splunk can store your logs, you need to create an index (think of it as a folder where specific logs go).

1. In Splunk, go to **Settings → Indexes → New Index**
2. Index name: `wineventlog`
3. Leave everything else as default
4. Click **Save**

If you skip this step, Splunk silently drops all incoming logs because it has nowhere to put them. I learned this the hard way.

### Enable the Receiving Port

Splunk needs to listen on a port for incoming data from the forwarder.

1. Go to **Settings → Forwarding and Receiving**
2. Click **Configure Receiving**
3. Click **New Receiving Port**
4. Enter `9997`
5. Save

### Configure the Forwarder

Now tell the forwarder what logs to collect and where to send them.

Navigate to:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local
```

Create a file called `inputs.conf` and paste this:

```ini
[WinEventLog://Security]
disabled = 0
start_from = newest
index = wineventlog

[WinEventLog://System]
disabled = 0
start_from = newest
index = wineventlog
```

This tells the forwarder to collect Windows Security and System logs and send them to the `wineventlog` index.

In the same folder, create a file called `outputs.conf` and paste this:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 127.0.0.1:9997
```

This tells the forwarder to send everything to Splunk on port 9997 (localhost since both are on the same machine).

### Restart the Forwarder

Open CMD as admin:

```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk restart
```

### Verify It Works

Go to Splunk and run:

```spl
index=wineventlog
```

You should start seeing events flowing in. If nothing shows up, check:

- Is the forwarder running? → `sc query SplunkForwarder` (should say RUNNING)
- Is port 9997 listening? → `netstat -an | findstr 9997` (should show LISTENING and ESTABLISHED)
- Does the index exist? → Settings → Indexes → look for `wineventlog`

---

## Part 3 — Generating Security Events

A SIEM with only normal logon events isn't very interesting. To practice detection, you need to generate activity that looks like an attack.

### Simulate a Brute Force Attack

Lock your PC (Win + L) and enter the wrong password 15-20 times, then log in with the correct password. This creates a bunch of EventCode 4625 (failed logon) followed by a 4624 (successful logon) — the exact pattern of a brute force attack that eventually succeeds.

### Simulate Account Persistence

Open CMD as admin and run:

```cmd
net user testattacker Password123! /add
net localgroup administrators testattacker /add
net user testattacker /delete
```

This creates a new user, adds it to the admin group, then deletes it. Splunk will capture EventCode 4720 (account created), 4732 (added to admin group), and 4726 (account deleted). This is exactly what an attacker does when they want to create a backdoor account.

### Simulate Reconnaissance

Open PowerShell and run commands that attackers typically use after gaining access:

```powershell
whoami
net user
net localgroup administrators
systeminfo
ipconfig /all
```

If command line auditing is enabled, these show up as EventCode 4688 with the full command line visible.

### Enable Command Line Auditing

This is important — without this, EventCode 4688 only shows the process name, not what command was actually run.

1. Open `gpedit.msc`
2. Navigate to: Computer Configuration → Administrative Templates → System → Audit Process Creation
3. Enable **Include command line in process creation events**
4. Then go to: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Detailed Tracking
5. Set **Audit Process Creation** to **Success**

---

## Part 4 — Detection Queries

These are the SPL queries I use to find suspicious activity in the logs.

### Brute Force Detection

Find accounts with a high number of failed logons:

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name
| where count > 5
| sort -count
```

### Brute Force Timeline

See when the failed logons happened (useful for spotting spikes):

```spl
index=wineventlog EventCode=4625
| timechart span=5m count
```

### Brute Force Followed by Success

This is the dangerous one — failed attempts followed by a successful logon means the password was guessed:

```spl
index=wineventlog EventCode=4625 OR EventCode=4624
| eval target_account=if(EventCode=4625, mvindex(Account_Name, 1), mvindex(Account_Name, 0))
| stats count(eval(EventCode=4625)) as Failed, count(eval(EventCode=4624)) as Success by target_account
| where target_account!="JADS-LAPTOP$" AND target_account!="-" AND target_account!="SYSTEM"
| sort -Failed
```

A note on the `mvindex` usage here: in 4625 events, the `Account_Name` field is multi-valued. Position 0 is the machine account (Subject), position 1 is the actual account that failed. Without `mvindex`, Splunk mixes these up and you get misleading results.

### New Account Creation

Catch when someone creates a new user:

```spl
index=wineventlog EventCode=4720
| table _time, Account_Name, Security_ID, ComputerName
```

### User Added to Admin Group

Catch privilege escalation via group membership:

```spl
index=wineventlog EventCode=4732
| table _time, Account_Name, Security_ID, ComputerName
```

### Backdoor Account Pattern

Account created and immediately added to admin group — classic attacker persistence:

```spl
index=wineventlog EventCode=4720 OR EventCode=4732
| transaction Account_Name maxspan=5m
| where eventcount > 1
| table _time, Account_Name, EventCode, duration
```

### Logon Activity by Type

Understand how users are authenticating:

```spl
index=wineventlog EventCode=4624
| stats count by Logon_Type
| eval description=case(
    Logon_Type=2, "Interactive (keyboard)",
    Logon_Type=3, "Network (SMB/share)",
    Logon_Type=4, "Batch",
    Logon_Type=5, "Service",
    Logon_Type=7, "Unlock",
    Logon_Type=10, "Remote Desktop (RDP)",
    Logon_Type=11, "Cached credentials",
    1=1, "Other"
)
| table Logon_Type, description, count
| sort -count
```

### Suspicious Process Execution

Detect common recon commands (requires command line auditing enabled):

```spl
index=wineventlog EventCode=4688
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*net localgroup*" OR CommandLine="*systeminfo*" OR CommandLine="*ipconfig*"
| table _time, Account_Name, CommandLine, ParentProcessName
```

### PowerShell Execution

```spl
index=wineventlog EventCode=4688 NewProcessName="*powershell*"
| table _time, Account_Name, CommandLine, ParentProcessName
```

### Audit Log Cleared

An attacker covering their tracks:

```spl
index=wineventlog EventCode=1102
| table _time, Account_Name, ComputerName
```

### Full Event Overview

Quick summary of everything happening in your environment:

```spl
index=wineventlog
| stats count by EventCode
| eval description=case(
    EventCode=4624, "Successful Logon",
    EventCode=4625, "Failed Logon",
    EventCode=4634, "Logoff",
    EventCode=4648, "Explicit Credential Logon",
    EventCode=4672, "Special Privileges Assigned",
    EventCode=4688, "Process Created",
    EventCode=4720, "User Account Created",
    EventCode=4726, "User Account Deleted",
    EventCode=4732, "Member Added to Security Group",
    EventCode=1102, "Audit Log Cleared",
    1=1, "Other"
)
| table EventCode, description, count
| sort -count
```

---

## Part 5 — Setting Up Alerts

Alerts turn passive log collection into active monitoring. Instead of manually running queries, Splunk checks automatically and notifies you when something is wrong.

To create an alert: **Settings → Searches, Reports, and Alerts → New Alert**

### Alert 1 — Brute Force Detection

- **Title:** Brute Force — Multiple Failed Logons
- **Description:** Detects accounts with more than 5 failed logon attempts, indicating a possible brute force attack
- **Search:**
  ```spl
  index=wineventlog EventCode=4625
  | stats count by Account_Name
  | where count > 5
  ```
- **Schedule:** every 5 minutes
- **Trigger:** Per-Result, Number of Results > 0
- **Action:** Log Event → `bruteforce attempt detected`

### Alert 2 — New Admin Account

- **Title:** New Account Created or Added to Admin Group
- **Description:** Detects new user account creation or addition to administrator group, which could indicate an attacker establishing persistence
- **Search:**
  ```spl
  index=wineventlog EventCode=4720 OR EventCode=4732
  | table _time, Account_Name, EventCode, ComputerName
  ```
- **Schedule:** every 5 minutes
- **Trigger:** Per-Result, Number of Results > 0
- **Action:** Log Event → `new account or admin group change detected`

### Alert 3 — Audit Log Cleared

- **Title:** Security Log Cleared — Possible Tampering
- **Description:** Detects when the security audit log is cleared, a common technique attackers use to cover their tracks
- **Search:**
  ```spl
  index=wineventlog EventCode=1102
  | table _time, Account_Name, ComputerName
  ```
- **Schedule:** every 5 minutes
- **Trigger:** Per-Result, Number of Results > 0
- **Action:** Log Event → `audit log cleared`

### Alert 4 — Suspicious Recon Commands

- **Title:** Suspicious Reconnaissance Commands Detected
- **Description:** Detects common post-exploitation enumeration commands like whoami, net user, and systeminfo
- **Search:**
  ```spl
  index=wineventlog EventCode=4688
  | search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*net localgroup*" OR CommandLine="*systeminfo*"
  | table _time, Account_Name, CommandLine
  ```
- **Schedule:** every 5 minutes
- **Trigger:** Per-Result, Number of Results > 0
- **Action:** Log Event → `recon commands detected`

---

## Part 6 — Important Windows Event IDs

These are the event codes that matter most for security monitoring. Knowing what these mean is essential for any SOC role.

### Authentication Events

| EventCode | Description | Why It Matters |
|-----------|-------------|----------------|
| 4624 | Successful logon | Normal activity, but check logon types and timing |
| 4625 | Failed logon | Brute force indicator when count is high |
| 4634 | Logoff | Session tracking |
| 4648 | Logon with explicit credentials | Someone used "Run As" or passed credentials manually |
| 4672 | Special privileges assigned | Admin-level logon — track who gets elevated access |

### Logon Types (inside EventCode 4624)

| Logon Type | Meaning | Security Context |
|-----------|---------|-----------------|
| 2 | Interactive | Someone at the keyboard |
| 3 | Network | Accessing a share or SMB — watch for lateral movement |
| 4 | Batch | Scheduled task ran |
| 5 | Service | A Windows service started |
| 7 | Unlock | Workstation unlocked |
| 10 | RemoteInteractive | RDP session — monitor for unauthorized remote access |
| 11 | Cached credentials | Logged in with cached creds (domain controller unreachable) |

### Account Management Events

| EventCode | Description | Why It Matters |
|-----------|-------------|----------------|
| 4720 | User account created | Could be attacker creating backdoor account |
| 4722 | User account enabled | Reactivating a disabled account |
| 4724 | Password reset attempted | Attacker resetting password to take over account |
| 4726 | User account deleted | Covering tracks after using a temp account |
| 4728 | Member added to global security group | Privilege escalation |
| 4732 | Member added to local security group | Privilege escalation (e.g., adding to Administrators) |

### Process and System Events

| EventCode | Description | Why It Matters |
|-----------|-------------|----------------|
| 4688 | New process created | Track what executables are running and their command lines |
| 4697 | Service installed | Attacker installing a malicious service for persistence |
| 7045 | New service installed (System log) | Same as 4697 but logged differently |
| 1102 | Audit log cleared | Almost always malicious — attackers covering tracks |

### Failure Status Codes (inside EventCode 4625)

| Status Code | Meaning |
|-------------|---------|
| 0xC000006D | Bad username or password |
| 0xC000006A | Correct username, wrong password (useful for distinguishing brute force from typos) |
| 0xC0000072 | Account disabled |
| 0xC0000234 | Account locked out |
| 0xC0000064 | Username does not exist |

---

## Tools Used

- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free license, 500MB/day)
- [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)
- Windows 10/11 with built-in Security Event Logging
- SPL (Search Processing Language)

---

## What I Learned

- How to set up end-to-end log ingestion from endpoint to SIEM
- How to troubleshoot data ingestion issues (port listening, index creation, forwarder connectivity)
- How to read and interpret Windows Security Event Logs
- How to write SPL queries for threat detection
- How to build automated alerts that detect attacks in near real-time
- The importance of multi-value field handling in Splunk (the `mvindex` lesson with 4625 events)
- How brute force attacks, privilege escalation, and attacker persistence look in raw log data
