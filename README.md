# 🔵 SOC Home Lab — Threat Detection & Incident Response

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Platform](https://img.shields.io/badge/Platform-Windows_11-blue)
![Attacker](https://img.shields.io/badge/Attacker-Kali_Linux-black)

---

## Overview



This is a fully operational SOC home lab where I designed the 
environment, executed the attacks, built the detections, investigated 
the alerts, and documented the findings

Three real attack scenarios were simulated against a Windows 11 
target using Kali Linux as the attacker machine. Every attack was 
detected using Splunk Enterprise with custom SPL detection rules 
mapped to the MITRE ATT&CK framework. A full incident report was 
produced covering evidence, timeline and response actions.

This project demonstrates the ability to detect, investigate and respond to real-world attack patterns using SIEM tooling in a controlled lab environment

---

## Skills Demonstrated

| Skill | Proof |
|---|---|
| Detection Engineering | 6 custom SPL detection rules built and validated |
| Log Analysis | 1,093+ security events analysed across 3 incidents |
| Threat Intelligence | Full MITRE ATT&CK kill chain mapped |
| Incident Response | Complete incident report with timeline and containment |
| Endpoint Monitoring | Sysmon + Windows Security Auditing configured from scratch |
| Network Analysis | Nmap reconnaissance detected and correlated in Splunk |
| Attacker Methodology | Brute force, LotL, encoded commands, payload staging simulated |
| SIEM Administration | Splunk Universal Forwarder configured, inputs.conf tuned |

---

## Lab Architecture

| Component | Details |
|---|---|
| Attacker | Kali Linux VM — 192.168.56.105 |
| Target | Windows 11 Home VM — 192.168.56.104 |
| SIEM | Splunk Enterprise 10.2.2 |
| Endpoint Monitoring | Sysmon + Windows Security Auditing |
| Network | VirtualBox Host-Only Adapter — Isolated |
| Hypervisor | Oracle VirtualBox |


---

## Attack Scenarios Simulated

| # | Incident | Attack Type | Tool Used | MITRE | Events Detected |
|---|---|---|---|---|---|
| INC-001 | [Network Reconnaissance](attacks/01-network-reconnaissance.md) | Port & Service Scanning | Nmap 7.95 | T1595, T1046 | 44 Events |
| INC-002 | [Brute Force + Remote Access](attacks/02-brute-force.md) | Credential Brute Force + WinRM Shell | Hydra 9.5 + Evil-WinRM 3.7 | T1110, T1021.006 | 1,093 Events |
| INC-003 | [Post-Exploitation PowerShell](attacks/03-powershell-execution.md) | Living-off-the-Land Execution | PowerShell (Built-in) | T1059.001, T1087, T1105 | 45+ Events |

---

## 🔗 Full Attack Kill Chain

These scenarios are not independent events - they represent a unified attack chain that reflects real-world adversary behavior across multiple stages of compromise.
```text
[Kali Linux — Attacker]
        |
        v
STAGE 1 — RECONNAISSANCE
Nmap discovers port 5985 (WinRM) open on target
        |
        v
STAGE 2 — CREDENTIAL ACCESS
Hydra brute forces WinRM credentials for targetuser
        |
        v
STAGE 3 — INITIAL ACCESS
Evil-WinRM establishes remote shell as windows\targetuser
        |
        v
STAGE 4 — EXECUTION & DISCOVERY
PowerShell executes: whoami, net user, systeminfo, encoded commands
        |
        v
STAGE 5 — COLLECTION & STAGING
Invoke-WebRequest downloads payload to C:\Windows\Temp
```
**MITRE Chain:**
`T1595 → T1046 → T1110 → T1021.006 → T1059.001 → T1087 → T1105`

---

## Detection Rules Built

| # | Rule | Detects | MITRE |
|---|---|---|---|
| 1 | [Port Scan Detection](detection-rules/01-port-scan.spl) | 20+ ports hit from same IP in 1 minute | T1046 |
| 2 | [Brute Force Detection](detection-rules/02-brute-force.spl) | 5+ failed logins from same IP in 5 minutes | T1110 |
| 3 | [Account Compromise](detection-rules/03-account-compromise.spl) | Failures followed by success from same IP | T1110 |
| 4 | [Encoded PowerShell](detection-rules/04-encoded-powershell.spl) | -EncodedCommand flag in CommandLine | T1059.001 |
| 5 | [Recon Command Sequence](detection-rules/05-recon-commands.spl) | whoami, systeminfo, net.exe from PowerShell parent | T1087 |
| 6 | [File Write to Temp](detection-rules/06-file-write-temp.spl) | PowerShell writing files to C:\Windows\Temp | T1074 |

---

## 🔍 Detection Deep Dive: Brute Force Attack

This is a full walkthrough of one detection rule — from alert
to investigation to response. This is the workflow a SOC analyst
follows in a real environment.

### SPL Query

```spl
index=main EventCode=4625
| bucket _time span=5m
| stats count by _time, IpAddress, Account_Name
| where count > 5
| eval alert="BRUTE FORCE DETECTED"
| eval MITRE="T1110"
```

### Why This Works

Windows logs every failed authentication attempt as Event ID 4625.
In normal usage, a legitimate user rarely fails to log in more than
twice before contacting support. When a single source IP generates
more than 5 failures against the same account within 5 minutes,
that pattern is statistically inconsistent with human behaviour
and consistent with automated credential stuffing.

The `bucket` command groups events into 5-minute windows so the
count resets per time period — this prevents a low-and-slow attack
spread across hours from avoiding detection. The `stats count by`
groups by both IP and account so we catch attacks targeting
multiple accounts from the same source.

### What the Analyst Does After This Alert Fires

1. Confirm the source IP — is it internal or external?
2. Check if any Event ID 4624 (successful login) followed the
   failures from the same IP — if yes, account is likely compromised
3. Check what account was targeted — service account, admin,
   or standard user?
4. Look at the timeframe — was this during business hours or 3am?
5. Check for lateral movement — did that IP or account do
   anything after the login?
6. Escalate if compromise is confirmed, block the source IP,
   disable the account

### False Positives to Consider

- **Helpdesk password resets** — admin staff resetting passwords
  can trigger multiple 4625 events
- **Service accounts** — misconfigured services using expired
  credentials generate repeated failures
- **VPN lockouts** — users on VPN with cached wrong credentials
  generate bursts of failures

### Tuning Strategy

- Whitelist known service account IPs from this rule
- Raise threshold to 10 if false positive rate is too high
  in your environment
- Add `Logon_Type=3` condition to focus only on network logons,
  filtering out local login failures

---

##  SOC Analyst Workflow Demonstrated

This project follows the full SOC analyst workflow from log
ingestion to documentation.

| Step | Action | Tool Used |
|---|---|---|
| 1 | Log Ingestion | Sysmon + Windows Security Auditing → Splunk UF |
| 2 | Detection Triggered | Custom SPL rules fire on anomalous events |
| 3 | Alert Triage | Analyst reviews alert — real or false positive? |
| 4 | Investigation | Event correlation across EventCode 4624, 4625, 4688, 3 |
| 5 | Incident Classification | Mapped to MITRE ATT&CK techniques |
| 6 | Containment & Response | Block IP, disable account, isolate machine |
| 7 | Documentation | Incident report written with evidence and timeline |

---

## Key Findings

- Successfully detected all 3 attack scenarios in Splunk
- Built and validated 6 custom SPL detection rules
- **WinRM brute force generates 99.8% Event ID 4624 vs only 0.2%
  Event ID 4625** — detection behaviour differs significantly from
  RDP brute force and requires protocol-aware rule tuning
- Without enabling `ProcessCreationIncludeCmdLine_Output` in the
  registry, encoded PowerShell execution is completely invisible
  to Event ID 4688 — default Windows logging is insufficient
- The Splunk Universal Forwarder generated 72 false positive
  PowerShell events — demonstrating that tuning is not optional
  in a real SOC environment
- All three attacks form a single connected kill chain — not
  three isolated incidents

---

## 📸 Investigation Evidence

### Brute Force — 1,093 Events in Splunk
<img width="959" height="459" alt="splunk brutefore pattern" src="https://github.com/user-attachments/assets/b5d8a20d-a429-4741-9975-08cc6127ba23" />


### Evil-WinRM Shell Established After Brute Force
<img width="959" height="458" alt="Bruteforce Login" src="https://github.com/user-attachments/assets/1a60a13e-46bf-4424-8edc-083bdc7d24b8" />


### Nmap Discovering Port 5985 (WinRM Open)
<img width="424" height="342" alt="syn scan   port range" src="https://github.com/user-attachments/assets/8180617f-26a9-4ca3-88cc-d06f1aa6dee3" />


### PowerShell Recon Commands Caught in Splunk
<img width="424" height="342" alt="syn scan   port range" src="https://github.com/user-attachments/assets/6caf4c4b-e33d-4ef3-8e98-76853a28128b" />
<img width="959" height="403" alt="Identification of remote attacker vector" src="https://github.com/user-attachments/assets/7b77a3de-6b28-47c4-8db7-c248036a5520" />
<img width="957" height="403" alt="Suspicious shell execution" src="https://github.com/user-attachments/assets/e2a64775-ab0f-4ead-ac9c-59e07d3d236f" />


---

## Tools Used

- **Splunk Enterprise 10.2.2** — SIEM and log analysis
- **Splunk Universal Forwarder** — Log shipping from Windows to Splunk
- **Sysmon** — Endpoint telemetry (process creation, network connections)
- **Nmap 7.95** — Network reconnaissance
- **Hydra 9.5** — Credential brute force
- **Evil-WinRM 3.7** — Remote shell via WinRM
- **Oracle VirtualBox** — Hypervisor

---

## Documentation

- [Incident Report](reports/incident-report.md) — Full investigation
  report covering all 3 incidents with evidence, timeline, and
  response actions
- [Attack Write-ups](attacks/) — Detailed per-attack documentation
- [Detection Rules](detection-rules/) — All SPL rules with logic explained
- [Screenshots](screenshots/) — Evidence from Splunk and terminals

---

## 💼 Resume Description

* Designed and operated a personal SOC home lab to simulate, detect and investigate real-world cyberattacks. Executed a full 5-stage MITRE ATT&CK kill chain using Nmap, Hydra, Evil-WinRM, and PowerShell against a Windows 11 target. Engineered and tuned 6 custom Splunk SPL detection rules, analyzed 1,000+ security events, and performed alert triage to identify compromised activity. Identified protocol-specific detection gaps in WinRM authentication logs and documented findings in a structured incident report with timeline, evidence, and remediation actions.
---

## 👤 Author

**Ron Limo**  
BSc Information Technology — KCA University, Nairobi, Kenya  
Cybersecurity Analyst | SOC & Threat Detection  

🔗 GitHub: https://github.com/ronlimo  
📧 Email: ronkiptoo7@email.com | cyberkiptoo@gmail.com
