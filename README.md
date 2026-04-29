# 🔵 SOC Home Lab — Threat Detection & Incident Response

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Platform](https://img.shields.io/badge/Platform-Windows_11-blue)
![Attacker](https://img.shields.io/badge/Attacker-Kali_Linux-black)

## Overview

A hands-on home lab simulating real-world cyberattacks against a 
Windows 11 target machine and detecting them using Splunk Enterprise 
as the SIEM. This project covers the full attack lifecycle from 
reconnaissance through post-exploitation, and demonstrates 
end-to-end detection capability using custom SPL detection rules 
mapped to the MITRE ATT&CK framework.

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

![Lab Diagram](architecture/lab-diagram.png)

---

## Attack Scenarios Simulated

| # | Incident | Attack Type | Tool Used | MITRE Technique | Events Detected |
|---|---|---|---|---|---|
| INC-001 | [Network Reconnaissance](attacks/01-network-reconnaissance.md) | Port & Service Scanning | Nmap 7.95 | T1595, T1046 | 44 Events |
| INC-002 | [Brute Force + Remote Access](attacks/02-brute-force.md) | Credential Brute Force + WinRM Shell | Hydra 9.5 + Evil-WinRM 3.7 | T1110, T1021.006 | 1,093 Events |
| INC-003 | [Post-Exploitation PowerShell](attacks/03-powershell-execution.md) | Living-off-the-Land Execution | PowerShell (Built-in) | T1059.001, T1087, T1105 | 45+ Events |

---

## Kill Chain

These three attacks are not isolated — they form a complete
attack kill chain:

Nmap found port 5985 (WinRM) open
↓
Hydra brute forced WinRM credentials
↓
Evil-WinRM established remote shell
↓
PowerShell ran recon + staged payloads

MITRE Chain: T1595 → T1046 → T1110 → T1021.006 → T1059.001 → T1087 → T1105

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

## Key Findings

- Successfully detected all 3 attack scenarios in Splunk
- Built and validated 6 custom SPL detection rules
- WinRM brute force generates 99.8% Event ID 4624 vs 0.2% 
  Event ID 4625 — detection behaviour differs significantly 
  from RDP brute force
- All attacks mapped to MITRE ATT&CK framework
- Full incident report documented for all 3 scenarios

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
  report covering all 3 incidents
- [Attack Write-ups](attacks/) — Detailed per-attack documentation
- [Detection Rules](detection-rules/) — All SPL rules with logic explained
- [Screenshots](screenshots/) — Evidence from Splunk and terminals

---

## Author

**Ron**
BSc Information Technology — KCA University, Nairobi, Kenya
Blue Team / SOC Focus | TryHackMe | Splunk
