# INC-001: Network Reconnaissance

## Incident Details

| Field | Detail |
|---|---|
| Incident ID | INC-001 |
| Date | April 28, 2026 |
| Attacker IP | 192.168.56.105 (Kali Linux) |
| Target IP | 192.168.56.104 (Windows 11) |
| Tool Used | Nmap 7.95 |
| MITRE | T1595 — Active Scanning, T1046 — Network Service Discovery |

---

## Objective

Simulate an attacker performing network reconnaissance to map the 
attack surface of a target Windows machine before launching further 
attacks.

---

## Steps Taken

1. Ping sweep to confirm host was alive
2. Basic TCP port scan on top 1000 ports
3. Service version scan (-sV) to fingerprint services
4. Aggressive scan (-A) for OS detection and NSE scripts
5. Stealth SYN scan (-sS) to simulate evasive scanning
6. Port range scan (-p 1-1000)

---

## Commands Executed

```bash
nmap -sn 192.168.56.104
nmap 192.168.56.104
nmap -sV 192.168.56.104
nmap -A 192.168.56.104
sudo nmap -sS 192.168.56.104
nmap -p 1-1000 192.168.56.104
```

---

## Open Ports Discovered

| Port | Service | Significance |
|---|---|---|
| 135/tcp | MSRPC | Windows RPC |
| 139/tcp | NetBIOS-SSN | Legacy file sharing |
| 445/tcp | SMB | File sharing, lateral movement |
| 5357/tcp | WSDAPI | Web Services for Devices |
| **5985/tcp** | **WinRM** | **CRITICAL — enabled brute force in INC-002** |

---

## Detection in Splunk

```spl
index=main "192.168.56.105"
| spath input=_raw
| rename System.Computer as ComputerName, System.EventID as EventCode
| table _time, ComputerName, EventCode, _raw
| sort -_time
```

**Result:** 44 events returned from Kali IP showing rapid 
connection attempts across multiple ports — clear scan signature.

---

## Detection Rule

```spl
index=main EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports by _time, SourceIp
| where unique_ports > 20
| eval alert="PORT SCAN DETECTED"
| eval MITRE="T1046"
```

**Logic:** One source IP hitting 20+ distinct ports in 1 minute 
= automated port scanning behaviour.

---

## Screenshots
Nmap Scans
<img width="602" height="434" alt="service version scan" src="https://github.com/user-attachments/assets/99625d45-d8a2-4622-8055-912a209fc73f" />
<img width="959" height="460" alt="aggressive scan" src="https://github.com/user-attachments/assets/6a00d008-4e07-4751-b2f9-0521ca446648" />
<img width="424" height="342" alt="syn scan   port range" src="https://github.com/user-attachments/assets/a1bdd339-6a87-4398-beea-df33b8e263ab" />

Splunk Network Events
<img width="959" height="395" alt="unpacking the data" src="https://github.com/user-attachments/assets/ecde0c6c-c8e2-4ea4-affa-97f1877a356f" />
<img width="959" height="401" alt="Extracting" src="https://github.com/user-attachments/assets/bc3e23f4-8e8d-4196-ac48-624f003744e4" />


---

## MITRE ATT&CK

| Technique ID | Name | Application |
|---|---|---|
| T1595 | Active Scanning | Nmap ping sweep and aggressive scan |
| T1046 | Network Service Discovery | Port and service version scanning |

---

## Response Actions

1. Block 192.168.56.105 at the firewall immediately
2. Investigate all activity from this IP in the same time window
3. Restrict port 5985 (WinRM) to authorised management hosts only
4. Deploy network IDS rules for SYN scan patterns
