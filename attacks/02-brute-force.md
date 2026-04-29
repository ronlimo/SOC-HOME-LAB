# INC-002: Brute Force + Remote Access

## Incident Details

| Field | Detail |
|---|---|
| Incident ID | INC-002 |
| Date | April 28, 2026 |
| Attacker IP | 192.168.56.105 (Kali Linux) |
| Target IP | 192.168.56.104 (Windows 11) |
| Target Account | targetuser |
| Tools Used | Hydra 9.5 + Evil-WinRM 3.7 |
| MITRE | T1110 — Brute Force, T1021.006 — WinRM Remote Access |

---

## Objective

Using port 5985 (WinRM) discovered in INC-001, simulate a 
credential brute force attack and establish a remote shell 
on the target machine.

---

## Steps Taken

1. Created custom wordlist with 6 passwords including correct 
   password Password123
2. Ran Hydra against WinRM (port 5985) targeting targetuser
3. Pivoted to Evil-WinRM using discovered credentials
4. Confirmed access with whoami command inside remote shell

---

## Commands Executed

```bash
hydra -l targetuser -P ~/passwords.txt rdp://192.168.56.104 -t 4 -V
evil-winrm -i 192.168.56.104 -u targetuser -p Password123
whoami
```

---

## Evidence from Splunk

1,093 total events generated across EventCode 4624 and 4625.

| Event ID | Description | Count | Notes |
|---|---|---|---|
| 4624 | Successful Logon | 1,091 | WinRM handshake traffic logged as network logons |
| 4625 | Failed Logon | 2 | Only 2 explicit auth failures despite multiple attempts |

**Key Finding:** WinRM brute force generates 99.8% Event ID 4624 
vs only 0.2% Event ID 4625. This differs significantly from RDP 
brute force and requires protocol-aware detection tuning.

---

## Splunk Queries Used

```spl
index=main EventCode=4625
| table _time, Account_Name, IpAddress
| sort -_time
```

```spl
index=main (EventCode=4625 OR EventCode=4624)
| sort _time
```

---

## Detection Rules

**Brute Force Detection:**
```spl
index=main EventCode=4625
| bucket _time span=5m
| stats count by _time, IpAddress, Account_Name
| where count > 5
| eval alert="BRUTE FORCE DETECTED"
| eval MITRE="T1110"
```

**Account Compromise Detection:**
```spl
index=main (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
  count(eval(EventCode=4624)) as successes by src_ip, Account_Name
| where failures > 5 AND successes >= 1
| eval alert="POSSIBLE ACCOUNT COMPROMISE"
```

---

## Screenshots
Creating the targetuser
<img width="956" height="446" alt="windows target user created" src="https://github.com/user-attachments/assets/e862e792-1451-4d69-a9c1-0ecec5553fb8" />

Hydra Running
<img width="959" height="458" alt="Bruteforce Login" src="https://github.com/user-attachments/assets/3813ac06-465a-4580-94ba-cf8a866f6a9c" />

Splunk Events
<img width="417" height="225" alt="splunk 2" src="https://github.com/user-attachments/assets/2e3edf2c-f954-44e5-bcfd-f946ef31cda7" />
<img width="959" height="459" alt="splunk brutefore pattern" src="https://github.com/user-attachments/assets/a6587de9-1ff6-4f57-a6ee-2702ad23bb13" />

---

## MITRE ATT&CK

| Technique ID | Name | Application |
|---|---|---|
| T1110 | Brute Force | Hydra automated credential guessing against WinRM |
| T1021.006 | WinRM Remote Access | Evil-WinRM shell established using brute-forced credentials |

---

## Response Actions

1. Disable targetuser account immediately
2. Block 192.168.56.105 at firewall
3. Force password reset across all accounts
4. Implement account lockout after 5 failed attempts
5. Restrict WinRM to authorised IPs only
6. Deploy MFA on all remote access methods

