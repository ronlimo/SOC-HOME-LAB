# 🛰️ Incident INC-001: Network Reconnaissance (Nmap Scan)

## 📌 Overview
This attack simulates reconnaissance activity performed by an attacker using Nmap to identify open ports and services on a target machine.

---

## 🧪 Attack Details

- **Attacker Machine:** Kali Linux (192.168.56.105)  
- **Target Machine:** Windows 11 (192.168.56.104)  
- **Tool Used:** Nmap  

---

## ⚔️ Commands Executed

```bash
nmap -sn 192.168.56.104
nmap 192.168.56.104
nmap -sV 192.168.56.104
nmap -A 192.168.56.104
sudo nmap -sS 192.168.56.104
nmap -p 1-1000 192.168.56.104