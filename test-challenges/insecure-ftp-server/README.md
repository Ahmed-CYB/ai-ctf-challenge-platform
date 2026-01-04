# Insecure FTP Server - CTF Challenge

## 🎯 Challenge Description

You've discovered an FTP server running on a target machine. The server appears to have security misconfigurations that could allow unauthorized access. Your mission is to exploit these vulnerabilities and retrieve the flag.

## 📋 Challenge Information

- **Category**: Network Security
- **Difficulty**: Easy
- **Type**: Misconfiguration Exploitation
- **Flag Location**: `/home/ftpuser/flag.txt`

## 🚀 Quick Start

### Start the Challenge
```powershell
docker-compose up -d --build
```

### Check Status
```powershell
docker ps
```

### Access Attacker Machine
```powershell
docker exec -it insecure-ftp-attacker bash
```

## 🔍 Solution Steps

### From Attacker Container

1. **Scan the target**
```bash
nmap -p 21 172.23.142.10
```

2. **Connect to FTP**
```bash
ftp 172.23.142.10
# Username: anonymous
# Password: (press Enter)
```

3. **List files and get flag**
```bash
ls
get flag.txt
bye
cat flag.txt
```

## 🔐 Flag

`CTF{ftp_4n0nym0us_4cc3ss_1s_d4ng3r0us_2024}`

## 🧹 Cleanup

```powershell
docker-compose down
```

---

Good luck! 🎉
