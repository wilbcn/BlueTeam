# 🛡️ Practical SOC Workflows Using Windows Event and Sysmon Logs

## 📘 Overview
This project simulates a realistic security incident on a Windows system and demonstrates how a SOC (Security Operations Center) analyst might investigate and respond using Windows Event Logs and Sysmon telemetry. The lab follows the NIST SP 800-61 framework for incident response, emphasising hands-on detection, containment, and remediation.

This project serves both as a learning resource and as a proof of concept to reinforce Windows forensic workflows, enhance detection engineering intuition, and build investigative muscle memory for real-world SOC environments.

- **Disclaimer**: The EC2 instances were terminated post project completion, and therefore majority of IP's have not been redacted. These instances no longer exist.

## 🎯 Project Objectives
- To simulate attacker behavior including enumeration, reconnaissance, brute-force (dictionary-based) authentication attempts, and post-compromise actions such as privilege escalation and persistence.
- To conduct a structured SOC-style investigation using built-in tools (Event Viewer, PowerShell) and third-party utilities (Sysmon), while practicing detection logic, log correlation, and incident response techniques.

## Tools
- AWS EC2 instances (windows & ubuntu)
- [nmap](https://nmap.org/)
- [Hydra](https://www.kali.org/tools/hydra/)
- Windows Event Viewer
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 📌 Project Phases
| Phase | Title | Description |
|-------|-------|-------------|
| 1     | Pre attack activities | Carry out enumeration and reconnaissance on the vulnerable server |
| 2     | Brute-force (dict attack) | The attacker brute forces authentication into the server via a dictionary attack | 
| 3     | Post-compromise | The attackers post compromise actions such as privilege escalation and persistence |
| 4     | SOC Investigation | SOC team is alerted of the security events and begins investigations following NIST SP 800-61 framework for Incident Response |
| 5     | MITRE ATTACK | Correlate the security events to MITRE ATTACK tools & techniques |
| 6     | Lessons learned | Project overview and summary of findings |

### 1. Pre attack activities
The pre attack activities are simulated by me to better understand the tools, techniques, and through processes behind attacker behaviours for enumeration and reconnaissance. I begin by performing an `nmap` scan on the public IP address of the target server.

```
sudo nmap -sS -Pn 16.170.231.38
```

- `-sS`: SYN scan (stealth scan)
- `-Pn`: Skips host discovery (assumes host is up)

![image](https://github.com/user-attachments/assets/f489032b-e585-41cf-a6fa-7a311ce935fc)

The attacker notes that port 3389 (RDP) is open on service: `ms-wbs-server`. After discovering this via nmap, the attacker begins a dictionary attack using `Hydra`, on common username credentials such as `itadmin`. They create a `password.txt` file containing common and weak passwords to begin their attack.

![image](https://github.com/user-attachments/assets/8d291ff1-beac-474e-bdf9-bf463967b840)

With the first password list ready, they run Hydra against the public IP address of the server.

```
hydra -t 1 -W 3 -V -l itadmin -P passwords.txt rdp://16.170.231.38
```

![image](https://github.com/user-attachments/assets/72b187f8-094e-4f00-80d1-72974e738c27)

This reveals a successful authentication via password `Summer2025`. The attacker then accesses the remote machine via RDP using the details discovered through this enumeration and reconaissance. Once inside, the attacker elevates a new account and adds it so a security-enabled group `Administrators`. The new user `svc_task` is a common naming convention to evade detection, mimicking real windows service accounts.

```
PS C:\Windows\system32> net user svc_task notevil123! /add
The command completed successfully.

PS C:\Windows\system32> net localgroup administrators svc_task /add
The command completed successfully.

PS C:\Windows\system32>
```

The attacker then laterally moves to this new account 


  
