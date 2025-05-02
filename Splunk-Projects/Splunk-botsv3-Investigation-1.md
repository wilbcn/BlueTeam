# 🖥️ Splunk Investigations: First Investigation Using the BOTSv3 Attack Dataset

## 📖 Overview  
This project marks the beginning of a series of scenario-based investigations using the **BOTSv3 "attack-only" dataset**, mounted in a standalone Splunk Enterprise environment on an AWS EC2 instance. Setup of this Splunk Server can be found here [Setup](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-Enterprise-HomeLab.md)

The goal of this first investigation is to simulate an analyst workflow by using **Splunk Processing Language (SPL)** to uncover malicious activity, correlate evidence across different log sources, and map findings to the **MITRE ATT&CK Framework**.

This project serves as a learning resource for myself, reinforcing core security principles and best practices, and gaining hands on experience with industry standard tools. I will be investigating the data sources included with the attack dataset, outlined here. [Sources](https://github.com/splunk/botsv3?tab=readme-ov-file)

## 🎯 Goals

- Perform a realistic investigation
- Practice writing SPL queries
- Identify attacker techniques
- Map findings to MITRE ATT&CK TTPs
- Document investigation workflows
- Gain hands on experience and familiarity with log sources and common field data

### 1. Investigating `WinEventLog`

#### What is it?
The Windows event log is a detailed and chronological record of system, security and application notifications stored by the Windows operating system that network administrators use to diagnose system problems and predict future issues.

This sourcetype typically includes:
- **Security logs** (logon events, account lockouts, privilege use)
- **System logs** (service starts/stops, driver errors)
- **Application logs** (software behavior, crashes)
- **Setup and ForwardedEvents logs** (Windows updates, forwarded logs from other hosts)

- Example Event Codes

![image](https://github.com/user-attachments/assets/6c5e6f03-acdf-420b-8b8f-885cce4cca65)

- By running `index=botsv3 sourcetype="wineventlog"`, we get an overview of the data for this source type.

![image](https://github.com/user-attachments/assets/50cc6136-bf07-4e41-a889-a85e4e60213a)

- For my first investigation, I decided to hone in on event code `4720`, which covers new user account creation. This should be investigated and monitored for:
    - Prevention of privilege abuse
    - Detection of potential malicious activity
    - Operational purposes like getting information on user activity like user attendance, peak logon times, etc.
    - Compliance mandates

- This related to MITRE ATTACK Data Source code `DS0002`, which covers: A profile representing a user, device, service, or application used to authenticate and access resources.

```
index=botsv3 sourcetype="wineventlog" EventCode=4720
```

- This reveals just 1 event! Lets investigate further to see if this is malicious or not

![image](https://github.com/user-attachments/assets/07484ab8-237b-4540-98df-acfbc1198c24)

- From this, I extracted the following information to aid in our investigation
    - **Source**: `WinEventLog:Security`
    - **SecurityID/User**: `AzureAD\FyodorMalteskesko`
    - **New Account**: `svcvnc`
    - **ComputerName**: `FYODOR-L.froth.ly`
    - **Timestamp**: `08/19/2018 22:08:17 PM`
    - **Password**: Password Not Required' - Enabled - Potential concern
    - **Account Expires**: never

- Paying close attention to the timestamp, and the extracted information from our previous query, I investigated this event further to see if this user had been added to a security-enabled group.

```
index=botsv3 sourcetype="wineventlog" EventCode=4728
```

![image](https://github.com/user-attachments/assets/f85f1d80-a0af-4709-9000-1547b7b2d673)

- In the above screenshot, we have now confirmed that this new user was added to a security-enabled group (MITRE ATTACK Technique `T1098` - Account Manipulation). The time stamp also matches our first initial search `08/19/2018 22:08:17 PM`. I then further honed in on this new user `svcvnc`, to confirm the security group it was added to. The next event code search will be 4688: A new process has been created. 

```
index=botsv3 sourcetype="wineventlog" EventCode=4688 svcvnc
```

![image](https://github.com/user-attachments/assets/95b13684-5ddf-4fdb-b492-02f698fd40ed)

![image](https://github.com/user-attachments/assets/02c9db7d-301a-4fd9-ad9b-094189402ee3)

- Here we confirm that the identified user `AzureAD\FyodorMalteskesko` launched `net.exe` via `powershell.exe`, adding `svcvnc` account to the `Administrators group`. To investigate this user and any malicious activity, I ran the beloq SPL query.

```
index=botsv3 (Account_Name=svcvnc OR user=svcvnc)
```

- Excluding the already identified events, we now have additional logs to investigate. 

- 4724: An attempt was made to reset an accounts password 
![image](https://github.com/user-attachments/assets/d4f614f9-10ca-4500-83d6-04c6545abea6)

- 4738(S): A user account was changed. Attacker disabled `Password Not Required` and left `Account Enabled`. 
![image](https://github.com/user-attachments/assets/f12c7e97-ea68-463f-bda3-4e700e2588f8)

- 4722(S): A user account was enabled. Confirms that `svcvnc` was activated after creation.
![image](https://github.com/user-attachments/assets/bf032f43-7dc3-45dd-b51d-6dd0986de880)

### 🧾 Timeline of Events

| Time | Event ID | Description |
|------|----------|-------------|
| 08/19/18 22:08:17 | 4720 | `svcvnc` user account created |
| 08/19/18 22:08:17 | 4722 | Account `svcvnc` enabled |
| 08/19/18 22:08:17 | 4724 | Attempt to reset `svcvnc` password |
| 08/19/18 22:08:17 | 4738 | User account `svcvnc` modified (UAC flags) |
| 08/19/18 22:08:17 | 4728 | Added `svcvnc` to Administrators group |
| 08/19/18 22:08:35 | 4688 | PowerShell used to run `net.exe` for group addition |

### Security Implications
This is a typical attacker post-exploitation move:
- Create an new user account
- Elevate privileges quietly
- Use PowerShell and native tools to avoid detection
