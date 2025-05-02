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

- For my first investigation, I decided to hone in on event code `4720`, which covers new user account creation. This should be investigated and monitored for 
    - Prevention of privilege abuse
    - Detection of potential malicious activity
    - Operational purposes like getting information on user activity like user attendance, peak logon times, etc.
    - Compliance mandates

```
index=botsv3 sourcetype="wineventlog" EventCode=4720
```

- This reveals just 1 event! Lets investigate further to see if this is malicious or not

![image](https://github.com/user-attachments/assets/07484ab8-237b-4540-98df-acfbc1198c24)

- 

