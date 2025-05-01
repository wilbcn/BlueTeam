# 🖥️ Splunk Investigations: First Investigation Using the BOTSv1 Attack Dataset

## 📖 Overview  
This project marks the beginning of a series of scenario-based investigations using the **BOTSv1 "attack-only" dataset**, mounted in a standalone Splunk Enterprise environment on an AWS EC2 instance. Setup of this Splunk Server can be found here [Setup](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-Enterprise-HomeLab.md)

The goal of this first investigation is to simulate an analyst workflow by using **Splunk Processing Language (SPL)** to uncover malicious activity, correlate evidence across different log sources, and map findings to the **MITRE ATT&CK Framework**.

This project serves as a learning resource for myself, reinforcing core security principles and best practices, and gaining hands on experience with industry standard tools. I will be investigating the data sources included with the attack dataset, outlined here. [Sources](https://github.com/splunk/botsv1?tab=readme-ov-file).

## 🎯 Goals

- Perform a realistic investigation
- Practice writing SPL queries
- Identify attacker techniques
- Map findings to MITRE ATT&CK TTPs
- Document investigation workflows
- Gain hands on experience and familiarity with log sources and common field data

### 1. Investigating Sysmon
Sysmon is a Windows utility that logs system activity, including process creation, file changes, network connections, and more. It's valuable for detecting attacker behavior at the host level. This is a great starting place for my first investigation into the attack dataset from botsv1. 

#### Steps and code ran

- This SPL query checks sysmon logs on EventID 7: Image Load, which logs when a module is loaded in a specific process. This is useful for finding potentially malicious executables and .DLL files (Dynamic Link Library)

```
index=botsv1 sourcetype="xmlwineventlog" "<EventID>7"
```
