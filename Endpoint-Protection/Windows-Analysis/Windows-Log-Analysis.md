# 🛡️ Windows Log Analysis: SOC-style investigations on a Windows Endpoint

## 📘 Overview
In this project I aim to gain practical hands-on practice working with Windows Event Logs and Sysmon logs for SOC-style investigations. This project solidifies existing knowledge, and provides an opportunity to practice with new tools such as `EventLogXP`. I carried out this project on my own isolated Virtual Machine running a Windows 10 iso.

## 🎯 Project Objectives
Simulate and analyze common Windows endpoint events from a SOC perspective:

- **User Logons**
  - Detect RDP (Logon Type 10) and other remote logons
  - Identify failed login attempts (4625) and potential brute-force patterns

- **User Management**
  - Detect creation, deletion, disabling/enabling of accounts
  - Track password changes and group membership escalations

- **Sysmon Integration**
  - Configure Sysmon with a standard config
  - Observe key events (process creation, network connections, file changes)

- **Suspicious Process Execution**
  - Monitor execution of PowerShell, CMD, or unsigned binaries
  - Detect command-line flags and unusual parent-child relationships

- **Persistence Techniques**
  - Simulate registry-based persistence
  - Track relevant Sysmon and Event Log entries (e.g., autorun keys)

## Tools
[EventLogXP](https://eventlogxp.com/)


## 📌 Project Phases
| Phase | Title | Description |
|-------|-------|-------------|
| 1     | Logon Events | Simulate suspicious and normal logons |
| 2     | User Management | Create/delete/modify accounts and groups |
| 3     | Sysmon Events | Monitor processes, files, network, registry |
| 4     | Persistence | Simulate registry autorun and log detection |
| 5     | Summary & Lessons Learned | Summarize learnings, include screenshots/logs |
