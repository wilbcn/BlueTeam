# 🔍 Threat Hunting with DeepBlueCLI

## 📖 Overview
This project

## 🎯 Goals
✅ Get hands-on with DeepBlueCLI in a real environment  
✅ Simulate attacker behaviors using PowerShell and Windows utilities  
✅ Analyze event logs and identify indicators of compromise  
✅ Document the entire process as a public learning portfolio  

## Tools used
- **DeepBlueCLI**: A PowerShell-based threat hunting tool for Windows Event Logs.
- **Amazon EC2**: Our virtual HomeLab environment
- **Sysmon**: System Monitor to enhance Windows logging
- **PowerShell**: For both simulation and analysis scripting
- **Git**: For cloning repositories and version control

## Project walk-through
Below outlines the steps taken to configure and install DeepBlueCLI on our Cloud HomeLab environment. I then provide the setups taken to simulate security incidents, and how I investigated them leveraging this tool. 

## 1. Intalling DeepBlueCLI
In my EC2 HomeLab, I booted up PowerShell as Administrator, and ran the following commands.

```
PS C:\Users\Administrator> winget install --id Git.Git -e
PS C:\Users\Administrator> git --version
git version 2.49.0.windows.1
```

- Installs Git using Windows Package Manager. Afterwards, I had to close and reopen Powershell.

```
PS C:\Users\Administrator> git clone https://github.com/sans-blue-team/DeepBlueCLI.git
Cloning into 'DeepBlueCLI'...

PS C:\Users\Administrator> cd DeepBlueCLI
PS C:\Users\Administrator\DeepBlueCLI>
```

- Clones the DeepBlueCLI repository

```
PS C:\Users\Administrator> git clone https://github.com/SwiftOnSecurity/sysmon-config.git
Cloning into 'sysmon-config'...

PS C:\Users\Administrator> cd sysmon-config
PS C:\Users\Administrator\sysmon-config>
```

- Clones the Sysmon repository
- I then headed over to `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`, to download the Sysinternals Suite from Microsoft's official site.
- Saving and extracting the download to my desktop.

```
PS C:\Users\Administrator> cd Desktop/sysmon
PS C:\Users\Administrator\Desktop\sysmon> .\Sysmon64.exe -accepteula -i "C:\Users\Administrator\sysmon-config\sysmonconfig-export.xml"
```

- Installs Sysmon with the downloaded configuration and accepts the license agreement.
- Verify sysmon logs in event viewer, via path: `Applications and Services Logs → Microsoft → Windows → Sysmon`

![image](https://github.com/user-attachments/assets/b8e89b5e-0dd6-4219-b858-cafd3530310e)





