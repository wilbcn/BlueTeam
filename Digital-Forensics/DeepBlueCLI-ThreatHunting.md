# 🔍 Threat Hunting in Windows: Practical Event Log Analysis with DeepBlueCLI

## 📖 Overview
This project outlines the steps taken to get hands-on experience with **DeepBlueCLI**, a PowerShell Module for Threat Hunting via Windows Event Logs. This project also serves as practice before I sit the **Blue Team Level 1 Exam**.

DeepBlue is a simple tool which allows us to identify suspicious events using pre-determined signatures and patterns from Windows Event logs, without having to manually dig through them in Event Viewer or another program.

## 🎯 Goals
✅ Get hands-on with DeepBlueCLI in a real environment  
✅ Investigate simulated attacker behaviors using PowerShell and Windows utilities  
✅ Analyze event logs and identify indicators of compromise  
✅ Document the entire process as a public learning portfolio  

## Tools used
- **DeepBlueCLI**: A PowerShell-based threat hunting tool for Windows Event Logs.
- **Amazon EC2**: Our virtual HomeLab environment
- **PowerShell**: For both simulation and analysis scripting
- **Git**: For cloning repositories and version control
- **CyberChef**: For base64 encoding/decoding.

## Project walk-through
Below outlines the steps taken to configure and install DeepBlueCLI on our Cloud HomeLab environment. I then provide the setups taken investigate Security Incidents using this tool.

## 1. Installing DeepBlueCLI
In my EC2 HomeLab, I booted up PowerShell as Administrator, and ran the following commands.

- I Installed Git using Windows Package Manager. Afterwards, I had to close and reopen Powershell.

```
PS C:\Users\Administrator> winget install --id Git.Git -e
PS C:\Users\Administrator> git --version
git version 2.49.0.windows.1
```

- I then cloned the DeepBlueCLI repository and ran the below code to enable PowerShell & Command-Line Logging

```
PS C:\Users\Administrator> git clone https://github.com/sans-blue-team/DeepBlueCLI.git
Cloning into 'DeepBlueCLI'...

PS C:\Users\Administrator> cd DeepBlueCLI
PS C:\Users\Administrator\DeepBlueCLI>
```

```
# PowerShell Script Block Logging
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# PowerShell Transcription Logging (optional)
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1

# Enable Command Line Process Auditing
auditpol /set /subcategory:"Process Creation" /success:enable

# Show command-line arguments in logs
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Apply all changes
gpupdate /force
```

## 2. Exporting Security Logs
I have now used this EC2 instance for multiple CyberSecurity, BlueTeam focused projects. In that sense, I have already simulated security events from past projects which I can now utilise for a fundemental investigation using DeepBlueCLI.

- The following exports Windows event logs `Security` to our desktop. 
```
wevtutil epl Security C:\Users\Administrator\Desktop\Security.evtx
```

## 3. Analyse the exported logs
With these two files on our desktop, I then ran the DeepBlue PowerShell script on each file to simulate an investigation.

- Investigating `Security.evtx`

```
.\DeepBlue.ps1 -LogPath "C:\Users\Administrator\Desktop\Security.evtx"
```

![image](https://github.com/user-attachments/assets/693a58dc-2736-4718-bc83-c2bae279ac5e)

In the example output, we have discovered two security events worth investigating. `EventID: 4732 User added to local Administrators group`, `EventID: 4720 New User Created`. Although this was simulated in an earlier project, these actions in a real, production environment may warrant further investigation.

| Event ID | Description                        | Tactic               | Technique                     | MITRE ID |
|----------|------------------------------------|----------------------|-------------------------------|----------|
| 4720     | New user account created           | Persistence          | Create Account                | [T1136](https://attack.mitre.org/techniques/T1136/) |
| 4732     | User added to Administrators group | Privilege Escalation | Valid Accounts: Local Admins | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) |


## 4. Simulate a More Specific Attack
To further familiarise myself with this tool and what potentially to look out for during a proper investigation, I simulated some new security events. What I had in mind was running `obfuscated powershell code`, which could give me good hands-on experience on what this might look like.

Obfuscation is the act of hiding the real intent of a command or script. Attackers use it to:
- Bypass basic detection by EDR/antivirus
- Avoid keyword-based alerting
- Confuse analysts reviewing logs

- To simulate this, I headed over to `CyberChef`, a web app for encryption, encoding, compression and data analysis. Here I Base64-encoded a PowerShell command to prepare for our simulation.

![image](https://github.com/user-attachments/assets/78d71e16-d88f-4c23-b671-f161e3fa7b00)

- One of the most common methods of obfuscation is to Base64 encode PowerShell commands and run them with the `-EncodedCommand` flag. Now back to Powershell:

```
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACEAIABJACAAYQBtACAAaABhAHIAbQBsAGUAcwBzACAAOgAp
```

- Analysing with DeepBlueCLI

![image](https://github.com/user-attachments/assets/8a909861-7e12-4864-8806-67eb7cbd0728)

- This simulated attack is suspicious due to the use of `-EncodedCommand`, a strong behavioral indicator of obfuscation. The script was executed with `-NoProfile` and `-WindowStyle Hidden`, both of which are also red flags for attacker stealth. This simulated attack can also be linked to the MITRE ATTACK FRAMEWORK.

| Behavior                | Description                                | Tactic            | Technique                      | MITRE ID |
|------------------------|--------------------------------------------|-------------------|-------------------------------|----------|
| `-EncodedCommand` used | Base64-encoded PowerShell execution         | Execution         | PowerShell                    | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| `-NoProfile`, `-Hidden`| Stealthy execution flags to avoid detection| Defense Evasion   | Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) |

## 5. Lessons Learned and Key Takeaways
 DeepBlueCLI is a lightweight yet powerful tool for quickly surfacing suspicious behaviors from Windows Security event logs.
- Behavioral patterns such as obfuscated PowerShell (`-EncodedCommand`, `-NoProfile`, `-WindowStyle Hidden`) are common tactics attackers use to evade detection.
- Investigating and manually mapping findings to the MITRE ATT&CK framework builds a deeper understanding of real-world adversary techniques.
- Threat hunting is about developing intuition — knowing where to look and recognizing patterns of stealthy behavior.

This work was completed as part of my preparation for the **Blue Team Level 1 (BTL1) Exam** and reflects my ongoing commitment to gaining practical, hands-on experience toward my goal of becoming a strong Security Analyst.

