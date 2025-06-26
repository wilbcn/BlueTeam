# 🔎 Datadog: Introducing a new security tool!

## 📖 Overview
This project is an expansion on my hands-on SIEM series. In previous projects I have focused primarily on Splunk, leveraging its capabilities for investigative work on attacker datasets, and practice creating alerts / dashboards in a SOC-style mindset. In this project, I pivot to Datadog, a cloud-based monitoring and analytics platform. I explore Datadogs UI as a whole, while focusing on Datadog's Cloud SIEM tool which is a solution built on top of Datadog's log management platform, designed to detect threats in cloud-scale environments. With this project I am expanding my skillset, familiarising myself with security standard tools outside of Splunk, showcasing my proactiveness and adaptability to other platforms.

## 🎯 Goals
- Configure and launch a fresh EC2 instance running Windows
- Configure the Datadog Agent on this new virtual machine to ingest windows security logs
- Configure the `Windows Event Logs` content pack for Cloud SIEM
- Simulate a security event and handle the alert in Datadog

## Resources & Acknowledgements
- [Install User Agent](https://app.datadoghq.eu/fleet/install-agent/latest?platform=windows)
- [Log Collection](https://docs.datadoghq.com/integrations/win32_event_log/?tab=logs)



### Configuration Overview
In this section, I briefly cover the configuration and installation of the Datadog Agent on a brand new windows VM in AWS.

1. Once the new Windows VM in AWS was configured and launched (not shown), I headed over to `Datadog` -> `Integrations` -> `Fleet Automation`, and selected the appropriate host.

![image](https://github.com/user-attachments/assets/43f6f5c8-2dce-4838-890e-06b489fae71d)

2. On the `Installer` tab, I downloaded and ran the agent installer on the virtual machine, providing my API key when necessary.

![image](https://github.com/user-attachments/assets/3b674f6e-74fb-4250-b887-5120a356fd91)

3. From Datadog's Main Menu, I headed to `Infrastructure`, where the VM now appears. The next step was to enable log collection from the VM.
4. For this section I followed the datadog documentation on `integrations` -> `Windows Event Log`. By default - log collection is disabled in the Datadog Agent. I set `logs_enabled: true` in the `datadog.yaml` file (`C:\ProgramData\Datadog/datadog.yaml`).

![image](https://github.com/user-attachments/assets/1b17be16-dd41-406d-88a6-2a81bafa48f8)

5. In this project I am focusing on Windows Security Logs, which defines how I construct the `.yaml` file for log collection. I then created and edited the following file: (`C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml`).

- **From the documentation**
![image](https://github.com/user-attachments/assets/e8d95af6-7cf4-443a-9ceb-9752d12ee9f3)

- **My .yaml file**
![image](https://github.com/user-attachments/assets/1c9ca30f-9c49-4c35-a27f-a3b2f2fdd68a)

6. After restarting the Datadog agent via the CLI (`Restart-Service datadogagent -Force`), logs started to appear in `Log Explorer`. Datadog query `source:windows.events`.

![image](https://github.com/user-attachments/assets/63a41016-952b-4ed9-919f-dbc83c57c262)

7. At this stage I also enabled CWS and CSPM inside (`C:\ProgramData\Datadog\security-agent.yaml`). While not required for Cloud SIEM log-based detections, these protection features activate runtime security features that are part of Datadogs full security platform. CSPM for instance, continously scans cloud-based resources such as user roles and privileges, access keys or tokens, and infrastructure components, for vulnerable configurations.

- **CWS**: Cloud Workload Security
- **CSPM**: Cloud Security Posture Management

![image](https://github.com/user-attachments/assets/d56cbc16-c3e9-4960-ab15-35070f153d39)

8. The next step was to enable and configure `Cloud SIEM`. I went to `Security` -> `Cloud SIEM` -> `Content Packs`.
9. Here I ran through the appropriate actions, including install, and rearranging the index.

![image](https://github.com/user-attachments/assets/bcfc17fe-390a-4ab4-8b0b-fab6c83c78be)

10. After some time, the content pack switched to green/active and it was ready to use. The content pack comes with 76 detection rules and 1 custom dashboard, which I will leverage in the next section. 

![image](https://github.com/user-attachments/assets/9bc313f2-3efe-4302-9106-2fe37bf2ddcc)

### Simulating Security Events and navigating Datadog UI
Now that security logs are being successfully ingested into Datadog Log Explorer, and the content pack including security detection rules is operational, I ran a simulated security event to test detection rule logic and practice a SOC-style investigation using Datadog Cloud SIEM.

1. Expanding on the content pack, I filtered by detection rules on `user`. Here I came accross the detection rule `Windows hidden local user creation`.

![image](https://github.com/user-attachments/assets/447df121-1c47-442f-8e7f-7b6222efc1eb)

2. Expanding again on this specific rule, we are provided a complete overview of the rule which includes the related MITRE ATTACK techniques and tools, the goal and strategy of the rule, and the recommended Triage & Reponse steps during Incident Response. In summary, this rule detects when a new user account has been created (Event ID 4720), with a specific focus on accounts that end with a dollar `$`. Hidden user accounts typically end with this to mimic legitimate system accounts, making them less detectable and is an evasion tactic used by attackers to blend persistence mechanisms with legitimate system accounts.
3. To trigger the alert I ran the following line in `PowerShell` as Administrator on the Virtual Machine.

```
net user hiddenuser$ Passw0rd! /add
```

4. This created a `high` alert in the Datadog Cloud SIEM dashboard for Windows Event Log.

![image](https://github.com/user-attachments/assets/cb4d4c06-4d7b-4a8e-938f-ed2929385fab)

5. I then navigated to `Security` -> `Signals` where I could review this alert in full.

![image](https://github.com/user-attachments/assets/6ed89d61-f4a9-4b0c-b6be-bee9fa7f3add)

6. Clicking on the alert we are able to view the Playbook related to it, which provides clear instructions on the Triage & response steps for this kind of rule. We also have Triage and Take action buttons on the right hand side in blue. I swapped the Case from Open to In-Progress, and assigned it to myself.

![image](https://github.com/user-attachments/assets/b9d3ebe2-ac04-4311-9757-9522b7eae907)

7. This is a confirmed test to validate SIEM detection rules, however In production, I would declare this a P1 incident if the user was unknown or tied to suspicious lateral movement. I then archived the message with an appropriate comment.

![image](https://github.com/user-attachments/assets/109d04ff-80db-41e4-bbe3-c9fe8f46b5c8)

8. For hands-on practice, I simulated an investigation using the `Triage & Response` section of the Playbook.

![image](https://github.com/user-attachments/assets/5417746e-e4d7-41ba-9031-a5ef87d33f77)

1. Identify the `EC2AMAZ-NILIHU8` system where the hidden user account was created.
- Confirmed that the host `EC2AMAZ-NILIHU8` is the source Windows EC2 instance.

2. Examine the name of the newly created hidden account in the `TargetUserName` field.
- In the `JSON` section of the alert, we see the `TargetUserName` field is `hiddenuser$`
- Trailing $ is a common stealth technique

3. Identify which account created the hidden user by reviewing the `SubjectUserName` field.
- Above the target user is the `SubjectUserName`: Administrator

4. Check for account modifications such as modifying the `UserAccountControl` attribute to further conceal the account.
- Filter in `Log Explorer` on `EventID 4738`: User account was changed.
- Look for suspicious changes i.e. user no longer needs a password, password never expires, etc.

5. Review if the account was added to privileged groups by examining group membership change events.
- Filter in `Log Explorer` on `EventID 4728`: User added to a security-enabled global group
- Check which group they were added to, i.e. `Administrator`.

6. Look for logon success events associated with the account to determine if it's actively being used.
- Filter in `Log Explorer` on `EventID 4624`: Successful logon
- Also filtering purely on `TargetUserName:hiddenuser$` to see all related activity.

- **Account was created**
![image](https://github.com/user-attachments/assets/3cfc496a-4eab-481f-a22b-2491ce0e17f1)

- **With 0 Successful Logins**
![image](https://github.com/user-attachments/assets/d0a5b462-ffba-4865-8071-8206750b7aa5)

7. Examine any scheduled tasks or services configured to run under this account's context
- Filter in `Log Explorer` on `EventID 4698`: A scheduled task was created on a Windows System and `EventID 7045`: A new service was installed
- Review the image path or command being executed
- Review the user account under which the task/service runs
- Review the parent process
- Look for anomalies such as non-standard paths or anything running as the suspicious user.

8. 
