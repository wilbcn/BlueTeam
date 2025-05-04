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
    - **Password**: `Password Not Required' - Enabled - Potential concern`
    - **Account Expires**: `never`

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

![image](https://github.com/user-attachments/assets/44c58781-e216-47d1-9e3a-7abdfdc2a9f7)


- Here we confirm that the identified user `AzureAD\FyodorMalteskesko` launched `net.exe` via `powershell.exe`, adding `svcvnc` account to the `Administrators group`. The user then assigned a password to `svcvnc: Password123!`. To investigate this user and any malicious activity, I ran the beloq SPL query.

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

| Time               | Event ID | Description                                                                 |
|--------------------|----------|-----------------------------------------------------------------------------|
| 08/19/18 22:08:17  | 4720     | `svcvnc` user account was created                                           |
| 08/19/18 22:08:17  | 4722     | Account `svcvnc` was enabled                                                |
| 08/19/18 22:08:17  | 4724     | Password reset attempt for `svcvnc`                                         |
| 08/19/18 22:08:17  | 4738     | User account `svcvnc` modified (UAC flags and password settings updated)    |
| 08/19/18 22:08:17  | 4728     | `svcvnc` added to the Administrators group                                  |
| 08/19/18 22:08:17  | 4688     | `net1.exe` used to create `svcvnc` with password `Password123!`            |
| 08/19/18 22:08:35  | 4688     | `powershell.exe` used to run `net.exe` to add `svcvnc` to Administrators    |


### Security Implications
This is a typical attacker post-exploitation move:
- Create an new user account
- Elevate privileges quietly
- Use PowerShell and native tools to avoid detection

## Conclusion

Based on the analysis of the Windows event logs from the BOTS v3 dataset, it is highly likely that the AzureAD user `FyodorMalteskesko` was compromised. The account was used to create a backdoor user (`svcvnc`), assign it a password, and add it to the local Administrators group — performed PowerShell sessions. 

This activity strongly suggests post-exploitation attacker behavior, consistent with credential misuse, privilege escalation, and persistence tactics outlined in the MITRE ATT&CK framework. I now wanted to pivot onto other source types to look for malicious activity.

### 2. Investigating AWS Source Types

#### What is it?
- **AWS CloudWatch**: Cloudwatch monitors the health and performance of AWS Applications and resources. Helps support threat detection with log metrics.
- **CloudTrail**: Tracks all API activity, providing a detailed audit trail for security, compliance, and troubleshooting. Basically covers who did what, and is highly used in threat detection and incident response.

- I decided to investigate first **CloudTrail**, by running the below SPL query.

```
index="botsv3" sourcetype="aws:cloudtrail"
```

![image](https://github.com/user-attachments/assets/a63b6a89-e22d-4ba9-8b9d-7eec30b2677f)

- Taking a deeper look at some of the `interesting fields` we get with this search, there are two different event types: `AwsApiCall`, and `AwsConsoleSignIn`.

![image](https://github.com/user-attachments/assets/343fbf35-6c79-4013-b6cf-830f36b7a141)

- Additionally the second Eventtype field provides us with more ways we can filter with our SPL queries.

![image](https://github.com/user-attachments/assets/e911c1a5-d0ff-4a69-bffb-8829f474b313)

- By clicking on `AwsConsoleSignIn`, I added it to our search, which now gave us 4 events.

![image](https://github.com/user-attachments/assets/682565f6-8eea-4e55-8f3c-fab1c4e72873)

- Out of these 4 events, I spotted an anomaly address potentially worth investigating further: `157.97.121.132`. Lets investigate activity from this IP address. New query: `index="botsv3" sourcetype="aws:cloudtrail" src_ip="157.97.121.132"`. This gives us 19 events.

![aa47ca11-d6c6-47cd-a4d4-3e401ad47954](https://github.com/user-attachments/assets/3a258ba1-d2b0-4aae-a2f0-698d341fa199)

- By checking the `eventName` field, we can interpret the API Calls from the Suspicious IP. This is suspicious behaviour, and is perhaps a compromised user doing reconnaissance.
    - **ListAccessKeys x3**: Identifying credentials
    - **ListAccountAliases**: Potentially used in reconnaissance
    - **GetAccountPasswordPolicy**: Checking for weak password policies
    - **GetAccountSummary**: Recon for account-level security
    - **ListUsers**: Recon for IAM users
    - **GetUser**: Targeting a specific IAM user
    - **ListAttachedUserPolicies**: Lists IAM policies, scouting for privilege abuse
    - **ListGroups,ListSSHKeys**: Enumerate groups and SSH keys, more recon and perhaps more specific targeting


![image](https://github.com/user-attachments/assets/80900d10-32c4-4663-ab88-f219c59dffd4)

## Conclusion
This looks like a reconnaissance phase of an AWS compromise. The attacker is probing IAM structures, and looking for paths to escalate and exfiltrate credentials. All these events and actions were performed by the same recipient account.

### 3. Investigating http traffic

#### What is it?
HTTP (Hypertext Transfer Protocol) refers to the data exchanged between a web client, such as a browser, and a server. Port 80 is the default port for HTTP, and attackers exploit HTTP protocols through various methods like:
- HTTP flood DDoS attacks
- HTTP request smuggling
- HTTP host header attacks.

These attacks can disrupt services, steal information, or gain unauthorized access to systems

- Initial SPL query ran

```
index="botsv3" sourcetype="stream:http"
```

- For the `http_method` field, we can see the methods used and their count for http traffic. Straight away I am interested in investigating `PROPFIND`, witrh just `0.02%` of http traffic.

![image](https://github.com/user-attachments/assets/89ba56b5-36f4-485a-93a4-b2a814c189f7)

- This gives us just 2 events, with the below interesting fields
    - **dest_ip**: `172.16.0.109`
    - **src_ip**: `45.7.231.174, 61.75.35.114`
    - **http_comment**: `HTTP/1.1 503 Service Temporarily Unavailable`
    - **server**: `Apache/2.2.34 (Amazon)`
    - **timestamps**: `2018-08-20T14:55:24.603778Z,  2018-08-20T14:41:32.692841Z`

- The `PROPFIND` method is part of WebDAV, an extension of HTTP. It’s used by clients (like WebDAV-enabled applications or scripts) to ask a web server for information about files or directories — kind of like saying, “Show me what’s here.” This might be used by attackers to scan for accessible directories, list files, or check if WebDAV is enabled
- The destination `172.16.0.109` is an internal Apache web server
- The `503` responses suggest the server rejected the requests
- These 2 events suggest an attacker was likely probing the internal web server to identify accessible directories or check for WebDAV support, using a rare HTTP method (PROPFIND) that is commonly leveraged during reconnaissance phases of web exploitation.

- I then added the identified destination IP of the apache web server to our SPL query, investigating both `GET` and `POST` requests to this IP address.

```
index="botsv3" sourcetype="stream:http" dest_ip="172.16.0.109"
```
```
index="botsv3" sourcetype="stream:http" dest_ip="172.16.0.109" http_method=POST
```

- Interestingly, the only 2 IP addresses under this query match what we found before for `PROPFIND`: `45.7.231.174, 61.75.35.114`.
- All 94 events have `HTTP/1.1 404 Not Found`, suggesting a scanning or exploitation attempt
- Coupled with suspicious `uris`, this is potentially an automated web shell scanner
- First log entry `2018-08-20T14:41:33.698020Z`.

![image](https://github.com/user-attachments/assets/e67192ee-1114-497c-bc4c-1afe28f691f7)

```
index="botsv3" sourcetype="stream:http" dest_ip="172.16.0.109" http_method=GET
```

![image](https://github.com/user-attachments/assets/2f96f65a-7da4-4e29-90a1-42065716ad93)

- Above we have a summary of the targeted paths. Which suggest the attacker is specifically looking for misconfigured MySQL/phpMyAdmin portals, Default admin interfaces, and Web shells like /cmd.php. First log entry `2018-08-20T11:19:58.723681Z`, which is before the 2 `PROPFIND` events.

![image](https://github.com/user-attachments/assets/6cd95206-966b-47d7-a860-72a804ab0387)

- Furthermore, the above `http status codes` tell us nothign was actually successfully accessed, however the attacker was definately probing, and represents hostile behaviour.
- By paying close attention to the timestamps in these log entries, we are able to gather a timeline of http events, and a better understanding of what happened during this security incident.

### Timeline of HTTP Events

| Time                    | Event Type | HTTP Method | Details |
|-------------------------|------------|-------------|---------|
| 2018-08-20T11:19:58Z    | Initial Access | `GET`        | Attempted access to admin portals and known shell paths (e.g., `/cmd.php`, `/phpmyadmin/index.php`) |
| 2018-08-20T14:41:32Z    | Recon        | `PROPFIND`   | WebDAV probe to Apache server at `172.16.0.109` |
| 2018-08-20T14:41:33Z    | Exploitation Attempt | `POST`       | POST requests to common shell filenames (e.g., `/ak47.php`, `/xx.php`) — 94 events total |
| 2018-08-20T14:55:24Z    | Recon (repeat) | `PROPFIND`   | Second WebDAV probe to the same Apache server |

In concluson, our timeline suggests a probing attack on an apache web server, starting with direct access attempts via `GET`, followed by WebDAV probing, then a large amount of `POST` requests likely in an attempt to
upload or interact with the web shells. The overall aim was most likely persistence, such as a backdoor.

### 4. Key-takeaways and Lessons Learned
This project documented my first investigation into the BOTSv3 dataset, which includes a wide variety of attacker data to explore and analyze. I focused on three source types: Windows Event Logs, AWS CloudTrail logs, and captured HTTP traffic. For each, I was able to identify and investigate a security incident, digging deeper to understand what actually happened.

This was a fantastic learning experience — especially as I hadn’t worked with AWS sources before. I also came across PROPFIND, a completely new HTTP method to me, and took the time to understand what it does and how it can be abused during web-based attacks.

Overall, this investigation gave me hands-on experience that supports my preparation for the BTL1 exam, and builds a strong foundation as I continue working toward further certifications and expanding my skillset.

### 🧩 MITRE ATT&CK Techniques Observed

| Technique ID | Name                          | Observed In                  |
|--------------|-------------------------------|------------------------------|
| T1098        | Account Manipulation          | Windows Event Log (svcvnc)   |
| T1087        | Account Discovery             | AWS IAM Recon                |
| T1190        | Exploit Public-Facing App     | HTTP Web Shell Targeting     |
