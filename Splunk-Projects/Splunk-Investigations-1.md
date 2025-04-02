# 🔍 Splunk Cloud: Detecting & Mitigating Unauthorised Access to Sensitive Files

## 📖 Overview
This project expands upon my Splunk Cloud setup with Universal Forwarders by focusing on a specific security scenario: securing /etc/shadow and /etc/passwd from unauthorized access attempts.
The goal is to detect, alert, and mitigate potential threats using Splunk SPL searches, alerts, and the MITRE ATT&CK framework.

By structuring our detection and response techniques around MITRE's T1003.008 (OS Credential Dumping), I ensure alignment with real-world security methodologies. This project also serves as a learning resource for developing Blue Team skills, including log analysis, alerting, and security monitoring.

[Splunk Cloud Setup](https://github.com/wilbcn/Splunk/blob/main/Splunk-Cloud-HomeLab.md)

## 🎯 Goals
✅ Detect unauthorised access attempts on /etc/shadow and /etc/passwd.
✅ Create real-time alerts for security monitoring.
✅ Apply MITRE ATT&CK-aligned detection & mitigation strategies.
✅ Implement group-based access controls to proactively restrict access.
✅ Develop a structured approach to security monitoring in Splunk Cloud.

### 🔍 MITRE ATT&CK Framework Integration  
This project also allowed me to gain essential experience using MITRE ATT&CK. By structuring our tests and detections based on MITRE techniques, I can ensure our Splunk implementation mirrors industry best practices for security monitoring. Below are the MITRE techniques referred to in this project, which I carried out during the practical tests. 

| **Tactic** | **MITRE Technique** | **Simulated Test** | **Expected Detection or Action** |
|------------|------------------|------------------|------------------|
| **Credential Access** | `T1003.008 - OS Credential Dumping` | Unprivileged user attempts to read `/etc/shadow` | `index=linux_logs sourcetype=linux:audit file IN ("/etc/passwd", "/etc/shadow")` |
| **Detection Strategy** | `DS0022 - File Access Monitoring` | Create an alert based on secure file access violations | `index=linux_logs sourcetype=linux:audit "shadow-access" success=no` |
| **Mitigation Strategy** | `M1026 - Privileged Account Management` | Restrict file access using ACLs & Group-Based Policies | `setfacl -m g:general_users:--- /etc/shadow` |

## Project walk-through
This section provides a step-by-step breakdown of the process followed in this follow-up Splunk project. It demonstrates my enthusiasm for learning industry-relevant tools and developing the skills essential for an aspiring cybersecurity professional. Additionally, this serves as a learning resource that I can refer back to as I continue expanding my expertise.

### 1. Carrying out scenario-based Security Events in Linux
Generating security incidents to later analyse in Splunk. Overview of each security event and commands used.

### 1.1 Technique Overview
Unprivileged user attempts to read `/etc/shadow` [T1003.008 -  OS Credential Dumping](https://attack.mitre.org/techniques/T1003/008/)

### 1.2 Configure AuditD

For this test, I had to configure and enable AuditD. This audit logs, I could send changes to files such as `/etc/passwd` and `/etc/shadow` from our UF to Splunk Cloud. On our Linux machine as splunkadmin:
- Install and Enable AuditD
```
sudo apt update && sudo apt install auditd -y
sudo systemctl start auditd  
sudo systemctl enable auditd
```

- Verify AuditD is Running
```
sudo systemctl status auditd
```

-  Add Audit Rules for Unauthorised Access to /etc/passwd and /shadow
```
sudo auditctl -w /etc/passwd -p r -k passwd-access
sudo auditctl -w /etc/shadow -p r -k shadow-access
```

- Check Active Audit rules
```
sudo auditctl -l

-w /etc/passwd -p r -k passwd-access
-w /etc/shadow -p r -k shadow-access
```

- Persist Audit Rules (append to bottom of file)
```
sudo vi /etc/audit/rules.d/audit.rules

-w /etc/passwd -p r -k passwd-access
-w /etc/shadow -p r -k shadow-access
```

- Apply the changes
```
sudo systemctl restart auditd
```

- Forward AuditD Logs to Splunk
```
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf

[monitor:///var/log/audit/audit.log]
index = linux_logs
sourcetype = linux:audit
```

- Restart splunk UF
```
sudo systemctl restart SplunkForwarder
```

### 1.3 Simulating unauthorised access
Here I simulated access attempts from our non-admin user account to `/etc/shadow`. This is a system file in Linux that stores encrypted user passwords and is accessible only to the root user. Attempted access could be a potential security risk, and something we can simulate and take proactive action against in this project.

SPL Query: index=linux_logs sourcetype=linux:audit "shadow-access" success=no

![image](https://github.com/user-attachments/assets/e7b714da-e936-41f6-97aa-25f829549742)

- By expanding on these log entries, we are able to identify valuable information about this event.

| **Field**      | **Value**                           | **Explanation** |
|---------------|-----------------------------------|----------------|
| **`_time`**   | `2025-03-18T12:32:06.728+00:00`   | Timestamp of the event. |
| **`UID`**     | `badguy`                          | The user attempting access. |
| **`key`**     | `shadow-access`                   | AuditD rule matched (attempt to access `/etc/shadow`). |
| **`success`** | `no`                              | Access attempt **failed**. |
| **`exit`**    | `-13`                             | **Permission Denied** (`EACCES` error). |

- This confirms that `badguy` attempted to access `/etc/shadow` but was denied due to insufficient permissions. 

![image](https://github.com/user-attachments/assets/930f0466-d531-4f53-b8b4-5c43176f980c)

### 1.4 Creating the alert
Referring to the MITRE ATT&CK Framework (T1003.008 - /etc/shadow Credential Dumping), we can enhance our detection capabilities by creating an alert on Files Access attempts - Detection Strategy `DS0022`. After performing the SPL query, we can click save-as alert.

![image](https://github.com/user-attachments/assets/c8d4ada7-4c75-43fa-ba7c-b44d16b51490)

The alert was then created with an appropriate title and description. The cron job was set to every 5 minutes. I left the expiration at 24 hours as we are only testing. The trigger conditions were set so we would receive an alert each time the conditions were met. 

![image](https://github.com/user-attachments/assets/a62dd5ba-e742-49ee-bc7d-2a5ccd2893c4)

The alert was then configured to send to my email address (left blank for privacy reasons). With an appropriate subject and priority level.

![image](https://github.com/user-attachments/assets/eb505393-b72e-49eb-8dac-09b4521421ff)

![image](https://github.com/user-attachments/assets/718d4327-c957-46a3-b5eb-3d37e482ca73)

### 1.5 Triggering the alert.
Back in my Linux machine, I once again attempted to access `/etc/shadow` from our non-admin user. This successfully generated an alert, and I was notified via email!

![image](https://github.com/user-attachments/assets/167eb89e-839d-4509-9ed8-b16e0b1ecce1)

### 1.6 Mitigation techniques
After detecting unauthorised access attempts, I implement M1026 - Privileged Account Management to proactively restrict access to sensitive files. Instead of blocking users individually, I applied group-based restrictions to ensure that only privileged users can access `/etc/shadow` while logging violations for security monitoring.

- Current ownership and permissions. Only users in the shadow group have access to `/etc/shadow`

```
ls -l /etc/shadow /etc/passwd
-rw-r--r-- 1 root root   2014 Mar 18 10:30 /etc/passwd
-rw-r----- 1 root shadow 1135 Mar 18 10:30 /etc/shadow
```

- I then created some test users, and a general users group to add all non-admin users to.

e.g.
```
sudo useradd -m -s /bin/bash tomsmith
sudo passwd tomsmith
New password:
Retype new password:
passwd: password updated successfully
```

```
sudo addgroup general_users
[sudo] password for splunkadmin:
info: Selecting GID from range 1000 to 59999 ...
info: Adding group `general_users' (GID 1004) ...
```

- Test user was then added to the new group

```
sudo usermod -aG general_users tomsmith
splunkadmin@ip:~$ groups tomsmith
tomsmith : tomsmith general_users
```

- Now tomsmith belongs to general_users, which we will restrict. Firstly, I installed the ACL package.

```
sudo apt update && sudo apt install acl -y
```

- Applying group based restrictions. These commands remove `rwx` permissions for our `general_users` group on `/etc/shadow`, and read access only on `/etc/passwd`.
```
sudo setfacl -m g:general_users:--- /etc/shadow
sudo setfacl -m g:general_users:r-- /etc/passwd
```

- Confirming the ACL changes

```
getfacl /etc/shadow
getfacl: Removing leading '/' from absolute path names
# file: etc/shadow
# owner: root
# group: shadow
user::rw-
group::r--
group:general_users:---
mask::r--
other::---

getfacl /etc/passwd
getfacl: Removing leading '/' from absolute path names
# file: etc/passwd
# owner: root
# group: root
user::rw-
group::r--
group:general_users:r--
mask::r--
other::r--
```

- Standard users can read `passwd` by default, however, applying an explicit ACL (r-- for general_users) ensures we maintain control over access permissions, even if system defaults change in the future. Next I tested the applied changes. 

```
tomsmith@ip:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied

tomsmith@ip:~$ cat /etc/passwd

Allowed!
```

### 2. Summary and lessons learned
This project served as a continuation of my journey into learning Splunk while integrating MITRE ATT&CK techniques to simulate, detect, alert, and mitigate security threats. By focusing on unauthorised access attempts to `/etc/shadow` and `/etc/passwd`, I was able to apply real-world log analysis, alerting, and security hardening techniques used in Blue Team operations. 

While this project focused on securing sensitive files, it serves as a foundation for expanding into more advanced security monitoring. Future projects will explore additional attack simulations using Splunk detection, alerting, and mitigation strategies, aligned with MITRE ATT&CK tactics.

### Upcoming Projects  

| **Project Focus** | **MITRE ATT&CK ID** | **Description** |
|------------------|----------------------|------------------|
| 🏴‍☠️ **[Detecting Unauthorised Admin Account Creation](https://github.com/wilbcn/Splunk/blob/main/Splunk-Investigations-2.md)** | `T1098 - Account Manipulation` | Monitor and alert when a new admin account is created. Get practice with building dashboards. |




