# 🔍 Splunk Cloud: Detecting Unauthorised Admin Account Creation

## 📖 Overview
This project is a continuation of my Splunk series, aimed at gaining hands-on experience with the Splunk platform and learning how to use the Splunk Processing Language (SPL) effectively to investigate and report on security events. 
In this follow-up, I explore and continue learning key Splunk features such as alerts** and dashboards, while aligning all detection and mitigation strategies with the MITRE ATT&CK framework to mirror real-world security operations.
This projects focuses on unauthorised administrator account creation and privilege escalation on a Windows machine — a critical persistence tactic used by adversaries (MITRE Technique: `T1098 - Account Manipulation`).

To carry out this project, I configured universal forwarders on some EC2 instances.
[Splunk Cloud Setup](https://github.com/wilbcn/Splunk/blob/main/Splunk-Cloud-HomeLab.md)

## 🎯 Goals  
✅ Detect the creation of new administrator accounts on a Windows system.  
✅ Gain hands-on experience with SPL to perform targeted threat investigations.  
✅ Build real-time alerts to notify of privilege escalation events.  
✅ Design a Splunk dashboard to visualize account manipulation activity.  
✅ Align all detection and mitigation techniques with the MITRE ATT&CK framework.  

---

### 🔍 MITRE ATT&CK Framework Integration  
This project strengthens my understanding of adversary behavior by simulating account manipulation techniques and aligning detection strategies with the MITRE ATT&CK framework. By leveraging SPL, alerts, and dashboards, I aim to replicate how a SOC analyst would monitor for and respond to suspicious privilege escalation attempts.

| **Tactic**            | **MITRE Technique**                      | **Simulated Action**                       | **SPL Example / Evidence** |
|-----------------------|------------------------------------------|--------------------------------------------|-----------------------------|
| Persistence           | `T1136.001 - Create Account: Local Account` | Create a new local user account            | `index=* sourcetype="WinEventLog:Security" EventCode=4720` |
| Privilege Escalation  | `T1078.003 - Valid Accounts: Local Accounts` | Add that user to the Administrators group  | `index=* sourcetype="WinEventLog:Security" EventCode=4732` |

| **Strategy**                  | **MITRE ID**                     | **What It Detects**                                   | **Implementation**                |
|------------------------------|----------------------------------|--------------------------------------------------------|-----------------------------------|
| User Account Creation        | `DS0002 - User Account Creation` | Creation of new user accounts                          | Alert on `EventCode=4720`         |
| Privilege Escalation via Account | `DS0002 - User Account Authentication` | Existing account elevates another to admin             | Alert on `EventCode=4732`         |

| **Strategy**                 | **MITRE ID**   | **Purpose**                                                                 | **Action Plan**                                |
|-----------------------------|----------------|------------------------------------------------------------------------------|------------------------------------------------|
| Multi-Factor Authentication | `M1032`        | Prevent unauthorised access via MFA                                         | Enable MFA for all user/admin accounts         |
| User Account Management     | `M1018`        | Enforce strict control over account provisioning and usage                  | Regularly audit/remove unused/suspicious accounts |

---

## Project walk-through  
This section provides a step-by-step breakdown of the work carried out in this Splunk project. It demonstrates my ability to simulate adversarial tactics, detect privilege escalation using SPL, and take action through real-time alerts and visual dashboards. As with previous projects, this serves both as a practical security learning experience and a documented workflow I can refer to in the future.

### 1. Simulating Scenario-Based Security Events in Windows
Generating security incidents to later analyse in Splunk. Overview of each security event and commands used.

### 1.1 Technique Overview
A new user account is created. [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
The new user is added to the admin group. [T1078.003 - Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

### 1.2 Simulating the security event - New Admin creation
- In control panel, I navigated to User Accounts, User Accounts, Manage Accounts, and Add a user account
- I then created a new user account, opting for an 'IT-Looking' username, which a real attacker may use in order to blend in.
- Going into the settings for our new user, I then changed the account type to Administrator.

<img width="1125" alt="image" src="https://github.com/user-attachments/assets/04c2bc4c-9ec2-4b2e-a856-dd34a26b0187" />

### 1.3 Initial SPL search
Now that _suspicious_ admin has been created, I ran an initial query in Splunk to verify we were generating logs for this event.

```
index=* sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
```

![image](https://github.com/user-attachments/assets/ebc94f68-2b76-45e8-97e3-028c6a433ee2)

By expanding on these logs, we can see that the account `Administrator` has created a new user, called `system_admin`, at `03/24/2025 07:09:46 PM`

![image](https://github.com/user-attachments/assets/dc8580d1-5463-49d1-b845-ac365c3dcdc4)

This is a security concern for multiple reasons: 
- The name `system_admin` follows a suspicious naming pattern that an attacker might use to blend in.
- The account was created outside of regular working hours, which could indicate unauthorised activity.

Expanding on the next log, we are able to see than an account has been added to a `security-enabled local group`

![image](https://github.com/user-attachments/assets/92bb5224-c58d-4cd4-94f4-371f4bb0b758)

While this security event was logged in Splunk, `Event ID `4732` did not contain the resolved username of the account added to the Administrators group. 

### 1.4 Verifying in Windows Event Viewer
To confirm which user was added to the Administrators group, I used the Event Viewer directly on the Windows Machine. [Acknowledgement](https://www.blumira.com/blog/event-id-4732)

In Event Viewer, I applied a custom filter to show only Event ID `4732` from the last 24 hours:

<img width="546" alt="image" src="https://github.com/user-attachments/assets/906e3464-e97a-4464-a5b4-1f253e7512d0" />

This allowed me to confirm that `system_admin`, the newly created user account, was also added to the group `Administrators`.

<img width="1437" alt="image" src="https://github.com/user-attachments/assets/658a5430-38ee-4a0c-8d07-76bd56d6cd30" />

### 2. Detection Strategy Overview
For this scenario-based project, we are focusing on two different security concerns. A new user being added to the system, and a user being added to the group of Administrators. Based on these, I setup two different Splunk alerts, following recommended detection techniques: `DS0002 -  User Account Creation`, `DS0028 - User Account Authentication (Privilege Escalation)` 

### 2.1 Setting up Splunk Alerts
Both Splunk alerts are configured to search the last 15 minutes of logs on a 5-minute schedule, ensuring any security events—such as new account creation or privilege escalation—are reliably detected.

Alert 1 - Generates alerts on new user accounts being added to the system

![image](https://github.com/user-attachments/assets/de54b185-c737-4de5-ae6c-cf30245639af)

Alert 2 - Generates alerts when a user has been added to a security-enabled group. I.e. Admin

![image](https://github.com/user-attachments/assets/19470ab7-0a5f-4782-b9f7-3969892507dc)

### 2.2 Setting up Splunk Alerts
To test our alerts, I created another system user and added them to the group Administrator. I will later remove and clean up these test-sample accounts.

<img width="1122" alt="image" src="https://github.com/user-attachments/assets/385405ed-8780-4d14-b105-929ba5e31ba0" />

This action successfully generated alerts, as shown below. Next, I setup a new dashboard.

![image](https://github.com/user-attachments/assets/21b842c2-e4b2-4393-b2a2-a0dd04202763)

![image](https://github.com/user-attachments/assets/0975eb12-fb7f-4a88-80b7-0be88a0a413f)

### 3. Setting up Dashboards
To setup dashboards, I ran some further SPL searches, and saved them as dashboards. Dashboards offer rapid insight into security events, and allow us to correlate them. 

Alert 1 - Recent User Account Creations

```
index=* sourcetype="WinEventLog:Security" EventCode=4720
| table _time, host, Account_Name, Subject_Account_Name, Message
| sort -_time
```

![image](https://github.com/user-attachments/assets/b550ba7f-f8b7-40b8-9efc-8fdb895afc86)

Alert 2 - Users Added to Administrators Group

```
index=* sourcetype="WinEventLog:Security" EventCode=4732 Group_Name=Administrators
| table _time, Subject_Account_Name, Message
| sort -_time
```


Alert 3 - User Creation & Privilege Escalation Timeline

```
index=* sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| timechart span=1h count by EventCode
```


Alert 4 - Top System Accounts Creating New Users

```
index=* sourcetype="WinEventLog:Security" EventCode=4720
| stats count by Account_Name
| sort -count
```

These 4 alerts were saved to our new dashboard!

![image](https://github.com/user-attachments/assets/05f4d98d-ca51-4af3-a937-e156a9d5f54a)

Snippet:

![image](https://github.com/user-attachments/assets/ab5a115a-e71b-45ab-8e61-27a024471fcf)


### 4. Detecting user deletions
As part of the project clean-up phase, I removed unnecessary administrator accounts from the Windows machine.`M1018 - User Account Management`. 

However, this provided an excellent opportunity to simulate and monitor for user deletions — a behavior that could be associated with adversarial activity. `DS0002 - User Account Deletion`

I ran the below SPL query and saved it as an alert, which I then tested during the clean up phase.

```
index=* sourcetype="WinEventLog:Security" EventCode=4726
```

This successfully generated an alert to my email.

![image](https://github.com/user-attachments/assets/695ecfdb-b078-4d45-b6e9-a1c45e6c4ae4)

Filtering these events in Event Viewer.

<img width="965" alt="image" src="https://github.com/user-attachments/assets/194ea172-0bb0-4c35-b858-52f1131e6bac" />

### 5. Extra Mitigation - MFA
To strengthen our security posture and align with `M1032 - Multi-Factor Authentication`, we could integrate `Duo Security` to protect local and RDP access to our Windows EC2 instance. This adds a second layer of authentication, requiring users to approve a login attempt via a push notification, passcode, or phone call before full access is granted. This is especially effective in preventing unauthorised access to administrator accounts.

Although AWS EC2 does not natively support MFA for RDP sessions, installing Duo’s lightweight Windows agent on the instance would allows us to simulate enterprise-grade MFA enforcement.

🔗 [Duo MFA for RDP Setup Guide](https://duo.com/docs/rdp)

### 6. Summary & Lessons Learned

This project strengthened my practical understanding of Splunk by simulating unauthorized administrator account creation and linking it directly to relevant MITRE ATT&CK techniques. By detecting the creation of local accounts and monitoring for privilege escalation (T1136.001, T1078.003), I was able to build alerts and dashboards that mirror the type of activity a security analyst would investigate in a real-world scenario.

I also explored slightly more advanced SPL queries using `table`, `stats count`, and `timechart` to improve visibility and analysis of account activity. Integrating MITRE’s detection and mitigation strategies (DS0002, M1018, M1032) added realism and structure to this workflow.

In upcoming projects, I aim to do:
- Continue expanding detection coverage with more MITRE-aligned techniques.
- Integrate **Splunk** with **TheHive** for incident case management and enrichment.







