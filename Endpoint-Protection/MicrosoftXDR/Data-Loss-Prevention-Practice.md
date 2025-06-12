# 🛡️ Microsoft XDR: Hands-on practice with Data Loss Prevention (DLP)

## 📘 Overview
This project showcases my practical learning and hands-on experience with **Microsoft Purview Data Loss Prevention (DLP)** policies as part of my Microsoft XDR studies. Using a Microsoft 365 E5 trial and lab simulation, I created, tested, and documented several DLP policies designed to protect sensitive data from accidental or malicious exposure.

This project also serves as a learning resource for myself, helping to solidify my knowledge on this security tool.

## 🎯 Project Objectives
- Understand the core components and capabilities of Microsoft DLP.
- Create and apply DLP policies in Microsoft Purview for different use cases.
- Simulate policy matches using test content and observe policy behavior.
- Gain hands-on experience aligning DLP with regulatory compliance (e.g., GDPR, PCI).

## DLP Summary
Data loss prevention (DLP) is a cybersecurity strategy designed to prevent unauthorised access, usage, and transmission of sensitive data. It involves monitoring data at rest, in motion, and in use, to help prevent potential data breaches. DLP is implemented to protect confidential information and comply with industry regulatory compliances such as GDPR and HIPAA. These regulations require organisations to have rigorous data protection measures in place, where non-compliance can lead to severe penalities. 

DLP is important as it helps to ensure that sensitive information such as PII and intellectual property remain protected. Data breaches are costly and damage an organisations reputation, with long-term consequences. These breaches come with regulatory fines and loss of customer trust.

With DLP, we can define policies which outline the procedures and guidelines that an organisation uses to protect its sensitive data from unauthorised access, leakage, and retaining data integrity. DLP works by inspecting content accross locations such as email, SharePoint, OneDrive, and devices, using pre-defined/custom (sensitive) information types. For instance, credit card numbers or IDs. When content matches the defined conditions of a DLP policy, actions are taken such as sending alerts, and auditing user actions. This proactive monitoring helps prevent data leaks in real time, and this project aims to begin exploring DLP capabilities for hands-on experience as an aspiring cybersecurity analyst.

## DLP Policy goals
Setup policies for the following use cases:
- PII Detection & External Sharing Block: Detect and restrict external sharing of PII such as passport numbers
- Keyword Leakage: Prevent files with sensitive business tags from being shared externally (e.g, "Confidential", "Internal Use Only")
- File type-based policy: Detect and block specific file types from being shared externally (e.g., .zip, .exe)

### 1. DLP Policy for: PII Detection & External Sharing Block
This section outlines the steps taken to setup a DLP policy that detects and blocks the external sharing of personal identifiable information (PII).

1. Navigate to `https://purview.microsoft.com/home` -> `Data Loss Prevention` -> `Policies`
2. Then `Create Policy` -> `Categories` -> `Privacy` -> `U.K. Personally Identifiable Information (PII) Data`. This helps detect the presence of common PII information such as drivers licence and passport numbers.
3. Name and description of the policy.
![image](https://github.com/user-attachments/assets/654cb64f-44a6-4972-8996-394e4e2be31c)
4. For locations, we will be protecting the following for external sharing of PII.
![image](https://github.com/user-attachments/assets/c01c9ead-6aac-4461-b5ba-fe41290b677d)
5. I added several extra content types to the `info to protect` section, and added an additional condition for content shared with people outside my organization. 
![image](https://github.com/user-attachments/assets/251af404-d0e8-4731-a7a0-cf6fa32d88dc)
6. For `protection actions`, I set the following (1 instance for testing):
![image](https://github.com/user-attachments/assets/3c40c2a9-0218-4be5-bdd2-4b992d038d3e)
7. I also ensured that `Send an alert to admins when a rule match occurs` was set to on.
8. I switched the policy to on immediately so we can conduct tests. On the `Review and Finish` page, I hit `Submit`. 
![image](https://github.com/user-attachments/assets/77146853-ee00-4e25-a6a6-363dc0789b55)

### 1.1 Testing the new policy (PII Detection)
In order to simulate tests in this project, I have already setup two new test users in the Admin Portal.
![image](https://github.com/user-attachments/assets/e6e1f50b-2d0d-47c2-93ed-89b839431dbe)
![image](https://github.com/user-attachments/assets/2b88f785-a8f0-4e28-ac5b-f17e025a7350)

1. I first signed in to test user `Emma Cook` and navigated to Outlook.
2. I then drafted and sent an email to an external gmail address, containing a fake/generated UK passport number.
![image](https://github.com/user-attachments/assets/0e52641f-1b0d-470b-a600-64e00c2c68e3)
3. Test user Emma then received an email alert stating that her email conflicts with a policy in the organisation.
![image](https://github.com/user-attachments/assets/87114b4d-363d-4561-a2ea-bae8b1c02319)
4. I then went back to the `Purview Compliance Portal` -> `Data  Loss Prevention -> Alerts`.
5. While the DLP policy correctly triggered user notifications and email warnings when sensitive content was shared, no incident alert appeared in the DLP Alerts dashboard during testing. This behavior is likely due to limitations in the Microsoft 365 E5 Developer Trial, which may not support single-event alerting or advanced incident reporting.

### 2. DLP Policy for: Keyword leakage
In this section I create another DLP policy to trigger alerts on Keyword matches. These keywords mimic sensitive business tags, such as "Confidential" and "Internal Use Only". External sharing of confidential business information could happen by human-error, but could also be signs of malicious activity/data leakage. This rule helps to prevent that, providing alerts when the set tags are matched. These rules work well in combination with others, such as the next DLP rule that I set which blocks external sharing of certain file types (.exe, .zip) etc.

1. I headed to `Data Loss Prevention -> Classifiers -> Sensitive info types`.
2. Clicked `Create sensitive info type`
![image](https://github.com/user-attachments/assets/7459d569-a217-4648-9d86-f4d50258182b)
3. Then, created a new pattern with a keyword list, adding internal-like keywords to the list. Confidence level was set to low confidence.
![image](https://github.com/user-attachments/assets/063f6eeb-b565-4443-9bd4-64a60c5961c2)
4. Afterwards I clicked `Create` and `Finish`. 
5. Back to `Data Loss Prevention -> Policies`, and create a custom policy.
![image](https://github.com/user-attachments/assets/36c93455-3c24-4005-b789-bf64639f4e68)
6. Name the policy and add an appropriate description.
![image](https://github.com/user-attachments/assets/3acd0356-b593-4e6e-b690-b5c2a7d36326)
7. No Admin units assigned for these kind of policy tests. The policy was applied to all locations as the previous one (Email, SharePoiint, OneDrive, Teams).
8. I then created a custom rule for the policy, applying the earlier created sensitive info type, and choosing to alert on content shared externally.
![image](https://github.com/user-attachments/assets/858b36c2-b2bd-4683-9d42-655e209c2713)
9. User and Admin alerts were set to on.

### 2.1 Testing the new policy (Keyword leakage)
Using test user `Emma`, I simulated another external email with the subject "Confidential".
![image](https://github.com/user-attachments/assets/ddd45d52-3b9c-4fb4-941f-b70fe193c033)
Which successfully triggered the DLP policy with keyword classifier.
![image](https://github.com/user-attachments/assets/6a991b51-569f-4d6c-b315-959d500bd03e)

### 3. DLP Policy for: File types
For the third DLP policy, I setup a custom rule to detect file extensions such as executables and archives that are shared externally. 

1. Back in `Data Loss Prevention -> Create policy -> Custom policy`.
2. Name/Description: `Blocked File Types - Executables, Archives`.`This policy blocks sharing of specific high-risk file types (e.g., .exe, .zip, .pst) externally.`
3. For locations, I selected: `Exchange Email`, `SharePoint sites`, and `OneDrive accounts`. These 3 locations support policies for detecting file extensions.
4. For this policy we are created a customised/advanced DLP rule set.
![image](https://github.com/user-attachments/assets/e8dedde2-bac2-47d7-bed7-341d8b506cb3)
5. I turned out notifications for users to inform and educate them for the proper use of sensitive info.
6. After setting the severity to medium, I turned on the policy and submitted it.

### 3.1 Testing the new policy (Sensitive file types)
Emma Cook then sent an email with a .zip attachment to an external address, which correctly triggered a response:
![image](https://github.com/user-attachments/assets/ae49b664-7b84-4c4b-986d-48d4c67788ce)

### Project Summary
This was fundemental yet eye-opening hands-on experience with Microsoft Purview Data Loss Prevention (DLP). Through this project, I explored how DLP policies can be created, scoped, and tested across different scenarios.
I now have a much better grasp of how DLP fits into the broader Microsoft XDR and SOC workflow, from preventing accidental data leaks to supporting insider risk detection.

While this lab focused on core capabilities, I’m aware of other DLP expansion areas such as:

- User-based exceptions (e.g., policy overrides for execs)
- Endpoint DLP (protecting data on devices)
- Inbound data tagging (applying controls to external content)
- Integration with Microsoft Defender for Cloud Apps and Insider Risk Management

For the next project, I’ll be shifting focus to another Microsoft XDR area to continue building hands-on experience across the ecosystem.

