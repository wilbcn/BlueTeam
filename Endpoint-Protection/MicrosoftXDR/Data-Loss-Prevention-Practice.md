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
- insert
- insert

### 1. DLP Policy for: PII Detection & External Sharing Block
This section outlines the steps taken to setup a DLP policy that detects and blocks the external sharing of personal identifiable information (PII).

1. Navigate to `https://purview.microsoft.com/home` -> `Data Loss Prevention` -> `Policies`
2. Click `Create Policy`, on `Categories` I chose `U.K. Personally Identifiable Information (PII) Data`. This helps detect the presence of common PII information such as drivers licence and passport numbers.
3. I kept the name as default and description as default.
![image](https://github.com/user-attachments/assets/654cb64f-44a6-4972-8996-394e4e2be31c)
4. I did not assign any admin units, and left the locations to the preselected options.
![image](https://github.com/user-attachments/assets/1f49426e-c513-4eb4-969a-1c5280b6262f)
5. Continuing on with the policy settings, I added several extra content types to the `info to protect` section.
![image](https://github.com/user-attachments/assets/dff030d3-dc10-4adc-a25c-77b0b4be8e40)
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
![image](https://github.com/user-attachments/assets/17d770d3-4885-4de2-b992-8354d2008719)
3. Test user Emma then received an email alert stating that her email conflicts with a policy in the organisation.
![image](https://github.com/user-attachments/assets/fea45a60-59c4-4e2f-adfd-15a68bbb5da6)
4. I then went back to the `Purview Compliance Portal` -> `Data  Loss Prevention -> Alerts`.
5. While the DLP policy correctly triggered user notifications and email warnings when sensitive content was shared, no incident alert appeared in the DLP Alerts dashboard during testing. This behavior is likely due to limitations in the Microsoft 365 E5 Developer Trial, which may not support single-event alerting or advanced incident reporting.

### 2. DLP Policy for: Keyword leakage
In this section I create another DLP policy to trigger alerts on Keyword matches. These keywords mimic sensitive business tags, such as "Confidential" and "Internal Use Only".

1. I headed to `Data Loss Prevention -> Classifiers -> Sensitive info types`.
2. Clicked `Create sensitive info type`
![image](https://github.com/user-attachments/assets/7459d569-a217-4648-9d86-f4d50258182b)
3. Then, created a new pattern with a keyword list, adding internal-like keywords to the list. Confidence level was set to low confidence.
![image](https://github.com/user-attachments/assets/063f6eeb-b565-4443-9bd4-64a60c5961c2)
4. Afterwards I clicked `Create` and `Finish`. 
5. Back to `Data Loss Prevention -> Policies`, and create a custom policy.
![image](https://github.com/user-attachments/assets/36c93455-3c24-4005-b789-bf64639f4e68)
2. Name the policy and add an appropriate description.
![image](https://github.com/user-attachments/assets/3acd0356-b593-4e6e-b690-b5c2a7d36326)
3. No Admin units assigned for these kind of policy tests. The policy was applied to all locations as the previous one (Email, SharePoiint, OneDrive, etc).
4. I created a custom rule for the policy. Here I applied a custom condition, selecting sensitive info type.
![image](https://github.com/user-attachments/assets/b75889ce-c052-4487-b9da-ba51b9f54e2f)
5. I left actions and exceptions blank, but configured user notifications to inform users on alert trigger.

### 2.1 Testing the new policy (Keyword leakage)
Using test user `Emma`, I simulated another external email with the subject "Confidential".
![image](https://github.com/user-attachments/assets/ddd45d52-3b9c-4fb4-941f-b70fe193c033)
Which successfully triggered the DLP policy with keyword classifier.
![image](https://github.com/user-attachments/assets/6a991b51-569f-4d6c-b315-959d500bd03e)

### 3. DLP Policy for: File types




