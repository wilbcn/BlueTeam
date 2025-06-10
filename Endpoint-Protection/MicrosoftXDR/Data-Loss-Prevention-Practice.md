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
- insert
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
7. `Customize access and override settings` was left to default.
8. I switched the policy to on immediately so we can conduct tests. On the `Review and Finish` page, I hit `Submit`. 
![image](https://github.com/user-attachments/assets/77146853-ee00-4e25-a6a6-363dc0789b55)

### 1.1 Testing the new policy (PII Detection)


