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
- PII Detection & External Sharing Block: Detect and restrict external sharing of PII such as phone numbers
- Keyword Leakage: Prevent files with sensitive business tags from being shared externally (e.g, "Confidential", "Internal Use Only")
- insert
- insert
- insert

### 1. DLP Policy for: PII Detection & External Sharing Block
This section outlines the steps taken to setup a DLP policy that detects and blocks the external sharing of personal identifiable information (PII).



