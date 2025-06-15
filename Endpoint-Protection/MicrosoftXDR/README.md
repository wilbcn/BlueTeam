# Endpoint security with Microsoft XDR

Projects found in this folder showcase exploring the Microsoft XDR platform, where I carry out fundamental projects to help solidy existing knowledge and gain further experience using the XDR UI. I explore various areas of XDR, including Security, Purview, Entra, Email & Collaboration, and more.

## Data-Loss-Prevention-Practice
In this beginner project, I get familiar with Microsoft Purview and Data Loss Prevention capabilities (DLP). I created 3 policies for the organisation, including:
- PII Detection & External Sharing Block: Detect and restrict external sharing of PII such as passport numbers
- Keyword Leakage: Prevent files with sensitive business tags from being shared externally (e.g, "Confidential", "Internal Use Only")
- File type-based policy: Detect and block specific file types from being shared externally (e.g., .zip, .exe)

## Email-Collaboration-Threat-Protection
In this follow up project, I explore Email & Collaboration threat protection domain as part of Microsoft Defender for Office 365. I configured threat policies and test them against my test users, as well as carrying out simulated phishing campgains. This project served as fundamental yet practical hands on experience with these tools. In this project I created:
- Anti-phishing policy: User Impersonation Protection
- Anti-malware policy: Detect and investigate a test malware file
- Attack Simulation Training (AST): Simulate real-world phishing and social engineering attacks

## EntraID-User-Protection
In the third project of my Microsoft XDR series, I explore some of the capabilities of Entra ID, which focuses on identifying, analysing, and mitigating identity-related risks in real time. By leverading advanced machine learning and AI, behaviour anomalies can be detected and conditional access policies enforced to assist in preventing unauthorised access. Entra ID acts as a first line of defence against identity-based threats, ensuring that only legitimate users are able to gain access to their intended resources. In this project I:

- Create a conditional access policy to enforce MFA on the two test users.
- Create a conditional access policy to block access for user logins outside trusted location.
- Create a conditional access policy using an existing template: Require password change for high-risk users
- Set a custom banned password list for users

## Attack-Surface-Reduction
Another hands-on practical project, this time focusing on Defender for Endpoint. The goal of this project is to create and test Attack Surface Reduction (ASR) rules that harden Windows endpoints against common malware, hishing, and attacker exploitation techniques. ASR is a Defender for Endpoint feature, managed via Intune or other tools. In this project I: 

- Configure an ASR policy to block office child process creation
- Configure an ASR policy to block executables from Email and Webmail
- Configure an ASR policy to block untrusted and unsigned processes that run from USB
