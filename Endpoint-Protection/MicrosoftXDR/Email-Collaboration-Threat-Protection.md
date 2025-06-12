# 🛡️ Microsoft XDR: Email & Collaboration Threat Protection

## 📘 Overview
This project is a follow to my previous project in which I began exploring some of the capabilities of Data Loss Prevention (DLP) [project](https://github.com/wilbcn/BlueTeam/blob/main/Endpoint-Protection/MicrosoftXDR/Data-Loss-Prevention-Practice.md). This time I will be looking at Microsoft Defender for Office 365 and Exchange Online Protection through a SOC Lens. Here I implemented and tested security policies related to email threat detection and user safety, with the overall goal of gaining practical experience using the platform, as well as experience responding to threats like phishing or malware. 

This project also serves as a learning resource for myself, helping to solidify my knowledge on this security tool.

## 🎯 Project Objectives
- Understand and configure email threat protection features (e.g., anti-phishing, malware filtering).
- Create and simulate alert policies relevant to a SOC.
- Test Safe Links and Safe attachments in action.
- Explore how email security policies can feed into XDR visibility.
- Document findings, alert behaviour, and overall flows.

## Email & Collaboration Summary
Microsoft Email & Collaboration is a core part of XDR, focusing on securing communication channels such as email, and integrated apps like SharePoint, OneDrive, and Teams. It protects against a range of threats like phishing, malware, spam, impersonation, and malicious links/attachments. During my cybersecurity studies for my MSc, it has become apparent knowledge that email/phishing remains the #1 attack vector in most cyber incidents. This partly prompted my extra curricular studies in which I passed the BTL1 exam, as it contained a huge domain on phishing content. In this project, I explore XDR's capabilities for tackling this #1 threat, giving SOC teams visibility into suspicious attacker behaviour and user activity.

Email threats are typically the first step into broader attacks, such as credential harvesting and ransomware. In this sense, Blue teamers need the ability to monitor and respond to these threats quickly and efficiently. Within this collaboration tool, we have a wide variety of Alert and Threat policies, in which I aim to gain practical experience with in this project. Not only to solidify existing knowledge, but to showcase my enthusiam and learning progression as I continually work towards my career in Cybersecurity.

## Email & Collaboration Goals
- Anti-phishing policy - User Impersonation Protection
- Anti-malware policy



### 1. Anti-phishing Policy - User Impersonation Protection
User impersonation in phishing involves attackers mimicking the identity of a known/trusted individual or entity to decieve recipients into taking harmful actions. It is a common tactic in phishing emails, where the attacker pretends to be a legitimate sender, such as the IT Admin. To create this policy, I headed over to `https://security.microsoft.com` -> `Email & Collaboration` -> `Threat Policies` -> `Anti-phishing`.

Steps taken:
1. Firstly, I clicked on `create` under Anti-Phishing, and named the new policy `User Impersonation Protection`.
2. Under `Users, groups, and domains`, I added the two test users I created for the previous project. 
![image](https://github.com/user-attachments/assets/ca2ff660-00a2-4b46-ae0a-b3bc395ba412)
3. In the `Phishing threshold and protection` section, I toggled the radio button for user protection, domain protection (domains I own), mailbox intelligence and imnpersonation protection, and also spoof intelligence.
What do these mean?
- User protection: Watch for impersonation attempts against specific internal users. In this case, I am specifying the test users highlighted above.
- Domain protection: Protects against the 365 domain I created as part of the learning trial. Covers impersonation of my domain @domain.onmicrosoft.com.
- Mailbox intelligence: Inspects email patterns to detect anomalies. I.e. Someone who has never emailed Emma before suddenly sends her one.
- Spoof intelligence: Helps protect against forged email headers/domains, even if SPF/DKIM/DMARC checks pass.

4. For the actions section, I toggled move the message to the recipients junk email folder.
5. For Safety tips & indicators, I turned on safety tips for all recommendations. Finished and submitted!
![image](https://github.com/user-attachments/assets/c3a45db6-d687-46f0-94bf-114b7e2555f5)

### 1.1 Policy testing: Anti-phishing - User Impersonation Protection
To test this policy, I went and created a brand new gmail account, impersonating one of my test users Emma Cook. From her gmail account, I constructed and test an email to the other test user Tom.
![image](https://github.com/user-attachments/assets/107f17bd-f557-40b7-aeba-f204035f3c90)
The email was appropriately moved to Tom's junk folder. This will be due to `Spoof Intelligence`.
![image](https://github.com/user-attachments/assets/5a1f75be-b900-4a15-87e4-e431c51199bf)
Although the anti-phishing policy was configured to quarantine impersonated messages, this one was only moved to Junk. This is likely due to Exchange Online’s spam policies or spoof intelligence intercepting it before the custom policy actions applied.
As I continue into the next sections, I’ll attempt to trigger a quarantine event and generate a related alert or incident that I can investigate through Microsoft 365 Defender.

### 2. Anti-malware policy

