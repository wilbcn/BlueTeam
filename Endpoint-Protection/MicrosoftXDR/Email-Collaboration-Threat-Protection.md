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
- Anti-phishing policy: User Impersonation Protection
- Anti-malware policy: Detect and investigate a test malware file
- Attack Simulation Training (AST): Simulate real-world phishing and social engineering attacks


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
1. To test this policy, I went and created a brand new gmail account, impersonating one of my test users Emma Cook. From her gmail account, I constructed and test an email to the other test user Tom.
![image](https://github.com/user-attachments/assets/107f17bd-f557-40b7-aeba-f204035f3c90)
2. The email was appropriately moved to Tom's junk folder. This will be due to `Spoof Intelligence`.
![image](https://github.com/user-attachments/assets/5a1f75be-b900-4a15-87e4-e431c51199bf)
3. Although the anti-phishing policy was configured to quarantine impersonated messages, this one was only moved to Junk. This is likely due to Exchange Online’s spam policies or spoof intelligence intercepting it before the custom policy actions applied.
4. As I continue into the next sections, I’ll attempt to trigger a quarantine event and generate a related alert or incident that I can investigate through Microsoft 365 Defender.

### 2. Anti-malware policy
Defender for 365 has a default anti-malware policy, which detects and blocks common file types such as `.bat, .cmd, .appx` and more. With a custom policy, I can define explicitly who the policy applies to, including per user, group, role, or region. I can also fine tune the policy, enabling `zero-hour auto purge for malware`, and notification settings on quarantined/detected messages containing malware.

Steps taken:
1. Still in Email & Collaboration, I navigated to `Policies & Rules` -> `Threat Policies` -> `Anti-malware`.
2. I created a new anti-malware policy, enabling common attachment filters, and to quarantine the message when the filtered file types are found.
3. I added the two test users to the policy, as well as the organisations domain. 
4. I enabled zero-hour auto purge for malware, which quarantines any messages found to have malware after they are delivered to Exchange Online Mailboxes.
5. I also enabled Admin notifications, saved, and submitted the policy.
![image](https://github.com/user-attachments/assets/bfc69652-3d4d-4f22-be02-4c5d7febf226)

### 2.1 Policy testing: Anti-malware
To test this policy, I created a .txt document with a known anti-virus test string: `EICAR Standard Anti-Virus Test File`.
![image](https://github.com/user-attachments/assets/8825012d-d0a5-41be-afa8-eff725944309)

1. I logged in as test user Tom, and generated a fake/phishing style email addressed to Emma, with the malware attached disguised as an invoice.
![image](https://github.com/user-attachments/assets/ffbe31be-bfc7-4a62-80b5-223932ae3e75)
2. Back to the `security` dashboard, I navigated to `Email & Collaboration` -> `Review` -> `Quarantine`.
![image](https://github.com/user-attachments/assets/58dac7c6-234b-4fb1-87cd-78720069edee)
3. By selecting the email, we can preview the message to view the email that has been quarantined.
![image](https://github.com/user-attachments/assets/ef2fef34-3a51-4e50-a132-acae065d57bf)
4. Also by clicking on the email entry, we get the quarantine details. Here we can see that the new policy under `Policy name` was applied correctly, and it was correctly identified as malware.
![image](https://github.com/user-attachments/assets/0ca24a3a-ee90-4087-a4c1-84e952f2577f)
5. Further down we can find the threat classification as well as details on the original sender.
![image](https://github.com/user-attachments/assets/37357d6d-cab2-4904-b6c9-f8fd476a0a03)
6. At the very bottom of the report, we have the artifacts (urls/attachments) detected from the email. Here we can clearly see the attachment has been correctly detected as the EICAR test file.
![image](https://github.com/user-attachments/assets/c3f91885-45a8-491d-a1cb-350cf91c18d6)
7. By clicking on `View all Attachments`, we could then export the file for further investigations, though this should be done on an isolated virtual machine, configured for malware diagnosis and investigations.
8. While still in the quarantine details report, at the very top is the `Take action` button, where the SOC analyst/security person can choose the appropriate response actions.
![image](https://github.com/user-attachments/assets/82e042fa-b973-4b7d-a760-b5e50e24be04)
9. To remediate this test, under `Take action`, I submitted to microsoft to review as a confirmed threat. I added the test users to the impacted assets, and clicked submit.
![image](https://github.com/user-attachments/assets/ffabe7aa-eca1-4cca-ad6d-44313ab05339)
![image](https://github.com/user-attachments/assets/4149bf29-fdc0-4cf7-92f4-8a8b218326f9)
10. Additionally in `Email & Collaboration` -> `Explorer`, we have an overview of all emails, where we can filter by URLs, Top Clicks, Top targeted Users, and more. You can see the top message is the undeliverable message alert send to the admin email address from the EICAR test.
![image](https://github.com/user-attachments/assets/4c90cd67-fad9-46c3-8189-8df140a5c68d)
11. Also in the `Top targeted users` section, we have our two test users in which I have been simulating numerous tests for.
![image](https://github.com/user-attachments/assets/370e3305-07a5-454d-ae48-3b2c578f532a)
12. From this page, SOC analysts can also investigate and take actions against identified threats, as well as exporting the data. Outside of this project, I have been exploring the capabilities of `Explorer` to familiarise myself with it.

### 3. Attack Simulation Training
In `Email & Collaboration` -> `Attack simulation training` we can simulate phishing attacks against users within our organisation. This helps useful insights for SOC analysts/security professionals, such as users who have failed to spot phishing emails and require additional training. It also provides a clear overview of the organisation as a whole, supplying statistics which help to identify weak areas. Here we can also launch training campaigns, providing essential user training against the #1 attack vector, phishing emails. In this project, I will familiarise myself with the capabilities of `Attack simulation training`, and carry out a simulating phishing campaign against my test users.

1. To begin, I will launch an instant simulation against my organisation. Microsoft then chooses the simulation content for us, e.g. credential harvester + the payload.
![image](https://github.com/user-attachments/assets/622b376f-1155-46d7-ad04-17d25ed0c33e)
2. I then launched the generated simulation. Preview below:
![image](https://github.com/user-attachments/assets/be419768-626f-4b99-8c3a-28dfd91e2c2c)
3. In the `Simulations` tab, we are able to see this credential harvester and the time it was launched.
![image](https://github.com/user-attachments/assets/f227cbc0-7703-4d64-a7bd-534be6c3cd42)
4. The phishing simulation was correctly received, to which I reported it as phishing. This was successfully reflected in the campaigns report view.
![image](https://github.com/user-attachments/assets/a87761d8-8560-4071-b8e6-f7267737f51e)
5. Moving forward, I setup and launched a more customised phishing campaign. For this custom campaign, I chose `Link to Malware`.
6. For the payload and login page, I went with `One Drive Document Share`. This screen is really useful and even predicts the compromise rate based off of the payload chosen.
![image](https://github.com/user-attachments/assets/ec7756d3-1370-4639-a549-28bfc6d14f9a)
7. I targetted the two test users I have setup for these practical projects.
![image](https://github.com/user-attachments/assets/bf58b8b4-a5db-425d-8259-1491c5108d88)
8. I selected `Assign training for me`, which lets microsoft assign training courses based on the users interaction with the phishing campaign. The due date was set to 7 days, which is not so important for these tests but good to know we can specify this.
9. I went with the default landing page, which is displayed if the user was successfully phished.
![image](https://github.com/user-attachments/assets/cde2c8cf-a32b-4f8a-8544-8bf5ea99e599)
10. For the `end user notifications`, I went with a positive reinforcement notification to be delivered during the simulation, as well as weekly reminders for thet user training.
11. After reviewing the campaign, I launched it against the two test users.

### 3.1 Interacting with the phishing campaign
