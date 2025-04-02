# 📧 Investigating Phishing Emails: 1

## 📖 Overview
This document provides an overview of the steps taken to investigate a potential phishing email. In this scenario, I have received a real suspicious email, which inspired this project. I created this project to gain increased hands on experience and understanding of using a wide variety of tools for conducting phishing analysis, developing a better understanding of artifact collection, and phishing email diagnosis. Furthermore, to practice writing reports that a real security analyst might write up when investigating suspicious emails.

💡 This project was inspired by my learning in the** [**Blue Team Level 1**](https://www.securityblue.team/blue-team-level-1) course, where I gained a solid introduction into email analysis and artifact collection.

You can find the setup of the secure VM in AWS here -> [EC2 VM](https://github.com/wilbcn/BlueTeam/blob/main/Digital-Forensics/EC2-HomeLab-Setup.md)

## 🎯 Goals
- Successfully analyse the suspicious email in a secure environment
- Collect all relevant artifacts and organise them
- Use the collected artifact to carry out the investigation
- Leverage analysis tools for practice
- Document findings and create a final report

---

## 🛠️ Tools used
- Email header analyzer: https://mxtoolbox.com/EmailHeaders.aspx
- URL2PNG: https://www.url2png.com/
- AbuseIPDB: https://www.abuseipdb.com
- Cisco Talos Intelligence: https://talosintelligence.com/reputation_center/l


## 1. Email overview.
I moved the suspicious email onto my EC2 VM, and opened it using Mozilla Thunderbird. For security/privacy reasons, my email address has been hidden. 

![image](https://github.com/user-attachments/assets/cfccbacc-fb3f-4f98-b81f-ede4dfbe4580)


An initial analysis provides us with several red flags which indicate a potential phishing email.

- Lack of personalised greeting. A legitimate email would address me formally.
- The apparent sender **mendesmend8pif@virgilio.it**. This is highly suspicious sender address.
- The overall body content is not that of a professional service, such as an estate agent advertising an apartment.
- No official company signature.
- The email itself is unsolicited.
- The email asks for me to engage with it in order to find out more information.
- Email was received at 21:39 CET. This is definately outside of working business hours for a legitimate source.

## 2. Collecting Artifacts.
To gather the email artifacts to investigate further into this email, I used the email header analyzer tool from mxtoolbox. I opened the .eml in notepad++, and copied the header into the tool.

✅ DMARC Compliant – The email passed DMARC authentication, meaning the sender’s domain has a DMARC policy in place.
✅ SPF Alignment & SPF Authenticated – The email originated from an authorized mail server, as specified in the domain’s SPF records.
✅ DKIM Alignment – The DKIM signature matches the expected sending domain, which typically confirms the email was not altered in transit.
❌ DKIM Authentication failed suggesting that:

- The DKIM signature may have been forged.
- The signature didn’t match the cryptographic key in DNS.
- The email could have been modified after signing, indicating a possible spoofing attempt.

![image](https://github.com/user-attachments/assets/9332d6af-42f8-44b3-bf02-dbd1f9a60dce)

The tool also provides us with a wide variety of valuable artifacts, under the headers section. 

| **Header Field**       | **Value** |
|------------------------|---------------------------------------------------|
| **Delivered-To**       | *(Hidden Address)* |
| **Return-Path**        | `<mendesmend8pif@virgilio.it>` |
| **Date**              | Thu, 20 Feb 2025 21:39:09 +0100 (CET) |
| **From**              | `mendesmend8pif@virgilio.it` |
| **Subject**           | Lloguer en Carrer Gran de Gràcia - Metro Lesseps Barcelona BBZM18 |
| **Received-SPF**      | `pass (google.com: domain of mendesmend8pif@virgilio.it designates 213.209.9.36 as permitted sender)` |
| **Client IP**         | `213.209.9.36` |
| **X-Originating-IP**  | `2.39.110.75` |

## 3. Investigations.
- Tool: URL2PNG

![image](https://github.com/user-attachments/assets/535eb3c0-7a40-44a5-a52c-ad8f9271373c)

By converting the web page into a png image, we can gain insights into the web page without actually visiting it. Here we can see that virgilio.it is an italian news website, which is very strange for an agency or person claiming to be advertise an apartment in Barcelona. 

- Tool: abuseipdb

![image](https://github.com/user-attachments/assets/80d3440f-1afe-497d-9976-25f5f1b1d6cd)

![image](https://github.com/user-attachments/assets/5888561d-0df7-4598-b166-812cfa4ee72f)

Neither the Client IP address, or the Originating IP address, have been flagged using this tool. However, this does not necessarily mean that these addresses are harmless. These addresses may have been compromised.

- Tool: Cisco Talos Intelligence
- Originating IP: 2.39.110.75

![image](https://github.com/user-attachments/assets/1fe3db21-b264-4294-a0ca-c16c48f4e9cd)

Using this tool we have various key take-aways.
- Location: As already discovered, the location of origin is Italy.
- The Sender IP reputation is **Poor**.
- The IP address has been listed on the **Spamhaus Blocklist**.
- Legitimate mail servers typically have consistent email traffic, but this one shows zero activity.
- Spam level critical, which further supports the phishing classification of this email.

- Client IP: 213.209.9.36

![image](https://github.com/user-attachments/assets/2c93b094-e743-42c8-9d82-95a968290ce5)

Key take-aways.
- The IP belongs to ItaliaOnline S.p.A, the parent company of virgilio.it, confirming it is an official email provider.
- The Reverse DNS matches, meaning the IP is properly configured for sending emails.
- Despite a **Good** sender reputation, Talos flags the spam level as **Critical**, which could indicate the server is sending a large amount of spam emails.
- A legitimate email provider should have a much larger email volume. 3.8 emails per day is very low, and ultimately suspicious.

These findings  suggests that the email was sent through a real server, but potentially from a compromised account.

## 3. Summary.
In conclusion, I have classified due to the following:
- The emails content is highly suspicious. There is no professional/business formatting, a lack of personalisation, and that this email was unsolicited.
- Using various tools, we find out that the originating IP address has been flagged for **spam**, along with a low traffic volume which is unlikely for a legitimate source.
- The sender domain **virgilio.it** is irrelevant to the context of the email, advertising apartments.

Classification: Spam!

This email is classified primarily as spam, whilst also potentially scouting for active mailboxes, aka mailbox probing. Users who interact or reply confirm to attackers that their mailbox is active, potentially exposing themselves to future, more sophisticated phishing campaigns. By engaging with this email, victims may provide the sender with sensitive information, thinking they are really enquiring about a real apartment advertisement, known as a credential harvester. 

## 4. Recommended actions.

| **Action** | **Explanation and Logic** |
|------------|---------------------------|
| **Block originating IP address (`2.39.110.75`) at email gateway or firewall.** | As this IP has a poor reputation and is listed on Spamhaus, blocking this IP will help reduce exposure to future spam or phishing emails originating from this address. |
| **Report the email to Spam/Phishing Databases.** | Reporting ensures that this email and its associated indicators become publicly recognizable. This helps reduce the effectiveness of phishing mail. |
| **Flag emails from the domain `virgilio.it`.** | Flagging emails from this domain could help mitigate similar threats. |
| **User awareness and training.** | Inform and educate users on how to identify phishing emails. |
| **Continuous Monitoring & Threat Intelligence Integration.** | Integrate threat intelligence platforms like the tools used in this investigation (e.g., Cisco Talos). |

## 5. Taking action
During our investigation, **AbuseIPDB** had 0 file reports for the identified addresses. By registering for reporting privileges, we can register this incident.

![image](https://github.com/user-attachments/assets/2aed25e3-637a-4bd6-807f-dec4877c108b)

In the above image, I have entered details from our investigation and submitted a report.

## 6. Future expansions
To further enhance my skills in phishing email analysis, I plan to investigate a broader range of phishing scenarios. In future expansions of this project, I aim to analyze phishing emails containing various types of malicious content, such as:

- Malicious attachments (e.g., documents with macros, executable payloads).
- Obfuscated or shortened URLs.
- Advanced social-engineering techniques designed to bypass detection.

Additionally, I plan to explore how phishing analysis can be automated and integrated into existing threat intelligence platforms and SIEM configurations. As part of my ongoing journey into cybersecurity, I'm actively gaining hands-on experience with Splunk and developing automated workflows through Python scripting to streamline threat detection and response.
