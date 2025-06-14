# 🛡️ Microsoft XDR: Introducing Protection in Entra ID

## 📘 Overview
In this hands-on and practical project, I look at Identity Protection policies in Entra ID. This is a follow up project, where I previously explored Email & Collaboration policies to better secure email communications. [project](https://github.com/wilbcn/BlueTeam/blob/main/Endpoint-Protection/MicrosoftXDR/Email-Collaboration-Threat-Protection.md). In this project I create a variety of policies related to user risks, user sign-ins, baseline conditional user access, and more. These projects in XDR serve as a learning resource for myself, whilst also demonstrating my on-going learning into industry standard cybersecurity tools. 

## 🎯 Project Objectives
- Understand the core identity protection capabilities of Microsoft Entra ID.
- Configure Sign-in Risk and User Risk policies to detect suspicious activity.
- Enforce MFA and Conditional Access based on behavioral risk indicators.
- Implement RBAC to control administrative scope and privilege access (aligning with least privilege principles).

## Microsoft Entra Summary
Microsoft Entra ID Protection is a cloud-based security feature within Microsoft Entra ID. It enables employees to securely access both external resources, such as Microsoft 365 and the Microsoft Azure portal, and internal applications. Entra ID protection specifically focuses on identifying, analysing, and mitigating identity-related risks in real time. By leverading advanced machine learning and AI, behaviour anomalies can be detected and conditional access policies enforced to assist in preventing unauthorised access. Entra ID acts as a first line of defence against identity-based threats, ensuring that only legitimate users are able to gain access to their intended resources. 

The core capabilities of Entra ID Protection are:
- **Sign-in Risk Detections**: Flags suspicious login attempts based on behavioral analytics and known attack patterns.
- **User Risk Detections**: Continuosly assesses user behavior to determine if their account is compromised.
- **Risk-based Access Control Policies**: Adapts access permissions based on real-time risk assessments.
- **MFA Policies**: Enforces MFA based on sign-in metrics.
- **Conditional Access Policies**: Set conditional access policies based on risk factors such as user location, device health, and sign-in behaviour. 
- **Threat Intelligence Integration**: Leverages Microsofts threat intelligence netowork to identify known attack patterns and techniques.
- **Automated Responses**: Automated responding to security events such as account blocking and password resets etc.
- **Real-Time and Offline Detections**: Detects both live and offline threats by analysing risk factors.

## Entra ID Goals
- Create a conditional access policy to enforce MFA on the two test users.
- Create a conditional access policy to block access for user logins outside trusted location.
- Create a conditional access policy using an existing template: Require password change for high-risk users
- Set a custom banned password list for users

### 1. Conditional Acess Policy: MFA for test users
Microsoft recommends using **Conditional Access policies** over standalone User Risk and Sign-in policies. This offers more granular control over the policy, allowing us to combine sign-in or user risks with further conditions. 
In this section, I will create a conditional access policy on 

Steps taken:
1. Before getting started, I disabled the `security defaults` before enabling a `Conditional Access Policy`.
2. This policy was created under `Entra` -> `Protection` -> `Identity Protection` -> Conditional Access` -> `New Policy`.
3. This new policy will enforce MFA for my two test users created in a previous project, Tom & Emma. Microsoft recommends leaving at least one user out of new policies to avoid account lockouts.
4. On the new policy screen I appropriately named the new policy `MFA for test users`. I then added the two test users under the `Users` section.
5. For `Target Resources` I chose `All resouces (formerly All cloud apps)`. `Network` and `Conditions` were not configured as they are not required for this policy.
6. For `Grant` I toggled `Grant Access` and checked `Require multifactor authentication`.
7. I also applied a sign-in frequency of 1 hour. This means periodic reauthentication will be enforced every 1 hour.
![image](https://github.com/user-attachments/assets/e318f1e0-0b36-4b1c-a515-b90c9dfd0a8f)
8. The new appears under `Conditional Access | Policies`. 
![image](https://github.com/user-attachments/assets/c5bd3cc6-275a-4ef7-b153-ed0a1d2de0a2)

### 1.1 Testing the policy: MFA for test users
MFA was enforced when I tried logging in as the test user Emma, confirming the policy is up and running. 
![image](https://github.com/user-attachments/assets/f681e009-ffd8-4a0a-82ae-856f24b73265)

### 2. Conditional Acess Policy: Block Access from Unsupported or Untrusted Locations
The goal of this policy is to block sign-ins from locations not explicitly marked as trusted (e.g., outside my home country or a defined IP range). This policy will help mitigate risks like foreign login attempts, which could be from compromised user credentials.

Steps taken:
1. To begin with, I first created a new `Named location` which I can later utilise during the policy creation process. The new named location was added under `Entra` -> `Identity Protection | Dashboard` -> `Security | Named locations`.
2. I added a new country by clicking on `+ Countries Location`, naming it `Trusted - Home Country (Spain)`.
3. The country lookup method was left at default (IPv4/6 lookup), and I then selected `Spain` from the menu.
![image](https://github.com/user-attachments/assets/01dd3b2a-1cde-4fcf-8983-9023e498e7b0)
4. We can see the new named location in the list, as well as that is has not yet been configured to any policy. Lets fix that!
5. I then proceeded to create a new policy named
6. The two test users were added, and `target resources` were selected as `All Resources`.
7. Under `Network` and `Conditions`, all networks and locations were included in the policy. Meaning anything outside the trusted location would violate the policy.
8. For Exclude I selected from the menu our new named location: `Trusted - Home Country (Spain)`.
9. Block access was selected for `Grant`, and I created and enabled the new policy.
![image](https://github.com/user-attachments/assets/99be408d-cdad-40a9-9b86-c1b29d008988)
10. Policy list:
![image](https://github.com/user-attachments/assets/71bc80a1-b3e6-4e0e-82e8-269b6095b760)

### 2.1 Testing the policy: Block access for user logins outside trusted location
I then initiated a login from the U.K., which is outside of the `named locations` we set earlier. This correctly appeared with status `Failure`, in the `Users | Sign-in logs`.
![image](https://github.com/user-attachments/assets/2a02b62e-dcf2-4f03-9114-4b55093d7880)
There is no high-level “alert” to be triggered because Microsoft saw this as a policy success, not a security escalation. However if connected to `Microsoft Sentinel`, we could create analytical rules for this kind of policy violation.

### 3. Conditional Access Policy from template: Require password change for high-risk users
In the `Conditional Access | Policies` page we can also setup a new policy using an existing template. These templates fall under multiple categories, including secure foundation, zero trust, remote work, and more.

Steps taken:
1. In the `Conditional Access | Policies` page, I clicked `New policy from template`.
2. Under `Zero Trust` I chose `Require password change for high-risk users`. 
![image](https://github.com/user-attachments/assets/f2609137-770f-4dc7-937a-4893b6c6169f)
3. A user is flagged as high-risk when Microsoft detects credible indicators that their identity might be under attacker control. We dont control this but instead control how to respond with policies and manual remediations.
![image](https://github.com/user-attachments/assets/b6e8bf42-cfef-4e51-9a85-c80d4b229665)
4. These risky sign-ins would appear in the `Report` section of `Identity Protection`.
![image](https://github.com/user-attachments/assets/d6a4e8ad-ca11-483e-ab87-100bf80edb5f)

### 4. Authentication methods: Set a custom banned password list for users
In Entra `Authentication methods`, we have the option to enforce a custom list of banned passwords, providing an extra layer of security for password-based authentication by enforcing both a global and custom list of banned words for user passwords. Here we cant define detailed password complexity rules directly, instead microsoft enforces default cloud password policies which define the minimum length, character complexity etc. [Password Policy](https://www.cayosoft.com/azure-security-best-practices/azure-ad-password-policy/#Section3). The custom passwords I create later must at least comply with the restrictions.

![image](https://github.com/user-attachments/assets/b2b78dfc-2d31-4f35-b697-4576bd8ee8c8)

Creating custom banned passwords are still highly useful, as they allow organisations to proactively block predictable, weak, or company-related passwords that attackers often guess in spray attacks. Practicing this now reinforces the importance of credential hygiene and helps simulate real-world security baselines that reduce the success rate of password-based attacks — even in lightweight, cloud-native environments like my test lab.

### Goals of the custom banned password list
Prevent users from choosing the following:
- Obvious weak passwords
- Password tied to the organisations identity or culture
- Varients of breached passwords
- Predictable patterns attackers would try in password spray attacks


Steps taken:
1. To create the custom banned password list, I headed to `Entra` -> `Protection` -> `Authentication methods` -> `Password protection`.
2. By toggling enforce custom list, we now access to type or paste in a custom list of banned passwords.
3. For this project and test scenario, we are creating a custom banned password list for a hypothetical organisation. The below information outlines the logic tied to this banned password list.

- **Company name**: Big Blue Security
- **Location**: Barcelona
- **Domain**: Cybersecurity

Along side the above, I will also be targeting other common buzzwords and themes such as:
- Seasonal passwords like `Summer2025`
- Weak/Predictable passwords like `CyberAdmin123` or `SOCAdmin1`

4. With this logic in mind, I created the below custom banned password list and hit `Save`:
![image](https://github.com/user-attachments/assets/826e916c-3447-4b52-a42f-aceac6685b7a)

![image](https://github.com/user-attachments/assets/deadc742-c9a3-4f54-9ba9-2ff87e35a0ff)

### 4.1 Testing the custom banned password list
To verify this custom list was working, I logged in as one of my test users and attempted to change their password.

1. As test user Emma, in `myaccount.microsoft.com` I clicked on `Change Password`, and entered one of the blocked passwords from the custom list.
![image](https://github.com/user-attachments/assets/9caa74b8-028c-40b1-a9c8-72b287533175)
2. The new password was not accepted! An invalid word was used.

### Project Summary
In this project, I explored some of the core identity protection features within Microsoft Entra, focusing on conditional access policies and authentication hardening. Through these hands-on configurations and tests, I implemented a variety of key policies including MFA enforcement, geo-based access restrictions, and automated remediation for high-risk users. I additionally configured a custom banned password list to reflect real-world credential hygiene standards.

This practical experience helped reinforce critical identity security concepts such as least privilege, zeor trust, and credential protection. This project is a learning resource for myself, helping to solidify knowledge as I carry out projects and work with industry standard security tools. I aim to continue on this path working with Microsoft Defender to build a strong foundational knowledge base. 
