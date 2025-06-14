# 🛡️ Microsoft XDR: EntraID Policies

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
- Create a policy to enforce MFA on the two test users.


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



