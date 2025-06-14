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

