# 🛡️ Microsoft XDR: Attack Surface Reduction (WIP)

## 📘 Overview
Another hands-on practical project, this time focusing on Defender for Endpoint. The goal of this project is to create and test Attack Surface Reduction (ASR) rules that harden Windows endpoints against common malware, hishing, and attacker exploitation techniques. ASR is a Defender for Endpoint feature, managed via Intune or other tools. These projects serve as a learning resource for myself, whilst also demonstrating my on-going learning into industry standard cybersecurity tools. 

**Policy Tests**: Licensing limitations in the current lab environment prevented me from testing these policies on the Microsoft Office applications. However the exercise of configuring and targeting these policies through Intune is still highly valuable, demonstrating practical familiarity with endpoint protection techni  ues. 

## 🎯 Project Objectives
- Configure and familiarise myself with ASR policies and their capabilities
- 

## Attack Surface Reduction (ASR) Summary
An attack surface includes all the places in which an attacker could comprimise the organisations devices (endpoints) or networks. Reducing the attack surface means we are giving attackers fewer ways to perform their attacks, targeting software behaviours such as:
- Launching executable files and scripts that attempt to download or run files
- Running obfuscated / suspicious scripts
- Suspicious app behaviours

These software behaviours are sometimes seen in legitimate applications, however in this case they are risky as attackers commonly abuse them through malware. ASR rules cna help minimise this risk and help keep the organisation safe. [Resource](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction)

## ASR Goals
- Configure an ASR policy to block office child process creation
- 

### 1. ASR Policy: Block Office Child Process Creation
ASR policies will directly affect the devices(endpoints) within my organisation. Before creating the first policy, I configured, deployed, and onboarded a device in Azure on Windows (not shown).

![image](https://github.com/user-attachments/assets/22d04581-01f1-4de1-b61e-d5fb7003ca99)

Attack surface reduction is currently located under `intune.microsoft.com` -> `Endpoint security` -> `Attack surface reduction`. This policy will block child process creation from Microsoft Office applications like Word, Excel, and PowerPoint. Malware is often disguised as legitimate business documents in these applications can spawn malicious child processes when opened, such as PowerShell or CMD, to download additional payloads, establish persistence, or data exfiltration. 

1. In `Attack surface reduction` I clicked `Create Policy`, selecting `Windows` as the platform and `Attack Surface Reduction Rules` as the Profile.
2. In the `Create Policy` screen I appropriately name and added a description to the policy.
![image](https://github.com/user-attachments/assets/6e0f0b6a-6329-497f-a53b-f49adc7fd364)
3. For `Configuration settings` I selected the `Block` action under `Block all Office applications from creating child processes`. The `ASR Only Per Rule Exclusions` was not changed, however this would allow trusted internal macros for automation to still run in explicitly defined scenarios, which is useful to know.
![image](https://github.com/user-attachments/assets/96e3def9-949d-4e34-bc9b-a3bc5ce4b202)
4. `Scope Tags` is intended for organising policies at scale. For my small test lab setup, I skipped this stage.
5. `Assignments` determines which devices or groups get the ASR policy. For this section I created a brand new Group called `Test Lab Devices`, and assigned the VM to this group. Now back to the policy screen, I can select this group as part of the assignments (Include).

![image](https://github.com/user-attachments/assets/c3c11735-3f4c-471b-a1c7-495b7dedcf19)

![image](https://github.com/user-attachments/assets/749367eb-388d-4e83-9f0c-9db6f7f42afa)

6. On the next screen for `Review + Create`, everything checks out, so I hit `save`.

![image](https://github.com/user-attachments/assets/bfd4e3f4-92d8-45d3-b0ad-620860198e80)

![image](https://github.com/user-attachments/assets/ef2dde41-7d38-4324-a057-6e80be79f2fd)

### 2. ASR Policy:
