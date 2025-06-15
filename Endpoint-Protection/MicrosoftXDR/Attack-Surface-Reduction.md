# 🛡️ Microsoft XDR: Introducing Endpoint security with Attack Surface Reduction 

## 📘 Overview
Another hands-on practical project, this time focusing on Defender for Endpoint. The goal of this project is to create and test Attack Surface Reduction (ASR) rules that harden Windows endpoints against common malware, hishing, and attacker exploitation techniques. ASR is a Defender for Endpoint feature, managed via Intune or other tools. These projects serve as a learning resource for myself, whilst also demonstrating my on-going learning into industry standard cybersecurity tools. 

**Policy Tests**: Licensing limitations in the current lab environment prevented me from testing these policies on the Microsoft Office applications. However the exercise of configuring and targeting these policies through Intune is still highly valuable, demonstrating practical familiarity with endpoint protection techni  ues. 

## 🎯 Project Objectives
- Configure and familiarise myself with ASR policies and their capabilities.
- Create 3 ASR policies to reduce the attack surface of my organisations endpoint devices.
- Understand what these ASR policies do and how they protect the organisation from their related common attacks.

## Attack Surface Reduction (ASR) Summary
An attack surface includes all the places in which an attacker could comprimise the organisations devices (endpoints) or networks. Reducing the attack surface means we are giving attackers fewer ways to perform their attacks, targeting software behaviours such as:
- Launching executable files and scripts that attempt to download or run files
- Running obfuscated / suspicious scripts
- Suspicious app behaviours

These software behaviours are sometimes seen in legitimate applications, however in this case they are risky as attackers commonly abuse them through malware. ASR rules cna help minimise this risk and help keep the organisation safe. [Resource](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction)

## ASR Goals
- Configure an ASR policy to block office child process creation
- Configure an ASR policy to block executables from Email and Webmail
- Configure an ASR policy to block untrusted and unsigned processes that run from USB

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

### 2. ASR Policy: Block Executables from Email and Webmail
Malware can be delivered as attachments or via links in phishing emails. This policy blocks common executables when launched from Outlook or browser downloads, such as `.exe`, `.bat`, `.scr`, etc. In `Email & Collaboration`, we can also set anti-malware policies, the difference being is that here we are focusing n endpoint/device security. `Email & Collaboration` anti-malware policies scan email messages before they reach user inboxes. For this policy in ASR, we are focusing no local execution on a device post download.

1. In `Attack surface reduction` I clicked `Create Policy`, selecting `Windows` as the platform and `Attack Surface Reduction Rules` as the Profile.
2. The difference with this policy, is this time I selected to `block executable content from email client and webmail`.
![image](https://github.com/user-attachments/assets/bc3ef9da-9298-40f2-9b73-c332c0ac94f1)
3. The policy was also set to our Test Lab VM, but in a production setting you could apply this to any number of users, user groups, and device groups.
![image](https://github.com/user-attachments/assets/ad3c6d63-1d2e-4455-8a5d-c88f86ff6ca6)
4. This ASR rule reinforces defence-in-depth by introducing device-level policy enforcement. With this policy in place I now have layered security controls in place, where anti-malware policies in Defender for 365 will block/quarantine executable attachments before reaching the endpoint. However with this extra policy, if a threat somehow got past email filtering, this rule ensures that the executable can't be run on the device/endpoint.

### 3. ASR Policy: Block untrusted and unsigned processes that run from USB
USB malware delivery is used by attackers to gain access to a system, typically involving tactics like leaving a USB device in a public or office setting with hopes that a curious employee plugs it in. These devices typically contain preloaded malware like trojans or ransomware. This policy blocks these processes from running directly from the USB, helping reduce the risk of drive-by execution attacks. 

1. For this third policy, I chose the appropriate rule:
![image](https://github.com/user-attachments/assets/9fb34491-0c5c-45cc-a32e-22aa4cc1f019)
2. In my current lab environment I do not have an endpoint to assign this to, as the only endpoint is a VM. In this case on assignments, I chose `All devices`, so in the event a new physical endpoint is onboarded, it is covered by this policy.
![image](https://github.com/user-attachments/assets/4926fc2e-55fa-4f91-8c9c-22d0444f56eb)

### Summary
In this short introductory project to ASR, I configured 3 policies to better secure the endpoint devices in my organisation. These ASR rules focus on blocking malicious behaviours commonly used by attackers, such as child process abuse, executable delivery via phishing, and USB-based malware, all to reduce the attack surface area at the endpoint level.

While testing was limited due to lab constraints, the hands-on experience gained using this Intune tool provided valuable familiarity with how endpoint hardening policies are deployed. As a next step, I intend to stay within Intune, but pivot onto **Endpoint Detection and Response (EDR)** policies, and **Firewall** policies. Where ASR acts as a preventative layer, EDR and Firewall policies expand my defence strategy to include detection, containment, and network-layer control, continuing my journey into a layered, proactive cybersecurity approach.














