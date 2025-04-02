# 🏠 Home Lab: Active Directory Setup (VirtualBox)

## 📖 Overview
This guide documents the setup of an **Active Directory (AD) home lab** using **VirtualBox**, featuring a **Windows Server (Domain Controller)** and a **Windows 10 client**. The project was completed by following a tutorial from Josh Madakor, a cybersecurity professional and educator.

Beyond simply replicating the steps, this documentation highlights my understanding of the technical concepts, the reasoning behind key configurations, and how each component interacts within the domain environment. The lab serves as a foundation for exploring Active Directory administration, Group Policies, network management, and security testing, making it a valuable hands-on learning experience in cybersecurity and IT infrastructure.

## Acknowledgements
- How to Setup a Basic Home Lab Running Active Directory (Oracle VirtualBox) | Add Users w/PowerShell - https://www.youtube.com/watch?v=MHsI8hJmggI

## 🎯 Goals
- Gain hands-on experience with **Active Directory Domain Services (AD DS)**.
- Set up a **Windows Server Domain Controller** and join a **Windows 10 client**.
- Configure **DHCP, DNS, and Group Policies (GPOs)**.
- Learn **basic user management and security principles**.

## 🛠️ **Lab Setup: Tools, Software, Network Architecture**

**Network Architecture**
- The Domain Controller (DC) has two network adapters (NICs):
1. NIC1 (Internet-facing) → Connects the DC to the home router.
2. NIC2 (Internal, Static IP) → Acts as the default gateway for internal clients.
- Active Directory Domain Services (AD DS) is installed on the DC to manage authentication and domain resources.
- RAS/NAT is configured to allow internal clients to access the internet while remaining in the private AD environment.
- The DHCP Server on the DC assigns IP addresses to internal clients within the specified range.

Below is the network architecture we will configure. During the network config, I elaborate on these parameters.

![image](https://github.com/user-attachments/assets/6ca339b3-81a4-4fae-a18e-bb9ae381c48d)

**Domain Controller** - Windows Server 2019 (64 bit iso) - https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019
**Client Machine** - Windows 10 pro - https://www.microsoft.com/en-us/software-download/windows10

## Project walk-through
This section provides a step-by-step breakdown of the Active Directory setup, including configuration details, logical explanations, and supporting screenshots to illustrate each step.

### 1. Configure, Mount, and boot Windows Server 2019
1. Click new in VirtualBox to add a new virtual machine. I named this Domain Controller, and set the appropriate memory and dedicated CPU cores.
2. Referring to our network architecture, our DC needs two NICS (internet/internal). I set adapter one to NAT, and adapter two to internal network.

![image](https://github.com/user-attachments/assets/e43637d9-7453-449d-8183-b00e8460b7c7)

3. I then mounted the Microsoft Server ISO, and booted up the VM.

![image](https://github.com/user-attachments/assets/9ccfe474-4411-42f2-a4ed-3e99b9dab2da)

4. I then ran through the setup process, configuring the built-in Administrator account used to sign into the VM.
5. Next I configured guest additions by running the VBoxWindowsAdditions-amd64 file, and restarting the PC. VirtualBox Guest Additions enhances the performance and usability of the virtual machine with a wide variety of features.
6. After the restart, I logged in with the recently set Admin credentials. I then named our system to DomainController.

![image](https://github.com/user-attachments/assets/6b7e9915-3d56-4759-ba51-4672695e73f2)

### 2. Configure the two NICS (Internet/Internal)
1. Back before we mounted the iso during the virtual box configuration, we selected two network adapters. In our system, we need to distinguish which of these adapters is intended to be for internet access, and for internal connections.

![image](https://github.com/user-attachments/assets/946e760a-5860-4098-a100-c0986bf6d246)

2. By investigating the **details** of these two network adapters, I was able to logically work out which was which.

![image](https://github.com/user-attachments/assets/11aaeba7-325f-4f9a-b04c-e9365382723d)

3. The assigned IPv4 address of this NIC tells us this is the internet facing network. I then renamed this to INTERNET so that later on we can tell these apart.

![image](https://github.com/user-attachments/assets/c0e787e4-0815-46d7-8920-d45cc4772afb)

4. The other network adapter had been given a IPv4 169. address, which happens when Windows fails to obtain an IP from a DHCP server. Since the Domain Controller (DC) will provide DHCP and routing, we need to set a static IP address. I also appropriately renamed this one.

![image](https://github.com/user-attachments/assets/258a7a9e-0020-44ac-adf2-dd438a92ea70)

5. To set a static ip address for the internal network, I went to the properties of this NIC, and double clicked on the IPv4 option.
Here I have set the parameters:
🔹 IP Address: 172.16.0.1  
🔹 Subnet Mask: 255.255.255.0 (/24)  
🔹 Default Gateway: None  
🔹 Preferred DNS: 127.0.0.1

![image](https://github.com/user-attachments/assets/1a9a92a2-f161-4adc-9a7c-18ced718ed55)

We are using the 172.16.0.1/24 IP range, which belongs to the private IP address space. The /24 subnet mask allows all devices within this range to communicate internally within our Active Directory domain.

We dont set a default gateway on the internal network because the Domain Controller itself will act as the default gateway for the internal network. Devices in the internal network will route through the Domain Controller to reach other networks

For the preferred DNS, we set 127.0.0.1 (localhost), which tells the server to use itself as the DNS resolver. Since this server will be running DNS, it needs to query itself for domain name lookups.  

### 3. Configuring Active Directory Domain Services (AD DS)
AD DS is the core service that will enable us to create a domain, which our clients can then join, creating a centralised network for managing our users, groups, and PC systems. With AD DS, clients can then log into any domain-joined device using their credentials. AD DS also installs DNS (Domain name system), allowing our clients to find the Domain Controller in order to authenticate. We can also create security groups, enforce policies, restrict access, and manage general configurations.

1. From the server manager dashboard on the DC, click Add roles and features. This was my first time using the server manager, so after reading the recommended tasks before proceeding, I went back and checked that our version of windows was up to date.

![image](https://github.com/user-attachments/assets/e19fcc80-d912-429d-b934-513eb515c714)

**Commands ran in powershell as Administrator**
```powershell
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck  
Import-Module PSWindowsUpdate

Install-WindowsUpdate -AcceptAll -AutoReboot
```

2. After installing the updates and rebooting the VM, it was time to configure AD DS. We set the destination server to DomainController, which refers to the VM running Windows Server 2019. You can see in the IP address field a 10.0.2.15 address and the beginning of our private network address 172. This confirms the machine is correctly configured with dual-networking.

![image](https://github.com/user-attachments/assets/04f1edd1-f426-484d-9a94-f74d0222ea3d)

3. From the server roles screen, tick the box next to Active Directory Domain Services, then install.
4. After AD DS has finished installing, we need to deploy it. In the server manager notifications, we can promote our server to the domain controller.

![image](https://github.com/user-attachments/assets/8e172c58-eb64-4285-9bab-b061f01578db)

5. In the deployment configuration, we add a new forest. For this fundamental project, we call it mydomain.com. Then finish the configuration and hit install. The PC will restart, and the login afterwards now reflects our changes.

![image](https://github.com/user-attachments/assets/700a9365-5c4b-4c72-9c30-74c8bc3f4ff9)

![image](https://github.com/user-attachments/assets/ee5042e1-6b82-44ae-b81b-41e33a937670)

### 4. Create a dedicated domain admin.
After deploying AD DS, we need to create a separate domain Admin account, instead of relying on the default Administrator account. 
- This is a best security practice, as the default account is a high value target for attackers.
- Creating a separate domain admin account allows us to disable or limit the default admin account to reduce attack exposure.
- By creating a custom domain admin, we can enforce role-based access and apply group policies to limit excessive permissions.
- Organisations usually require named admin accounts for accountability and to meet security compliance standards.
- Furthermore, by using individual named domain admin accounts, we can log and audit actions more effectively in Event Viewer & Security Logs.

1. From the start menu, head to administrative tools, and open Active Directory Users and Computers.

![image](https://github.com/user-attachments/assets/6c3ceff0-3fe6-4067-a4b8-c8eed59b2126)

2. Create a new Organisational Unit under the domain **mydomain.com**, and call it Admins. Then create the admin user. I used the naming convention a-username, to signify this admin account. That way if more admins are added, we can adhere to this naming convention.
3. In the properties of this user, change the **Member Of** settings, and add **Domain Admins**, a preloaded security group which finalises our new user as an Admin.
4. Log out of the PC, and back in using the new Domain Admin details.

### 5. Setting up Routing & Remote Access, Network Address Translation (RAS/NAS)
Clients in our private network **172.16.0.X** require internet access. By configuring RAS/NAS, internal clients will be able to communicate with external networks using the Domain Controllers internet NIC. Remember that the DC has two NICS, with NIC 2 (internal/static) acting as the default gateway for our internal network. As private addresses are not routable over the internet, NAT is configured to translate these private IPs into public ones. This setup keeps our internal network isolated from direct internet exposure, reducing attack vectors.

1. From the server manager dashboard, add a new role or feature once again, and select our domain server during setup.
2. Select Remote Access, and also routing, and finish the install.
3. In server manager, navigate to tools, and open up routing and remote access.

![image](https://github.com/user-attachments/assets/089f58e9-d124-4714-a9d3-254775ea62e7)

4. By right clicking on the domain controller, we can configure and enable how our internal clients are going to connect to the internet. We select our Internet facing NIC (This is where renaming them earlier comes in handy), and finish the setup.

![image](https://github.com/user-attachments/assets/45e8520b-a8ca-444d-b158-954e65d60f51)

5. Right click on the DOMAINCONTROLLER, and hit refresh and or restart if it does not appear green.

![image](https://github.com/user-attachments/assets/43e7f923-e379-4299-a733-f114adb5cc86)

### 6. Setting up DHCP server on our domain controller
Dynamic Host Configuration Protocol (DHCP) ensures that internal network clients automatically receive correct IP configurations, allowing them to communicate within the domain and access the internet through NAT. Instead of manually assigning static IP addresses to every device, DHCP dynamically distributes IPs within our specified range. Since DHCP is hosted on the DC, it ensures that only trusted, domain-joined machines can receive IPs. New devices joining the network automatically receive an IP, avoiding conflicts and manual assignments. Also, IP address leases ensure that unused addresses return to the available pool.

1. From the server manager dashboard, click add new role or features. Select our domain, and this time install DHCP server.
2. After installation, still in server manager, go to Tools, and DHCP.
3. Expand on the domain controller, and add a new scope to IPv4. Here we are defining the scope to the private network range we identified as part of the network architecture for this project. IPs can be leased to our clients within our private network within this IP range (start/end).

![image](https://github.com/user-attachments/assets/4ef89105-6c3a-4c8a-b156-d3165cb805e5)

4. Extra settings such as lease duration was left at 8 days, and the default gateway was set to 172.16.0.1. Remember this address is the internal NIC on our Domain Controller. Check the option to activate the scope now, and check the DHCP tool now has our new scope.

![image](https://github.com/user-attachments/assets/884efbb1-6476-40ec-85b5-191bbd76bfc1)

5. Click on the domaincontroller.mydomain.com and hit authorize and refresh. IPv4 and IPv6 should turn green! Notice that Address Leases is empty, as so far we have not configured any clients within our private network to lease addresses to. This is the next step.

![image](https://github.com/user-attachments/assets/ccee2e67-23ba-4fe8-a97a-8e2bc79b1367)

### 7. Adding active directory general users
1. For our regular users, clients in the private network, we need to create a new Organisational Unit called GeneralUsers.
2. Below I have created our first user, which is for testing our network architecture. 

![image](https://github.com/user-attachments/assets/4480aca4-75b7-474f-b123-3846f3c92de6)

3. When we created Tom Smith as a new user, Active Directory automatically placed him into the Domain Users security group by default.

![image](https://github.com/user-attachments/assets/0900f4a9-a853-46e9-8102-b13297798473)

### 8. Setting up the win10 virtual machine in VB
With the Domain Controller (DC) and network configuration in place, the next step was to create a Windows 10 virtual machine (VM). This VM will act as a client machine, allowing us to:

- Log in as domain users and test authentication.
- Join the Active Directory (AD) domain to integrate with the network.

1. In the Oracle Virtual Box Manager, begin the new virtual machine process. Ensure that the only network adapter has been set to internal. 
2. Download the media creation tool from microsoft and run it to configure the windows 10 iso file.
3. Finish setting up the VM, naming it CLIENT1, and selecting Windows 10 64-Bit as the OS.

![image](https://github.com/user-attachments/assets/7626ae9d-d65b-477e-b55a-06c1fa0b88c0)

4. Boot up the VM and run through the windows setup process, choosing **Set up for an organisation** when the option appears. When prompted to sign in, choose **Domain join instead**.

![image](https://github.com/user-attachments/assets/b8d00990-2952-40e7-8d81-bce0a1719539)

5. Sign in as **local user**, with no password. We will be signing out shortly to access our GeneralUser client we made before. 
6. Running **ipconfing** in cmd, we can see that:
CLIENT1 has successfully been assigned an IP inside the internal network (172.16.0.100).

- IP Address: 172.16.0.100 → This is assigned correctly from your internal network.  
- Subnet Mask: 255.255.255.0 → Matches the /24 subnet you set earlier.  
- Default Gateway: 172.16.0.1 → This is your Domain Controller
- DNS Suffix: mydomain.com → This confirms that your machine is receiving domain-related DNS settings.

7. To confirm that our network configuration, NAT, and DNS settings were working correctly, I performed a ping test to google.com, which successfully resolved and responded.

- DNS is functioning properly, resolving external domain names.
- The client has connectivity to the Domain Controller (DC) as its default gateway (172.16.0.1).
- The DC is correctly handling NAT, forwarding traffic to the internet and receiving responses back.

![image](https://github.com/user-attachments/assets/d1760576-d882-42f9-85c1-c87b10745dd1)

8. In our client system settings, we change the PC name to CLIENT1, and finish joining our domain. To do this, we will need to enter our Domain Admin details. Afterwards, restart the PC.

![image](https://github.com/user-attachments/assets/061ef98d-d961-4c4e-8e92-2bf06b075eac)

![image](https://github.com/user-attachments/assets/13c9f0a5-7347-4081-9776-2bfb2db0ea70)

9. Back in the Domain controller (Windows Server), we can see that 1 address is now being leased! Additionally, our CLIENT1 appears in the computers folder.

![image](https://github.com/user-attachments/assets/c3092ab9-6699-4bb7-9cfc-5cae0fa22546)

![image](https://github.com/user-attachments/assets/66425779-6dcf-4d25-b12c-7a73c4219d27)

10. With the Windows 10 client successfully joined to the domain and assigned a leased IP address, the next step was to enable the user account before logging in. Before a domain user can sign in, their account must be enabled in Active Directory. Open Active Directory Users and Computers, navigate to the GeneralUsers folder, right-click the user (e.g., Tom Smith) and select Enable Account. The option now displays "Disable Account", confirming the change.
After enabling the account, I was able to log into CLIENT1 using Tom Smith's credentials, successfully authenticating against the Domain Controller.

![image](https://github.com/user-attachments/assets/9f3a525d-f3f0-4eef-ae2a-b74357b75cac)

### 10. Future projects and expansions
This project was my first hands-on experience with Active Directory and my first time setting up virtual machines (VMs) using VirtualBox. This project served as a solid introduction to domain controllers, DHCP, DNS, NAT, user management, and security configurations. I also learned how networking and authentication work in an enterprise-like environment, setting the foundation for further exploration. To continue building on this knowledge, I plan to expand my lab with various follow-up projects:

### Expanding into Secure Environments & Artifact Analysis
With this hands-on experience in setting up and managing VMs, I plan to expand my home lab by configuring secure environments for digital forensics and artifact analysis. This will allow me to further develop skills in incident response, file integrity validation, and forensic data examination—key areas in Blue Team operations.

As part of my training in Blue Team Level 1, I intend to:

- Set up a dedicated forensic analysis VM with tools like FTK Imager for disk and memory analysis.
- Practice hash generation and integrity verification using SHA256, MD5, and other cryptographic hashing techniques.
- Conduct malware artifact analysis, examining file behaviors and registry changes in an isolated environment.
- Explore log analysis and SIEM tools to improve detection and investigation techniques.
- Analyze phishing emails by collecting and examining email artifacts (headers, attachments, embedded links) to identify threats, track indicators of compromise (IOCs), and produce investigative reports.

### Delve into Active Directory Security Groups & Group Policies (GPOs)
I also aim to gain a better understanding of how organizations leverage security groups and GPOs to enhance their security posture.

- Learn how GPOs enforce security policies and restrict access to system settings, software, and devices.
- Explore Security Groups, RBAC, and OUs to manage user permissions and enforce department-specific access controls.

### Explore Event Viewer to address potential security concerns.
To deepen my understanding of Active Directory security and gain familiarity with its monitoring tools, I plan to:

- Track failed login attempts and suspicious activities using Event Viewer.
- Implement Account Lockout Policies to mitigate brute-force attacks.
- Identify common AD security weaknesses and apply defensive measures against privilege escalation.





