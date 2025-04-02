# 🏠 Creating a Secure VM in AWS EC2

## 📖 Overview
This document outlines the setup of an **Amazon EC2 Instance** designed to serve as a secure environment for conducting cybersecurity projects, including digital forensics, network analysis, and threat intelligence. By utilizing a secure VM, I adhere to best security practices while gaining valuable hands-on experience in a controlled and safe setting.

I already have quite a bit of experience with AWS Services, which you can find here. [AWS Projects](https://github.com/wilbcn/AWS-Projects) 

## 🎯 Goals
- Create a new VPC and subnet for this VM
- Create a new Amazon EC2 instance inside the VPC
- Create an internet gateway and attach it to the VM
- Update the VPC route table to allow internet access
- Connect to the instance via RDP on my local machine, and begin creating projects!

### 1. Create a new VPC/Subnet
1. I navigated over to Amazon VPC, and clicked create VPC.
2. I named this VPC-HomeLab, and set the CIDR IP range to 10.0.0.0/28. This gives us a small amount of usable IPs, but thats fine. I intend on just creating this one secure VM for carrying out cybersecurity projects.

<img width="1064" alt="image" src="https://github.com/user-attachments/assets/bc54d2ef-0594-4d6f-839f-c57e109f201d" />

### 2. Create a new Subnet
1. I went to Subnets, under the VPC sub menu, and clicked create subnet.
2. I named this HomeLab-Subnet, and set the CIDR range to match the VPC.

<img width="1290" alt="image" src="https://github.com/user-attachments/assets/d193b87e-4264-478c-b4eb-22841a8aa77a" />

### 3. Launch a new instance
1. From the EC2 menu, I clicked launch instance. I selected the options to setup a Windows Server 2025 AMI.
2. I selected T3.Large, as we may need sufficient vCPU and RAM to handle forensic tools like FTK Imager.
3. I generated a key-pair and saved the .pem to my desktop
4. I created a new security group called SG-HomeLab, and allowed RDP traffic from my IP address only.
5. I selected our newly made VPC and subnet, and launched the instance. The public IP address is not shown in the screenshot.

<img width="1171" alt="image" src="https://github.com/user-attachments/assets/10286c23-87e2-4442-ad29-7a054d2075f2" />

### 4. IGW and Update Route Table
1. In VPC, I created a new internet gateway, and attached it to the new VPC made for the HomeLab.
2. Then I update dthe route table to include destination 0.0.0.0/0 - IGW

<img width="1600" alt="image" src="https://github.com/user-attachments/assets/795c1a1e-4a59-4ce9-9c6d-99ef10a4d70a" />

### 5. Configure RDP
1. After initialising, I clicked on our instance and hit the connect button. Here by going to the RDP tab, we can upload our .pem, and get the password to successfully connect to this VM.
2. After decrypting the password and noting it down securely, we could now try and connect!
3. Using the public ipv4 address of our VM, username Administator, and our decrypted password, I successfully accessed our secure VM.

### Key Takeaways
- **Secure and Isolated Environment**: The VM is built inside a dedicated VPC and subnet, ensuring a controlled and secure space for cybersecurity experiments.
- **Versatile Cybersecurity Lab**: This VM serves as a foundation for multiple security and forensic projects, including:
  - **Analyzing user browser history** to detect suspicious activity.
  - **Leveraging FTK Imager** to acquire and analyze forensic disk images.
  - **Wireshark for network analysis**, allowing for packet capture and threat detection.
  - **Malware analysis tools** to examine and reverse-engineer potential threats.
  - **Phishing investigation techniques**, studying email headers and forensic artifacts.

  - and more...!
    
- **AWS Best Practices**: The instance follows best security practices, including restricted inbound traffic, key-pair authentication, and controlled administrative access.
- **Scalability & Future Projects**: This VM setup can be referenced for all future cybersecurity investigations and forensic experiments, streamlining future configurations and deployments.
