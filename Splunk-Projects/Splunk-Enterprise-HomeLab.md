# 🖥️ Splunk Enterprise: Manual Data Ingestion & Lab Setup for Security Analysis

## 📖 Overview
This documentation outlines the setup and configuration of a Splunk Enterprise standalone instance for manual data ingestion and security analysis.  
The objective of this project is to build a longer-term hands-on environment for learning SPL (Search Processing Language), performing threat hunting, and preparing for the BTL1 certification.  
Log sources include **BOTSv1**, **Suricata**, and **Sysmon** datasets.

## 🎯 Goals
- **Deploy and configure Splunk Enterprise** on a standalone server (EC2 Linux instance).
- **Install Apps and Add-ons** from Splunkbase
- **Manually ingest datasets** such as BOTSv1, Suricata logs, and Sysmon logs.  
- **Develop scenario-based investigations** to simulate security incidents.  
- **Integrate analysis with the MITRE ATT&CK Framework** for adversary behavior mapping.

### Learning & Practical Applications
- Building a **medium-term Splunk lab** suitable for threat detection and log analysis.
- Mastering **manual data ingestion techniques** into custom indexes.
- Developing **SPL search queries** for security investigation.
  
## Project Walk-Through
This section documents the step-by-step process followed to build the lab environment, including:

### 1. Launch a new instance for Splunk Enterprise
Here I configured and launched a brand new EC2 instance to host our splunk enterprise server. 

[Guide](https://navyadevops.hashnode.dev/step-by-step-guide-installing-splunk-server-on-aws-linux)

#### Steps:
1. Navigated to **EC2 → Instances → Launch Instance**
2. Selected the below AMI:
   - Ubuntu 24.04 LTS (or Amazon Linux 2)
3. Selected the below instance type:
   - t3.medium
4. Created a new key pair for SSH access, and saved it to my desktop
5. Configured the following network settings:
   - Isolated Homelab VPC and subnet (pre-configured with IGW etc)
   - Auto assign public IP set to enabled
6. Configured Security Group rules for our instance:
   - Allow inbound traffic **only from my IP**
   - TCP 22 (SSH)
   - TCP 8000 (Splunk Web)
7. Configured instance storage:
   - 20 GB, suitable for our lightweight Splunk Enterprise lab. We can increase this when necessary.
8. Launched the instance!

### 2. Installing Splunk Enterprise Server on our EC2 Instance
In this stage, I connected to our new instance via ssh, and began configuring the Splunk Server.

#### Steps:
1. To connect to the EC2 Instance I used **MobaXTerm**, an SSH Client for Windows. I started a new session, adding the public IP address of our instance, selecting the `.pem`, and defining the username `ubuntu`.
2. Once successfully logged in, I then ran the below code to configure the Spunk Server.

```
root@my-ip-address:~# cd /opt 
```
```
root@my-ip-address:/opt# wget -O splunk-9.4.2-e9664af3d956-linux-amd64.tgz "https://download.splunk.com/products/splunk/releases/9.4.2/linux/splunk-9.4.2-e9664af3d956-linux-amd64.tgz"
```
```
root@my-ip-address:/opt# tar xvzf splunk-9.4.2-e9664af3d956-linux-amd64.tgz
```
```
root@my-ip-address:/opt# cd splunk/bin
```
```
root@my-ip-address:/opt/splunk/bin#  sudo ./splunk start --accept-license
This appears to be your first time running this version of Splunk.

Splunk software must create an administrator account during startup. Otherwise, you cannot log in.
Create credentials for the administrator account.
Characters do not appear on the screen when you type in credentials.

Please enter an administrator username: splunk_admin
```
```
root@my-ip-address:/opt/splunk/bin#  sudo ./splunk enable boot-start
```
```
root@my-ip-address:/opt/splunk/bin# /opt/splunk/bin/splunk status
splunkd is running (PID: 1543).
splunk helpers are running (PIDs: 1544 1692 1697 1772 1822 2210 2342 2345).
```

3. I then logged into the Splunk Server using the new `splunk_admin` account via my web browser to verify everything had been setup correctly.

![image](https://github.com/user-attachments/assets/beaac792-3f88-4ba5-a1cd-bf069ef7b151)

### 3. Enabling HTTPS on the Splunk Server
By default, Splunk Enterprise runs on `http`, which is an insecure protocol. For best security practices, before continuining with this setup, I made changes to the server to run on `https` instead, using Splunk’s built-in self-signed cert.

[Guide](https://docs.splunk.com/Documentation/Splunk/9.4.1/Security/TurnonbasicencryptionwithSplunkWeb)

#### Steps:
1. On Splunk Web, I headed to **settings -> system -> server settings -> general settings
2. Toggled the radio button to `Yes` for `Enable SSL (HTTPS) in Splunk Web?`, then clicked save.
3. Back to the CLI now, I restarted splunk. 
```
root@my-ip-address:/opt/splunk/etc/system# sudo /opt/splunk/bin/splunk restart
```
4. I was then able to successfully access the Splunk Server via `https`.

### 4. Retrieving the BOTS v1 Dataset
Before I begin investigating the dataset, the BOTSv1 repo advises installing various apps and add-ons to fully explore and analyse it. To do this, I followed the following resources

- [Install Apps & Add-ons](https://docs.splunk.com/Documentation/AddOns/released/Overview/Singleserverinstall)
- [Dataset](https://github.com/splunk/botsv1)

#### Steps:
1. I downloaded the below add-ons via their splunkbase link.

![image](https://github.com/user-attachments/assets/cba57096-6de5-4e02-9ce0-dcd1590ddd07)

2. To install these, I clicked the gear icon next to Apps -> Install app from file -> Browse

![image](https://github.com/user-attachments/assets/82d50428-5309-4859-88cc-519fd92a2e00)

3. I went ahead and repeated these steps for the remaining add-ons.
4. Since the full BOTSv1 dataset exceeds 20 GB, I opted to use the smaller "attack-only" version instead. This still provides rich hands-on experience investigating malicious activity, while keeping the setup lightweight and manageable. To add the data manually, I went to settings -> add data. I selected the dataset, and created a new index called `botsv1`. 

![image](https://github.com/user-attachments/assets/d86bd987-efdf-4be4-9714-ae6fec73af01)

5. Once the dataset had completed processing, I ran a simple SPL query to verify our dataset was ingested correctly.



### 5. Key-takeaways and Future work



