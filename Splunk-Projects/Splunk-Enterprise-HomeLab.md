# 🖥️ Splunk Enterprise: Manual Data Ingestion & Lab Setup for Security Analysis

## 📖 Overview
This documentation outlines the setup and configuration of a Splunk Enterprise standalone instance for manual data ingestion and security analysis.  
The objective of this project is to build a longer-term hands-on environment for learning SPL (Search Processing Language), performing threat hunting, and preparing for the BTL1 certification.  
Log sources: **BOTSv3**

## 🎯 Goals
- **Deploy and configure Splunk Enterprise** on a standalone server (EC2 Linux instance).
- **Install Apps and Add-ons** from Splunkbase
- **Manually ingest datasets** such as BOTSv3 attack dataset
- **Prepare the environment** for investigative follow up projects

### Learning & Practical Applications
- Building a **medium-term Splunk lab** suitable for threat detection and log analysis.
- Mastering **manual data ingestion techniques** into custom indexes.
- Developing **SPL search queries** for security investigation.

### 1. Launch a new instance for Splunk Enterprise
Here I configured and launched a brand new EC2 instance to host our splunk enterprise server. 

[Guide](https://navyadevops.hashnode.dev/step-by-step-guide-installing-splunk-server-on-aws-linux)

#### Steps:
1. Navigated to **EC2 → Instances → Launch Instance**
2. Selected the below AMI:
   - Ubuntu 24.04 LTS (or Amazon Linux 2)
3. Selected the below instance type:
   - t3.xlarge
4. Created a new key pair for SSH access, and saved it to my desktop
5. Configured the following network settings:
   - Isolated Homelab VPC and subnet (pre-configured with IGW etc)
   - Auto assign public IP set to enabled
6. Configured Security Group rules for our instance:
   - Allow inbound traffic **only from my IP**
   - TCP 22 (SSH)
   - TCP 8000 (Splunk Web)
7. Configured instance storage:
   - 30 GB
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
root@my-ip-address:/opt/splunk/bin# ./splunk start --accept-license
This appears to be your first time running this version of Splunk.

Splunk software must create an administrator account during startup. Otherwise, you cannot log in.
Create credentials for the administrator account.
Characters do not appear on the screen when you type in credentials.

Please enter an administrator username: splunk_admin
```
```
root@my-ip-address:/opt/splunk/bin# ./splunk enable boot-start
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
root@my-ip-address: /opt/splunk/bin/splunk restart
```
4. I was then able to successfully access the Splunk Server via `https`.

### 4. Retrieving and mounting the BOTSv3 Dataset
Before I begin investigating the dataset, the dataset repository advises installing various apps and add-ons to fully explore and analyse it. To do this, I followed the following resources

- [Install Apps & Add-ons](https://docs.splunk.com/Documentation/AddOns/released/Overview/Singleserverinstall)
- [Dataset](https://github.com/splunk/botsv3?tab=readme-ov-file)

#### Steps:
1. I downloaded the below add-ons via their splunkbase link.

![image](https://github.com/user-attachments/assets/d92d5292-ca36-477f-abfb-045ef870c77b)

![image](https://github.com/user-attachments/assets/f1c90ce7-b913-4765-91d7-637534c51457)

2. Apps and add-ons go into `/opt/splunk/etc/apps/`. I then installed all the Splunk apps and add-ons in bulk via the CLI by copying them directly into this directory.

![image](https://github.com/user-attachments/assets/a1b09016-df00-43fa-aeb6-509c5f208815)

3. Back on Splunk Web, we can see that these apps have been successfully loaded

![image](https://github.com/user-attachments/assets/2ee05914-111a-4164-a655-0b5feb072014)

4. Now I mounted the `BOTS V3 Dataset`. This is installed the same way as apps and add-ons, where it should be unpacked in the same directory `/opt/splunk/etc/apps/`.
5. Once the dataset had been extracted, I ran an initial SPL query on the Splunk Server to verify we could now properly query the dataset. 

```
index=botsv3 earliest=0
```

![image](https://github.com/user-attachments/assets/34fb2028-2bd5-4eac-80cf-dc4e1793a90a)

### 5. Key-Takeaways and Future expansions
This project documented the setup of a secure EC2 instance, the installation and configuration of Splunk Enterprise, and the proper mounting of the Battle of the SOC (BOTSv3) dataset. It provides a solid baseline environment for practicing real-world threat investigations using Splunk.

With the BOTSv3 dataset now accessible, I can begin manually analyzing attacker activity, gaining hands-on experience with:

- Splunk Processing Language (SPL)
- Log analysis
- Threat detection techniques

Additionally, the end-to-end deployment of this lab environment served as valuable operational experience — from cloud configuration and security hardening to data ingestion and Splunk indexing — all of which support my preparation for the BTL1 exam.

➡️ Check out the first follow-up project, where I begin actively investigating the attack data: [Project](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-botsv3-Investigation-1.md)


