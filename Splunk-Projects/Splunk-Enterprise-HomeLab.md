# 🖥️ Splunk Enterprise: Manual Data Ingestion & Lab Setup for Security Analysis

## 📖 Overview
This documentation outlines the setup and configuration of a Splunk Enterprise standalone instance for manual data ingestion and security analysis.  
The objective of this project is to build a longer-term hands-on environment for learning SPL (Search Processing Language), performing threat hunting, and preparing for the BTL1 certification.  
Log sources include **BOTSv1**, **Suricata**, and **Sysmon** datasets.

## 🎯 Goals
- **Deploy and configure Splunk Enterprise** on a standalone server (EC2 Linux instance).  
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
1. Navigated to **EC2 → Instances → Launch Instance**
