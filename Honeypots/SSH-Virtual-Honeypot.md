# Cowrie-Based Honeypot Deployment on AWS

## 📚 Overview

<project intro>

---


## 🎯 Project Goals

- Deploy a low-interaction honeypot in the cloud securely
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Gain practical experience with legal and ethical security practices
- Establish groundwork for future behavioral honeypot research

---

## 📦 Phase 1 – Cloud Setup

### ☁️ AWS EC2 Configuration
- **Region**: `eu-west-2` (London) 🇬🇧 (GDPR-compliant region)
- **Instance Type**: `t3.xlarge` (4 vCPU, 16GB RAM)
- **AMI**: Ubuntu 22.04 LTS
- **Storage**: 128GB
- **VPC**: New, isolated VPC and subnet

### 🔐 Security Group Rules

| Port | Purpose | Source | Description |
|------|---------|--------|-------------|
| 22 | SSH access | Your IP only | Admin access |
| 2222 | Cowrie honeypot port | 0.0.0.0/0 | Attract SSH attacks |
| (Optional) 23 | Fake Telnet | 0.0.0.0/0 | Enable if configured |

### 🗝️ SSH Key Pair
- Create a new key pair
- Connect with:  
  `ssh -i "key.pem" ubuntu@<public-ip>`

---

## 🧪 Phase 2 – Honeypot Installation

### 🔧 System Prep

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git python3 python3-venv python3-pip -y
