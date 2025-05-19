# Cowrie-Based Honeypot Deployment on AWS 2.0

## 📚 Overview
This follow up project is an adaptation and refinement of my original Cowrie honeypot deployment, found here: [link](https://github.com/wilbcn/BlueTeam/edit/main/Honeypots/Cowrie-Virtual-Honeypot.md). This project serves as both a trial phase towards my research project proposal on honeypot realism and fingerprinting (University project), as well as a continuation of hands-on experience that covers multiple security domains like OS hardening and network security.

---

## 🎯 Project Goals

- Deploy a secure SSH honeypot in AWS (secure admin access)
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Configure the EC2 instance with the `CIS Hardened Image Level 1 on Ubuntu Linux Server 24.04 LTS`
- Lay the foundation for the next trial phase, of Splunk integration for log aggregation and analysis

---

## Acknowledgements
- [Cowrie Documentation](https://docs.cowrie.org/en/latest/README.html)

## Tools & Resources
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Hardened AMI](https://aws.amazon.com/marketplace/pp/prodview-6l5e56nst6r3g)
- [WHOIS Lookup](https://whois.domaintools.com/)
- Amazon EC2 Instances
- Cowrie SSH Honeypot

---

## 📦 1 – Cloud Setup

