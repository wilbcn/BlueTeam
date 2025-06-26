# 🔎 Datadog: Introducing a new security tool!

## 📖 Overview
This project is an expansion on my hands-on SIEM series. In previous projects I have focused primarily on Splunk, leveraging its capabilities for investigative work on attacker datasets, and practice creating alerts / dashboards in a SOC-style mindset. In this project, I pivot to Datadog, a cloud-based monitoring and analytics platform. I explore Datadogs UI as a whole, while focusing on Datadog's Cloud SIEM tool which is a solution built on top of Datadog's log management platform, designed to detect threats in cloud-scale environments. With this project I am expanding my skillset, familiarising myself with security standard tools outside of Splunk, showcasing my proactiveness and adaptability to other platforms.

## 🎯 Goals
- Configure and launch a fresh EC2 instance running Windows
- Configure the Datadog Agent on this new virtual machine to ingest windows security logs
- Configure the `Windows Event Logs` content pack for Cloud SIEM
- Simulate a security event and handle the alert in Datadog

## Resources & Acknowledgements
- [Install User Agent](https://app.datadoghq.eu/fleet/install-agent/latest?platform=windows)
- [Log Collection](https://docs.datadoghq.com/integrations/win32_event_log/?tab=logs)



### Configuration Overview
In this section, I briefly cover the configuration and installation of the Datadog Agent on a brand new windows VM in AWS.

1. Once the new Windows VM in AWS was configured and launched (not shown), I headed over to `Datadog` -> `Integrations` -> `Fleet Automation`, and selected the appropriate host.

![image](https://github.com/user-attachments/assets/43f6f5c8-2dce-4838-890e-06b489fae71d)

2. On the `Installer` tab, I downloaded and ran the agent installer on the virtual machine, providing my API key when necessary.

![image](https://github.com/user-attachments/assets/3b674f6e-74fb-4250-b887-5120a356fd91)

3. From Datadog's Main Menu, I headed to `Infrastructure`, where the VM now appears. The next step was to enable log collection from the VM.
4. For this section I followed the datadog documentation on `integrations` -> `Windows Event Log`. By default - log collection is disabled in the Datadog Agent. I set `logs_enabled: true` in the `datadog.yaml` file (`C:\ProgramData\Datadog/datadog.yaml`).

![image](https://github.com/user-attachments/assets/1b17be16-dd41-406d-88a6-2a81bafa48f8)

5. In this project I am focusing on Windows Security Logs, which defines how I construct the `.yaml` file for log collection. I then created and edited the following file: (`C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml`).

- **From the documentation**
![image](https://github.com/user-attachments/assets/e8d95af6-7cf4-443a-9ceb-9752d12ee9f3)

- **My .yaml file**
![image](https://github.com/user-attachments/assets/1c9ca30f-9c49-4c35-a27f-a3b2f2fdd68a)

6. After restarting the Datadog agent via the CLI (`Restart-Service datadogagent -Force`), logs started to appear in `Log Explorer`.

![image](https://github.com/user-attachments/assets/0a426d92-1b43-44b5-b0c1-e36af917bf27)

7. At this stage I also enabled CWS and CSPM inside (`C:\ProgramData\Datadog\security-agent.yaml`). While not required for Cloud SIEM log-based detections, these protection features activate runtime security features that are part of Datadogs full security platform. CSPM for instance, continously scans cloud-based resources such as user roles and privileges, access keys or tokens, and infrastructure components, for vulnerable configurations.

- **CWS**: Cloud Workload Security
- **CSPM**: Cloud Security Posture Management

![image](https://github.com/user-attachments/assets/d56cbc16-c3e9-4960-ab15-35070f153d39)

8. 
