# ☁️ Splunk Cloud: Configuring Universal Forwarders & Performing Foundational Searches

## 📖 Overview
This documentation outlines the process of configuring **Splunk Cloud** to receive and analyze log data from both **Windows** and **Linux** instances using **Universal Forwarders (UF)**. The goal of this project is to develop hands-on experience with **log aggregation, security monitoring, and Splunk Processing Language (SPL)** within my **HomeLab setup**.  

## 🎯 Goals
- **Ingest and analyse system logs** from Windows and Linux endpoints.  
- **Perform scenario-based investigations** to detect and respond to security events.  
- **Utilise Splunk’s Searching & Reporting app** to query, visualize, and analyze data.  

### Learning & Practical Applications  
- Hands-on experience with **Splunk Universal Forwarders**.  
- Understanding **SPL queries** for event correlation and threat detection.  
- Investigating **custom scenario-based log data** for security analysis.  

## Project walk-through
This section provides a step-by-step breakdown of the steps taken in order to carry out this fundemental project with Splunk. The Splunk Cloud instance will act as the Indexer and the Search Head in our setup.

### 1. Configure Universal Forwader on Windows End-Point
In this section, I explain how I configured a Universal Forwarder on an EC2 instance running windows. Setup of this EC2 instance was done before hand, which has been configured in an isolated VPC and subnet, with security group rules to allow only RDP access from my IP address.

- On my windows VM, I set up a new account on Splunk and launched the Splunk Cloud Platform as an administrator.
- Once logged in, I went to **Universal Forwarder** on the left hand side, and downloaded the customised universal forwarder credentials package. This package ensures a secure and authenticated connection between our end points, and the splunk cloud platform.

![image](https://github.com/user-attachments/assets/1b30f6e3-c4a0-44b5-be9f-5b63e4e95782)

![image](https://github.com/user-attachments/assets/8062bb13-c00b-4ff9-918e-7f9e5017325e)

- Then I headed to [Splunk Universal Forwarder Download](https://www.splunk.com/en_us/download/universal-forwarder.html) and got the free download of the Universal Forwarder. I selected this one as it matches our Windows EC2 architecture.

![image](https://github.com/user-attachments/assets/2e675de7-5e09-4d73-94c2-420cc7b980e2)

- Both files are now prepared and ready on my desktop.

![image](https://github.com/user-attachments/assets/a8f3e39c-18d9-4fc7-991d-8cc5b6b44f3a)

- I Ran the installer file (.msi), and configured it with the following settings.
    - Splunk Cloud instance
    - Install UF as a local system (So Splunk UF has access to all required system logs and events etc.)
    - Enable all log sources, so we gain maximum visiblity into the system for our security analysis later.
    - Create an admin account that will manage the UF.
    - Then hit install.

- Now I opened the command prompt as administator, and installed the credentials package to enable a secure connection to our cloud deployment.

![image](https://github.com/user-attachments/assets/9da572a6-60e9-499d-b854-d696184beb6c)

- Then I restarted the splunk forwarder. Restarting the UF is necessary to apply configuration changes and establish the connection to Splunk Cloud.

![image](https://github.com/user-attachments/assets/10e6a383-57fc-41db-a43b-eeb102c26706)

- Now back on the Cloud platform, I ran a query to test for successful data integration from our windows machine. 

![image](https://github.com/user-attachments/assets/3c7ba20c-0e11-4c9c-a7d2-05f45bf403dc)

- Look at all the data coming in! Successful data ingestion verifies proper configuration of the UF and demonstrates Splunk Cloud’s capability to collect, index, and search data from remote sources in near-real-time.
- I have now configured an AWS EC2 Windows instance to simulate an endpoint used by an end-user for daily tasks. The Splunk Universal Forwarder (UF) is installed on this instance to continuously collect and forward log data—including system events and user activity—directly to Splunk Cloud.

### 2. Configure Universal Forwader on Linux End-Point
In this section, I explain how I configured a Universal Forwarder on an EC2 instance running Linux Ubuntu. This instance was also setup before hand in an isolated VPC and subnet, with security group rules to allow only ssh access from my IP address.

### 2.1. Configure a new admin user
For our Linux instance, I decided to create a new dedicated admin user (splunkadmin) instead of the default ubuntu user. This was mostly to gain more experience with Linux user management, but also is a good security practice instead of directly using the default system user for administrative tasks. By default we do not ssh as the root user, and also the root user should only be used sparingly, as anything that is typed can be executed. 

- Creating our dedicated splunkadmin user

```
sudo useradd -m -s /bin/bash splunkadmin
sudo passwd splunkadmin
New password:
Retype new password:
passwd: password updated successfully
sudo usermod -aG sudo splunkadmin
su - splunkadmin
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

whoami
splunkadmin
pwd
/home/splunkadmin
```

- Since we set a password for splunkadmin, an entry now exists in /etc/shadow, ensuring password-based authentication is active
- With our admin setup, I will now proceed to configure the Universal Forwarder on our linux machine.

### 2.2. Linux universal forwarder
- Here I navigated to the Splunk Universal Forwarder download page, and copied the wget link for the .deb package. Ill run this on our Linux machine directly.

<img width="1293" alt="image" src="https://github.com/user-attachments/assets/f65cc74c-e8fc-4206-bf74-caaade3b2478" />

```
ls -l
total 96712
-rw-rw-r-- 1 splunkadmin splunkadmin 99029222 Feb 25 20:07 splunkforwarder-9.4.1-e3bdab203ac8-linux-amd64.deb
```

```
sudo dpkg -i splunkforwarder-9.4.1-e3bdab203ac8-linux-amd64.deb
[sudo] password for splunkadmin:
Selecting previously unselected package splunkforwarder.
(Reading database ... 70610 files and directories currently installed.)
Preparing to unpack splunkforwarder-9.4.1-e3bdab203ac8-linux-amd64.deb ...
no need to run the pre-install check
Unpacking splunkforwarder (9.4.1) ...
Setting up splunkforwarder (9.4.1) ...
find: ‘/opt/splunkforwarder/lib/python3.7/site-packages’: No such file or directory
find: ‘/opt/splunkforwarder/lib/python3.9/site-packages’: No such file or directory
complete
```

- To finish the configuration, I changed the owner of Splunk UF to our splunkadmin.

```
ls -l
total 4
drwxr-xr-x 9 splunkfwd splunkfwd 4096 Mar 15 16:26 splunkforwarder
sudo chown -R splunkadmin:splunkadmin /opt/splunkforwarder
ls -l
total 4
drwxr-xr-x 9 splunkadmin splunkadmin 4096 Mar 15 16:26 splunkforwarder
```

- Then I enabled Splunk UF to start on boot. I added splunkadmin rather than systemd-managed. 

```
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunkadmin
```

- I then confirmed Splunk UF Service is running

```
sudo systemctl status SplunkForwarder
[sudo] password for splunkadmin:
● SplunkForwarder.service - Systemd service file for Splunk, generated by 'splunk enable boot-start'
     Loaded: loaded (/etc/systemd/system/SplunkForwarder.service; enabled; preset: enabled)
     Active: active (running) since Sat 2025-03-15 17:12:24 UTC; 2min 58s ago
    Process: 529 ExecStartPre=/bin/bash -c chown -R splunkadmin:splunkadmin /opt/splunkforwarder (code=exited, status=0/SUCCESS)
   Main PID: 623 (splunkd)
      Tasks: 45 (limit: 9367)
     Memory: 161.4M (peak: 194.8M)
        CPU: 3.864s
     CGroup: /system.slice/SplunkForwarder.service
             ├─623 splunkd --under-systemd --systemd-delegate=no -p 8089 _internal_launch_under_systemd
             └─917 "[splunkd pid=623] splunkd --under-systemd --systemd-delegate=no -p 8089 _internal_launch_under_systemd [process-runner]"
```

- I also verified Splunk UF is Enabled on Boot

```
sudo systemctl is-enabled SplunkForwarder
enabled
```

### 2.3. Install the credentials package
- Firstly I went and downloaded the credentials package from my Splunk Cloud Platform. I then transferred the package to our Linux instance.

```
ls -l
total 96720
-rw-r--r-- 1 splunkadmin splunkadmin     6723 Mar 16 11:11 splunkclouduf.spl
```

- Now to install the package and restart the forwarder.

```
sudo /opt/splunkforwarder/bin/splunk install app /home/splunkadmin/splunkclouduf.spl
Warning: Attempting to revert the SPLUNK_HOME ownership
Warning: Executing "chown -R splunkadmin:splunkadmin /opt/splunkforwarder"
Splunk username: uf_admin
Password:
App '/home/splunkadmin/splunkclouduf.spl' installed
You need to restart the Splunk Server (splunkd) for your changes to take effect.
/opt/splunkforwarder/bin$ sudo systemctl restart SplunkForwarder
/opt/splunkforwarder/bin$
```

- Check that Splunk UF is successfully forwarding logs to Splunk Cloud. Also note that no inactive forwarders are listed!

```
sudo /opt/splunkforwarder/bin/splunk list forward-server
Warning: Attempting to revert the SPLUNK_HOME ownership
Warning: Executing "chown -R splunkadmin:splunkadmin /opt/splunkforwarder"
Your session is invalid.  Please login.
Splunk username: uf_admin
Password:
Active forwards:
	inputs.prd-p-mw2cn.splunkcloud.com:9997 (ssl)
Configured but inactive forwards:
	None
```

- Now I configured the linux UF to monitor /var/log/syslog and /var/log/auth.log. As we are not using a deployment server (splunk enterprise feature), we need to configure this manually in our cloud setup.

```
sudo tee /opt/splunkforwarder/etc/system/local/inputs.conf > /dev/null <<EOL
[monitor:///var/log/syslog]
index = linux_logs
sourcetype = syslog

[monitor:///var/log/auth.log]
index = linux_logs
sourcetype = linux:auth
EOL
```

```
cat /opt/splunkforwarder/etc/system/local/inputs.conf
[monitor:///var/log/syslog]
index = linux_logs
sourcetype = syslog

[monitor:///var/log/auth.log]
index = linux_logs
sourcetype = linux:auth
```

```
sudo systemctl restart SplunkForwarder
```

```
Monitored Files:
	$SPLUNK_HOME/etc/splunk.version
	/var/log/auth.log
	/var/log/syslog
```

- In my cloud platform, I then added a new index for "linux_logs".

![image](https://github.com/user-attachments/assets/6fc3b53f-8d83-4296-91db-364602e85fb4)

- This is working as expected!

![image](https://github.com/user-attachments/assets/d206daa1-b7ce-4f08-a14f-b4dbdf5c0fa5)

### 3. Carrying out basic searches
The goal of this project was to develop a fundamental understanding of log collection, forwarding, and searching within Splunk Cloud. Now that our Windows and Linux instances are successfully sending logs, we can begin exploring basic SPL queries.

### 3.1. Search Query: Detecting incorrect logins (Linux)
To simulate real-world attack scenarios, I attempted to log into our Linux machine using several **non-existent usernames**. This generated logs that are useful for investigating potential **enumeration attacks**, where an attacker systematically attempts different usernames to discover valid accounts.

By searching for **failed login attempts with invalid users**, we can detect **unauthorized access attempts** and take action to harden authentication security.

```
index=linux_logs "Invalid user"
```

![image](https://github.com/user-attachments/assets/7f1f3c81-98cf-4308-96fe-7844bc6cf701)

- Future expansion: Set up Splunk alerts to notify administrators when multiple failed login attempts occur within a short time frame.

### 3.2 Search Query: Detecting successful logins (Linux)
After testing incorrect login attempts, I also wanted to verify that our Universal Forwarder is capturing successful SSH logins.

```
index=linux_logs "session opened"
```

![image](https://github.com/user-attachments/assets/3096a29a-9f3b-4fbb-8ad0-f5adec17252a)

```
index=linux_logs "session opened" OR "session closed"
```

![image](https://github.com/user-attachments/assets/8e6edc8a-2774-438f-b516-6972e15020fa)

### 3.3 Search Query: Detecting Admin account creation
In this scenario, we executed a search using **EventCode 4720**, which corresponds to the creation of new user accounts in Windows.

By expanding the log entry, we can see that a new Administrator account named `steven9` was created. This could indicate:
- A legitimate administrative action** (e.g., IT setup).  
- A potential security risk, such as unauthorized privilege escalation.  

```
index=* sourcetype="wineventlog:security" EventCode=4720
```

![image](https://github.com/user-attachments/assets/279006f3-24cb-4608-86c0-fcdfcedec2e3)

### 3.4 Search Query: Detecting successful logins (Windows)
To confirm that our Universal Forwarder (UF) is successfully capturing authentication events, we used EventCode 4624, which represents successful user logins in Windows.
By analysing these logs, we can verify who is accessing the Windows EC2 instance, identify expected vs. unexpected logins, and track potential unauthorised access attempts.

```
index=* sourcetype="wineventlog:security" EventCode=4624
```
![image](https://github.com/user-attachments/assets/22eff1c8-7528-42f9-b21d-f915189f12d6)

### 4. Takeaways and follow up projects
This project served as a fundamental introduction to Splunk Universal Forwarders, focusing on log collection and forwarding from Windows and Linux instances to Splunk Cloud. By successfully configuring UFs and running basic SPL queries, we established a strong foundation for log analysis and security monitoring. 

In the future I aim to expand on this project, building scenario-based investigations to simulate more security events. Additionally, carry out more advanced SPL searches to detect anomalies and trends, and to get familiar with the SPL language. Also, creating alerts and reports in splunk, much like a cybersecurity professional would do in a real world setting. Finally, leveraging dashboards for proactive monitoring. 

[Follow up Project](https://github.com/wilbcn/Splunk/blob/main/Splunk-Investigations.md)







