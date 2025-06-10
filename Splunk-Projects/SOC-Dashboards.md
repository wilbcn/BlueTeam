# 🔎 Splunk Dashboards: Creating SOC-style Splunk dashboards

## 📖 Overview
I have been learning Splunk for a while now, creating and deploying EC2 instances to configure Splunk Universal Forwarders, and investigating BOTS (Battle Of The SOC) datasets CTF style learning. In this project, I aim to continue to work this these attack datasets, however this time focusing on creating dashboards, that would be relevant and used in a SOC environment. In this project, I create dashboards for the following security events:

- AWS IAM Activity
- Email Traffic
- Web Traffic

## 🎯 Goals
- Insert
- Insert

### Pre-project Planning
Before starting this project, I ran the below SPL query to get a better understanding of the sourcetypes within the data. That way I can logically pick sourcetypes that contain event data, for meaningful dashboards.

```
index=* | stats count by sourcetype | sort -count
```

Sourcetypes to focus on:
- `aws:cloudtrail`: Cloud Attack Surface
- `stream:smtp`: Email Traffic
- `osquery:results`: Track suspicious processes
- `stream:dns + stream:http`: Network Threat Detection

### 1. Dashboard Overview: AWS IAM Activity

![image](https://github.com/user-attachments/assets/d06e7acd-d283-4422-a6e0-6d7b67ec3c06)

### 1.1 Dashboard use cases
- Total IAM Actions
- Top IAM Users by Activity
- Access Key Activity
- Top Activity by Source IP

### 1.2 Total IAM Actions
To create a panel for Total IAM Actions, I ran the below query in SPL.

```
index=botsv3 sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
| stats count AS "IAM Actions"
```

Using this SPL Query, I created a new dashboard titled `AWS IAM Activity`, and saved this search to it. I edited this panel to be displayed as a single value.

### 1.3 Top IAM Users by Activity
To create a panel for the top IAM users by activity, I ran the below query in SPL.

```
index=* sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
| stats count by userIdentity.userName
| sort -count
| head 10
```

I saved this panel as a barchart, and moved it along side `Total IAM Actions`.

![image](https://github.com/user-attachments/assets/bdc25383-9ec2-4639-aed9-8ed305bfa7e0)

### 1.4 Access Key Activity
For this panel, I will focus on Access Keys. I ran the following SPL query, which creates a table of users with access key activity. Here we can potentially spot unusual activity related to IAM access keys, such as a suspicious user changing or deleting an access key.

```
index=* sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com" eventName="*AccessKey*"
| where isnotnull(user) AND user!="" 
| table eventTime, user, eventName
```

![image](https://github.com/user-attachments/assets/5d2a670a-778c-4f99-adad-89b8b1b90762)

Here we can clearly see that `nullweb_admin` has carried out suspicious access key activity.

### 1.5 Top Activity by Source IP
For this last panel for the IAM dashboard, I ran the below SPL query, which shows for each user how many events they triggered and what IPs they used. We then filter for the most active users first, in descending order.

```
index=* sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
| stats count as activity_count, values(src_ip) as ip_list by user
| sort -activity_count
```

![image](https://github.com/user-attachments/assets/039ba0c9-ba25-4d09-b132-d4fd34d88c80)

### 2. Dashboard Overview: Email Traffic

![image](https://github.com/user-attachments/assets/5c6fa544-f4c6-4773-bfe0-c316681b0823)

### 2.1 Dashboard use cases
- Total email traffic
- Top email traffic by source IP
- Top rare values
- Suspicious Emails by subject
- Emails with suspicious attachments

### 2.2 Total Email Traffic
General overview of Email Traffic. Could be refined further for daily or weekly activity, if a date/time baseline had been established by the organisation. 
Query ran:

```
index=* sourcetype="stream:smtp"
| stats count AS "Email Traffic"
```

![image](https://github.com/user-attachments/assets/f033333e-7fd6-4dd6-8f55-4661306c6018)

### 2.3 Top email traffic by source IP
Useful if a large amount of email traffic relates to unknown IP ranges.
Query ran:

```
index=* sourcetype="stream:smtp"
| stats count by src_ip
| rename src_ip as "Source IP Address"
| sort -count
| head 10
```

![image](https://github.com/user-attachments/assets/8578d9e0-36c4-47b7-8807-35c5bceb7820)

### 2.4 Top Rare Values
Useful for finding potential anomalies.
Query ran:

```
index=* sourcetype="stream:smtp"
| stats count by src_ip
| rename src_ip as "Source IP Address"
| sort count
| head 10
```

![image](https://github.com/user-attachments/assets/d21af827-30e8-43fa-9d42-6b9078576066)

### 2.5 Suspicious Emails By Subject
Althrough I am limited to the dataset, I can still logically setup a dashboard panel for suspicious subjects, whilst including known event data.

Subject examples that show up in the data:
- `Quarantined Email`
- `[FrothlyBeers/BrewingIOT] Aws apikey exposed on GitHub`
- `Amazon Web Services: New Support case: 5244329601`
- `Draft Financial Plan for Brewery FY2019`

These subjects are suspicious because they relate to:
- Email quarantine notices (often used in phishing)
- API key exposure (data leak)
- AWS support (possible spoof or security alert)
- Financial documents (sensitive content)

The below key words don't exist in the dataset. However, these are common **Phishing Email** subject keywords, used to create a sense of urgency.
- `Urgent`
- `Act Now`
- `Immediate Action Required`
- `Exposed`
- `Verify`
- `Click here`

Query ran:

```
index=* sourcetype="stream:smtp"
| spath subject
| spath sender
| spath receiver_email{}
| search subject="*apikey*" OR subject="*support case*" OR subject="*quarentine*"
       OR subject="*financial*" OR subject="*urgent*" OR subject="*immediate action*"
       OR subject="*act now*" OR subject="*exposed*" OR subject="*click here*"
       OR subject="*verify*"
| rename "receiver_email{}" as recipients
| table _time, subject, sender, recipients
| sort -_time
```

![image](https://github.com/user-attachments/assets/35bb4c17-6b7b-44e5-9d99-113a40eb9411)

This was great practice with spath for nested JSON data. This panel is really useful, can could be further expanded in a real production environment for more common Phishing and Malicious email indicators.

### 2.6 Emails with suspicious attachments
While the BOTS v3 dataset includes limited examples of email attachments, the SPL query and dashboard developed here were constructed with that constraint in mind. The current implementation focuses on identifying the presence of attachments in general; however, in a production environment, this logic should be expanded to detect a broader range of potentially malicious file types — such as .exe, .doc, .xls, .ps1, .zip, and others commonly used in phishing and malware delivery.

This approach reflects a logical use of the dataset’s available content while acknowledging the need for broader detection coverage in real-world applications.

```
index=* sourcetype="stream:smtp"
| spath sender
| spath receiver_email{}
| spath attach_filename{}
| where isnotnull('attach_filename{}') AND 'attach_filename{}' != ""
| rename "attach_filename{}" as attachments
| rename "receiver_email{}" as recipients
| table _time, sender, recipients, attachments
| sort -_time
```

![image](https://github.com/user-attachments/assets/2bbbe664-d84c-46c4-9bb1-530666c145e9)

### 3. Dashboard Overview: Web Traffic

### 3.1 Dashboard use cases
- Top External Domains (DNS)
- Top Addresses (HTTP)
- HTTP Traffic over non-standard ports
- 

### 3.1 Top External Domains
intro
```
index=* sourcetype="stream:dns"
| rename "hostname{}" as domain, sourcetype as protocol
| stats count by protocol, domain
| sort -count
| head 10
```


### 3.2 Top Addresses (HTTP/S)
Intro

```
index=* sourcetype="stream:http"
| spath dest_ip
| rename dest_ip as "destination address", sourcetype as protocol
| stats count by "destination address", protocol
| sort -count
| head 10
```


### 3.3 HTTP/S traffic over non-standard ports
Intro

```
index=* sourcetype="stream:tcp"
| rename src_ip as "Source IP", dest_ip as "Destination IP", dest_port as "Port", app as "Application Layer Protocol"
| search "Application Layer Protocol"=http OR "Application Layer Protocol"=https
| where Port!=80 AND Port!=443
| stats count by "Source IP", "Destination IP", "Port", "Application Layer Protocol"
| sort -count
```

