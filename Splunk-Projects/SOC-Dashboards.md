# 🔎 Splunk Dashboards: Creating SOC-style Splunk dashboards

## 📖 Overview
I have been learning Splunk for a while now, creating and deploying EC2 instances to configure Splunk Universal Forwarders, and investigating BOTS (Battle Of The SOC) datasets CTF style learning. In this project, I aim to continue to work this these attack datasets, however this time focusing on creating dashboards, that would be relevant and used in a SOC environment. In this project, I create dashboards for the following security events:

- AWS IAM Activity
- Email Traffic
- Insert

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

dashboard screenshot

### 2.1 Dashboard use cases
- Total email traffic
- Top email traffic by source IP
- Top rare values
- Suspicious Emails by subject

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

```


