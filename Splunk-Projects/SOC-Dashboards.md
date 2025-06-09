# 🔎 Splunk Dashboards: Creating SOC-style Splunk dashboards

## 📖 Overview
I have been learning Splunk for a while now, creating and deploying EC2 instances to configure Splunk Universal Forwarders, and investigating BOTS (Battle Of The SOC) datasets CTF style learning. In this project, I aim to continue to work this these attack datasets, however this time focusing on creating dashboards, that would be relevant and used in a SOC environment. In this project, I create dashboards for the following security events:

- AWS IAM Activity
- Insert
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

![image](https://github.com/user-attachments/assets/1861e96e-5a6a-47c3-b018-e4141b951c83)

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

![image](https://github.com/user-attachments/assets/a5341783-3c7f-4c96-91cb-c744fd5a686f)

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
