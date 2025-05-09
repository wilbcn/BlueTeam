# 🖥️ Splunk Investigations: Analysing the BOTSv3 dataset to answer CTFs

## 📖 Overview  
Since configuring my Splunk Enterprise server on AWS and my initial analysis of the attack dataset, I was kindly provided with the dataset ctf questions and answers. This project documents my thought process on how I was able to answer the outlined questions. This document serves more of a learning resource for myself, but equally showcases my on going dedication improving my analytical skills and investigation skills using Splunk.

Setup of this Splunk Server can be found here [Setup](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-Enterprise-HomeLab.md)
A pre-investigation without access to the CTF q/a's can be found here [Link](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-botsv3-Investigation-1.md)

Below I will outline each question individually, and any steps or thought processes taken in order to successfully locate the answer.

## 🎯 Goals
- Answer a wide variety of CTF question and answers from the BOTSv3 attack dataset
- Logically carry out investigations using Splunk and analyse the returned events
- Prepare myself for the BTL1 exam !

### Question 1: List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment?
To answer this question, I ran an initial query focusing on AWS cloud trail, which covers API calls made from AWS users.

```
index="botsv3" sourcetype="aws:cloudtrail"
```

- From here, I spotted interesting field: `user`, which I honed in on.

```
index="botsv3" sourcetype="aws:cloudtrail" | dedup user | table user
```

![image](https://github.com/user-attachments/assets/38da1542-f389-4c8d-b6f6-121e9da59dc5)

- By looking back at the original question, here we are looking at AWS IAM Users, not services or anything else. This way, we can pick out the answers quite easily.

**Answers**: `bstoll, btun, splunk_access, web_admin`

### Question 2: What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)?
This question still revolves around API calls, so I will stick to focusing on the previous source type for cloud trail.

```
index="botsv3" sourcetype="aws:cloudtrail"
```

- After running this query, I browsed through the list of interesting fields, and could not initially see anything related to MFA. I noticed we had 348 more fields (extra interesting fields) that can add and filter through to aid our search. Here I searched for `multi` and `mfa` and came accross:

![image](https://github.com/user-attachments/assets/10d55657-9d54-49e5-8a08-d5bae540f470)

![image](https://github.com/user-attachments/assets/ee79e0f9-454b-4d5f-bd3a-b83b98cee900)

**Answer**: `userIdentity.sessionContext.attributes.mfaAuthenticated`

### Question 3: What is the processor number used on the web servers?
I was a bit stuck on this one. I initially searched through http events for web traffic,  hoping this might be in the metadata somewhere. Going back to the BOTSv3 documentation on source types, I noticed we have `hardware`.

```
index="botsv3" sourcetype="hardware"
```

![image](https://github.com/user-attachments/assets/af25117c-105c-4ae3-8e8f-576f47ecffad)

**Answer**: `E5-2676`

### Question 4: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?
More API related questions. I can again focus on cloud trail as a basic. 

```
index="botsv3" sourcetype="aws:cloudtrail"
```






