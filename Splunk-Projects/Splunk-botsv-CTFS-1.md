# 🖥️ Splunk Investigations: Analysing the BOTSv3 dataset to answer CTFs

## 📖 Overview  
Since configuring my Splunk Enterprise server on AWS and my initial analysis of the attack dataset, I was kindly provided with the dataset ctf questions and answers. This project documents my thought process on how I was able to answer the outlined questions. This document serves more of a learning resource for myself, but equally showcases my on going dedication improving my analytical skills and investigation skills using Splunk.

- Setup of this Splunk Server can be found here [Setup](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-Enterprise-HomeLab.md)
- A pre-investigation without access to the CTF q/a's can be found here [Link](https://github.com/wilbcn/BlueTeam/blob/main/Splunk-Projects/Splunk-botsv3-Investigation-1.md)

This document covers the first 20 questions of the BOTSv3 dataset. Below I have outlined each question individually, and any steps or thought processes taken in order to successfully locate the answer. 

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

```
index="botsv3" sourcetype="aws:cloudtrail" IAM eventSource="iam.amazonaws.com"
```

- By adding the event source to our search, we confirm the IAM users.

![image](https://github.com/user-attachments/assets/0fc0590d-8ed4-4304-b9ab-70ca1f499407)


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

- From here, I filtered down on `interesting fields`, choosing `eventSource - s3.amazonaws.com`.

```
index="botsv3" sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com"
```

- By looking at `eventName`, I get an initial understanding on the API calls made in relation to S3 buckets.

![image](https://github.com/user-attachments/assets/3a6fa9fd-c826-4ff0-a69d-b0a3247a8a5a)

- I then ran an updated SPL query to take a closer look at this. Here I uniquely filter on the eventName field, and display it in a table.

```
index="botsv3" sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com" | dedup eventName | table eventName
```

- Out of the 15 events, one stood out initially. In AWS - PUT operations modify or set configurations.

![image](https://github.com/user-attachments/assets/14711345-e8c6-497c-bc8e-4fc3fccdda2c)

- I then referred to the official AWS documentation on this API call to confirm my suspicions. [Link](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html)
- Back to the question, we need to find the eventID of this API call. 

```
index="botsv3" sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com"  eventName=PutBucketAcl
```

- We now just have 2 events to investigate to find out answer.

![image](https://github.com/user-attachments/assets/f03b22cd-1893-44a2-b876-86a89f4e21d9)

- By examining the raw text of these two events, we find the uri `http://acs.amazonaws.com/groups/global/AllUsers` and permission `FULL_CONTROL`.

![image](https://github.com/user-attachments/assets/24d70cee-5552-4e2d-8135-5d888ec220d0)

- The `eventID` within this event data gives us the answer.

**Answer**: ab45689d-69cd-41e7-8705-5350402cf7ac

### Question 5: What is the name of the S3 bucket that was made publicly accessible?
We already had the answer to this from the previous question. In the raw data we have:

![image](https://github.com/user-attachments/assets/a5812cbd-3e71-445e-aeaf-30bd6b52db1a)

**Answer**: `frothlywebcode`

### Question 6: What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?
Now that we know the name of the bucket that was made publicly accessible, we can use this in our search. We are looking for a text file, which we could also add to the search.

```
index="botsv3" frothlywebcode *.txt
```

- The `uri` fields reveal the answer.

![image](https://github.com/user-attachments/assets/269b3e31-2ceb-4d96-8ae3-6df765f0a4a0)

**Answer**: `OPEN_BUCKET_PLEASE_FIX.txt`


### Question 7: What is the size (in megabytes) of the .tar.gz file that was successfully uploaded into the S3 bucket while it was publicly accessible?
Similar approach as the previous question, by adding the file extension to our SPL query we are able to hone in on the answer.

```
index="botsv3" frothlywebcode *.tar.gz
```

- In the extra fields, I added a bunch I thought migtht be helpful, such as `object_size` and `bytes`.

![image](https://github.com/user-attachments/assets/922ce5c4-a1ac-4c7e-9cb9-1e1c3d13686e)

Convert to KB:
3,076,532 bytes ÷ 1,024 = 3,004.34 KB

Convert to MB:
3,076,532 bytes ÷ 1,048,576 = 2.935 MB

**Answer**: `2.935 MB`

### Question 8: A Frothly endpoint exhibits signs of coin mining activity. What is the name of the first process to reach 100 percent CPU processor utilization time from this activity on this endpoint?
For this question, I referred to the hints from the spreadsheet, as I wasn't sure on the sourcetype to begin with. I then ran an initial query:

```
index="botsv3" sourcetype="perfmonmk:process"
```

- Fortunately, we immediately have this interesting field `process_cpu_used_percent` which matches the question. I selected 100 for 100% and ran a new filter.

![image](https://github.com/user-attachments/assets/82770621-ef15-4453-a9fb-bc15697ea0d7)

```
index="botsv3" sourcetype="perfmonmk:process" process_cpu_used_percent=100
```

- Under the `instance` field we have our 4 contenders for the answer.

![image](https://github.com/user-attachments/assets/26e1152f-3c97-4577-829f-0d7ff4ab0098)

- I then ran the below query, which displays processes at 100% in a table, with their time stamp in ascending order (earliest first).
```
index="botsv3" sourcetype="perfmonmk:process" process_cpu_used_percent=100 | table _time | sort + _time
```

- By clicking on the earliest result at: `2018-08-20 09:36:26` We have our answer.

**Answer**: `MicrosoftEdgeCP#2`
**Comment**: The actual answer `chrome#5` at `2018-08-20 13:37:50` is therefore incorrect!!


### Question 9: When a Frothly web server EC2 instance is launched via auto scaling, it performs automated configuration tasks after the instance starts. How many packages and dependent packages are installed by the cloud initialization script?
As this question revolves around the launching, or initialisation of an EC2 instance. The appropriate source type log might be `cloud-init-output`. I had to look this up, but cloud-init is the tool that handles initialization and configuration of cloud instances at boot time. Initial query ran:

```
index="botsv3" sourcetype="cloud-init-output"
```

![image](https://github.com/user-attachments/assets/8f2cdeb9-e291-4ca4-9fb5-2861b3664656)

- This returned 23 events. I then simply added keyword "packages" to the query:

```
index="botsv3" sourcetype="cloud-init-output" packages
```

- Which revealed our answers.

![image](https://github.com/user-attachments/assets/64a0a527-3e45-4229-a8cd-29822e14f61c)

**Answer**: `7,13`

### Question 10: What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency?
This was a simply one. We'd already found out the endpoint related to crypto mining: `MicrosoftEdgeCP#2`. So I ran:

```
`index="botsv3" MicrosoftEdgeCP#2`
```

- By looking at the field `host`, we have our answer

**Answer**: `BSTOLL-L`

### Question 11: How many cryptocurrency mining destinations are visited by Frothly endpoints?
To find these destinations, I looked up events from DNS sources

```
`index="botsv3" source="stream:dns"` 
```

- This returned 175,094 events, so I added some keywords to our search to hopefully narrow this down.

```
index="botsv3" source="stream:dns" *monero* OR *coin* OR *crypto*
```

- Giving us 14 events. Under `query`, I appear to have found our first destination.

![image](https://github.com/user-attachments/assets/96279f72-7756-435f-ac3e-c89dfca24df8)

- Checking on VirusTotal

![image](https://github.com/user-attachments/assets/4f75c5a4-45b9-414b-88ae-338c70f6fa86)

![image](https://github.com/user-attachments/assets/19ebe5d1-4e2a-4ab8-b109-ba5ef4e80e4b)

```
index="botsv3" source="stream:dns" *monero* OR *coin* OR *crypto* | dedup query{} | table query{}
```

![image](https://github.com/user-attachments/assets/d49a598f-bf0d-4802-8383-5fbeb82fd043)

**Answer**: 6

### Question 12: Using Splunk's event order functions, what is the first seen signature ID of the coin miner threat according to Frothly's Symantec Endpoint Protection (SEP) data?
Taking a look at the BOTSv3 documentation, we have multiple sources for data that come under `symantec`. Symantec endpoint logs in Splunk provide visibility into endpoint-level events like malware detections, file quarantines, policy enforcement, process activity, IPS/Firewall blocks, and system scans. Initial query ran:

```
index="botsv3" sourcetype="symantec:ep:security:file"
```

- This gave me just 46 events to filter through. Linking back to the question, we are interested in the `signature_id` field, which has just two options.

![image](https://github.com/user-attachments/assets/83c90d49-c085-4af0-b35e-a396c68f7f89)

- I then ran another query, filtering on `signature_id` to find the earliest instance.

```
index="botsv3" sourcetype="symantec:ep:security:file" | table signature_id _time | sort + _time
```

![image](https://github.com/user-attachments/assets/40c2f8fd-fe7d-4bb3-a78b-855c82792abc)

- Strange question when both results have the exact same time stamp. 

![image](https://github.com/user-attachments/assets/55f4b7b0-8146-4891-bc27-9a7eabe2cbd0)

**Answer**: `30358`

### Question 13: According to Symantec's website, what is the severity of this specific coin miner threat?
Here I searched on Google `symantec signature ID 30358`.

![image](https://github.com/user-attachments/assets/124c9238-ed20-49a5-a9e2-43476d508b7b)

**Answer**: `Medium`

### Question 14: What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat?
This question leads me to think something has been blocked or whitelisted. As previously mentioned, we now know that symantec events include `IPS/Firewall blocks`, so this is a potentially good place to start.

```
index="botsv3" sourcetype="symantec:ep:security:file" "blocked"
```

- With this query, I expanded the returned events and it was now clear a block action had taken place under signature: `Web Attack: JSCoinminer Download 8`

![image](https://github.com/user-attachments/assets/f0b031cc-5009-48a1-bde9-840b51dd4f57)

- The `Host_Name` field reveals the answer.

**Answer**: `BTUN-L`

### Question 15: What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?
FQDN stands for Fully Qualified Domain Name. To work out the answer to this, I began key-word searching with common operating systems.

```
index="botsv3" "Windows 10"
```

- Knowing about these sources such as `operatingsystem` and `cisconvmsysdata` will be useful for future related investigations. 

![image](https://github.com/user-attachments/assets/bee77407-ede6-49c3-9ca0-53c58087da9b)

- I then changed my search to filter on this new source.

```
index="botsv3" source="operatingsystem"
```

- Under the `OS` field, we now have two options. 

![image](https://github.com/user-attachments/assets/c569f2e4-a1b3-4011-a8d1-4f3ef12a37e7)

- I then ran some transforming commands to get a better idea of what endpoints were running which OS. This filters for unique endpoints and displays a table their related OS.

```
index="botsv3" source="operatingsystem" | dedup host | table host OS
```

![image](https://github.com/user-attachments/assets/74080182-f073-4605-b8ed-61ba22f5013d)

**Answer**: `BSTOLL-L.froth.ly`

### Question 16: According to the Cisco NVM flow logs, for how many seconds does the endpoint generate Monero cryptocurrency?
Going back to the previous question, I came accross the source `cisconvmsysdata`. Cisco NVM stands for Network Visibility Module, basically log records of network activity from endpoints. I started my investigation on this question leveraging this source.

```
index="botsv3" source="cisconvmsysdata"
```

- Returning just 11 events to investigate.

![image](https://github.com/user-attachments/assets/0861ec23-a1dc-4266-8a1e-54fa04346848)

- Going back to **Question 10**, we identified that the endpoint successful in mining cryptocurrency was `BSTOLL-L.froth.ly`. In the `vsn` field from our latest search, we can now filter directly onto this endpoint.

![image](https://github.com/user-attachments/assets/856fc2cf-165c-40cf-b64a-285ac577de6e)

```
index="botsv3" source="cisconvmsysdata" vsn="BSTOLL-L.froth.ly"
```

- Now I have just two events. Although this turned out to be a dead end to answer the question directly. I had to look up online the SPL search in order to calculate the difference. Bit of an odd question, but good to start using new source types like `cisconvmsysdata`. 

```
index=botsv3 source=cisconvmflowdata *coinhive* | stats max(_time) as maxtime min(_time) as mintime | eval difference=maxtime-mintime
```

**Answer**: `1652` seconds

### Question 17: What kind of Splunk visualization was in the first file attachment that Bud emails to Frothly employees to illustrate the coin miner issue?
The question explicitly mentions emails, so I began searching for `smtp` events. I ran the below query including Buds email address, giving us 11 events.

```
index=botsv3 sourcetype="stream:smtp" | spath sender_email | search sender_email="bstoll@froth.ly"
```

- The field `content{}` most likely has what we are after, so i further refined our search:

![image](https://github.com/user-attachments/assets/1b22f5a1-13cc-440c-be68-697aab4574da)

```
index=botsv3 sourcetype="stream:smtp" | spath sender_email | search sender_email="bstoll@froth.ly" | dedup content{} | table content{}
```

![image](https://github.com/user-attachments/assets/416fc0dd-6a6d-47b8-8363-fc95f5bbc477)

**Answer**: `Splunk Chart`

### Question 18: What IAM user access key generates the most distinct errors when attempting to access IAM resources?
Going back to question 1, I came accross `eventSource="iam.amazonaws.com`, which I re-used to begin searching for the answer.

```
index=botsv3 sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com"
```

- In the interesting fields, we have `user_access_key`.

![image](https://github.com/user-attachments/assets/d23133e8-a812-47db-9bd5-0074e5df6bd2)

- So the answer will be one of these user access keys. By filtering on unique `errorMessage`, I was able to locate the answer.

```
index=botsv3 sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com" | dedup errorMessage | stats count by user_access_key, errorMessage | table user_access_key, errorMessage, count
```

![image](https://github.com/user-attachments/assets/73018d2f-f2f3-45e8-a99a-ed08f27bcc1a)

- `AKIAJOGCDXJ5NW5PXUPA` user access key has 5 unique errors.

**Answer**: `AKIAJOGCDXJ5NW5PXUPA`

### Question 19: 
