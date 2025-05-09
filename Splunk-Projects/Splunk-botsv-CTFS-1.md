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
