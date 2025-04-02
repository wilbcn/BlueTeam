# 🏠 Collecting and Investigating Web Browser History Artifacts

## 📖 Overview
This document details the steps taken to gain hands-on experience with **Windows Browser History Capturer/Viewer** as part of a digital forensics investigation. In this project, we simulated a scenario where a test user, **Tom Smith**, engaged in web browsing activities using **Microsoft Edge**. As the system administrator, we conducted an analysis of their browsing history, capturing and examining the data using forensic tools to identify any suspicious activity.

💡 **This project was inspired by my learning in the** [**Blue Team Level 1**](https://www.securityblue.team/blue-team-level-1) **course, reinforcing key digital forensics concepts in a controlled environment. By applying real-world investigative techniques within a secure VM, I am able to deepen my understanding of forensic methodologies while gaining practical experience with industry-standard tools and software.

You can find the setup of the secure VM in AWS here -> [EC2 VM](https://github.com/wilbcn/DigitalForensics/blob/main/AWS-SecureVM/README.md)

## 🎯 Goals
- Create a **Non-Admin User** and simulate **suspicious activity**
- Perform various web searches using this test user to generate **normal** and **suspicious** logs
- Capture and investigate browser history using **Windows Browser History Capturer/Viewer**
- Analyze and interpret findings

---

## **1. Create a Non-Admin User**
1. Logging into the VM as an **Admin user**, I ran **lusrmgr.msc** and hit enter.
2. We created a **standard user account** named **Tom Smith**, setting the username as `g-tomsmith` (`G` representing General User).
3. We configured the password to never expire and disabled the **'change password at login'** option.

![image](https://github.com/user-attachments/assets/f18fb8fe-b96c-466e-9cca-6ac74c158509)

4. I then verified this new user was part of the **Users group**, rather than **Administrators**.

![image](https://github.com/user-attachments/assets/ed795615-cf42-4c87-bd93-a9271ca16f5f)

---

## **2. Simulate Suspicious Browser Activity**
1. By right-clicking on **Microsoft Edge** from the toolbar and selecting **Run as a different user**, we logged in as `g-tomsmith` and generated activity.
2. During this stage, Tom navigated through a mix of **legitimate websites**, including social media platforms, alongside **potentially suspicious sites and search queries**.

---

## **3. Capture and Analyze the Data as an Admin**
1. After waiting around 5 minutes to ensure activity was cached, we proceeded with capturing it.
2. Using **Windows Browser History Capturer**, we selected relevant filters such as **history, cache, and deleted history** to extract browsing data.

![image](https://github.com/user-attachments/assets/4be0e1e9-23ca-4a26-aa53-6c4f6d259c34)

3. In **Browser History Viewer**, we loaded the extracted history by selecting the capture folder from our desktop and clicking **Load**.

![image](https://github.com/user-attachments/assets/3ee1ce8f-d079-4fb3-a433-cd614ec09026)

4. Once loaded, we analyzed the captured data. The records revealed that **Tom Smith** had visited common websites like `https://docs.aws.amazon.com/`. However, we also detected suspicious activity, including searches related to **accessing the dark web** and **permanently deleting browser history**.

![image](https://github.com/user-attachments/assets/51c98060-c8b1-444e-8184-0a43f210aec2)

5. The tool provided a **timeline of browsing events**, allowing us to better understand user actions. Additionally, we filtered for **file downloads** using the `file://` prefix to detect any suspicious downloads.

![image](https://github.com/user-attachments/assets/7cb82c5e-ca0c-4d3c-b496-d2ce1d3f5ed5)

---

## **🔍 Key Takeaways**
- **Understanding Digital Artifacts**: Browser history provides critical insights into **user behavior**, **search patterns**, and **potential intent**, making it a fundamental forensic artifact.
- **Realistic Investigation Approach**: Simulating investigations in a controlled environment helps bridge **theoretical knowledge** with **practical hands-on experience**.
- **Importance of User Privilege Separation**: Conducting forensic analysis as an **Administrator** while investigating activities of a **Non-Admin user** reinforces best security practices.
- **Leveraging Forensic Tools Effectively**: Tools like **Windows Browser History Capturer/Viewer** offer structured data representation, allowing forensic analysts to detect anomalies, suspicious searches, and downloaded files.
- **Filtering for Suspicious Activity**: The ability to search for **file downloads, cache history, and deleted records** provides additional layers of investigation, crucial for cybersecurity professionals.

This project marks one of my initial steps toward becoming a cybersecurity professional. I plan to continue honing my skills and documenting my journey through various follow-up projects, exploring additional digital forensic tools such as FTK Imager and more.
