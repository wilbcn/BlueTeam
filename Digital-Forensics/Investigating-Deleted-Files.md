# 🔍 Recovering Deleted Files & Investigating Potential Threats

## 📖 Overview
This project demonstrates a **forensic investigation** into **deleted files** within a **Windows virtual machine (VM)**. The objective is to **recover files that were moved to the Recycle Bin**, analyze them for **potential threats**, and determine whether they indicate malicious intent.

We leverage **RBCmd.exe**, a **Windows forensic tool**, to extract and restore deleted files. Additionally, we utilize **metadata analysis, hashing, and threat intelligence tools** such as **ExifTool, CSVQuickViewer, and VirusTotal** to conduct a comprehensive investigation.

### **🔹 Real-World Scenario**
This is a **scenario-based forensic project** in which an **insider threat actor** attempts to **conceal malicious activity** by moving suspicious files to the **Recycle Bin**, assuming they are permanently hidden. However, they fail to **empty the bin**, making forensic recovery possible.

💡 **This project was inspired by my learning in** [**Blue Team Level 1**](https://www.securityblue.team/blue-team-level-1), reinforcing key digital forensics concepts in a controlled environment. By applying **real-world investigative techniques** within a secure VM, I am deepening my understanding of forensic methodologies while gaining **hands-on experience with industry-standard tools**.

📌 **AWS VM Setup for Forensics:**  
You can find the full **AWS EC2 virtual machine setup guide** here → [EC2 VM](https://github.com/wilbcn/DigitalForensics/blob/main/AWS-SecureVM/README.md)

---

## 🔧 Tools & Acknowledgements
| **Tool**            | **Purpose** |
|---------------------|------------|
| [RBCmd.exe](https://github.com/EricZimmerman/RBCmd) | Recover deleted files from the Recycle Bin |
| [ExifTool](https://exiftool.org/) | Extract metadata from files |
| [CSVQuickViewer](https://sourceforge.net/projects/csvquickviewer/) | Analyze forensic CSV output |
| [VirusTotal](https://www.virustotal.com/gui/home/upload) | Scan file hashes for malware |

---

## 🎯 Project Goals
- 🕵 **Simulate suspicious file activity** (moving potentially malicious files to the Recycle Bin).
- 🔍 **Identify and recover deleted files** using **RBCmd.exe**.
- 📝 **Analyze recovered files** using **ExifTool** and **CSVQuickViewer**.
- 🛡 **Verify file integrity & detect potential malware** using **SHA-256 hashing & VirusTotal**.

---

## **1. Preparing Suspicious Files**
To create a realistic forensic scenario, we generate three suspicious files, delete them, and attempt to recover and investigate them.

| **File Name**              | **Description** |
|---------------------------|----------------|
| `payslips_Dec_24.zip`     | **EICAR test file** (renamed as a fake payslip to disguise intent) |
| `ransomware.txt`          | A **text file containing a simulated ransom note** |
| `new_employee_contract_2025.docx` | A **Word document with a macro** (non-functional for safety) |

---

## **2. Uploading Files to the VM**
1. Upload these files to the **Windows VM**.  
2. **Move them to the Recycle Bin** (but do NOT empty it).  

📌 **Scenario Explanation:**  
- The user attempts to hide evidence of malicious activity by deleting the files.  
- However, forensic tools can still recover them, as the Recycle Bin has not been emptied.  
- This allows us to replicate real-world forensic investigations.

---

## **3. Recovering Deleted Files Using RBCmd.exe**
1. Run PowerShell as Administrator
2. Create a directory to store the recovered files

   ```powershell
   mkdir C:\Users\Administrator\Desktop\RecoveredFiles
   ```
   
![image](https://github.com/user-attachments/assets/c3b4f4e8-4821-4b1d-96e3-ef270ce179fa)

3. Open CMD as Administrator and change to the recycle bin folder

   ```powershell
   C:\$Recycle.Bin
   ```
   
4. List the contents of the recycle bin to determine user-specific folders:

![image](https://github.com/user-attachments/assets/e1672e82-f6d8-4584-808a-097fb3c38a45)

Here, we can see an entry dated **13/02/2025**, which matches the `whoami` output. Since this is an **Amazon EC2 VM**, running these tasks as a default user was not straightforward, but we were still able to gain hands-on experience with these tools.

---

## **4. Create the CSV file and load it into CSVQuickViewer**
1. Create the CSV file: 

   ```powershell
   C:\Users\Administrator\Desktop\Tools>RBCmd.exe -d C:\$Recycle.Bin\S-1-5-21-3939027288-1751461437-3338404962-500 --csv C:\Users\Administrator\Desktop\RecoveredFiles
   ```

2. Then run CSVQuickViewer application, and load the data.

![image](https://github.com/user-attachments/assets/cc77723b-475f-47e6-91eb-d48419ceda60)

With this CSV loaded, we now have crucial information on the hidden files. Inside the recycle bin, we have identified 3 files. We can now proceed to investigate these 3 files to see if they are harmless or malicious.

1. $I7HD0FZ.docx - new_employee_contract_2025.docx

2. $IA0ATM0.txt - ransomware.txt

3. $IO2U9UF.zip - payslips_Dec_24.zip

All deleted on 13/2/2025 around Midday 12:00:00

---

## **5. Begin investigating the identified files
1. Copy the files to our local folder for further investigations

   ```powershell
   C:\Users\Administrator\Desktop\RecoveredFiles>xcopy C:\$Recycle.Bin\S-1-5-21-3939027288-1751461437-3338404962-500\* C:\Users\Administrator\Desktop\RecoveredFiles\ /H /E /C /I
   ```

![image](https://github.com/user-attachments/assets/c328c277-a8c4-4022-b7ed-05d7b1ce804c)

2. Rename the files back to their original names in powershell.

![image](https://github.com/user-attachments/assets/0c2b2308-c338-4ae2-a5ea-dc78f2d10d2f)

![image](https://github.com/user-attachments/assets/ffa8f78e-bd17-4263-83be-6b635a0f6b7f)

3. Safely opening up the ransomware.txt file to reveal its contents. We can now see that the user was potentially going to use this document to conduct a ransomware attack!

![image](https://github.com/user-attachments/assets/c6a8f97c-c3d3-4baf-a11c-e5f59f2baf26)

4. Using exiftool on the word document 'new_employee_contract_2025.docx'

   ```powershell
   C:\Users\Administrator\Desktop\Tools\exiftool.exe C:\Users\Administrator\Desktop\RecoveredFiles\File_Archive\new_employee_contract_2025.docx
   ```

![image](https://github.com/user-attachments/assets/e34731e7-837c-4d74-b932-1c75532b1a74)

This analysis aimed to locate any hidden macros. Although the macro did not execute anything, this exercise demonstrated how such a payload might be embedded in a **malicious Word document.**

5. The final step was generating a SHA256 hash for the **payslips_Dec_24.zip** file and checking its status in **VirusTotal.**

![image](https://github.com/user-attachments/assets/822e7039-de4e-44fc-854c-de6987574d5b)

![image](https://github.com/user-attachments/assets/f3029ba8-0d19-4ca8-b1aa-2891d21ac15b)

This test revealed that the **payslips.zip** file contained a **malicious EICAR test file,** disguised as legitimate payslips. This suggests an attempt to trick users into opening the file, a common phishing tactic.

## **Key takeaways**
- This project was designed to provide hands-on experience in digital forensics, simulating real-world tasks that a cybersecurity professional may perform daily.
- By engaging in this fundamental exercise, i enhanced my understanding of forensic investigation tactics, tools, and methodologies.
- This exercise demonstrated key digital forensics techniques that can be used to recover and analyze suspicious files.



