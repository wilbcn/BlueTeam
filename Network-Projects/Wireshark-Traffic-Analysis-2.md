# 📡 Wireshark Project 2: Download From Fake Software Site

This follow-up Wireshark project dives into another real-world malware PCAP, this time focusing on a file downloaded from a fake software site. It’s part of my ongoing series exploring malicious traffic and network behavior. These projects reflect my commitment to building practical skills with industry tools like Wireshark, while strengthening my understanding of networking and threat analysis.

## 🎯 Objectives

- Answer the provided questions from the Malware Sample PCAP provider, listed in the tools & resources
- Demonstrate how I investigated and was able to workout the answer to each question, ensuring a logical and well-thought approach to each one.

Questions to answer:

- What is the IP address of the infected Windows client?
- What is the mac address of the infected Windows client?
- What is the host name of the infected Windows client?
- What is the user account name from the infected Windows client?
- What is the likely domain name for the fake Google Authenticator page?
- What are the IP addresses used for C2 servers for this infection?

## Tools & Resources
- [Sample PCAP source](https://www.malware-traffic-analysis.net/2025/01/22/index.html)




## 📖 Project Walkthrough: Analysing a Real-World PCAP in Wireshark
This section breaks down the steps and thought process I followed while working through this PCAP. 

### 1. PCAP Summary and Overview
For this section, I explored **Statistics** and other options in Wireshark, to gain an initial understanding of what we are working with.

**Capture File Properties**
- Total Packets: 39427
- File Size: 26MB
- First Packet: 2025-01-22 19:44:56
- Last Packet: 2025-01-22 20:38:18
- Duration: 53 minutes, 22 seconds
- SHA256: e59db1c07c6fdefafa0abdbca03248c341cdc36c09c34753204d3162802a3586
- SHA1: 7b2ecacbbefa615157c2cc2ecdbe43f0677fcbad

**Conversations Extract**

![image](https://github.com/user-attachments/assets/5adf4699-f94f-4ff5-b566-d58b7dcff6a5)

![image](https://github.com/user-attachments/assets/55e62ea2-5d64-4703-81cc-8d4ef6202258)

Key takeaways:
- `freedomlovestyle.life`
    - Somewhat suspicious domain name
    - 10MB, 10940 packets
    - Non-standard port: `elvin-client`
    - Multiple TCP streams associated
    - Has the most traffic
    - `DESKTOP-L8C5GSJ.bluemoontuesday.com` is the local machine
    - Most likely the top candidate for the payload and fake download site.
    
- `hosted-by.csrp.host`
    - 7MB, 9076 packets
    - Ports used: `HTTP`
    - Multiple stream IDs observed
    - Potentially related to `freedomlovestyle.life`. 

- `srv-45-125-66-252.serveroffer.net`
    - Low byte count, but the domain look suspicious
    - Ports used: `HTTPS`
    - Stream ID: 288
    - 107kB, potential beaconing or C2

- `authenticatoor.org`
    - 2MB, 2470 packets
    - Clearly suspicious due to misspelling of “authenticator”
    - Stream ID 50

### 2. Investigating the PCAP
Now it was time to investigate the PCAP file, leveraging the findings from our initial analysis and overview in section 1. We have lots to investigate, such as multiple suspicious domains and use of non-standard ports. 

The first thing I did, was apply the stream id `61` as a filter from **statistics -> conversations -> TCP**. This stream contained the highest number of packets exchanged with our local machine, from address `hosted-by.csrp.host` 

After applying this filter, I noticed straight away a GET request on a .ps1 (powershell) file served via HTTP, highlighted below.

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/05e94e58-0e23-46df-b010-2271ba1180e2" />

By following the HTTP stream, I was able to see the servers response and the payload content. The .ps1 file appears to be obfuscated PowerShell code, leveraging GetString() and System.Text.Encoding::UTF8. The script was likely designed to decode and execute malicious commands on the target system.

<img width="964" alt="image" src="https://github.com/user-attachments/assets/2ebfb770-c608-4c70-8a70-92a6fa31f8dd" />

A reverse DNS on the `host: 5.252.153.241` confirms this is the domain where our user initiated a GET request on the powershell file.

![image](https://github.com/user-attachments/assets/0cf98ab9-2d9c-41d0-bbd3-00701e39f36f)

The next step in the investigation was to determine if the script was executed, and what hapened next. 



