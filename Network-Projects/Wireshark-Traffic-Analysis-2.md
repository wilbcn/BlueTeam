# 📡 Wireshark Project 2: Download From Fake Software Site

This follow-up Wireshark project dives into another real-world malware PCAP, this time focusing on a file downloaded from a fake software site. It’s part of my ongoing series exploring malicious traffic and network behavior. These projects reflect my commitment to building practical skills with industry tools like Wireshark, while strengthening my understanding of networking and threat analysis.

## 🎯 Objectives

- Answer the provided questions from the Malware Sample PCAP provider, listed in the tools & resources
- Demonstrate how I investigated and was able to workout the answer to each question, ensuring a logical and well-thought approach to each one.
- Answer the **questions** and the bottom of the report!


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
    - Most likely the top candidate for the payload or C2
    - Underlying IP 45.125.66.32 is malicious on VT.

- `hosted-by.csrp.host`
    - 7MB, 9076 packets
    - Ports used: `HTTP`
    - Multiple stream IDs observed
    - Underlying IP is very malicious on VT: 5.252.153.241 

- `srv-45-125-66-252.serveroffer.net`
    - Low byte count, but the domain look suspicious
    - Ports used: `HTTPS`
    - Stream ID: 288
    - 107kB,
    - Underlying IP 45.125.66.252 is malicious on VT. Within the same /24 subnet as `freedomlovestyle.life`

- `authenticatoor.org`
    - 2MB, 2470 packets
    - Clearly suspicious due to misspelling of “authenticator”
    - Stream ID 50
    - 6/94 VT Score. Phishing Label
    - Underlying IP 82.221.136.26 marked as malicious and phishing on VT.

### 2. Investigating the PCAP
Now it was time to investigate the PCAP file, leveraging the findings from our initial analysis and overview in section 1. We have lots to investigate, such as multiple suspicious domains and use of non-standard ports. 

The first thing I did, was apply the stream id `61` as a filter from **statistics -> conversations -> TCP**. This stream contained the highest number of packets exchanged with our local machine, from address `hosted-by.csrp.host` 

After applying this filter, I noticed straight away a GET request on a .ps1 (powershell) file served via HTTP, highlighted below.

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/05e94e58-0e23-46df-b010-2271ba1180e2" />

By following the HTTP stream, I was able to see the servers response and the payload content. The .ps1 file appears to be obfuscated PowerShell code, leveraging GetString() and System.Text.Encoding::UTF8. The script was likely designed to decode and execute malicious commands on the target system.

<img width="964" alt="image" src="https://github.com/user-attachments/assets/2ebfb770-c608-4c70-8a70-92a6fa31f8dd" />

A reverse DNS on the `host: 5.252.153.241` confirms this is the domain where our user initiated a GET request on the powershell file.

![image](https://github.com/user-attachments/assets/0cf98ab9-2d9c-41d0-bbd3-00701e39f36f)

Continuining to navigate this stream, we can see that an additional GET request is made to `/1517096937`. It repeatedly tries to get this file, returning multiple `HTTP/1.1 404 Not Found`. It does eventually return a `HTTP/1.1 200 OK`, however the repeated not found responses indicate malware behaviour. 

Digging deeper into the stream, we have more successful GET requests for file downloads. These are then saved to `C:\ProgramData\huo`. Below is an overview of the 4 files from this HTTP stream, related to our suspicious host `hosted-by.csrp.host`.

<img width="721" alt="image" src="https://github.com/user-attachments/assets/f20b8932-edcc-4a28-bc95-2f6d31fabb7d" />

By key-word searching for `create-shortcut` I discovered that `TeamViewer.exe` was added to the start up folder, ensuring persistence on reboot. 

<img width="684" alt="image" src="https://github.com/user-attachments/assets/42ba9881-8647-4520-8e0d-8a8afe8df2a4" />

Furthermore, this function sends a "log" or execution result back to the attacker's Command & Control (C2) server.

<img width="351" alt="image" src="https://github.com/user-attachments/assets/3e39c341-dbb4-4244-a5f3-4a43ddc1a3f4" />

For an overview of GET requests from this malicious IP, I ran the following filter:

```
http.request.method == "GET" && ip.dst == 5.252.153.241
```

<img width="1435" alt="image" src="https://github.com/user-attachments/assets/c54a3e4d-e888-4cdb-bd57-ec2ba828f18e" />

Which confirms our 5 critical payloads which are worth investigating. Additionally, the exfiltration callback, which confirms successful injection and startup persistence. 

```
GET /api/file/get-file/29842.ps1
GET /api/file/get-file/TeamViewer
GET /api/file/get-file/Teamviewer_Resource_fr
GET /api/file/get-file/TV
GET /api/file/get-file/pas.ps1
GET /1517096937?k=message%20=%20startup%20status%20=%20success
GET /1517096937?k=message%20=%20startup%20status%20=%20success
```

### 3. Exporting HTTP objects - Investigating the payloads
By navigating to **File -> Export Objects -> HTTP**, and applying filename extension filters, I was able to export the files we have flagged as malicious. Example:

<img width="926" alt="image" src="https://github.com/user-attachments/assets/44d2ab75-d6d4-45da-bc57-d175135d4c8c" />

Each exported file was then reviewed for indicators of compromise. While a full dynamic analysis is outside the scope of this project, static inspection and threat intelligence lookups were performed to identify common traits or known signatures.


### 3.1 Checking file hashes
The first thing I did was generate SHA256 Hashes of each of these files, and generate reports using **VirusTotal**, and **Cisco Talos Intelligence**.

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          4/7/2025  11:05 AM           1512 29842.ps1
-a----          4/7/2025  11:05 AM           1553 pas.ps1
-a----          4/7/2025  11:05 AM        4380968 TeamViewer
-a----          4/7/2025  11:06 AM         668968 Teamviewer_Resource_fr
-a----          4/7/2025  11:06 AM          12920 TV

PS C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports> Get-FileHash *

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          B8CE40900788EA26B9E4C9AF7EFAB533E8D39ED1370DA09B93FCF72A16750DED       C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports\...
SHA256          A833F27C2BB4CAD31344E70386C44B5C221F031D7CD2F2A6B8601919E790161E       C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports\...
SHA256          904280F20D697D876AB90A1B74C0F22A83B859E8B0519CB411FDA26F1642F53E       C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports\...
SHA256          9634ECAF469149379BBA80A745F53D823948C41CE4E347860701CBDFF6935192       C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports\...
SHA256          3448DA03808F24568E6181011F8521C0713EA6160EFD05BFF20C43B091FF59F7       C:\Users\Administrator\Desktop\Wireshark PCAPS\Wireshark Exports\TV
```

Querying the file hashes on reputable threat intelligence platforms provides deeper context on the attack, helping to identify known malware families, associated campaigns, and threat actor behavior.

File scan results:

File: 29842.ps1
Result: 27/62 VT Score. Flagged as malicious. Threat label: trojan.powershell/obfuse. First seen 2025-01-22 16:41:17 UTC. Related to IP address `5.252.153.241` which we already flagged. 

File: pas.ps1
Result: 25/62 VT Score. Flagged as malicious. Threat label: trojan.powershell/malgent. First seen 
2025-01-22 17:35:46 UTC. Also tied to identified malicious IP.

File: TeamViewer
Result: 0/72 VT Score. Also unknown on Cisco Talos. Most likely a legitimate file being abused.

File: Teamviewer_Resource_fr
Result: 0/72 VT Score. Also unknown on Cisco Talos. Also a potentially normal file being abused.

File: TV
Result: 47/73 VT Score. Flagged as malicious. Threat label: trojan.malgent/ahcr. First seen 2025-01-22 11:49:32 UTC. 

While I was using threat intelligence platforms, I decided now is a good time to check out our offending IP address `5.252.153.241`. VT labels this as malicious, with VY score 12/97. First seen on 2025-01-22 16:49:21 UTC. Also, although unknown on `AbuseIPDB`, we know for a fact from our investigation this is a malicious IP address. 

### 4. Finding the C2 server
Now that I have identified that `5.252.153.241` // `hosted-by.csrp.host` is malicious, I wanted to check out the other flagged addresses, as well the beginning of a timeline of events.

By filtering for `http` traffic, we get the below packets.

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/853acb08-6d5c-4204-9bfd-2c2ec0f4f28e" />

Here I learned something new. The request for connecttest.txt is legit Windows behavior, and a **red herring** in our timeline. This is good to know for future investigations. It indicates the host had just joined the network or refreshed its connectivity—providing context for the timing of the first PowerShell download.

The second identified address to investigate is `freedomlovestyle.life`,  IP address `45.125.66.32`. I applied a filter from **Statistics -> Endpoints** to investigate further.

```
ip.addr==45.125.66.32 && tcp.port==2917
```

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/0e706d0c-536a-4e5a-863c-6511a4bc7902" />

Traffic to `freedomlovestyle.life` begins after the malicious .ps1 file was downloaded from `hosted-by.csrp.host`, which occured at `19:45:56`. This rules it out as the trigger, but is now considered post-infection traffic, and is most likely the Command & Control C2 server. This address had the most packets too from our initial overview: 10940 packets. In summary, this address is highly-likely to be the C2 server because:
- Strong timing indicator of beaconing, post compromise
- Unusual port 2917 Elvin-client. Non standard port is typical in C2 servers to evade detection
- Traffic after TLS handhsake is application data only, normal for TLS-based C2 channels.
- Beaconing patterns: Each packet is exactly 1414 bytes, suggesting a scripted or automated payload — not standard browsing behavior.
- No legitimate purpose. The domain and domain TLD is suspicious.
- Scan on VT showed as malicious (45.125.66.32)
- AbuseIPDB: 45.125.66.32 is known in their database, and has 100% confidence of abuse.

In summary, this identified address is our C2 server, along side `45.125.66.252`:`srv-45-125-66-252.serveroffer.net`, which is part of the /24 subnet. 

### 4. Finding the fake software site for initial download
From our flagged addresses, we have one remaining: `authenticatoor.org`.

Applying a filter on the underlying IP, shows us that all traffic related to this address happened before the payload download (.ps1).

<img width="1435" alt="image" src="https://github.com/user-attachments/assets/3bf8029c-5655-4427-a16c-d22afdd5d43e" />

Starting with the payload itself, we know that the timestamp is `2025-01-22 19:45:56`. We should investigate all network activity just before that. 

Next filters ran:

```
tcp.port == 443
```

This showed all encrypted communications. Among the most notable pre-payload domains was authenticatoor.org, which showed multiple connections just seconds before the download.

```
tls.handshake.type == 2
```

This helped us identify successful TLS handshakes:

<img width="1431" alt="image" src="https://github.com/user-attachments/assets/05bf7765-734b-4c33-9f50-92763a7738ec" />

Here we clearly see a TLS Server Hello from `google-authenticator.burleson-appliance.net → authenticatoor.org`. This is a typosquatted and deceptive domain, mimicking the legitimate "Google Authenticator" service, likely to trick the user into initiating a download.

`google-authenticator.burleson-appliance.net` web page does not load anymore. However, It is marked as malicious/phishing on VT.

### 5. Key Findings and Lessons Learned

- **How to spot beaconing**
  - Regular, repeating packet intervals (often identical in size and timing)
  - High volume of small packets to the same IP/port (e.g., C2 over port 2917)

- **Post-infection behavior**
  - Payloads downloaded to hidden directories (e.g., `C:\ProgramData\huo`)
  - Persistence via shortcut creation in startup folder
  - Callback logs sent to C2 confirming success (`GET /1517096937?k=...`)

- **Writing down the first recorded packet for endpoints is crucial for understanding a timeline of events**
  - Helps trace back the initial access point (e.g., `authenticatoor.org` before `.ps1` download)
  - Clarifies the flow from infection vector → payload delivery → callback

- **TLS filtering is key when payloads are delivered via HTTPS**
  - Use `tcp.port == 443` and `tls.handshake.type == 2` to identify Server Hello patterns and domain involvement

- **Typosquatting and fake domains are common lures**
  - E.g., `authenticatoor.org`, `google-authenticator.burleson-appliance.net` mimicking legitimate services to trick users

### 6. Project wrap-up and answering the questions

Questions to answer:

- What is the IP address of the infected Windows client? `10.1.17.215`
- What is the mac address of the infected Windows client? `00:d0:b7:26:4a:74`
- What is the host name of the infected Windows client? `DESKTOP-L8C5GSJ.bluemoontuesday.com`
- What is the user account name from the infected Windows client? Filter: `dhcp` -> 
- What is the likely domain name for the fake Google Authenticator page? `authenticatoor.org`
- What are the IP addresses used for C2 servers for this infection? `45.125.66.32` `45.125.66.252` `5.252.153.241`

