# Cowrie-Based Honeypot Deployment on AWS

## 📚 Overview

This documentation outlines the process of configuring and deploying a virtual machine in AWS to host a Cowrie SSH honeypot, with the goal of gaining hands-on experience in honeypot deployment and behavioral data collection. Honeypots are a foundational concept in cybersecurity, touching on key areas such as network security, secure architecture, and command-line interface (CLI) proficiency.

This project serves as an ideal entry point into Honeypots, offering practical exposure to deploying deception-based security mechanisms in the cloud. In addition to Cowrie, the project also highlights opportunities for future integration with tools like Splunk and various AWS-native services (e.g., CloudWatch, VPC Flow Logs), aligning with my broader goal of developing practical, cross-platform skills with industry-standard tools.

---

## 🎯 Project Goals

- Deploy a SSH honeypot in the cloud securely
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Gain practical experience with legal and ethical security practices
- Establish groundwork for future behavioral honeypot research

---

## Acknowledgements
- [Cowrie Documentation](https://docs.cowrie.org/en/latest/README.html)

## Tools used
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [WHOIS Lookup](https://whois.domaintools.com/)
- Amazon EC2 Instances
- Cowrie SSH Honeypot

---

## 📦 1 – Cloud Setup

In this phase, I outline the steps taken to configure and launch a new EC2 instance that will serve as our SSH honeypot. This virtual machine must be carefully provisioned—with appropriate instance specifications, network isolation, and security controls—to ensure it can run the honeypot reliably and safely in a cloud environment. 

- Public IP redacted for security reasons

### 1.1 - Honeypot Overview

Firstly I logged into my AWS account, and navigated to `EC2`. From here, I selected `launch instance` to begin setting up our Virtual Machine. I have provided an overview of the EC2 configuration as well as any necessary explanations. 

- **Instance Name**: `Cowrie-Honeypot`
- **Region**: `eu-north-1a` (GDPR-compliant region)
- **Instance Type**: `t3.xlarge` (4 vCPU, 16GB RAM)
- **AMI**: `Ubuntu Server 24.04 LTS (HVM),EBS General Purpose (SSD) Volume Type`.
- **Storage**: `128GB`

### 1.2 - Network settings

- **VPC**: A new VPC was created to ensure full isolation of the honeypot from any other cloud resources. An Internet Gateway was attached to the VPC and added to VPC route table.
- **Subnet**: A new Subnet was created within eu-north-1a for logical separation.
- **Auto-assign public IP**: This is required so the honeypot can be accessed by external attackers. Without a public IP, no unsolicited traffic can reach the system.

### 1.3 - Security Group Rules

| Port | Purpose | Source | Description |
|------|---------|--------|-------------|
| 22 | SSH access | My IP only | For administrative access to the server |
| 2222 | Cowrie honeypot port | 0.0.0.0/0 | Used to attract SSH scans/attacks (Rule to be activated after Cowrie is running) |

### 1.4 - SSH Key Pair

- Create a new key pair
- Run `chmod 600 example_key.pem`. This permission is required by SSH to prevent unauthorised access and is enforced by AWS security standards.
- Connect with:  
  `ssh -i "example_key.pem" ubuntu@<public-ip>`

---

## 2 – Honeypot Installation

Now that the EC2 instance was up and running, I connected for the first time from my local machine. To begin with, I ran some commands to refresh the system’s package list and apply the latest updates.

```
sudo apt update

sudo apt upgrade
```

Next, I installed system-wide support for Python virtual environments and other dependencies, as per the Cowrie guide.

```
sudo apt-get install git python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
```

To continue with the Cowrie setup, I created a dedicated user account on the system. Creating a dedicated non-root user helps limits the potential damage an attacker could do if they manage to escape or exploit the honeypot—following the principle of least privilege for better security and containment.

```
ubuntu@my-ip-address:~$ sudo adduser --disabled-password cowrie
info: Adding user `cowrie' ...
info: Selecting UID/GID from range 1000 to 59999 ...
info: Adding new group `cowrie' (1001) ...
info: Adding new user `cowrie' (1001) with group `cowrie (1001)' ...
info: Creating home directory `/home/cowrie' ...
info: Copying files from `/etc/skel' ...
Changing the user information for cowrie
Enter the new value, or press ENTER for the default
	Full Name []:
	Room Number []:
	Work Phone []:
	Home Phone []:
	Other []:
Is the information correct? [Y/n]
info: Adding new user `cowrie' to supplemental / extra groups `users' ...
info: Adding user `cowrie' to group `users' ...
ubuntu@my-ip-address:~$ sudo su - cowrie
cowrie@my-ip-address:~$
```

Then I ran the below command to clone the Cowrie source code, and moved to the Cowrie directory.

```
cowrie@my-ip-address:~$ git clone http://github.com/cowrie/cowrie
Cloning into 'cowrie'...
warning: redirecting to https://github.com/cowrie/cowrie/
remote: Enumerating objects: 18878, done.
remote: Counting objects: 100% (71/71), done.
remote: Compressing objects: 100% (54/54), done.
remote: Total 18878 (delta 60), reused 16 (delta 16), pack-reused 18807 (from 2)
Receiving objects: 100% (18878/18878), 10.36 MiB | 17.45 MiB/s, done.
Resolving deltas: 100% (13294/13294), done.
cowrie@my-ip-address:~$ ls -l
total 4
drwxrwxr-x 11 cowrie cowrie 4096 Apr  9 18:44 cowrie
cowrie@my-ip-address:~$ cd cowrie
cowrie@my-ip-address:~/cowrie$
```

Now I needed to setup a virtual environment, which is an isolated Python environment that prevents package conflicts and also keeps Cowrie’s dependencies separate from the rest of the system.

![image](https://github.com/user-attachments/assets/8fa34e53-9e82-4e45-9aba-b03ca3a22545)

```
cowrie@my-ip-address:~/cowrie$ python3 -m venv cowrie-env
cowrie@my-ip-address:~/cowrie$ source cowrie-env/bin/activate
(cowrie-env) cowrie@my-ip-address:~/cowrie$ python3 -m pip install --upgrade pip
(cowrie-env) cowrie@my-ip-address:~/cowrie$ python3 -m pip install --upgrade -r requirements.txt
```

The Cowrie configuration file is stored in `cowrie.cfg.dist` and `cowrie.cfg` (Located in `cowrie/etc`).

```
(cowrie-env) cowrie@my-ip-address:~/cowrie/etc$ ls -l
total 44
-rw-rw-r-- 1 cowrie cowrie 37839 Apr  9 18:44 cowrie.cfg.dist
```

`cowrie.cfg` is our custom config file. The guide states: Both files are read on startup, where entries from `cowrie.cfg` take precedence. The `.dist` file can be overwritten by upgrades, `cowrie.cfg `will not be touched. To run with a standard configuration, there is no need to change anything. 

For now, I copied the `.dist` file to `cowrie.cfg`, which gives us a starting point for customisation later on if we would like to.

```
(cowrie-env) cowrie@my-ip-address:~/cowrie/etc$ cp cowrie.cfg.dist cowrie.cfg
(cowrie-env) cowrie@my-ip-address:~/cowrie/etc$ ls -l
total 84
-rw-rw-r-- 1 cowrie cowrie 37839 Apr  9 19:03 cowrie.cfg
-rw-rw-r-- 1 cowrie cowrie 37839 Apr  9 18:44 cowrie.cfg.dist
```

With that last step finished, I can now start Cowrie (As a non-root user `cowrie`).

```
cowrie@my-ip-address:~/cowrie$ bin/cowrie start
```

In the below code, I confirmed that Cowrie is listening on port `2222`. I then went back to AWS and finished the Security Group rule to allow attackers access to our Honeypot. Port 22 is also open, however our Security Group rule allows only SSH access from my IP only.

```
sudo apt install net-tools

ubuntu@my-ip-address:~$ sudo netstat -tulnp | grep LISTEN
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      1276/python3
tcp6       0      0 :::22                   :::*                    LISTEN      1/init
```

## 3 – Log Verification

Cowrie logs are stored under `/cowrie/var/log/cowrie/cowrie.log`. To verify this is working as expected, I attempted to SSH into our Honeypot on port 2222 from another virtual machine. This was correctly logged, shown below:

```
cowrie@my-ip-address:~/cowrie/var/log/cowrie$ tail -f cowrie.log

2025-04-10T09:12:30.264217Z [-] Removing stale pidfile /home/cowrie/cowrie/var/run/cowrie.pid
2025-04-10T09:12:30.266800Z [-] Python Version 3.12.3 (main, Feb  4 2025, 14:48:35) [GCC 13.3.0]
2025-04-10T09:12:30.266838Z [-] Twisted Version 24.11.0
2025-04-10T09:12:30.266851Z [-] Cowrie Version 2.6.1
2025-04-10T09:12:30.270937Z [-] Loaded output engine: jsonlog
2025-04-10T09:12:30.272586Z [twisted.scripts._twistd_unix.UnixAppLogger#info] twistd 24.11.0 (/home/cowrie/cowrie/cowrie-env/bin/python3 3.12.3) starting up.
2025-04-10T09:12:30.272702Z [twisted.scripts._twistd_unix.UnixAppLogger#info] reactor class: twisted.internet.epollreactor.EPollReactor.
2025-04-10T09:12:30.282281Z [-] CowrieSSHFactory starting on 2222
2025-04-10T09:12:30.283256Z [cowrie.ssh.factory.CowrieSSHFactory#info] Starting factory <cowrie.ssh.factory.CowrieSSHFactory object at 0x7c438e05e3f0>
2025-04-10T09:12:30.356696Z [-] Ready to accept SSH connections
2025-04-10T09:18:08.515886Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: my-ip-address:49838 (my-ip-address:2222) [session: 3fcd5e77623d]
2025-04-10T09:18:08.528496Z [HoneyPotSSHTransport,my-ip-address] Remote SSH version: SSH-2.0-PuTTY_Release_0.83
2025-04-10T09:18:08.541675Z [HoneyPotSSHTransport,my-ip-address] SSH client hassh fingerprint: 4a3e3c55af41b23589ff4c9d6aee4404
2025-04-10T09:18:08.543818Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256' key alg=b'ssh-ed25519'
2025-04-10T09:18:08.544875Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes256-ctr' b'hmac-sha2-256' b'none'
2025-04-10T09:18:08.545383Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes256-ctr' b'hmac-sha2-256' b'none'
2025-04-10T09:18:15.457957Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
2025-04-10T09:18:15.458409Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2025-04-10T09:18:21.867916Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'ubuntu' trying auth b'none'
2025-04-10T09:18:23.884222Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'ubuntu' trying auth b'password'
2025-04-10T09:18:23.884679Z [HoneyPotSSHTransport,my-ip-address] Could not read etc/userdb.txt, default database activated
2025-04-10T09:18:23.885105Z [HoneyPotSSHTransport,my-ip-address] login attempt [b'ubuntu'/b''] failed
2025-04-10T09:18:24.886877Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'ubuntu' failed auth b'password'
2025-04-10T09:18:24.887112Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] unauthorized login: ()
2025-04-10T09:18:42.212612Z [HoneyPotSSHTransport,my-ip-address] Got remote error, code 13 reason: b'Unable to authenticate'
2025-04-10T09:18:42.213129Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
2025-04-10T09:18:42.213323Z [HoneyPotSSHTransport,my-ip-address] Connection lost after 33.7 seconds

This log extract showcases that someone (me) attempted to access the Honeypot via SSH on port 2222, with user `ubuntu`. Cowrie can allow us to simulate a successful login however, which we need to define seperately. Later I will showcase this so we can begin to capture more attacker behaviour.
```

## 4 - First Real Attacker Session Logged

On 10/04/2025, the honeypot logged an unsolicited connection from IP `60.21.134.178`. The attacker connected twice using the `libssh` SSH client and attempted public key authentication with a randomised username (`wqmarlduiqkmgs`). The session caused Cowrie to raise an `Unhandled Error` due to a malformed authentication packet, which is common with automated or poorly written scanning tools.

Key behavioral characteristics:
- No password-based brute force attempts
- No shell interaction
- Session duration: 1.6 seconds
- Behavior suggests a **low-complexity scanner**, not a human attacker

The full Cowrie log for this interaction is shown below:
```
2025-04-10T10:17:28.580651Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 60.21.134.178:9893 (10.0.0.11:2222) [session: 4eedb436f764]
2025-04-10T10:17:40.912746Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
2025-04-10T10:17:40.912963Z [HoneyPotSSHTransport,1,60.21.134.178] Connection lost after 12.3 seconds
2025-04-10T10:17:41.161561Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 60.21.134.178:33446 (10.0.0.11:2222) [session: 3cd4817c270f]
2025-04-10T10:17:41.205739Z [HoneyPotSSHTransport,2,60.21.134.178] Remote SSH version: SSH-2.0-libssh_0.7.4
2025-04-10T10:17:41.675742Z [HoneyPotSSHTransport,2,60.21.134.178] SSH client hassh fingerprint: e37f354a101aff5871ba233aa82b84ec
2025-04-10T10:17:41.676561Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256@libssh.org' key alg=b'ssh-ed25519'
2025-04-10T10:17:41.676699Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes256-ctr' b'hmac-sha2-256' b'none'
2025-04-10T10:17:41.678893Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes256-ctr' b'hmac-sha2-256' b'none'
2025-04-10T10:17:42.144789Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
2025-04-10T10:17:42.392631Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2025-04-10T10:17:42.737884Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'wqmarlduiqkmgs' trying auth b'publickey'
2025-04-10T10:17:42.738161Z [HoneyPotSSHTransport,2,60.21.134.178] Unhandled Error
	Traceback (most recent call last):
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/internet/posixbase.py", line 491, in _doReadOrWrite
	    why = selectable.doRead()
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/internet/tcp.py", line 250, in doRead
	    return self._dataReceived(data)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/internet/tcp.py", line 255, in _dataReceived
	    rval = self.protocol.dataReceived(data)
	  File "/home/cowrie/cowrie/src/cowrie/ssh/transport.py", line 145, in dataReceived
	    self.dispatchMessage(messageNum, packet[1:])
	  File "/home/cowrie/cowrie/src/cowrie/ssh/transport.py", line 149, in dispatchMessage
	    transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/transport.py", line 792, in dispatchMessage
	    self.service.packetReceived(messageNum, payload)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/service.py", line 50, in packetReceived
	    return f(packet)
	  File "/home/cowrie/cowrie/src/cowrie/ssh/userauth.py", line 73, in ssh_USERAUTH_REQUEST
	    return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py", line 173, in ssh_USERAUTH_REQUEST
	    d = self.tryAuth(method, user, rest)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py", line 148, in tryAuth
	    ret = f(data)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/userauth.py", line 263, in auth_publickey
	    algName, blob, rest = getNS(packet[1:], 2)
	  File "/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/common.py", line 38, in getNS
	    (l,) = struct.unpack("!L", s[c : c + 4])
	struct.error: unpack requires a buffer of 4 bytes

2025-04-10T10:17:42.748252Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
2025-04-10T10:17:42.748456Z [HoneyPotSSHTransport,2,60.21.134.178] Connection lost after 1.6 seconds
```

## Brief analysis of identified IP address

For additional enrichment, I investigated the IP address `60.21.134.178` captured during the first unsolicited connection to the honeypot.

![image](https://github.com/user-attachments/assets/094d378a-ed44-4573-917b-c62fb1c51a07)

![image](https://github.com/user-attachments/assets/6d4ee674-847f-4e2b-aef2-fb940c2fe975)

Honeypots are intentionally deployed in passive and non-advertised environments. Meaning they are not exposed to regular internet users or legitimate traffic. This means that any unsolicited interaction with our honeypot is almost certainly malicious.

## 5 - Enable Simulated Logins with Fake Users in Cowrie
Cowries default credentials file can be found here: 

```
cowrie@my-ip-address:~/cowrie/etc$ more userdb.example
# Example userdb.txt
# This file may be copied to etc/userdb.txt.
# If etc/userdb.txt is not present, built-in defaults will be used.
#
# ':' separated fields, file is processed line for line
# processing will stop on first match
#
# Field #1 contains the username
# Field #2 is currently unused
# Field #3 contains the password
# '*' for any username or password
# '!' at the start of a password will not grant this password access
# '/' can be used to write a regular expression
#
root:x:!root
root:x:!123456
root:x:!/honeypot/i
root:x:*
tomcat:x:*
oracle:x:*
*:x:somepassword
*:x:*
```

This file outlines how Cowrie processes fake user logins, including support for wildcards, password restrictions, and regular expressions. If no userdb.txt file exists, Cowrie falls back to built-in defaults. To increase realism and allow simulated logins—which is essential for observing attacker behaviour, I copied the example file and created my own set of fake users:

```
cowrie@my-ip-address:~/cowrie/etc$ cp userdb.example userdb.txt
cowrie@my-ip-address:~/cowrie/etc$ ls -l
total 88
-rw-rw-r-- 1 cowrie cowrie 37839 Apr  9 19:03 cowrie.cfg
-rw-rw-r-- 1 cowrie cowrie 37839 Apr  9 18:44 cowrie.cfg.dist
-rw-rw-r-- 1 cowrie cowrie   589 Apr  9 18:44 userdb.example
-rw-rw-r-- 1 cowrie cowrie   589 Apr 10 10:35 userdb.txt
cowrie@my-ip-address:~/cowrie/etc$ vi userdb.txt
# Example userdb.txt
# This file may be copied to etc/userdb.txt.
# If etc/userdb.txt is not present, built-in defaults will be used.
#
# ':' separated fields, file is processed line for line
# processing will stop on first match
#
# Field #1 contains the username
# Field #2 is currently unused
# Field #3 contains the password
# '*' for any username or password
# '!' at the start of a password will not grant this password access
# '/' can be used to write a regular expression
#
root:x:*
admin:x:*
cowrie:x:*
guest:x:*
```

These entries allow attackers to "successfully" authenticate with any password for the listed users. This gives us access to a fake shell environment where every command is then logged, enabling deeper behavioral insights. With these changes made, I restarted Cowrie to apply the new configuration.

```
cowrie@my-ip-address:~/cowrie$ bin/cowrie restart
Stopping cowrie...
Using default Python virtual environment "/home/cowrie/cowrie/cowrie-env"
Starting cowrie: [twistd  --umask=0022 --pidfile=var/run/cowrie.pid --logger cowrie.python.logfile.logger cowrie ]...
/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/transport.py:105: CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  b"3des-cbc": (algorithms.TripleDES, 24, modes.CBC),
/home/cowrie/cowrie/cowrie-env/lib/python3.12/site-packages/twisted/conch/ssh/transport.py:112: CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  b"3des-ctr": (algorithms.TripleDES, 24, modes.CTR),
```

## 6 - Project wrap-up and Future Integrations

With Cowrie now live on AWS and successfully logging unsolicited traffic, this project has achieved its core goals:

- Hands-on experience logging, interpretation, and attacker fingerprinting
- Secure cloud-based deployment of a low-interaction honeypot
- Exposure to real-world SSH scanning and brute force activity
- Successful simulation of fake login sessions for behavioral data capture

### Key findings

- The honeypot received real attack traffic within hours of going live.
- A connection attempt caused an `Unhandled Error`, showing Cowrie’s ability to detect malformed SSH payloads.
- Simulated login environments are now active, enabling us to track attacker commands and behaviors post-authentication.
- There are many options available now for expansion of our setup. Cowrie offers multiple options for customisation honeypots, with banners, fake file systems, and more.

### Future Expansion Possibilities

As a next phase, I plan to explore the following extensions to this environment:
- **Port Switching Strategy**: Move Cowrie to port `22` and shift admin SSH to `22222` to increase attacker interactions
- **CloudWatch Metrics & Alerts**: Configure connection alerts with refined rules
- **VPC Flow Logs**: Enable network logging IP correlation and pattern detection
- **Splunk Cloud Integration**: Configure Cowrie to push logs to Splunk for advanced querying
