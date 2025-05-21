# Cowrie-Based Honeypot Deployment on AWS 2.0

## 📚 Overview
This follow up project is an adaptation and refinement of my original Cowrie honeypot deployment, found here: [link](https://github.com/wilbcn/BlueTeam/edit/main/Honeypots/Cowrie-Virtual-Honeypot.md). This project serves as both a trial phase towards my research project proposal on honeypot realism and fingerprinting (University project), as well as a continuation of hands-on experience that covers multiple security domains like OS hardening and network security.

---

## 🎯 Project Goals

- Deploy a secure SSH honeypot in AWS (secure admin access)
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Allow brute force attempts after a defined number - Edit the config file
- Lay the foundation for the next trial phase, of Splunk integration for log aggregation and analysis
- Begin the trial phase of my ssh honeypot research in cowrie

---

## Acknowledgements
- [Cowrie Documentation](https://docs.cowrie.org/en/latest/README.html)

## Tools & Resources
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [WHOIS Lookup](https://whois.domaintools.com/)
- [SSH Client](https://mobaxterm.mobatek.net/)
- Amazon EC2 Instances
- Cowrie SSH Honeypot

---

## 📦 1. – Cloud Setup
In this follow up project, I create a brand new ec2 instance with similar configurations as the original deployment. 

- Public IP redacted for security reasons

### 1.1 - Honeypot Overview
Once inside my AWS account, I navigated to EC2 and selected launch instance. I named it `Cowrie-Trial-01`, and selected `Ubuntu Server 24.04 LTS`.

With the AMI successfully selected, I then chose our instance type `t3.medium`. I aim to deploy two contrasting honeypots for a comparative analysis, and therefore predict that this instance type will be a cost effective yet appropriate solution for my project.

I then created a new key pair for secure admin access. We use SSH keys to access the system securely, while cowrie as a honeypot simulates password logins for the attacker. Attackers interact with Cowries fake shell, not the real system.

![image](https://github.com/user-attachments/assets/f090f1a7-882d-448d-a501-4eab90ada4ac)

I then created a brand new VPC and subnet in `eu-north-1a` (not shown), and enabled auto-assign public IP.

![image](https://github.com/user-attachments/assets/62569a11-dd8c-4176-9e27-59cc9f0e75d2)

Next, I needed a new Security Group to allow remote Admin access. For this deployment, I allowed inbound SSH connections from my IP only on port 22 and port 22222. However later this will be changed so that admin logons are only accessible on port 22222, and public access over port 22.

For storage, I chose `30 GB of EBS General Purpose (SSD)`

#### Honeypot summary
| Attribute              | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| Instance Name          | `Cowrie-Trial-01`                                                    |
| Instance Type          | `t3.medium` (2 vCPUs, 4 GB RAM)                                      |
| AMI Used               | Ubuntu 24.04 LTS 							|
| Storage                | 30 GB EBS (General Purpose SSD)                                      |
| Admin SSH Access       | Port `22` and `22222`, restricted to admin IP only                   |
| Attacker SSH Port      | Not yet configured                                                   |
| Key Pair Auth          | Key-based authentication for admin access                            |
| Region / Subnet        | `eu-north-1a`, custom VPC with auto-assigned public IP               |
| Purpose                | Trial phase setup to validate Cowrie configuration and EC2 settings  |

### 2. - Honeypot Installation
To connect to the brand new EC2 instance, I used `MobaXTerm`, a free SSH client. The first step taken was to restrict the .pem permissions via ssh terminal.

```
chmod 400 cowrie-trial-01.pem
ls -l
total 8
-r--------@ 1 user  staff  1674 20 May 17:09 cowrie-trial-01.pem
```

On the SSH client, I then successfully logged into the ec2 instance for the first time. To begin with, I ran some commands to refresh the system’s package list and apply the latest updates. The following segment mirrors the steps taken in the original deployment linked at the top of this project.

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
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      14348/python3
tcp6       0      0 :::22                   :::*                    LISTEN      1/systemd
```

```
cowrie@my-ip-address:~/cowrie/var/log/cowrie$ tail -f cowrie.log
2025-05-19T13:57:33.133409Z [-] Cowrie Version 2.6.1
2025-05-19T13:57:33.137922Z [-] Loaded output engine: jsonlog
2025-05-19T13:57:33.139717Z [twisted.scripts._twistd_unix.UnixAppLogger#info] twistd 24.11.0 (/home/cowrie/cowrie/cowrie-env/bin/python3 3.12.3) starting up.
2025-05-19T13:57:33.139875Z [twisted.scripts._twistd_unix.UnixAppLogger#info] reactor class: twisted.internet.epollreactor.EPollReactor.
2025-05-19T13:57:33.148834Z [-] CowrieSSHFactory starting on 2222
2025-05-19T13:57:33.149651Z [cowrie.ssh.factory.CowrieSSHFactory#info] Starting factory <cowrie.ssh.factory.CowrieSSHFactory object at 0x7c7304d83c50>
2025-05-19T13:57:33.150183Z [-] Generating new RSA keypair...
2025-05-19T13:57:33.281551Z [-] Generating new ECDSA keypair...
2025-05-19T13:57:33.283926Z [-] Generating new ed25519 keypair...
2025-05-19T13:57:33.295947Z [-] Ready to accept SSH connections
```

Cowrie is now configured and running on port 2222 (default) and ready to accept SSH connections. 

### 3. - Changing Honeypot access to port 22
By default Cowrie will run on port 2222/2223. To run the honeypot on port 22, I need to move the real SSH service to a new port. To avoid lock-outs during this trial phase, I will leave Admin access open on port 22 until non-standard port 22222 is correctly working for Admin access. Seting up the administrative port:

```
sudo vi /etc/ssh/sshd_config
```

<img width="855" alt="image" src="https://github.com/user-attachments/assets/5abdb542-8e24-4650-9d20-e445e6515e3e" />

I then elevated sudo privileges to user `cowrie` temporarily. This is so cowrie user can successfully configure authbind, which allows it to bind to restricted ports like port 22 without needing full root access. Normally, only the root user can listen on ports below 1024 — authbind is a secure workaround that lets a non-root service (like Cowrie) safely take over port 22.

<img width="707" alt="image" src="https://github.com/user-attachments/assets/faf6722e-dad4-4618-80ec-cf31020cea98" />

```
visudo /etc/sudoers
Add under root:
cowrie ALL=(ALL) NOPASSWD: ALL
Change %sudo:
%sudo ALL=(ALL) NOPASSWD: ALL
```

As cowrie user:

```
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 770 /etc/authbind/byport/22
```

Exit cowrie back to root user and:

```
Exit back to root
visudo /etc/sudoers
Revert settings to
cowrie ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
```

I then added the following line export AUTHBIND_ENABLED=yes to ~/.bash_profile.
This ensures that every time the cowrie user logs in or starts a session, the system knows to enable authbind for Cowrie automatically.
Without this, Cowrie won't know it's allowed to bind to port 22, and will silently fail or fall back to its default port (like 2222).

Earlier we created a copy of `cowrie.cfg.dist` as `cowrie.cfg`. This copy file is what we should use to make changes from the baseline cowrie configuration. I then edited this copy file, changing the endpoint to listen on port 22 rather than 2222 for incoming SSH connections. 

<img width="937" alt="image" src="https://github.com/user-attachments/assets/69100738-98a4-455f-a425-3dd0d65aada7" />

Then I restarted the SSH daemon.

```
sudo systemctl restart ssh.service
```

```
sudo systemctl status ssh.service
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled; preset: enabled)
    Drop-In: /usr/lib/systemd/system/ssh.service.d
             └─ec2-instance-connect.conf
     Active: active (running) since Tue 2025-05-20 18:12:32 UTC; 6s ago
TriggeredBy: ● ssh.socket
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 1186 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 1188 (sshd)
      Tasks: 1 (limit: 4584)
     Memory: 1.2M (peak: 1.4M)
        CPU: 19ms
     CGroup: /system.slice/ssh.service
             └─1188 "sshd: /usr/sbin/sshd -D -o AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f -o AuthorizedKeysCommandUser ec2-instance-connect [listener] 0 of 10-10>

May 20 18:12:32 my-ip systemd[1]: Starting ssh.service - OpenBSD Secure Shell server...
May 20 18:12:32 my-ip sshd[1188]: Server listening on :: port 22222. #  admin access
May 20 18:12:32 my-ip sshd[1188]: Server listening on :: port 22. # later to be publicly accessible
May 20 18:12:32 my-ip systemd[1]: Started ssh.service - OpenBSD Secure Shell server.
```

As you can see, we are now listening on both port `22222` and port `22`, for admin access. After opening a new SSH client session and testing ssh login (success), I can safely remove the security group rule in AWS for Admin SSH access on this port. Furthemore, I can remove the line from `/etc/ssh/sshd_config`. 

Bouncing sshd after changes:

```
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl restart ssh.service
```

Listening on `22222` only:

```
sudo systemctl status ssh.socket
● ssh.socket - OpenBSD Secure Shell server socket
     Loaded: loaded (/usr/lib/systemd/system/ssh.socket; enabled; preset: enabled)
    Drop-In: /run/systemd/generator/ssh.socket.d
             └─addresses.conf
     Active: active (running) since Tue 2025-05-20 17:58:13 UTC; 32min ago
   Triggers: ● ssh.service
     Listen: [::]:22222 (Stream)
      Tasks: 0 (limit: 4584)
     Memory: 8.0K (peak: 264.0K)
        CPU: 1ms
     CGroup: /system.slice/ssh.socket

May 20 17:58:13 my-ip systemd[1]: Listening on ssh.socket - OpenBSD Secure Shell server socket.

ubuntu@my-ip:~$ sudo ss -tulnp | grep 22
tcp   LISTEN 0      4096               *:22222            *:*    users:(("sshd",pid=1556,fd=3),("systemd",pid=1,fd=220))
```

Testing login on new port:

```
ssh -i cowrie-trial-01.pem -p 22222 ubuntu@ec2-ip
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-1029-aws x86_64)
```

I then stop/started cowrie, starting the process with `authbind` for port 22.

```
cd ~/cowrie
bin/cowrie stop
authbind --deep bin/cowrie start
```

Back in AWS, I updated the rule on port 22 to be publicly accessible via SSH. Afterwards I tested root access into the cowrie system on port 22 (ips redacted). Success!

```
ssh root@my-ip
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@svr04:~# ls -l
root@svr04:~# pwd
/root
root@svr04:~#
```

This was successfully logged in cowries log file:

```
root@my-ip:/home/cowrie/cowrie/etc# sudo su - cowrie
cowrie@my-ip:~$ tail -f ~/cowrie/var/log/cowrie/cowrie.log
2025-05-21T10:52:29.484214Z [HoneyPotSSHTransport,0,my-ip] Command found: exit
2025-05-21T10:52:29.484439Z [twisted.conch.ssh.session#info] exitCode: 0
2025-05-21T10:52:29.484597Z [cowrie.ssh.connection.CowrieSSHConnection#debug] sending request b'exit-status'
2025-05-21T10:52:29.484886Z [HoneyPotSSHTransport,0,my-ip] Closing TTY Log: var/lib/cowrie/tty/6b601548f8d080e2f46f599077711d48b9f35c3b22f2ebcb48d848dfec533e1c after 20.2 seconds
2025-05-21T10:52:29.485310Z [cowrie.ssh.connection.CowrieSSHConnection#info] sending close 0
2025-05-21T10:52:29.525576Z [cowrie.ssh.session.HoneyPotSSHSession#info] remote close
2025-05-21T10:52:29.525836Z [HoneyPotSSHTransport,0,my-ip] Got remote error, code 11 reason: b'disconnected by user'
2025-05-21T10:52:29.526113Z [HoneyPotSSHTransport,0,my-ip] avatar root logging out
2025-05-21T10:52:29.526217Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
2025-05-21T10:52:29.526279Z [HoneyPotSSHTransport,0,my-ip] Connection lost after 27.3 seconds
```

### 4. - Modifying cowrie login credentials
Cowrie uses `etc/userdb.txt` to define what login combinations are accepted or rejected. By copying `userdb.example` to `userdb.txt` and changing this file, I can:

- Simulate real-looking credentials
- Make the honeypot appear more realistic
- Observe attacker behavior when they succeed in logging in

By default, we have the following configuration:

![image](https://github.com/user-attachments/assets/847250f6-5045-4cf7-aef6-9db91a7090b2)

This screen shot outlines the expected syntax which will come in handy as my research project progresses:

```
# Field #1 contains the username
# Field #2 is currently unused
# Field #3 contains the password
# '*' for any username or password
# '!' at the start of a password will not grant this password access
# '/' can be used to write a regular expression
```

Cowrie stops/denys at the first match, so any modifications to this file should start with the intended, specific rejections. 

In general, modifying this file will require future research in order to find an optimal solution for increasing honeypot realism. However for this trial phase, I have implemented the following configuration. It will be interesting to see how long it takes for a successful login. (currently inbound rules on port 22 are blocked until configurations have been set). I used a combination of the top most used usernames and passwords from this resource [Link](https://www.f5.com/labs/articles/threat-intelligence/spaceballs-security--the-top-attacked-usernames-and-passwords)

New `userdb.txt` configuration:

```
root:x:!root
root:x:!123456
root:x:!/honeypot/i
root:x:11111
root:x:admin
admin:x:admin
admin:x:admin123
admin:x:password
oracle:x:support
ubuntu:x:ubuntu
user:x:password
*:x:!*
```

```
bin/cowrie stop
authbind --deep bin/cowrie start
```

### 5. - Investigating inbound traffic
In this final step, I re-opened port 22 publicly, and monitored for inbound ssh connections from 15:45 BST. 12 or so minutes later, I had our first hit at: 14:57.

```
2025-05-21T14:57:47.537178Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 211.101.246.5:56070 (10.0.0.5:22) [session: 6e42da3ce654]
2025-05-21T14:57:47.537755Z [HoneyPotSSHTransport,1,211.101.246.5] Remote SSH version: SSH-2.0-Go
2025-05-21T14:57:49.127069Z [HoneyPotSSHTransport,1,211.101.246.5] SSH client hassh fingerprint: 084386fa7ae5039bcf6f07298a05a227
2025-05-21T14:57:49.128079Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256@libssh.org' key alg=b'ecdsa-sha2-nistp256'
2025-05-21T14:57:49.128170Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-05-21T14:57:49.128234Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-05-21T14:57:50.381508Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
2025-05-21T14:57:50.381928Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2025-05-21T14:57:51.202638Z [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'' trying auth b'none'
2025-05-21T14:57:56.243079Z [cowrie.ssh.transport.HoneyPotSSHTransport#info] connection lost
2025-05-21T14:57:56.243265Z [HoneyPotSSHTransport,1,211.101.246.5] Connection lost after 8.7 seconds
```

#### 📊 Breakdown of Cowrie Log Snippet (Attacker Activity)

| **Timestamp**            | **Event**                                                             | **Explanation**                                                                 |
|--------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `2025-05-21T14:57:47.537` | New connection: `211.101.246.5:56070 → 10.0.0.5:22`                    | External attacker connected to honeypot port 22                                 |
| `2025-05-21T14:57:47.537` | Remote SSH version: `SSH-2.0-Go`                                       | Client is using the Go SSH library — likely a scanner or automation tool       |
| `2025-05-21T14:57:49.127` | SSH client hassh fingerprint: `084386fa7ae5039bcf6f07298a05a227`       | Client key fingerprint — can help identify botnet reuse                        |
| `2025-05-21T14:57:49.128` | KEX and crypto negotiated                                              | Secure session negotiated using `curve25519`, `aes128-ctr`, etc.               |
| `2025-05-21T14:57:50.381` | NEW KEYS                                                               | Key exchange completed — encrypted channel is ready                            |
| `2025-05-21T14:57:50.381` | Starting service: `ssh-userauth`                                       | SSH client is beginning authentication process                                 |
| `2025-05-21T14:57:51.202` | Trying auth: `none`                                                    | Client attempted to login with no username/password — a common recon technique |
| `2025-05-21T14:57:56.243` | Connection lost after 8.7 seconds                                      | Client disconnected — likely a passive scan, no brute-force this time          |

#### Initial Summary
- This was an automated scan using a Go-based SSH client
- The client completed the full SSH handshake but skipped login (auth `none`)
- It is likely part of a broad passive scan rather than a targeted attack
- Valuable metadata was captured: IP address, SSH client version, key fingerprint, crypto used.

### 6. - Analysing logs
Approximately 5 minutes later, this ip repeatedly connected via numerous different ports.

```
2025-05-21T15:02:35.804354Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 211.101.246.5:44818 (10.0.0.5:22) [session: 76b8d5c8894f]
2025-05-21T15:02:37.366941Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 211.101.246.5:44832 (10.0.0.5:22) [session: 9dfbe1823a95]
2025-05-21T15:02:39.792149Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 211.101.246.5:44846 (10.0.0.5:22) [session: c5c1808e131f]
```

This address also began attempting to brute force the SSH server. At this point, I switched off the server, and began collecting the attacker metrics we have so far from the cowrie log file.

#### Full Summary

| **Metric** | **Count** |
|------------|-----------|
| Unique IPs  | 1 (211.101.246.5) |
| Successful Logins | 0 |
| Failed Logins | 6 |
| Auth attempts logged | 26 |

| **Usernames** | **Passwords** |
|---------------|---------------|
| root | password (!Q2w3e4r)|
| pi | password (raspberry)| 
| nginx | password (nginx)|
| apache | password (apache123) |
| hadoop | password (hadoop) |
| test | password (1234qwer) |
| hive | none |
| mongo | none |
| git | none |
| wang | none |
| gpadmin | none |
| flash | none |
| lighthouse | none |
| sonar | none |

Additionally, I ran this IP address on VirusTotal, which results support that this address is malicious, and is known for port scanning and SSH brute force attempts.

<img width="1439" alt="image" src="https://github.com/user-attachments/assets/cd256860-973e-4bf5-aa37-faa9ebeb1106" />

<img width="575" alt="image" src="https://github.com/user-attachments/assets/1ada09cd-64c6-4b51-a757-e7314b0851f8" />

### 7. - Key takeaways and future expansions
As a follow-up to my original Cowrie deployment, this project involved configuring and launching a new EC2 instance with a more realistic honeypot setup. Key improvements included:

- Exposing the honeypot on the standard SSH/SFTP port (22) instead of the default Cowrie port (2222)
- Securing admin access via a non-standard port (22222)
- Customising the credential configuration to allow or reject specific username/password combinations

This deployment served as a trial phase for my broader research on attacker behavior post-compromise. While full interaction analysis is reserved for the next stage, this phase already provided valuable insight into brute-force patterns and varied username and password attempts. 

In future deployments, I aim to implement Splunk Universal Forwarders for log aggregation and analysis, as well as exploring in more detail how I can further improve honeypot realism.

