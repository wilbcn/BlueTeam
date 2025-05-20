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

I then elevated sudo privileges to user `cowrie` temporarily. This is so cowrie user can successfully configure authbind, which will allow

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

I then added the following line `export AUTHBIND_ENABLED=yes` to `bash_profile`. This

Earlier we created a copy of `cowrie.cfg.dist` as `cowrie.cfg`. Next I edited this copy file, changing the endpoint SSH options to: `listen_endpoints = tcp:22:interface=0.0.0.0`.

```
diff cowrie.cfg cowrie.cfg.dist

211c211
< listen_endpoints = tcp:22:interface=0.0.0.0 # new file
---
> listen_endpoints = tcp:6415:interface=127.0.0.1
599a600,601
> listen_endpoints = tcp:2222:interface=0.0.0.0
>
677a680,681
>
> listen_endpoints = tcp:2223:interface=0.0.0.0
```

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
May 20 18:12:32 my-ip sshd[1188]: Server listening on :: port 22222.
May 20 18:12:32 my-ip sshd[1188]: Server listening on :: port 22.
May 20 18:12:32 my-ip systemd[1]: Started ssh.service - OpenBSD Secure Shell server.
```

As you can see, we are now listening on both port `22222` and port `22`, for admin access. After opening a new SSH client session and testing ssh login (success), I can safely remove the security group rule in AWS for Admin SSH access on this port. Furthemore, I can remove the line from `/etc/ssh/sshd_config`. 

```
ssh -i cowrie-trial-01.pem -p 22222 ubuntu@ec2-ip
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-1029-aws x86_64)
```




