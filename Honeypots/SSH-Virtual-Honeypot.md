# Cowrie-Based Honeypot Deployment on AWS

## 📚 Overview

<project intro>

---

## 🎯 Project Goals

- Deploy a low-interaction honeypot in the cloud securely
- Simulate a vulnerable SSH service to attract real-world attacks
- Log attacker behavior and extract useful insights
- Gain practical experience with legal and ethical security practices
- Establish groundwork for future behavioral honeypot research

---

## Acknowledgements
- [Cowrie Documentation](https://docs.cowrie.org/en/latest/README.html)





---

## 📦 1 – Cloud Setup
In this phase, I outline the steps taken to configure and launch a new EC2 instance that will serve as our SSH honeypot. This virtual machine must be carefully provisioned—with appropriate instance specifications, network isolation, and security controls—to ensure it can run the honeypot reliably and safely in a cloud environment. 

- Public IP redacted for security reasons

### 1.1 ☁Honeypot Overview
Firsly I logged into my AWS account, and navigated to `EC2`. From here, I selected `launch instance` to begin setting up our Virtual Machine. I have provided an overview of the EC2 configuration as well as any necessary explanations. 

- **Instance Name**: `Cowrie-Honeypot`
- **Region**: `eu-north-1a` (GDPR-compliant region)
- **Instance Type**: `t3.xlarge` (4 vCPU, 16GB RAM)
- **AMI**: `Ubuntu Server 24.04 LTS (HVM),EBS General Purpose (SSD) Volume Type`.
- **Storage**: `128GB`

### 1.2 Network settings
- **VPC**: A new VPC was created to ensure full isolation of the honeypot from any other cloud resources. An Internet Gateway was attached to allow inbound and outbound traffic. IGW was also added to VPC route table.
- **Subnet**: A new Subnet was created within eu-north-1a for logical separation.
- **Auto-assign public IP**: This is required so the honeypot can be accessed by external attackers. Without a public IP, no unsolicited traffic can reach the system.

### Security Group Rules

| Port | Purpose | Source | Description |
|------|---------|--------|-------------|
| 22 | SSH access | Your IP only | For administrative access to the server |
| 2222 | Cowrie honeypot port | 0.0.0.0/0 | Used to attract SSH scans/attacks (Rule to be activated after Cowrie is running) |

### SSH Key Pair
- Create a new key pair
- Run `chmod 600 example_key.pem`. This permission is required by SSH to prevent unauthorised access and is enforced by AWS security standards.
- Connect with:  
  `ssh -i "example_key.pem" ubuntu@<public-ip>`

---

## 2 – Honeypot Installation
Now that the EC2 instance was up and running, I connected for the first time from my local machine. To begin with, I ran some commands to refresh the system’s package list and apply the latest updates.

```
sudo apt update
```
```
sudo apt upgrade
```

Next, I installed system-wide support for Python virtual environments and other dependencies, as per the Cowrie guide.

```
sudo apt-get install git python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
```

To continue with the Cowrie setup, I created a new user in our Linux machine. Creating a dedicated non-root user helps limits the potential damage an attacker could do if they manage to escape or exploit the honeypot—following the principle of least privilege for better security and containment.

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

With that last step finished, I can now start Cowrie.





