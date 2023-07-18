# SnafflePy
Snaffler reimplementation in Python - https://github.com/SnaffCon/Snaffler 

Tested with Python 3.10.6

## Installation (Linux) :

1. Clone this repository

2. Optional but encouraged, create a virtual enviroment for this project

3. `pip install -r requirements.txt` 

## Usage

`usage: snaffler.py [-h] [-u username] [-p password] [-d domain] [-v] [-i] [-n] targets [targets ...] `

## Options
1. targets               IPs, hostnames, CIDR ranges, or files contains targets to snaffle

2. -h, --help            show help message and exit
3. -u username, --username username	 username for LDAP login and SMB
4. -p password, --password password      password for LDAP login and SMB
5. -d domain, --domain domain            Domain to authenticate to
6. -H hash, --hash hash  		 NT hash for authentication
7. -v, --verbose        		 Show debugging information 
8. -i, --no-discovery    		 Disables computer and share discovery (more stealthy, maybe)
9. -n, --disable-computer-discovery      Disable computer discovery, requires a single host or list of hosts to do discovery on
