# Snafflepy
Snaffler reimplementation in Python - https://github.com/SnaffCon/Snaffler 

Tested with Python 3.10.6

## Installation (Linux) :

1. Clone this repository

2. Optional but encouraged, create a virtual enviroment for this project

3. `pip install -r requirements.txt` 

## Usage

`usage: snaffler.py [-h] [-u username] [-p password] [-d domain] [-v] [-i] [-n] targets [targets ...] `

positional arguments:
  targets               IPs, hostnames, CIDR ranges, or files contains targets to snaffle

options:
  -h, --help            show this help message and exit
  -u username, --username username
                        domain username
  -p password, --password password
                        password for domain user
  -d domain, --domain domain
                        FQDN domain to authenticate to
  -H hash, --hash hash  NT hash for authentication
  -v, --verbose         Show more info
  -i, --no-discovery    Disables computer and share discovery (more stealthy)
  -n, --disable-computer-discovery
                        Disable computer discovery, requires a list of hosts to do discovery on
