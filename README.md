# SnafflePy
Snaffler reimplementation in Python - https://github.com/SnaffCon/Snaffler 

Tested with Python 3.10.6

## Installation (Linux) :

1. Clone this repository

2. Optional but encouraged, create a virtual enviroment for this project

3. `pip install -r requirements.txt` 

## Usage

`usage: snaffler.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-v] [--go-loud] [-i] [-n] targets [targets ...]`

## Options
~~~
options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        domain username
  -p PASSWORD, --password PASSWORD
                        password for domain user
  -d DOMAIN, --domain DOMAIN
                        FQDN domain to authenticate to, if this option is not provided, SnafflePy will attempt to automatically discover the domain for you
  -H HASH, --hash HASH  NT hash for authentication
  -v, --verbose         Show more info
  --go-loud             Don't try to find anything interesting, literally just go through every computer and every share and print out as many files as possible. Use at your own
                        risk
  -i, --no-share-discovery
                        Disables share discovery (more stealthy)
  -n, --disable-computer-discovery
                        Disable computer discovery, requires a list of hosts to do discovery on
~~~