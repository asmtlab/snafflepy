# SnafflePy
Snaffler reimplementation in Python - https://github.com/SnaffCon/Snaffler 

Thank you to MANSPIDER for the helpful code that I stole: https://github.com/blacklanternsecurity/MANSPIDER

Tested with Python 3.10.6

This tool works by first sending a LDAP query to the specified target to discover other domain joined machines, and then attempts to login (authenticated or not) through SMB and retrieve interesting files (currently work in progress). 

### Current Features: 
SnafflePy includes different options and methods of enumeration. It can discover AD joined computers automatically by performing specific LDAP queries to Active Directory and include them in its target list, or if you want to disable this, it can also manually take in a list of IPs, hostnames, or CIDR ranges as its targets. It can also return every share and filename that is readable on the target network, authenticated or unauthenticated. If the credentials provided fail, then SnafflePy will automatically attempt to login via a Guest user, and if that fails it will attempt to login via a “NULL” session. It also supports the original TOML rule formats from Snaffler and uses them to identify interesting share names and return them to the user. 

### Features to Add: 
1. Classifier system from Snaffler to find interesting files
2. Make it way faster
3. Output to JSON

## Use case:

Sometimes you do not always have access to a domain joined windows machine when you want to Snaffle. With this tool, you can "snaffle" (just get every file from every file share as of right now, but I am working on adding the classifier system that the real Snaffler uses) from a non windows machine!  

## Installation (Linux):

1. Clone this repository

2. Optional but encouraged, create a virtual enviroment for this project

3. `pip install -r requirements.txt` 

## Usage and Options
~~~
SnafflePy by @robert-todora
usage: snaffler.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-H HASH] [-v] [--go-loud] [-m size] [-i] [-n] targets [targets ...]

A "port" of Snaffler in python

positional arguments:
  targets               IPs, hostnames, CIDR ranges, or files contains targets to snaffle. If you are providing more than one target, the -n option must be used.

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

  --go-loud             Don't try to find anything interesting, literally just go through every computer and every share and print out as many files as possible. Use at your own risk

  -m size, --max-file-snaffle size
                        Max filesize to snaffle in bytes (any files over this size will be dropped)
  -i, --no-share-discovery
                        Disables share discovery (more stealthy)
  -n, --disable-computer-discovery
                        Disable computer discovery, requires a list of hosts to do discovery on
~~~

## Examples

1. Print out every file in every share on all reachable targets 

`python3 snaffler.py <IP> -u <username> -p <password> -d <domain> --go-loud` 

## Output
![output](https://github.com/robert-todora/snafflepy/assets/59801737/7bcb3ded-c75e-4d90-bc34-b9db7b42cac9)
