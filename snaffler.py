import argparse
import sys
import logging
from snaffcore.go_snaffle import *
from snaffcore.utilities import *

log = logging.getLogger('snafflepy')
log.setLevel(logging.INFO)

def parse_arguments():
    syntax_error = False
    print("SnafflePy by @robert-todora")

    parser = argparse.ArgumentParser(add_help=True, prog='snafflepy', description='A "port" of Snaffler in python')
    parser.add_argument("targets", nargs='+',type=make_targets,required=True, help="IPs, hostnames, CIDR ranges, or files contains targets to snaffle")
    parser.add_argument("-u","--username", metavar='username',type=str, help="domain username")
    parser.add_argument("-p","--password", metavar='password',type=str, help="password for domain user")
    #parser.add_argument('--dcip', metavar='[IP addr]', help="IP address of domain controller")
    parser.add_argument("-d", "--domain", metavar='domain', default="", help="FQDN domain to authenticate to")
    parser.add_argument("--test", metavar='test', type=bool, default=False, help="switch to testing mode")
    parser.add_argument("-f", "--file", help="path to file with list of targets")
    options = parser.parse_args()

    try:
      if len(sys.argv) == 1:
          parser.print_help()
          sys.exit(1)      

    except argparse.ArgumentError as e:
        syntax_error = True
        log.error(e)
        log.error('Check your syntax')

    finally:
      if syntax_error:
          parser.print_help()
          sys.exit(2)
      else:
          return options
      

def print_banner():
    print(r'''  
  O~~ ~~                         O~~    O~~ O~~          O~~~~~~~           
O~~    O~~                     O~     O~    O~~          O~~    O~~         
 O~~      O~~ O~~     O~~    O~O~ O~O~O~ O~ O~~   O~~    O~~    O~~O~~   O~~
   O~~     O~~  O~~ O~~  O~~   O~~    O~~   O~~ O~   O~~ O~~~~~~~   O~~ O~~ 
      O~~  O~~  O~~O~~   O~~   O~~    O~~   O~~O~~~~~ O~~O~~          O~~~  
O~~    O~~ O~~  O~~O~~   O~~   O~~    O~~   O~~O~        O~~           O~~  
  O~~ ~~  O~~~  O~~  O~~ O~~~  O~~    O~~  O~~~  O~~~~   O~~          O~~   
                                                                    O~~     ''')
    print("")
    print("")


def main():
    print_banner()
    snaffle_options = parse_arguments()
    begin_snaffle(snaffle_options)
    

    print("I snaffled 'til the snafflin was done")


if __name__ == '__main__':
    main()
