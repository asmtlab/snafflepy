import argparse
import sys
import logging
from snaffcore.begin import *

log = logging.getLogger('manspider')
log.setLevel(logging.INFO)

def parse_arguments():
    syntax_error = False
    print("SnafflePy: A Port by @robert-todora")

    parser = argparse.ArgumentParser(add_help=True, prog='snafflepy', description='A "port" of Snaffler in python')
    parser.add_argument("-u","--username", metavar='username',type=str, help="domain username")
    parser.add_argument("-p","--password", metavar='password',type=str, help="password for domain user")
    parser.add_argument('--dcip', metavar='[IP addr]', required=True, help="IP address of domain controller")
    parser.add_argument("-d", "--domain", metavar='domain', default="", help="FQDN domain to authenticate to")
    parser.add_argument("-t", "--test", metavar='test', type=bool, default="False", help="switch to testing mode")

    options = parser.parse_args()

    try:
      if len(sys.argv) == 1:
          parser.print_help()
          sys.exit(1)
  
      print(options.username, options.password, options.dcip, options.domain)
      print(type(options.username), type(options.password), type(options.dcip), type(options.domain))

    except argparse.ArgumentError as e:
        syntax_error = True
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

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
