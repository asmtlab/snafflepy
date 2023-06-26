import argparse
import sys
import ldap3


def parse_arguments():
    print("SnafflePy: A Port by @robert-todora")

    parser = argparse.ArgumentParser(add_help=True, prog='snafflepy', description='A "port" of Snaffler in python')
    parser.add_argument("-u","--username", metavar='username',type=str, nargs=1, help="domain username")
    parser.add_argument("-p","--password", metavar='password',type=str, nargs=1, help="password for domain user")
    parser.add_argument('--dc-ip', metavar='[IP addr]', required=True, nargs=1, help="IP address of domain controller")
    parser.add_argument("-d", "--domain", metavar='domain', default="", help="FQDN domain to authenticate to")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)


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
    parse_arguments()
    print("I snaffled 'til the snafflin was done")


# TODO: Create SnaffleRunner class with equivalent functions and call the Run() method here.
if __name__ == '__main__':
    main()
