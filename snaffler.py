import argparse
import sys
import logging

from snaffcore.go_snaffle import *
from snaffcore.utilities import *
from snaffcore.logger import *

log = logging.getLogger('snafflepy')
log.setLevel(logging.INFO)


def parse_arguments():
    syntax_error = False
    print("SnafflePy by @robert-todora")

    # TODO - Check that if targets > 1 then "-n" needs to be set to true
    parser = argparse.ArgumentParser(
        add_help=True, prog='snaffler.py', description='A "port" of Snaffler in python')
    parser.add_argument("targets", nargs='+', type=make_targets,
                        help="IPs, hostnames, CIDR ranges, or files contains targets to snaffle. If you are providing more than one target, the -n option must be used.")
    parser.add_argument("-u", "--username", metavar='username',
                        type=str, help="domain username")
    parser.add_argument("-p", "--password", metavar='password',
                        type=str, help="password for domain user")
    parser.add_argument("-d", "--domain", metavar='domain',
                        default="", help="FQDN domain to authenticate to")
    parser.add_argument("-H", "--hash", metavar='hash',
                        default="", help="NT hash for authentication")
    parser.add_argument("-v", "--verbose",
                        action='store_true', help="Show more info")
    # parser.add_argument("-e", "--exclude",  )

    # TODO
    parser.add_argument("-i", "--no-share-discovery", action='store_true',
                        help="Disables share discovery (more stealthy)")
    parser.add_argument("-n", "--disable-computer-discovery", action='store_true',
                        help="Disable computer discovery, requires a list of hosts to do discovery on")

    try:
        if len(sys.argv) <= 1:
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
            options = parser.parse_args()
            if options.verbose:
                log.setLevel('DEBUG')

            targets = set()
            [[targets.add(t) for t in g] for g in options.targets]
            options.targets = list(targets)

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

    print("\nI snaffled 'til the snafflin was done")
    print("View log file at ~/.snafflepy/logs/")
    sys.exit(1)


if __name__ == '__main__':
    main()
