import sys
# import socket
# import urllib.parse
# import dns.resolver

from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE
from time import sleep
from .smb import *
from .utilities import *
from .file import *
from .classifier import *
# import pprint

log = logging.getLogger('snafflepy')


def begin_snaffle(options):

    # Prepare classifiers for use in naive_classify()
    snaff_rules = Rules()
    prepped_rules = snaff_rules.prepare_classifiers()
    # for dict_rules in prepped_rules:
    #   for actual_rule in dict_rules['ClassifierRules']:
    #       pprint.pprint(actual_rule['Triage'])

    print("Beginning the snaffle...")
    sleep(0.2)

    if not options.domain:
        log.info("Domain not provided, retrieving automatically.")
        s = Server(options.targets[0], get_info=ALL)
        c = Connection(s)
        if not c.bind():
            log.error("Could not get domain automatically")
            sys.exit(1)
        else:
            try:
                options.domain = str(
                    s.info.other["ldapServiceName"][0].split("@")[1]).lower()
            except Exception as e:
                log.error("Could not get domain automatically")
                sys.exit(1)
        c.unbind()

    domain_names = []
    # TODO: Talk to AD via LDAP to get list of computers with file shares
    if options.disable_computer_discovery:
        log.info(
            "Computer discovery is turned off. Snaffling will only occur on the host(s) specified.")

    else:
        login = access_ldap_server(
            options.targets[0], options.username, options.password)
        domain_names = list_computers(login, options.domain)
        # list_computers() returns list so need to individually add entry
        for target in domain_names:
            log.debug(
                f"Found{target}, adding to targets to snaffle...")
            sleep(0.5)
            try:
                # TODO: Try to fix this? - How to resolve internal IP address from Hostname
                # Supposedly SMBConnection should be able to take a hostname but not working as intended on the HTB enviroment I am using for testing
                # ip = resolve(options.domain, target)
                options.targets.append(target)
            except Exception as e:
                log.debug(f"Exception: {e}")
                log.warning(f"Unable to add{target} to targets to snaffle")
                continue
    log.debug(f"Targets that will be snaffled: {options.targets}")

    # Login via SMB
    # log.info("Preparing classifiers...")
    # prepare_classifiers()

    if options.no_share_discovery:
        try:
            smb_client = SMBClient(
                options.targets[0], options.username, options.password, options.domain, options.hash)
        except:
            log.error(f"Error logging in to SMB on {options.targets[0]}")

    if options.go_loud:
        log.warning("[GO LOUD ACTIVATED] Enumerating all shares for all files...")
        for target in options.targets:
            try:
                smb_client = SMBClient(
                    target, options.username, options.password, options.domain, options.hash)
                smb_client.login()
                for share in smb_client.shares:
                    try:
                        files = smb_client.ls(share, "")

                        for file in files:
                            # filelist.append(file)
                            # Ask do they want file sizes?
                            log.info(f"{target} Found file in {share}: {file.get_longname()}")
                            # naive_classify(share, file, prepped_rules)
                            # log.info(f"{target} Found file in {share}: {file}")
                    except FileListError:
                        log.error(
                            "Access Denied, cannot list files in %s" % share)
                        continue

            except Exception as e:
                log.error(f"Error creating SMBClient object, {e}")
    else: 
        pass

def access_ldap_server(ip, username, password):
    log.info("Accessing LDAP Server")
    server = Server(ip, get_info=DSA)
    try:
        conn = Connection(server, username, password)
        # log.debug(server.schema)

        if not conn.bind():
            log.critical(f"Unable to bind to {server} as {username}, ")
        return conn

    except Exception as e:
        log.critical(f'Error logging in to {ip}')
        log.info("Trying guest session... ")

        try:
            conn = Connection(server, username='Guest', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server} as {username}")
            return conn

        except Exception as e:
            log.critical(f'Error logging in to {ip}, as {username}')
            log.info("Trying null session... ")

            conn = Connection(server, username='', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server} as {username}")
                return None
            return conn

# 2nd snaffle step, finding additional targets from original target via LDAP queries


def list_computers(connection: Connection, domain):
    dn = get_domain_dn(domain)
    # filter = "(objectCategory=computer)"
    if connection is None:
        log.critical("Connection is not established")

    try:
        connection.search(search_base=dn, search_filter='(&(objectCategory=Computer)(name=*))',
                          search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)
        # log.debug(connection.entries)
        # connection.search(search_base=dn,search_filter=filter,search_scope=SUBTREE,attributes=ALL_ATTRIBUTES)
        domain_names = []

        log.debug(connection.entries)
        for entry in connection.entries:
            sep = str(entry).strip().split(':')
            domain_names.append(sep[6])

        return domain_names

    except Exception as e:
        log.critical(f"Unable to list computers: {e}")
        return None

# TODO


def naive_classify(share, file, rules: Rules):
    log.info(f"{share}: {file.get_longname()}")

    if is_interest(file, rules):
        log.info(f"Found interesting file: {share}/{file}")

# These functions resolve to public IP Address: 

''' 
def resolve(nameserver, host_fqdn):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    answer = resolver.query(host_fqdn, "A")
    return answer


def get_ip(target):
    try:
        print(socket.gethostbyname(target))
    except socket.gaierror:
        parsed_url = urllib.parse.urlparse(target)
        hostname = parsed_url.hostname
        try:
            answers = dns.resolver.query(hostname, 'A')
            for rdata in answers:
                print(rdata.address)
        except dns.resolver.NXDOMAIN:
            print('ip not found') 
'''
