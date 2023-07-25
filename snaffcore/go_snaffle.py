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

    snaff_rules = Rules()
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    # Automatically get domain from target if not provided 
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

    # log.debug(f"Targets that will be snaffled: {options.targets}")

    # Login via SMB
    # log.info("Preparing classifiers...")
    # prepare_classifiers()

    try:
        smb_client = SMBClient(
            options.targets[0], options.username, options.password, options.domain, options.hash)
    except:
        log.error(f"Error logging in to SMB on {options.targets[0]}")
    if options.go_loud:
        log.warning(
            "[GO LOUD ACTIVATED] Enumerating all shares for all files...")
    for target in options.targets:
        try:
            smb_client = SMBClient(
                target, options.username, options.password, options.domain, options.hash)
            if not smb_client.login():
                log.error(f" Unable to login to{target}")
                continue
            for share in smb_client.shares:
                try:
                    if not options.go_loud:
                        classify_share(share, snaff_rules)
                    # else:
                    #    log.info(f"Found share: {share}")

                    files = smb_client.ls(share, "")

                    for file in files:
                        size = file.get_filesize()
                        name = file.get_longname()
                        file = RemoteFile(name, share, target, size)

                        if options.go_loud:
                            # Dont care about empty files
                            if size == 0:
                                continue
                            try:
                                file.get(smb_client)
                                log.info(f"{target}: {share}\\{name}")
                            except FileRetrievalError:
                                log.debug(f"Unable to download ({target}\\\\{share}\\{name})")
                        else:
                            if size >= options.max_file_snaffle:
                                pass
                            else:
                                try:
                                    classify_file(file, snaff_rules, smb_client)
                                except FileRetrievalError as e:
                                    log.debug(f"{e}")
                                    continue

                except FileListError:
                    log.error(
                        "Access Denied, cannot list files in %s" % share)
                    continue

        except Exception as e:
            log.debug(f"{e}")


def access_ldap_server(ip, username, password):
    log.info("Accessing LDAP Server")
    server = Server(ip, get_info=DSA)
    try:
        conn = Connection(server, username, password)
        # log.debug(server.schema)

        if not conn.bind():
            log.critical(f"Unable to bind to {server}")
            return None
        return conn

    except Exception as e:
        log.critical(f'Error logging in to {ip}')
        log.info("Trying guest session... ")

        try:
            conn = Connection(server, user='Guest', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server} as {username}")
                return None
            return conn

        except Exception as e:
            log.critical(f'Error logging in to {ip}, as {username}')
            log.info("Trying null session... ")

            conn = Connection(server, user='', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server}")
                return None
            return conn

# 2nd snaffle step, finding additional targets from original target via LDAP queries

def list_computers(connection: Connection, domain):
    dn = get_domain_dn(domain)
    # filter = "(objectCategory=computer)"
    if connection is None:
        log.critical("Connection is not established")
        sys.exit(2)

    try:
        connection.search(search_base=dn, search_filter='(&(objectCategory=Computer)(name=*))',
                          search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)
        domain_names = []

        for entry in connection.entries:
            sep = str(entry).strip().split(':')
            domain_names.append(sep[6])

        return domain_names

    except Exception as e:
        log.critical(f"Unable to list computers: {e}")
        return None

# TODO


def classify_file(file: RemoteFile, rules: Rules, smb_client: SMBClient):
    is_interest_file(file, rules, smb_client)

def classify_share(share, rules: Rules):
    is_interest_share(share, rules)

