import sys

from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE
from .smb import *
from .utilities import *
from .file import *
from .classifier import *

log = logging.getLogger('snafflepy')

def begin_snaffle(options):

    snaff_rules = Rules()
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    # Automatically get domain from target if not provided 
    if not options.domain:
        options.domain = get_domain(options.targets[0])
        if options.domain == "":
            sys.exit(2)

    domain_names = []
    if options.disable_computer_discovery:
        log.info(
            "Computer discovery is turned off. Snaffling will only occur on the host(s) specified.")

    else:
        login = access_ldap_server(
            options.targets[0], options.username, options.password)
        domain_names = list_computers(login, options.domain)
        for target in domain_names:
            log.debug(
                f"Found{target}, adding to targets to snaffle...")
            try:
                options.targets.append(target)
            except Exception as e:
                log.debug(f"Exception: {e}")
                log.warning(f"Unable to add{target} to targets to snaffle")
                continue
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
                log.error(f"Unable to login to{target}")
                continue
            for share in smb_client.shares:
                try:
                    if not options.go_loud:
                        is_interest_share(share, snaff_rules)
                    files = smb_client.ls(share, "")

                    for file in files:
                        size = file.get_filesize()
                        name = file.get_longname()
                        file = RemoteFile(name, share, target, size)

                        if options.go_loud:
                            try:
                                file_text = termcolor.colored("[File]", 'green')
                                file.get(smb_client)
                                print(file_text, f"\\\\{target}\\{share}\\{name}")
                            except FileRetrievalError as e:
                                dir_path = file.name
                                # Check if its a directory, and try to list files/more directories here
                                smb_client.handle_download_error(share, dir_path, e)
                                if str(e).find("ACCESS_DENIED"):
                                        log.debug(f"Access Denied \\\\{target}\\{share}\\{file}")
                                continue
                        else:
                            if size >= options.max_file_snaffle:
                                continue
                            else:
                                try:
                                    is_interest_file(file, snaff_rules, smb_client)
                                except FileRetrievalError as e:
                                    if str(e).find("ACCESS_DENIED"):
                                        log.debug(f"Access Denied, cannot download \\\\{target}\\{share}\\ {file}")
                                    continue

                except FileListError as e:
                    log.error(f"{share}, {e}")
                    continue

        except Exception as e:
            log.debug(f"{e}")


def access_ldap_server(ip, username, password):
    # log.info("Accessing LDAP Server")
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



