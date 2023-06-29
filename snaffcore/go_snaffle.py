import sys
from ldap3 import *
from time import sleep
from .smb import *

log = logging.getLogger('snafflepy')

def begin_snaffle(options):
    print("Beginning the snaffle...")
    sleep(0.2)
    
    # TODO: Talk to AD via LDAP to get list of computers with file shares 

    # Login via SMB
    for target in options.targets:
        try:
            smb_client = SMBClient(target, options.username, options.password, options.domain, options.hash)
            smb_client.login()
            
            for share in smb_client.shares:
                try:
                    files = smb_client.ls(share, "")

                    for file in files:
                        print("Found file in %s: %s" % (share, file))

                except FileListError:
                    print("Access Denied, cannot list files in %s" % share)
                    continue

        except Exception as e:
            print("Exception: ", e)
        