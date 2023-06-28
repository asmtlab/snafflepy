import sys
from ldap3 import *
from time import sleep
from .smb import *

log = logging.getLogger('snafflepy')

def begin_snaffle(options):
    print("Beginning the snaffle...")
    sleep(0.2)
    

    # TESTING
    if options.test:
        server = Server('testing server', get_info=ALL)
        conn = Connection(server, user='cn=user0,ou=test,o=lab', password='test0000', client_strategy=MOCK_SYNC)

        conn.strategy.add_entry('cn=user0,ou=test,o=lab', {'userPassword': 'test0000', 'sn': 'user0_sn', 'revision': 0})
        conn.strategy.add_entry('cn=user1,ou=test,o=lab', {'userPassword': 'test1111', 'sn': 'user1_sn', 'revision': 0})
        conn.strategy.add_entry('cn=user2,ou=test,o=lab', {'userPassword': 'test2222', 'sn': 'user2_sn', 'revision': 0})
    
        if conn.bind():
            print(server.info)
        else:
            print("Error connecting to domain")
            print(conn.result)
            sys.exit(2)
    else:
        
        # Login through LDAP  
        #server = Server(options.targets[0], get_info=ALL)
        #conn = Connection(server)
        
        # if not conn.bind():            
        #     print("Error connecting to domain")
        #     print(conn.result)
        #     sys.exit(2)
        
        #print(server.info)
        
        # Login via SMB
        for target in options.targets:
            try:
                smb_client = SMBClient(target, options.username, options.password, options.domain, options.hash)
                smb_client.login()
                
                for share in smb_client.shares:
                    print(share)

            except Exception as e:
                print("Exception: ", e)