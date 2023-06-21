from queue import Queue
from enum import Flag


class AdData:
    def __init__(self):
        self.domain_computers = []
        self.domain_users = []
        self.dfs_shares_dict = {}
        self.dfs_namespace_paths = []
        self.current_domain = None
        self.domain_name = ""
        self.target_domain = ""
        self.target_dc = ""
        self.target_domain_netbios_name = ""
        self.directory_search = None
        self.mq = Queue()

        self.DirectoryContext = None
        self.DomainControllers = []

    def get_domain_computers(self):
        return self.domain_computers

    def get_domain_users(self):
        return self.domain_users

    def get_dfs_shares_dict(self):
        return self.dfs_shares_dict

    def get_dfs_namespace_paths(self):
        return self.dfs_namespace_paths

    def get_directory_search(self):
        if self.directory_search is None:
            # set_directory_search()
            pass
        return self.directory_search

    def get_netbios_domain_name(self):
        return

    def set_directory_search(self):
        pass

    def set_dfs_path(self):
        pass

    def set_domain_computers(self):
        pass

    def set_domain_users(self):
        pass

    class UserAccountControlFlags(Flag):
        Script = 0x1
        AccountDisabled = 0x2
        HomeDirectoryRequired = 0x8
        AccountLockedOut = 0x10
        PasswordNotRequired = 0x20
        PasswordCannotChange = 0x40
        EncryptedTextPasswordAllowed = 0x80
        TempDuplicateAccount = 0x100
        NormalAccount = 0x200
        InterDomainTrustAccount = 0x800
        WorkstationTrustAccount = 0x1000
        ServerTrustAccount = 0x2000
        PasswordDoesNotExpire = 0x10000
        MnsLogonAccount = 0x20000
        SmartCardRequired = 0x40000
        TrustedForDelegation = 0x80000
        AccountNotDelegated = 0x100000
        UseDesKeyOnly = 0x200000
        DontRequirePreauth = 0x400000
        PasswordExpired = 0x800000
        TrustedToAuthenticateForDelegation = 0x1000000
        NoAuthDataRequired = 0x2000000
