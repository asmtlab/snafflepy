# import queue
import ldap3


class DirectorySearch:
    def __init__(self, domain_controller, domain_name, ldap_username, ldap_password, ldap_port, secure_ldap, is_falted):
        self.domain_controller = domain_controller
        self.domain_name = domain_name
        self.base_ldap_path = "DC=" + self.domain_name.replace(".", ",DC=")
        # TODO: figure out the active directory library equivalent for python
        self.domain = None
        self.ldap_username = ldap_username
        self.ldap_password: ldap_password
        self.ldap_port = ldap_port
        self.secure_ldap = secure_ldap
        self.is_falted = is_falted
        self.connection_pool = []
        self.domain_guid_map = {}

    def get_domain_name(self):
        if self.domain_name is None:
            return
        return self.domain_name

    async def get_one(self):
        return

    # https://ldap3.readthedocs.io/en/latest/tutorial_searches.html
    def query_ldap(self):
        return

    def ranged_retrieval_async(self):
        return

    def get_attribute_from_guid(self, guid: str, name: str):
        return self.domain_guid_map.get(guid, name)

    def set_domain_name(self):
        return

    def get_global_catalog_connection(self):
        return

    def get_ldap_conenction(self):
        return

    def create_search_request(self):
        return


