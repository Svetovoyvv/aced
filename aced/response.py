from impacket.ldap.ldaptypes import ACL, LDAP_SID, SR_SECURITY_DESCRIPTOR


class Response:
    
    def __init__(self):
        self.security_descriptor: SR_SECURITY_DESCRIPTOR = SR_SECURITY_DESCRIPTOR()
        self.dnshostname: str = ""
        self.objectsid: str = ""
        self.sAMAccountName: str = ""
        self.description: str = ""
        self.memberOf: str = ""
        self.members: str = ""



    @property
    def owner_sid(self) -> LDAP_SID:
        return self.security_descriptor['OwnerSid']

    @property
    def dacl(self) -> ACL:
        return self.security_descriptor["Dacl"]
