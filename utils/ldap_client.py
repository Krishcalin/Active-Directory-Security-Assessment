"""LDAP/LDAPS client for Active Directory read-only queries."""

import logging
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, BASE, Tls

logger = logging.getLogger(__name__)


class ADLdapClient:
    """Read-only LDAP client for Active Directory."""

    def __init__(self, server, domain, username, password, port=None,
                 use_ssl=False, auth="simple", verify_ssl=True, timeout=30):
        self.server_addr = server
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.auth_type = auth.lower()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.conn = None
        self.base_dn = None
        self.domain_dn = None
        self.config_dn = None
        self.schema_dn = None

    def connect(self):
        """Establish LDAP connection and discover base DNs."""
        tls_config = None
        if self.use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED if self.verify_ssl else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2
            )

        server = Server(
            self.server_addr,
            port=self.port,
            use_ssl=self.use_ssl,
            tls=tls_config,
            get_info=ALL,
            connect_timeout=self.timeout
        )

        if self.auth_type == "ntlm":
            user = f"{self.domain}\\{self.username}" if "\\" not in self.username else self.username
            self.conn = Connection(
                server, user=user, password=self.password,
                authentication=NTLM, read_only=True,
                receive_timeout=self.timeout
            )
        else:
            self.conn = Connection(
                server, user=self.username, password=self.password,
                authentication=SIMPLE, read_only=True,
                receive_timeout=self.timeout
            )

        if not self.conn.bind():
            raise ConnectionError(f"LDAP bind failed: {self.conn.result}")

        # Discover base DNs from RootDSE
        info = server.info
        if info:
            self.domain_dn = str(info.other.get("defaultNamingContext", [""])[0]) if info.other.get("defaultNamingContext") else None
            self.config_dn = str(info.other.get("configurationNamingContext", [""])[0]) if info.other.get("configurationNamingContext") else None
            self.schema_dn = str(info.other.get("schemaNamingContext", [""])[0]) if info.other.get("schemaNamingContext") else None

        if not self.domain_dn:
            self.domain_dn = ",".join(f"DC={p}" for p in self.domain.split("."))

        if not self.config_dn:
            self.config_dn = f"CN=Configuration,{self.domain_dn}"

        self.base_dn = self.domain_dn
        logger.info("Connected to %s, base DN: %s", self.server_addr, self.base_dn)
        return True

    def disconnect(self):
        """Close LDAP connection."""
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass
            self.conn = None

    def search(self, base=None, filter_str="(objectClass=*)", attributes=None,
               scope=SUBTREE, size_limit=1000, paged_size=500):
        """Perform LDAP search. Returns list of entry dicts."""
        if not self.conn:
            return []
        search_base = base or self.base_dn
        attrs = attributes or ["*"]

        try:
            self.conn.search(
                search_base=search_base,
                search_filter=filter_str,
                search_scope=scope,
                attributes=attrs,
                size_limit=size_limit,
                paged_size=paged_size
            )
            results = []
            for entry in self.conn.entries:
                d = {"dn": str(entry.entry_dn)}
                for attr in entry.entry_attributes:
                    val = entry[attr].values
                    d[str(attr).lower()] = val if len(val) > 1 else val[0] if val else None
                results.append(d)
            return results
        except Exception as e:
            logger.error("LDAP search failed (base=%s, filter=%s): %s", search_base, filter_str, e)
            return []

    def search_one(self, base, filter_str="(objectClass=*)", attributes=None):
        """Search and return first result or empty dict."""
        results = self.search(base=base, filter_str=filter_str,
                              attributes=attributes, scope=BASE, size_limit=1)
        return results[0] if results else {}

    def get_domain_info(self):
        """Get domain-level attributes."""
        return self.search_one(self.base_dn, attributes=[
            "msDS-Behavior-Version", "whenCreated", "objectSid",
            "minPwdLength", "minPwdAge", "maxPwdAge", "lockoutThreshold",
            "lockoutDuration", "lockOutObservationWindow", "pwdHistoryLength",
            "pwdProperties", "ms-DS-MachineAccountQuota",
            "tombstoneLifetime", "msDS-DeletedObjectLifetime"
        ])

    def get_domain_controllers(self):
        """Get all domain controllers."""
        return self.search(
            filter_str="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            attributes=["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                         "whenCreated", "lastLogonTimestamp"]
        )

    def get_users(self, filter_extra="", attributes=None):
        """Get AD user objects."""
        base_filter = "(&(objectCategory=person)(objectClass=user)"
        if filter_extra:
            base_filter += filter_extra
        base_filter += ")"
        default_attrs = [
            "sAMAccountName", "userAccountControl", "memberOf",
            "pwdLastSet", "lastLogonTimestamp", "whenCreated",
            "servicePrincipalName", "adminCount", "description",
            "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "userPrincipalName", "distinguishedName"
        ]
        return self.search(filter_str=base_filter, attributes=attributes or default_attrs)

    def get_groups(self, filter_extra=""):
        """Get AD group objects."""
        base_filter = "(&(objectCategory=group)"
        if filter_extra:
            base_filter += filter_extra
        base_filter += ")"
        return self.search(filter_str=base_filter, attributes=[
            "cn", "member", "memberOf", "groupType", "adminCount",
            "description", "whenCreated", "managedBy"
        ])

    def get_group_members(self, group_dn):
        """Get members of a specific group (recursive)."""
        return self.search(
            filter_str=f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
            attributes=["sAMAccountName", "userAccountControl", "adminCount",
                         "pwdLastSet", "lastLogonTimestamp", "whenCreated"]
        )

    def get_gpos(self):
        """Get Group Policy Objects."""
        return self.search(
            base=f"CN=Policies,CN=System,{self.base_dn}",
            filter_str="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "versionNumber",
                         "flags", "whenCreated", "whenChanged"]
        )

    def get_trusts(self):
        """Get domain trust objects."""
        return self.search(
            filter_str="(objectClass=trustedDomain)",
            attributes=["cn", "trustDirection", "trustType", "trustAttributes",
                         "trustPartner", "securityIdentifier", "whenCreated"]
        )

    def get_certificate_templates(self):
        """Get AD CS certificate templates from configuration partition."""
        return self.search(
            base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_dn}",
            filter_str="(objectClass=pKICertificateTemplate)",
            attributes=["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                         "pKIExtendedKeyUsage", "msPKI-RA-Signature",
                         "msPKI-Certificate-Application-Policy",
                         "nTSecurityDescriptor", "whenCreated"]
        )

    def get_enrollment_services(self):
        """Get AD CS enrollment services."""
        return self.search(
            base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_dn}",
            filter_str="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName", "certificateTemplates",
                         "cACertificate", "nTSecurityDescriptor"]
        )

    def get_fine_grained_password_policies(self):
        """Get fine-grained password policies (PSOs)."""
        return self.search(
            base=f"CN=Password Settings Container,CN=System,{self.base_dn}",
            filter_str="(objectClass=msDS-PasswordSettings)",
            attributes=["cn", "msDS-PasswordSettingsPrecedence",
                         "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge",
                         "msDS-MaximumPasswordAge", "msDS-PasswordHistoryLength",
                         "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold",
                         "msDS-LockoutDuration", "msDS-LockoutObservationWindow",
                         "msDS-PasswordReversibleEncryptionEnabled",
                         "msDS-PSOAppliesTo"]
        )

    def get_service_accounts(self):
        """Get managed service accounts and group managed service accounts."""
        return self.search(
            filter_str="(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))",
            attributes=["cn", "sAMAccountName", "objectClass", "servicePrincipalName",
                         "msDS-ManagedPasswordInterval", "whenCreated",
                         "msDS-GroupMSAMembership", "userAccountControl"]
        )
