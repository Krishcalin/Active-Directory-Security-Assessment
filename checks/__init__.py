from .domain_config import DomainConfigChecker
from .kerberos_security import KerberosSecurityChecker
from .password_policy import PasswordPolicyChecker
from .privileged_accounts import PrivilegedAccountsChecker
from .group_policy import GroupPolicyChecker
from .ldap_security import LdapSecurityChecker
from .dns_security import DnsSecurityChecker
from .trust_relationships import TrustRelationshipsChecker
from .certificate_services import CertificateServicesChecker
from .replication_security import ReplicationSecurityChecker
from .object_permissions import ObjectPermissionsChecker
from .service_accounts import ServiceAccountsChecker
from .authentication_security import AuthenticationSecurityChecker
from .lateral_movement import LateralMovementChecker
from .audit_logging import AuditLoggingChecker

ALL_CHECKERS = {
    "domain_config": DomainConfigChecker,
    "kerberos_security": KerberosSecurityChecker,
    "password_policy": PasswordPolicyChecker,
    "privileged_accounts": PrivilegedAccountsChecker,
    "group_policy": GroupPolicyChecker,
    "ldap_security": LdapSecurityChecker,
    "dns_security": DnsSecurityChecker,
    "trust_relationships": TrustRelationshipsChecker,
    "certificate_services": CertificateServicesChecker,
    "replication_security": ReplicationSecurityChecker,
    "object_permissions": ObjectPermissionsChecker,
    "service_accounts": ServiceAccountsChecker,
    "authentication_security": AuthenticationSecurityChecker,
    "lateral_movement": LateralMovementChecker,
    "audit_logging": AuditLoggingChecker,
}
