"""Unit tests for AD security scanner using mock LDAP responses."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from checks.domain_config import DomainConfigChecker
from checks.kerberos_security import KerberosSecurityChecker
from checks.password_policy import PasswordPolicyChecker
from checks.privileged_accounts import PrivilegedAccountsChecker
from checks.group_policy import GroupPolicyChecker
from checks.ldap_security import LdapSecurityChecker
from checks.dns_security import DnsSecurityChecker
from checks.trust_relationships import TrustRelationshipsChecker
from checks.certificate_services import CertificateServicesChecker
from checks.replication_security import ReplicationSecurityChecker
from checks.object_permissions import ObjectPermissionsChecker
from checks.service_accounts import ServiceAccountsChecker
from checks.authentication_security import AuthenticationSecurityChecker
from checks.lateral_movement import LateralMovementChecker
from checks.audit_logging import AuditLoggingChecker
from utils.severity import compute_posture_score, score_to_grade, severity_counts

MOCK_PATH = os.path.join(os.path.dirname(__file__), "test_data", "mock_responses.json")
with open(MOCK_PATH, "r", encoding="utf-8") as f:
    MOCK = json.load(f)


class MockLdapClient:
    def __init__(self, data):
        self.data = data
        self.domain = "corp.com"
        self.base_dn = "DC=corp,DC=com"
        self.config_dn = "CN=Configuration,DC=corp,DC=com"
        self.schema_dn = "CN=Schema,CN=Configuration,DC=corp,DC=com"
        self.server_addr = "dc01.corp.com"
        self.use_ssl = False

    def get_domain_info(self):
        return self.data.get("domain_info", {})

    def get_domain_controllers(self):
        return self.data.get("domain_controllers", [])

    def get_users(self, filter_extra="", attributes=None):
        users = self.data.get("users", [])
        if "servicePrincipalName=*" in filter_extra:
            return [u for u in users if u.get("serviceprincipalname")]
        if "65536" in filter_extra:  # DONT_EXPIRE_PASSWORD
            return [u for u in users if int(u.get("useraccountcontrol", 0)) & 0x10000]
        if "32" in filter_extra:  # PASSWORD_NOT_REQUIRED
            return [u for u in users if int(u.get("useraccountcontrol", 0)) & 0x20]
        return users

    def get_groups(self, filter_extra=""):
        return []

    def get_group_members(self, group_dn):
        dn_lower = group_dn.lower()
        if "domain admins" in dn_lower:
            return self.data.get("domain_admins", [])
        if "enterprise admins" in dn_lower:
            return self.data.get("enterprise_admins", [])
        if "schema admins" in dn_lower:
            return self.data.get("schema_admins", [])
        if "protected users" in dn_lower:
            return self.data.get("protected_users", [])
        if "backup operators" in dn_lower:
            return self.data.get("backup_operators", [])
        return []

    def get_gpos(self):
        return self.data.get("gpos", [])

    def get_trusts(self):
        return self.data.get("trusts", [])

    def get_certificate_templates(self):
        return self.data.get("certificate_templates", [])

    def get_enrollment_services(self):
        return self.data.get("enrollment_services", [])

    def get_fine_grained_password_policies(self):
        return self.data.get("fgpp", [])

    def get_service_accounts(self):
        return self.data.get("service_accounts", [])

    def search(self, base=None, filter_str="", attributes=None, scope=None, size_limit=1000, paged_size=500):
        if "524288" in filter_str:  # unconstrained delegation
            return self.data.get("unconstrained_delegation", [])
        if "16777216" in filter_str:  # constrained delegation T2A4D
            return []
        if "AllowedToActOnBehalfOfOtherIdentity" in filter_str:
            return []
        if "2097152" in filter_str:  # DES only
            return []
        if "krbtgt" in filter_str:
            return [u for u in self.data.get("users", []) if u.get("samaccountname") == "krbtgt"]
        if "objectSid=*-500" in filter_str:
            return [{"samaccountname": "Administrator", "useraccountcontrol": "512", "dn": "CN=Administrator,CN=Users,DC=corp,DC=com"}]
        if "Recycle Bin" in str(base or ""):
            return []
        if "dSHeuristics" in filter_str:
            return []
        if "pKICertificateTemplate" in filter_str:
            return self.data.get("certificate_templates", [])
        if "pKIEnrollmentService" in filter_str:
            return self.data.get("enrollment_services", [])
        if "ms-Mcs-AdmPwd" in filter_str or "msLAPS" in filter_str:
            return []
        if "Pre-Windows 2000" in str(base or ""):
            return [{"member": ["CN=SomeUser,CN=Users,DC=corp,DC=com"]}]
        if "objectClass=domain" in filter_str:
            return [self.data.get("domain_info", {})]
        if "adminCount=1" in filter_str:
            return [{"samaccountname": "orphan_admin"}]
        if "Backup Operators" in filter_str or "Account Operators" in filter_str or "Print Operators" in filter_str:
            return self.data.get("backup_operators", [])
        return []

    def search_one(self, base, filter_str="", attributes=None):
        results = self.search(base=base, filter_str=filter_str, attributes=attributes)
        return results[0] if results else {}


class TestDomainConfig(unittest.TestCase):
    def test_findings(self):
        c = DomainConfigChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_low_functional_level(self):
        c = DomainConfigChecker(MockLdapClient(MOCK))
        f = c.run_all()
        dom = [x for x in f if x["id"] == "DOM-001"]
        self.assertTrue(len(dom) > 0)

class TestKerberos(unittest.TestCase):
    def test_findings(self):
        c = KerberosSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_kerberoastable(self):
        c = KerberosSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        krb = [x for x in f if x["id"] == "KRB-001"]
        self.assertTrue(len(krb) > 0)
    def test_unconstrained(self):
        c = KerberosSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        uc = [x for x in f if x["id"] == "KRB-003"]
        self.assertTrue(len(uc) > 0)

class TestPasswordPolicy(unittest.TestCase):
    def test_findings(self):
        c = PasswordPolicyChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_min_length(self):
        c = PasswordPolicyChecker(MockLdapClient(MOCK))
        f = c.run_all()
        pwd = [x for x in f if x["id"] == "PWD-001"]
        self.assertTrue(len(pwd) > 0)
    def test_no_lockout(self):
        c = PasswordPolicyChecker(MockLdapClient(MOCK))
        f = c.run_all()
        lock = [x for x in f if x["id"] == "PWD-006"]
        self.assertTrue(len(lock) > 0)

class TestPrivilegedAccounts(unittest.TestCase):
    def test_findings(self):
        c = PrivilegedAccountsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_enterprise_admins(self):
        c = PrivilegedAccountsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        ea = [x for x in f if x["id"] == "PRIV-002"]
        self.assertTrue(len(ea) > 0)

class TestGroupPolicy(unittest.TestCase):
    def test_findings(self):
        c = GroupPolicyChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestLdapSecurity(unittest.TestCase):
    def test_findings(self):
        c = LdapSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestDnsSecurity(unittest.TestCase):
    def test_findings(self):
        c = DnsSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestTrusts(unittest.TestCase):
    def test_findings(self):
        c = TrustRelationshipsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_sid_filtering(self):
        c = TrustRelationshipsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        sid = [x for x in f if x["id"] == "TRUST-001"]
        self.assertTrue(len(sid) > 0)

class TestCertServices(unittest.TestCase):
    def test_findings(self):
        c = CertificateServicesChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_esc1(self):
        c = CertificateServicesChecker(MockLdapClient(MOCK))
        f = c.run_all()
        esc1 = [x for x in f if x["id"] == "ADCS-001"]
        self.assertTrue(len(esc1) > 0)

class TestReplication(unittest.TestCase):
    def test_findings(self):
        c = ReplicationSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestObjectPerms(unittest.TestCase):
    def test_findings(self):
        c = ObjectPermissionsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestServiceAccounts(unittest.TestCase):
    def test_findings(self):
        c = ServiceAccountsChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestAuthSecurity(unittest.TestCase):
    def test_findings(self):
        c = AuthenticationSecurityChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestLateralMovement(unittest.TestCase):
    def test_findings(self):
        c = LateralMovementChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)
    def test_no_laps(self):
        c = LateralMovementChecker(MockLdapClient(MOCK))
        f = c.run_all()
        laps = [x for x in f if x["id"] == "LAT-001"]
        self.assertTrue(len(laps) > 0)

class TestAuditLogging(unittest.TestCase):
    def test_findings(self):
        c = AuditLoggingChecker(MockLdapClient(MOCK))
        f = c.run_all()
        self.assertGreater(len(f), 0)

class TestScoring(unittest.TestCase):
    def test_perfect(self):
        self.assertEqual(compute_posture_score([]), 100)
    def test_critical(self):
        self.assertEqual(compute_posture_score([{"severity": "CRITICAL"}]), 85)
    def test_grade(self):
        self.assertEqual(score_to_grade(95), "A")
        self.assertEqual(score_to_grade(50), "F")
    def test_counts(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}, {"severity": "HIGH"}]
        c = severity_counts(findings)
        self.assertEqual(c["CRITICAL"], 1)
        self.assertEqual(c["HIGH"], 2)

if __name__ == "__main__":
    unittest.main()
