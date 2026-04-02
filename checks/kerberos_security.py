"""Kerberos security checks."""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

UAC_DISABLE = 0x2
UAC_DONT_EXPIRE_PWD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_ONLY = 0x200000
UAC_DONT_REQUIRE_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def _uac(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


class KerberosSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running Kerberos security checks...")
        self._check_kerberoastable()
        self._check_asrep_roastable()
        self._check_unconstrained_delegation()
        self._check_constrained_delegation()
        self._check_rbcd()
        self._check_des_accounts()
        self._check_krbtgt_password()
        self._check_protected_users()
        return self.findings

    def _check_kerberoastable(self):
        users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        targets = []
        admin_targets = []
        for u in users:
            uac = _uac(u.get("useraccountcontrol", 0))
            if uac & UAC_DISABLE:
                continue
            name = u.get("samaccountname", "unknown")
            admin = u.get("admincount", 0)
            try:
                admin = int(admin)
            except (TypeError, ValueError):
                admin = 0
            if admin == 1:
                admin_targets.append(name)
            else:
                targets.append(name)

        if admin_targets:
            self.findings.append({
                "id": "KRB-001", "title": f"{len(admin_targets)} admin account(s) with SPN (Kerberoastable)",
                "severity": "CRITICAL", "category": "Kerberos Security",
                "resource": ", ".join(admin_targets[:10]),
                "actual": f"{len(admin_targets)} admin accounts with SPNs: {', '.join(admin_targets[:5])}",
                "expected": "No admin accounts with SPNs",
                "recommendation": "Remove SPNs from admin accounts or migrate to gMSA. Kerberoastable admin accounts allow offline password cracking",
                "remediation_cmd": "Set-ADUser <account> -ServicePrincipalNames @{Remove='<SPN>'}"
            })
        if targets:
            self.findings.append({
                "id": "KRB-001", "title": f"{len(targets)} user account(s) with SPN (Kerberoastable)",
                "severity": "HIGH", "category": "Kerberos Security",
                "resource": f"{len(targets)} accounts",
                "actual": f"{len(targets)} accounts: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}",
                "expected": "Migrate SPN accounts to gMSA",
                "recommendation": "Convert service accounts with SPNs to Group Managed Service Accounts (gMSA) to eliminate Kerberoasting risk",
                "remediation_cmd": "New-ADServiceAccount -Name <gMSA> -DNSHostName <host> -PrincipalsAllowedToRetrieveManagedPassword <group>"
            })

    def _check_asrep_roastable(self):
        users = self.ldap.get_users()
        targets = []
        for u in users:
            uac = _uac(u.get("useraccountcontrol", 0))
            if uac & UAC_DISABLE:
                continue
            if uac & UAC_DONT_REQUIRE_PREAUTH:
                targets.append(u.get("samaccountname", "unknown"))
        if targets:
            self.findings.append({
                "id": "KRB-002", "title": f"{len(targets)} account(s) vulnerable to AS-REP roasting",
                "severity": "HIGH", "category": "Kerberos Security",
                "resource": ", ".join(targets[:10]),
                "actual": f"DONT_REQUIRE_PREAUTH set: {', '.join(targets[:5])}",
                "expected": "Kerberos pre-authentication required for all accounts",
                "recommendation": "Enable Kerberos pre-authentication for all accounts to prevent AS-REP roasting attacks",
                "remediation_cmd": "Set-ADAccountControl -Identity <account> -DoesNotRequirePreAuth $false"
            })

    def _check_unconstrained_delegation(self):
        results = self.ldap.search(
            filter_str="(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))",
            attributes=["sAMAccountName", "userAccountControl", "dNSHostName"]
        )
        targets = [r.get("samaccountname", "unknown") for r in results]
        if targets:
            self.findings.append({
                "id": "KRB-003", "title": f"{len(targets)} non-DC account(s) with unconstrained delegation",
                "severity": "CRITICAL", "category": "Kerberos Security",
                "resource": ", ".join(targets[:10]),
                "actual": f"Unconstrained delegation: {', '.join(targets[:5])}",
                "expected": "No non-DC accounts with unconstrained delegation",
                "recommendation": "Replace unconstrained delegation with constrained delegation or RBCD. Unconstrained delegation allows credential theft from any authenticating user",
                "remediation_cmd": "Set-ADAccountControl -Identity <account> -TrustedForDelegation $false"
            })

    def _check_constrained_delegation(self):
        results = self.ldap.search(
            filter_str="(userAccountControl:1.2.840.113556.1.4.803:=16777216)",
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"]
        )
        targets = [r.get("samaccountname", "unknown") for r in results]
        if targets:
            self.findings.append({
                "id": "KRB-004", "title": f"{len(targets)} account(s) with protocol transition (T2A4D)",
                "severity": "HIGH", "category": "Kerberos Security",
                "resource": ", ".join(targets[:10]),
                "actual": f"Protocol transition enabled: {', '.join(targets[:5])}",
                "expected": "Review and minimize protocol transition usage",
                "recommendation": "Protocol transition allows service to obtain tickets on behalf of any user. Review if TRUSTED_TO_AUTH_FOR_DELEGATION is necessary",
                "remediation_cmd": "Set-ADAccountControl -Identity <account> -TrustedToAuthForDelegation $false"
            })

    def _check_rbcd(self):
        results = self.ldap.search(
            filter_str="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            attributes=["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
        )
        if results:
            names = [r.get("samaccountname", "unknown") for r in results]
            self.findings.append({
                "id": "KRB-005", "title": f"{len(results)} account(s) with Resource-Based Constrained Delegation",
                "severity": "MEDIUM", "category": "Kerberos Security",
                "resource": ", ".join(names[:10]),
                "actual": f"RBCD configured: {', '.join(names[:5])}",
                "expected": "RBCD should be reviewed and minimized",
                "recommendation": "Review RBCD configurations — they can be abused for privilege escalation if write access to the computer object is compromised",
                "remediation_cmd": "Set-ADComputer <computer> -PrincipalsAllowedToDelegateToAccount $null"
            })

    def _check_des_accounts(self):
        results = self.ldap.search(
            filter_str="(userAccountControl:1.2.840.113556.1.4.803:=2097152)",
            attributes=["sAMAccountName"]
        )
        if results:
            names = [r.get("samaccountname", "unknown") for r in results]
            self.findings.append({
                "id": "KRB-006", "title": f"{len(results)} account(s) using DES-only Kerberos encryption",
                "severity": "HIGH", "category": "Kerberos Security",
                "resource": ", ".join(names[:10]),
                "actual": f"DES encryption: {', '.join(names[:5])}",
                "expected": "AES-256 encryption for all accounts",
                "recommendation": "Disable DES encryption and enable AES for all Kerberos authentication",
                "remediation_cmd": "Set-ADAccountControl -Identity <account> -UseDESKeyOnly $false"
            })

    def _check_krbtgt_password(self):
        krbtgt = self.ldap.search(
            filter_str="(sAMAccountName=krbtgt)",
            attributes=["pwdLastSet", "sAMAccountName"]
        )
        if krbtgt:
            pwd_set = krbtgt[0].get("pwdlastset", None)
            if pwd_set:
                try:
                    if isinstance(pwd_set, datetime):
                        ts = pwd_set
                    else:
                        ticks = int(pwd_set)
                        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
                    days = (datetime.now(timezone.utc) - ts).days
                    if days > 180:
                        self.findings.append({
                            "id": "KRB-013", "title": f"krbtgt password last changed {days} days ago",
                            "severity": "HIGH", "category": "Kerberos Security",
                            "resource": "krbtgt", "actual": f"{days} days old", "expected": "< 180 days",
                            "recommendation": "Rotate krbtgt password twice (with replication interval between) to invalidate any forged Golden Tickets",
                            "remediation_cmd": "Reset-ADServiceAccountPassword -Identity krbtgt (run twice with 12-hour gap)"
                        })
                except (ValueError, TypeError, OverflowError):
                    pass

    def _check_protected_users(self):
        members = self.ldap.get_group_members(f"CN=Protected Users,CN=Users,{self.ldap.base_dn}")
        if not members:
            self.findings.append({
                "id": "KRB-012", "title": "Protected Users group is empty",
                "severity": "HIGH", "category": "Kerberos Security",
                "resource": "Protected Users", "actual": "0 members", "expected": "All privileged accounts",
                "recommendation": "Add all privileged accounts (Domain Admins, Enterprise Admins) to the Protected Users group to enforce Kerberos armor and disable NTLM",
                "remediation_cmd": "Add-ADGroupMember -Identity 'Protected Users' -Members <admin_account>"
            })
