"""Service account security checks."""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def _uac(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


class ServiceAccountsChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running service account checks...")
        self._check_gmsa_adoption()
        self._check_svc_admin_membership()
        self._check_svc_password_never_expires()
        self._check_svc_stale_passwords()
        self._check_svc_default_container()
        return self.findings

    def _check_gmsa_adoption(self):
        gmsa = self.ldap.get_service_accounts()
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        regular_svc = [u for u in spn_users if not any(
            c in str(u.get("dn", "")).lower() for c in ["managedserviceaccount", "gmsa"]
        ) and not (_uac(u.get("useraccountcontrol", 0)) & 0x2)]

        if not gmsa and regular_svc:
            self.findings.append({
                "id": "SVC-009", "title": "No gMSA deployed — all service accounts use regular passwords",
                "severity": "HIGH", "category": "Service Accounts",
                "resource": f"{len(regular_svc)} service accounts",
                "actual": f"{len(regular_svc)} regular SPN accounts, 0 gMSA",
                "expected": "Service accounts migrated to gMSA",
                "recommendation": "Deploy Group Managed Service Accounts (gMSA) to eliminate manual password management for service accounts",
                "remediation_cmd": "New-ADServiceAccount -Name <gMSA> -DNSHostName <host>.corp.com -PrincipalsAllowedToRetrieveManagedPassword <group>"
            })
        elif regular_svc:
            names = [u.get("samaccountname", "?") for u in regular_svc[:10]]
            self.findings.append({
                "id": "SVC-001", "title": f"{len(regular_svc)} service account(s) not using gMSA",
                "severity": "MEDIUM", "category": "Service Accounts",
                "resource": f"{len(regular_svc)} accounts",
                "actual": f"Regular SPN accounts: {', '.join(names[:5])}{'...' if len(names) > 5 else ''}",
                "expected": "Migrate to gMSA where possible",
                "recommendation": "Convert regular service accounts with SPNs to gMSA for automatic password rotation",
                "remediation_cmd": "New-ADServiceAccount -Name <gMSA> -DNSHostName <host>.corp.com"
            })

    def _check_svc_admin_membership(self):
        da_members = self.ldap.get_group_members(f"CN=Domain Admins,CN=Users,{self.ldap.base_dn}")
        da_names = {m.get("samaccountname", "").lower() for m in da_members}
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        admin_svc = [u.get("samaccountname", "?") for u in spn_users if u.get("samaccountname", "").lower() in da_names]
        if admin_svc:
            self.findings.append({
                "id": "SVC-002", "title": f"{len(admin_svc)} service account(s) in Domain Admins",
                "severity": "CRITICAL", "category": "Service Accounts",
                "resource": ", ".join(admin_svc),
                "actual": f"DA membership: {', '.join(admin_svc)}",
                "expected": "Service accounts with minimal required privileges",
                "recommendation": "Remove service accounts from Domain Admins and grant only the specific permissions they need",
                "remediation_cmd": "Remove-ADGroupMember -Identity 'Domain Admins' -Members <svc_account>"
            })

    def _check_svc_password_never_expires(self):
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        never_expire = []
        for u in spn_users:
            uac = _uac(u.get("useraccountcontrol", 0))
            if (uac & 0x10000) and not (uac & 0x2):
                never_expire.append(u.get("samaccountname", "?"))
        if never_expire:
            self.findings.append({
                "id": "SVC-003", "title": f"{len(never_expire)} service account(s) with password never expires",
                "severity": "MEDIUM", "category": "Service Accounts",
                "resource": f"{len(never_expire)} accounts",
                "actual": f"Never expires: {', '.join(never_expire[:5])}{'...' if len(never_expire) > 5 else ''}",
                "expected": "Password rotation enforced (gMSA or FGPP)",
                "recommendation": "Migrate to gMSA for automatic rotation, or enforce password changes via fine-grained password policy",
                "remediation_cmd": "Set-ADUser <account> -PasswordNeverExpires $false"
            })

    def _check_svc_stale_passwords(self):
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        now = datetime.now(timezone.utc)
        stale = []
        for u in spn_users:
            uac = _uac(u.get("useraccountcontrol", 0))
            if uac & 0x2:
                continue
            pwd = u.get("pwdlastset", None)
            if pwd:
                try:
                    if isinstance(pwd, datetime):
                        ts = pwd
                    else:
                        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(pwd) // 10)
                    if (now - ts).days > 365:
                        stale.append(u.get("samaccountname", "?"))
                except (ValueError, TypeError, OverflowError):
                    pass
        if stale:
            self.findings.append({
                "id": "SVC-004", "title": f"{len(stale)} service account(s) with passwords > 365 days old",
                "severity": "HIGH", "category": "Service Accounts",
                "resource": f"{len(stale)} accounts",
                "actual": f"Stale passwords: {', '.join(stale[:5])}{'...' if len(stale) > 5 else ''}",
                "expected": "Passwords rotated annually at minimum",
                "recommendation": "Rotate service account passwords and migrate to gMSA for automatic management",
                "remediation_cmd": "Set-ADAccountPassword -Identity <account> -Reset -NewPassword (ConvertTo-SecureString '<new_password>' -AsPlainText -Force)"
            })

    def _check_svc_default_container(self):
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        in_users_cn = [u.get("samaccountname", "?") for u in spn_users
                       if f"CN=Users,{self.ldap.base_dn}".lower() in str(u.get("dn", "")).lower()]
        if in_users_cn:
            self.findings.append({
                "id": "SVC-010", "title": f"{len(in_users_cn)} service account(s) in default Users container",
                "severity": "LOW", "category": "Service Accounts",
                "resource": f"{len(in_users_cn)} accounts",
                "actual": f"In CN=Users: {', '.join(in_users_cn[:5])}",
                "expected": "Dedicated Service Accounts OU",
                "recommendation": "Move service accounts to a dedicated OU with appropriate GPO and delegation",
                "remediation_cmd": "Move-ADObject -Identity <account_dn> -TargetPath 'OU=Service Accounts,DC=corp,DC=com'"
            })
