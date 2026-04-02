"""Privileged accounts security checks."""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def _uac(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


class PrivilegedAccountsChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running privileged accounts checks...")
        base = self.ldap.base_dn
        self._check_group_size("Domain Admins", f"CN=Domain Admins,CN=Users,{base}", 5, "PRIV-001")
        self._check_group_empty("Enterprise Admins", f"CN=Enterprise Admins,CN=Users,{base}", "PRIV-002")
        self._check_group_empty("Schema Admins", f"CN=Schema Admins,CN=Users,{base}", "PRIV-003")
        self._check_builtin_admin()
        self._check_stale_admins()
        self._check_admin_no_protected_users()
        self._check_orphaned_admincount()
        self._check_admin_spn()
        self._check_dangerous_groups()
        return self.findings

    def _check_group_size(self, group_name, group_dn, max_size, finding_id):
        members = self.ldap.get_group_members(group_dn)
        if len(members) > max_size:
            names = [m.get("samaccountname", "?") for m in members[:10]]
            self.findings.append({
                "id": finding_id, "title": f"{group_name} has {len(members)} members (exceeds {max_size})",
                "severity": "HIGH", "category": "Privileged Accounts",
                "resource": group_name, "actual": f"{len(members)} members: {', '.join(names)}",
                "expected": f"<= {max_size} members",
                "recommendation": f"Reduce {group_name} membership to essential accounts only. Use delegated admin roles for day-to-day tasks",
                "remediation_cmd": f"Remove-ADGroupMember -Identity '{group_name}' -Members <account> -Confirm:$false"
            })

    def _check_group_empty(self, group_name, group_dn, finding_id):
        members = self.ldap.get_group_members(group_dn)
        if members:
            names = [m.get("samaccountname", "?") for m in members[:10]]
            self.findings.append({
                "id": finding_id, "title": f"{group_name} has {len(members)} member(s) (should be empty)",
                "severity": "HIGH", "category": "Privileged Accounts",
                "resource": group_name, "actual": f"{len(members)} members: {', '.join(names)}",
                "expected": "Empty (populate only during changes)",
                "recommendation": f"Remove all members from {group_name}. Only add members temporarily when needed for schema/forest changes",
                "remediation_cmd": f"Remove-ADGroupMember -Identity '{group_name}' -Members <account> -Confirm:$false"
            })

    def _check_builtin_admin(self):
        admins = self.ldap.search(
            filter_str="(&(objectCategory=person)(objectClass=user)(objectSid=*-500))",
            attributes=["sAMAccountName", "userAccountControl", "pwdLastSet", "whenCreated"]
        )
        for admin in admins:
            name = admin.get("samaccountname", "Administrator")
            uac = _uac(admin.get("useraccountcontrol", 0))
            if not (uac & 0x2):
                if name.lower() == "administrator":
                    self.findings.append({
                        "id": "PRIV-004", "title": "Built-in Administrator account not renamed",
                        "severity": "MEDIUM", "category": "Privileged Accounts",
                        "resource": name, "actual": f"Account name: {name}", "expected": "Renamed to non-default name",
                        "recommendation": "Rename the built-in Administrator account to make it harder to target",
                        "remediation_cmd": "Rename-ADObject -Identity <AdminDN> -NewName 'DA-Admin'"
                    })

    def _check_stale_admins(self):
        da_members = self.ldap.get_group_members(f"CN=Domain Admins,CN=Users,{self.ldap.base_dn}")
        now = datetime.now(timezone.utc)
        stale = []
        for m in da_members:
            last = m.get("lastlogontimestamp", None)
            if last:
                try:
                    if isinstance(last, datetime):
                        ts = last
                    else:
                        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(last) // 10)
                    if (now - ts).days > 90:
                        stale.append(m.get("samaccountname", "?"))
                except (ValueError, TypeError, OverflowError):
                    pass
        if stale:
            self.findings.append({
                "id": "PRIV-008", "title": f"{len(stale)} stale admin account(s) (no logon > 90 days)",
                "severity": "HIGH", "category": "Privileged Accounts",
                "resource": ", ".join(stale[:10]),
                "actual": f"Inactive admins: {', '.join(stale[:5])}",
                "expected": "All admin accounts actively used or disabled",
                "recommendation": "Disable or remove admin accounts that haven't been used in 90+ days",
                "remediation_cmd": "Disable-ADAccount -Identity <account>"
            })

    def _check_admin_no_protected_users(self):
        da = self.ldap.get_group_members(f"CN=Domain Admins,CN=Users,{self.ldap.base_dn}")
        pu = self.ldap.get_group_members(f"CN=Protected Users,CN=Users,{self.ldap.base_dn}")
        pu_names = {m.get("samaccountname", "").lower() for m in pu}
        unprotected = [m.get("samaccountname", "?") for m in da if m.get("samaccountname", "").lower() not in pu_names]
        if unprotected:
            self.findings.append({
                "id": "PRIV-009", "title": f"{len(unprotected)} admin(s) not in Protected Users group",
                "severity": "HIGH", "category": "Privileged Accounts",
                "resource": ", ".join(unprotected[:10]),
                "actual": f"Not in Protected Users: {', '.join(unprotected[:5])}",
                "expected": "All admins in Protected Users",
                "recommendation": "Add all admin accounts to Protected Users group for Kerberos hardening and NTLM restriction",
                "remediation_cmd": "Add-ADGroupMember -Identity 'Protected Users' -Members <account>"
            })

    def _check_orphaned_admincount(self):
        results = self.ldap.search(
            filter_str="(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users," + self.ldap.base_dn + ")))",
            attributes=["sAMAccountName", "adminCount"]
        )
        if results:
            names = [r.get("samaccountname", "?") for r in results[:10]]
            self.findings.append({
                "id": "PRIV-010", "title": f"{len(results)} account(s) with orphaned adminCount=1",
                "severity": "MEDIUM", "category": "Privileged Accounts",
                "resource": f"{len(results)} accounts",
                "actual": f"Orphaned adminCount: {', '.join(names[:5])}",
                "expected": "adminCount cleared when removed from admin groups",
                "recommendation": "Clear adminCount and reset ACL inheritance for accounts no longer in privileged groups",
                "remediation_cmd": "Set-ADUser <account> -Clear adminCount"
            })

    def _check_admin_spn(self):
        da = self.ldap.get_group_members(f"CN=Domain Admins,CN=Users,{self.ldap.base_dn}")
        da_names = {m.get("samaccountname", "").lower() for m in da}
        spn_users = self.ldap.get_users(filter_extra="(servicePrincipalName=*)")
        admin_spn = [u.get("samaccountname", "?") for u in spn_users if u.get("samaccountname", "").lower() in da_names]
        if admin_spn:
            self.findings.append({
                "id": "PRIV-012", "title": f"{len(admin_spn)} Domain Admin(s) with SPN (Kerberoastable)",
                "severity": "CRITICAL", "category": "Privileged Accounts",
                "resource": ", ".join(admin_spn),
                "actual": f"Admin + SPN: {', '.join(admin_spn)}",
                "expected": "No admin accounts with SPNs",
                "recommendation": "Remove SPNs from admin accounts immediately — Kerberoastable admin credentials can be cracked offline",
                "remediation_cmd": "Set-ADUser <account> -ServicePrincipalNames @{Remove='<SPN>'}"
            })

    def _check_dangerous_groups(self):
        dangerous = {
            "Backup Operators": ("PRIV-013", "Can DCSync via backup privileges"),
            "Account Operators": ("PRIV-014", "Can create/modify accounts"),
            "Print Operators": ("PRIV-015", "Can load drivers on DCs — privilege escalation risk"),
        }
        for group_name, (fid, risk) in dangerous.items():
            members = self.ldap.search(
                filter_str=f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN={group_name},CN=Builtin,{self.ldap.base_dn}))",
                attributes=["sAMAccountName"]
            )
            if members:
                names = [m.get("samaccountname", "?") for m in members[:10]]
                self.findings.append({
                    "id": fid, "title": f"{group_name} has {len(members)} member(s) — {risk}",
                    "severity": "HIGH", "category": "Privileged Accounts",
                    "resource": group_name, "actual": f"{len(members)} members: {', '.join(names[:5])}",
                    "expected": "Empty or minimal membership",
                    "recommendation": f"Remove unnecessary members from {group_name}. {risk}",
                    "remediation_cmd": f"Remove-ADGroupMember -Identity '{group_name}' -Members <account>"
                })
