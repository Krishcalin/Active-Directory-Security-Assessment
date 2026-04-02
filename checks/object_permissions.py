"""AD object permission (ACL) security checks."""
import logging

logger = logging.getLogger(__name__)


class ObjectPermissionsChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running object permissions checks...")
        self._check_pre_win2k_group()
        self._check_domain_acls()
        self._check_adminsdholder()
        return self.findings

    def _check_pre_win2k_group(self):
        members = self.ldap.search(
            filter_str=f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{self.ldap.base_dn}))",
            attributes=["sAMAccountName"]
        )
        # Check if "Authenticated Users" is a member (common misconfiguration)
        group = self.ldap.search(
            base=f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{self.ldap.base_dn}",
            filter_str="(objectClass=group)",
            attributes=["member"]
        )
        if group:
            member_list = group[0].get("member", [])
            if not isinstance(member_list, list):
                member_list = [member_list] if member_list else []
            # If there are members, flag it
            if member_list:
                self.findings.append({
                    "id": "ACL-011", "title": "Pre-Windows 2000 Compatible Access group has members",
                    "severity": "HIGH", "category": "Object Permissions",
                    "resource": "Pre-Windows 2000 Compatible Access",
                    "actual": f"{len(member_list)} members",
                    "expected": "Empty (or only necessary service accounts)",
                    "recommendation": "Remove all unnecessary members from Pre-Windows 2000 Compatible Access group — it grants read access to all AD objects which aids reconnaissance",
                    "remediation_cmd": "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members <account>"
                })

    def _check_domain_acls(self):
        if not self.winrm:
            self.findings.append({"id": "ACL-001", "title": "Domain ACL audit skipped (no WinRM)", "severity": "INFO", "category": "Object Permissions", "resource": self.ldap.domain, "actual": "WinRM not available for ACL analysis", "expected": "WinRM for comprehensive ACL audit", "recommendation": "Re-run with WinRM for full domain object permission analysis", "remediation_cmd": "Enable-PSRemoting -Force"})
            return
        # Check for dangerous permissions on domain object
        output = self.winrm.run_ps("""
            Import-Module ActiveDirectory
            $domain = (Get-ADDomain).DistinguishedName
            $acl = Get-Acl "AD:\\$domain"
            $dangerous = $acl.Access | Where-Object {
                ($_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner') -and
                $_.IdentityReference -notlike '*Domain Admins*' -and
                $_.IdentityReference -notlike '*Enterprise Admins*' -and
                $_.IdentityReference -notlike '*Administrators*' -and
                $_.IdentityReference -notlike '*SYSTEM*'
            } | Select-Object IdentityReference,ActiveDirectoryRights | ConvertTo-Json
        """)
        if output and output.strip() not in ("", "null", "[]"):
            self.findings.append({
                "id": "ACL-001", "title": "Non-admin principals with dangerous permissions on domain object",
                "severity": "CRITICAL", "category": "Object Permissions",
                "resource": self.ldap.domain,
                "actual": f"Dangerous ACLs: {output[:300]}",
                "expected": "Only Domain Admins/Enterprise Admins with GenericAll/WriteDACL",
                "recommendation": "Remove GenericAll, WriteDACL, and WriteOwner permissions from non-admin principals on the domain object",
                "remediation_cmd": "Use dsacls or PowerShell Remove-ADPermission to revoke excessive permissions"
            })

    def _check_adminsdholder(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("""
            Import-Module ActiveDirectory
            $sdh = Get-ADObject 'CN=AdminSDHolder,CN=System,' + (Get-ADDomain).DistinguishedName
            $acl = Get-Acl "AD:\\$($sdh.DistinguishedName)"
            $custom = $acl.Access | Where-Object {
                $_.IdentityReference -notlike '*Administrators*' -and
                $_.IdentityReference -notlike '*Domain Admins*' -and
                $_.IdentityReference -notlike '*Enterprise Admins*' -and
                $_.IdentityReference -notlike '*SYSTEM*' -and
                $_.IdentityReference -notlike '*Account Operators*' -and
                ($_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite')
            } | Select-Object IdentityReference,ActiveDirectoryRights | ConvertTo-Json
        """)
        if output and output.strip() not in ("", "null", "[]"):
            self.findings.append({
                "id": "ACL-005", "title": "AdminSDHolder ACL has custom dangerous permissions",
                "severity": "CRITICAL", "category": "Object Permissions",
                "resource": "AdminSDHolder",
                "actual": f"Custom ACL entries: {output[:300]}",
                "expected": "Default AdminSDHolder ACL only",
                "recommendation": "AdminSDHolder ACL propagates to all protected accounts every 60 minutes. Remove unauthorized entries immediately",
                "remediation_cmd": "Reset AdminSDHolder ACL to defaults using dsacls or manually remove unauthorized ACEs"
            })
