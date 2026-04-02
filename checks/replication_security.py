"""AD replication security checks."""
import logging

logger = logging.getLogger(__name__)

GUID_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


class ReplicationSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running replication security checks...")
        self._check_dcsync_permissions()
        self._check_sysvol_replication()
        self._check_replication_health()
        return self.findings

    def _check_dcsync_permissions(self):
        # Search for non-DC principals with replication rights
        # This is a simplified check - full ACL parsing would require SDDL/binary descriptor analysis
        results = self.ldap.search(
            base=self.ldap.base_dn,
            filter_str="(objectClass=domain)",
            attributes=["nTSecurityDescriptor"]
        )
        # Since full SDDL parsing is complex, we check via WinRM if available
        if self.winrm:
            output = self.winrm.run_ps("""
                Import-Module ActiveDirectory
                $domain = (Get-ADDomain).DistinguishedName
                $acl = Get-Acl "AD:\\$domain"
                $dcGroup = (Get-ADGroup 'Domain Controllers').SID
                $acl.Access | Where-Object {
                    $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') -and
                    $_.IdentityReference -notlike '*Domain Controllers*' -and
                    $_.IdentityReference -notlike '*Enterprise Domain Controllers*' -and
                    $_.IdentityReference -notlike '*Administrators*'
                } | Select-Object IdentityReference,ObjectType | ConvertTo-Json
            """)
            if output and output.strip() not in ("", "null", "[]"):
                self.findings.append({
                    "id": "REPL-001", "title": "Non-standard accounts with DCSync permissions detected",
                    "severity": "CRITICAL", "category": "Replication Security",
                    "resource": self.ldap.domain,
                    "actual": f"Suspicious DCSync permissions found: {output[:200]}",
                    "expected": "Only Domain Controllers and Administrators with replication rights",
                    "recommendation": "Remove DCSync permissions (DS-Replication-Get-Changes-All) from non-DC accounts immediately — this allows full password hash extraction",
                    "remediation_cmd": "Remove-ADPermission -Identity 'DC=corp,DC=com' -User <account> -ExtendedRights 'Replicating Directory Changes All'"
                })
        else:
            self.findings.append({"id": "REPL-001", "title": "DCSync permission check skipped (no WinRM)", "severity": "INFO", "category": "Replication Security", "resource": self.ldap.domain, "actual": "WinRM not available for ACL analysis", "expected": "WinRM for DCSync permission audit", "recommendation": "Re-run with WinRM to check for unauthorized DCSync permissions", "remediation_cmd": "Enable-PSRemoting -Force"})

    def _check_sysvol_replication(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("Get-WmiObject -Class Win32_Service -Filter \"Name='DFSR'\" | Select-Object State | ConvertTo-Json")
        if output and "Running" not in output:
            self.findings.append({"id": "REPL-003", "title": "DFSR service not running (SYSVOL may use legacy FRS)", "severity": "HIGH", "category": "Replication Security", "resource": self.ldap.server_addr, "actual": "DFSR not running", "expected": "DFSR running for SYSVOL replication", "recommendation": "Migrate SYSVOL replication from FRS to DFSR using the DFSR Migration tool", "remediation_cmd": "dfsrmig /setglobalstate 3"})

    def _check_replication_health(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("repadmin /replsummary /errorsonly")
        if output and ("error" in output.lower() or "fail" in output.lower()):
            self.findings.append({"id": "REPL-004", "title": "AD replication errors detected", "severity": "HIGH", "category": "Replication Security", "resource": self.ldap.server_addr, "actual": f"Replication errors: {output[:200]}", "expected": "Healthy replication with no errors", "recommendation": "Investigate and resolve AD replication failures to ensure security policy consistency across all DCs", "remediation_cmd": "repadmin /replsummary && repadmin /showrepl"})
