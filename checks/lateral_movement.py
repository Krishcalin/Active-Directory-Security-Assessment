"""Lateral movement risk checks."""
import logging

logger = logging.getLogger(__name__)


class LateralMovementChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running lateral movement checks...")
        self._check_laps_deployed()
        self._check_rdp_restrictions()
        self._check_restricted_admin()
        self._check_remote_credential_guard()
        return self.findings

    def _check_laps_deployed(self):
        results = self.ldap.search(
            base=self.ldap.schema_dn or f"CN=Schema,CN=Configuration,{self.ldap.base_dn}",
            filter_str="(|(name=ms-Mcs-AdmPwd)(name=msLAPS-Password))",
            attributes=["name"]
        )
        if not results:
            self.findings.append({
                "id": "LAT-001", "title": "LAPS not deployed — local admin passwords likely reused",
                "severity": "CRITICAL", "category": "Lateral Movement",
                "resource": self.ldap.domain,
                "actual": "LAPS schema extension not found",
                "expected": "LAPS deployed for all workstations and servers",
                "recommendation": "Deploy Microsoft LAPS to randomize local administrator passwords on every domain-joined machine, preventing pass-the-hash lateral movement",
                "remediation_cmd": "Install-Module LAPS; Update-LapsADSchema; Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=corp,DC=com'"
            })
        else:
            # Check if LAPS passwords are being set
            computers_with_laps = self.ldap.search(
                filter_str="(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))",
                attributes=["cn"], size_limit=1
            )
            total_computers = self.ldap.search(
                filter_str="(&(objectCategory=computer)(!(primaryGroupID=516)))",
                attributes=["cn"], size_limit=1
            )
            if not computers_with_laps and total_computers:
                self.findings.append({
                    "id": "LAT-007", "title": "LAPS schema exists but no computers have LAPS passwords set",
                    "severity": "HIGH", "category": "Lateral Movement",
                    "resource": self.ldap.domain,
                    "actual": "LAPS deployed but no passwords managed",
                    "expected": "LAPS actively managing local admin passwords",
                    "recommendation": "Configure LAPS GPO and verify it is applied to computer OUs",
                    "remediation_cmd": "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=corp,DC=com'"
                })

    def _check_rdp_restrictions(self):
        if not self.winrm:
            self.findings.append({"id": "LAT-002", "title": "RDP restriction check skipped (no WinRM)", "severity": "INFO", "category": "Lateral Movement", "resource": self.ldap.domain, "actual": "WinRM not available", "expected": "WinRM for RDP config check", "recommendation": "Re-run with WinRM to audit RDP access restrictions", "remediation_cmd": "Enable-PSRemoting -Force"})
            return
        output = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue | Select-Object -ExpandProperty fDenyTSConnections")
        if output and output.strip() == "0":
            self.findings.append({
                "id": "LAT-002", "title": "RDP enabled on domain controller",
                "severity": "MEDIUM", "category": "Lateral Movement",
                "resource": self.ldap.server_addr,
                "actual": "RDP enabled (fDenyTSConnections = 0)",
                "expected": "RDP disabled or restricted to admin jump servers",
                "recommendation": "Disable RDP on DCs or restrict via GPO to specific admin workstations only",
                "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"
            })

    def _check_restricted_admin(self):
        if not self.winrm:
            return
        val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name DisableRestrictedAdmin -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableRestrictedAdmin")
        if not val or val.strip() != "0":
            self.findings.append({
                "id": "LAT-005", "title": "Restricted Admin mode for RDP not enabled",
                "severity": "MEDIUM", "category": "Lateral Movement",
                "resource": self.ldap.server_addr,
                "actual": "Restricted Admin disabled",
                "expected": "Restricted Admin enabled for admin RDP sessions",
                "recommendation": "Enable Restricted Admin mode to prevent credential caching during RDP sessions",
                "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name DisableRestrictedAdmin -Value 0"
            })

    def _check_remote_credential_guard(self):
        if not self.winrm:
            return
        val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name DisableRestrictedAdminOutboundCreds -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableRestrictedAdminOutboundCreds")
        if not val or val.strip() != "1":
            self.findings.append({
                "id": "LAT-006", "title": "Remote Credential Guard not configured",
                "severity": "LOW", "category": "Lateral Movement",
                "resource": self.ldap.server_addr,
                "actual": "Remote Credential Guard not active",
                "expected": "Remote Credential Guard enabled for admin connections",
                "recommendation": "Enable Remote Credential Guard to protect credentials during remote desktop connections",
                "remediation_cmd": "Configure via GPO: Computer Config > Admin Templates > System > Credentials Delegation > Remote host allows delegation of non-exportable credentials"
            })
