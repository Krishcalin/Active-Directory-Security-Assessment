"""Group policy security checks."""
import logging

logger = logging.getLogger(__name__)


class GroupPolicyChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running group policy checks...")
        self._check_audit_policy()
        self._check_ps_logging()
        self._check_credential_guard()
        self._check_laps()
        self._check_unlinked_gpos()
        return self.findings

    def _check_audit_policy(self):
        if not self.winrm:
            self.findings.append({"id": "GPO-001", "title": "Advanced audit policy check skipped (no WinRM)", "severity": "INFO", "category": "Group Policy", "resource": "Audit Policy", "actual": "WinRM not available", "expected": "WinRM connection for audit checks", "recommendation": "Re-run with WinRM enabled to check audit policy configuration", "remediation_cmd": "Enable-PSRemoting -Force"})
            return
        output = self.winrm.get_audit_policy()
        if not output or "No Auditing" in output:
            self.findings.append({"id": "GPO-001", "title": "Advanced audit policy not fully configured", "severity": "HIGH", "category": "Group Policy", "resource": "Audit Policy", "actual": "Missing audit categories", "expected": "All critical categories audited", "recommendation": "Configure advanced audit policy via GPO for Logon/Logoff, Account Management, DS Access, Privilege Use", "remediation_cmd": "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"})
        if output and "Process Creation" in output and "No Auditing" in output.split("Process Creation")[1][:50]:
            self.findings.append({"id": "GPO-004", "title": "Process creation auditing not enabled", "severity": "HIGH", "category": "Group Policy", "resource": "Audit Policy", "actual": "Process creation not audited", "expected": "Process creation with command-line auditing", "recommendation": "Enable 'Audit Process Creation' and 'Include command line in process creation events'", "remediation_cmd": "auditpol /set /subcategory:'Process Creation' /success:enable"})

    def _check_ps_logging(self):
        if not self.winrm:
            return
        ps_cfg = self.winrm.get_powershell_logging()
        if isinstance(ps_cfg, dict):
            if not ps_cfg.get("ScriptBlockLogging"):
                self.findings.append({"id": "GPO-002", "title": "PowerShell script block logging not enabled", "severity": "HIGH", "category": "Group Policy", "resource": "PowerShell Logging", "actual": "Disabled", "expected": "Enabled", "recommendation": "Enable PowerShell script block logging via GPO to detect malicious scripts and living-off-the-land attacks", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"})
            if not ps_cfg.get("Transcription"):
                self.findings.append({"id": "GPO-003", "title": "PowerShell transcription logging not enabled", "severity": "MEDIUM", "category": "Group Policy", "resource": "PowerShell Logging", "actual": "Disabled", "expected": "Enabled", "recommendation": "Enable PowerShell transcription for full command history capture", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name EnableTranscripting -Value 1"})

    def _check_credential_guard(self):
        if not self.winrm:
            return
        cg = self.winrm.get_credential_guard()
        if isinstance(cg, dict):
            services = cg.get("SecurityServicesRunning", [])
            if not services or 1 not in (services if isinstance(services, list) else []):
                self.findings.append({"id": "GPO-005", "title": "Credential Guard not running on DC", "severity": "HIGH", "category": "Group Policy", "resource": "Credential Guard", "actual": "Not running", "expected": "Credential Guard active", "recommendation": "Enable Windows Defender Credential Guard to protect NTLM hashes and Kerberos tickets in memory", "remediation_cmd": "Enable via GPO: Computer Config > Admin Templates > System > Device Guard > Turn On Virtualization Based Security"})

    def _check_laps(self):
        # Check if LAPS schema extension exists
        results = self.ldap.search(
            base=self.ldap.schema_dn or f"CN=Schema,CN=Configuration,{self.ldap.base_dn}",
            filter_str="(|(name=ms-Mcs-AdmPwd)(name=msLAPS-Password))",
            attributes=["name"]
        )
        if not results:
            self.findings.append({"id": "GPO-006", "title": "LAPS not deployed (schema extension missing)", "severity": "HIGH", "category": "Group Policy", "resource": "LAPS", "actual": "LAPS schema not found", "expected": "LAPS deployed for local admin password management", "recommendation": "Deploy Microsoft LAPS (or Windows LAPS) to automatically rotate local administrator passwords on domain-joined machines", "remediation_cmd": "Install-Module LAPS; Update-LapsADSchema; Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=corp,DC=com'"})

    def _check_unlinked_gpos(self):
        gpos = self.ldap.get_gpos()
        unlinked = []
        for gpo in gpos:
            flags = gpo.get("flags", 0)
            try:
                flags = int(flags)
            except (TypeError, ValueError):
                flags = 0
            name = gpo.get("displayname", gpo.get("cn", "unknown"))
            if flags & 3:
                unlinked.append(str(name))
        if unlinked:
            self.findings.append({"id": "GPO-010", "title": f"{len(unlinked)} disabled or unlinked GPO(s) found", "severity": "LOW", "category": "Group Policy", "resource": f"{len(unlinked)} GPOs", "actual": f"Disabled GPOs: {', '.join(unlinked[:5])}", "expected": "Remove unused GPOs", "recommendation": "Review and remove disabled/unlinked GPOs to reduce attack surface and simplify management", "remediation_cmd": "Remove-GPO -Name '<GPO_Name>'"})
