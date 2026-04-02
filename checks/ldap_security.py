"""LDAP security checks."""
import logging

logger = logging.getLogger(__name__)


class LdapSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running LDAP security checks...")
        self._check_ldap_signing()
        self._check_channel_binding()
        self._check_anonymous_bind()
        self._check_ldaps()
        return self.findings

    def _check_ldap_signing(self):
        if self.winrm:
            val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LDAPServerIntegrity")
            if val and val.strip() != "2":
                self.findings.append({"id": "LDAP-001", "title": "LDAP signing not required", "severity": "HIGH", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": f"LDAPServerIntegrity = {val.strip()}", "expected": "2 (Require signing)", "recommendation": "Set LDAP server signing to 'Require signing' to prevent LDAP relay attacks", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 2"})
            elif not val:
                self.findings.append({"id": "LDAP-001", "title": "LDAP signing configuration not found", "severity": "HIGH", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": "Registry key not set", "expected": "LDAPServerIntegrity = 2", "recommendation": "Configure LDAP signing requirement via GPO or registry", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 2"})
        else:
            self.findings.append({"id": "LDAP-001", "title": "LDAP signing check skipped (no WinRM)", "severity": "INFO", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": "WinRM not available", "expected": "WinRM for registry check", "recommendation": "Re-run with WinRM to check LDAP signing configuration", "remediation_cmd": "Enable-PSRemoting -Force"})

    def _check_channel_binding(self):
        if self.winrm:
            val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LdapEnforceChannelBinding")
            if not val or val.strip() != "2":
                self.findings.append({"id": "LDAP-002", "title": "LDAP channel binding not required", "severity": "HIGH", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": f"LdapEnforceChannelBinding = {val.strip() if val else 'not set'}", "expected": "2 (Always)", "recommendation": "Set LDAP channel binding to 'Always' to prevent NTLM relay to LDAP", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LdapEnforceChannelBinding -Value 2"})

    def _check_anonymous_bind(self):
        try:
            results = self.ldap.search(
                filter_str="(objectClass=dSHeuristics)",
                base=f"CN=Directory Service,CN=Windows NT,CN=Services,{self.ldap.config_dn}",
                attributes=["dSHeuristics"]
            )
            if results:
                heuristics = str(results[0].get("dsheuristics", ""))
                if len(heuristics) >= 7 and heuristics[6] == "2":
                    self.findings.append({"id": "LDAP-003", "title": "Anonymous LDAP bind allowed (dsHeuristics)", "severity": "HIGH", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": f"dsHeuristics[6] = 2 (anonymous bind enabled)", "expected": "Anonymous bind disabled", "recommendation": "Disable anonymous LDAP bind by modifying dsHeuristics 7th character to 0", "remediation_cmd": "Set-ADObject 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com' -Replace @{dSHeuristics='0000000'}"})
        except Exception:
            pass

    def _check_ldaps(self):
        if not self.ldap.use_ssl:
            self.findings.append({"id": "LDAP-005", "title": "Scanner connected via unencrypted LDAP (port 389)", "severity": "MEDIUM", "category": "LDAP Security", "resource": self.ldap.server_addr, "actual": "LDAP (unencrypted)", "expected": "LDAPS (port 636) or StartTLS", "recommendation": "Use LDAPS (port 636) for all LDAP communications to encrypt data in transit", "remediation_cmd": "Install SSL certificate on DC and configure LDAPS: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl"})
