"""Authentication security checks — NTLM, SMB signing, WDigest, credential caching."""
import logging

logger = logging.getLogger(__name__)


class AuthenticationSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running authentication security checks...")
        if not self.winrm:
            self.findings.append({"id": "AUTH-000", "title": "Authentication checks require WinRM (skipped)", "severity": "INFO", "category": "Authentication Security", "resource": self.ldap.domain, "actual": "WinRM not available", "expected": "WinRM for registry-based auth checks", "recommendation": "Re-run with WinRM enabled for complete authentication security assessment", "remediation_cmd": "Enable-PSRemoting -Force"})
            return self.findings
        self._check_ntlmv1()
        self._check_lm_hash()
        self._check_wdigest()
        self._check_smb_signing()
        self._check_smbv1()
        self._check_ntlm_restriction()
        self._check_credential_caching()
        return self.findings

    def _check_ntlmv1(self):
        ntlm = self.winrm.get_ntlm_settings()
        if isinstance(ntlm, dict):
            lm_level = ntlm.get("LMCompatibilityLevel", None)
            if lm_level is not None and int(lm_level or 0) < 5:
                self.findings.append({"id": "AUTH-001", "title": f"NTLMv1 allowed (LmCompatibilityLevel = {lm_level})", "severity": "CRITICAL" if int(lm_level or 0) < 3 else "HIGH", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": f"LmCompatibilityLevel = {lm_level}", "expected": "5 (Send NTLMv2 only, refuse LM & NTLM)", "recommendation": "Set LmCompatibilityLevel to 5 to enforce NTLMv2 and refuse LM/NTLMv1 authentication", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5"})

    def _check_lm_hash(self):
        val = self.winrm.get_lm_hash_setting()
        if val and val.strip() != "1":
            self.findings.append({"id": "AUTH-002", "title": "LM hash storage not disabled", "severity": "HIGH", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": f"NoLMHash = {val.strip()}", "expected": "NoLMHash = 1", "recommendation": "Disable LM hash storage to prevent extraction of weak LM password hashes", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 1"})

    def _check_wdigest(self):
        val = self.winrm.get_wdigest_setting()
        if val and val.strip() == "1":
            self.findings.append({"id": "AUTH-003", "title": "WDigest credential caching enabled", "severity": "CRITICAL", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": "UseLogonCredential = 1 (plaintext passwords in memory)", "expected": "UseLogonCredential = 0", "recommendation": "Disable WDigest to prevent plaintext credential caching in LSASS memory (Mimikatz target)", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0"})

    def _check_smb_signing(self):
        smb = self.winrm.get_smb_config()
        if isinstance(smb, dict):
            if not smb.get("RequireSecuritySignature", True):
                self.findings.append({"id": "AUTH-004", "title": "SMB signing not required on DC", "severity": "HIGH", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": "RequireSecuritySignature = False", "expected": "RequireSecuritySignature = True", "recommendation": "Enable mandatory SMB signing on all DCs to prevent NTLM relay and man-in-the-middle attacks", "remediation_cmd": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"})

    def _check_smbv1(self):
        smb = self.winrm.get_smb_config()
        if isinstance(smb, dict):
            if smb.get("EnableSMB1Protocol", False):
                self.findings.append({"id": "AUTH-005", "title": "SMBv1 enabled on domain controller", "severity": "CRITICAL", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": "SMBv1 enabled", "expected": "SMBv1 disabled", "recommendation": "Disable SMBv1 immediately — it is vulnerable to EternalBlue (MS17-010) and other critical exploits", "remediation_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"})

    def _check_ntlm_restriction(self):
        ntlm = self.winrm.get_ntlm_settings()
        if isinstance(ntlm, dict):
            restrict = ntlm.get("RestrictNTLM", None)
            audit = ntlm.get("AuditNTLM", None)
            if not restrict and not audit:
                self.findings.append({"id": "AUTH-006", "title": "NTLM authentication not restricted or audited", "severity": "MEDIUM", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": "No NTLM restrictions", "expected": "NTLM auditing enabled, working toward restriction", "recommendation": "Enable NTLM auditing first, then progressively restrict NTLM usage in favor of Kerberos", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name AuditReceivingNTLMTraffic -Value 2"})

    def _check_credential_caching(self):
        val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name CachedLogonsCount -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CachedLogonsCount")
        if val:
            try:
                count = int(val.strip())
                if count > 2:
                    self.findings.append({"id": "AUTH-007", "title": f"Credential caching count is {count} (too high)", "severity": "MEDIUM", "category": "Authentication Security", "resource": self.ldap.server_addr, "actual": f"CachedLogonsCount = {count}", "expected": "<= 2 on servers, 0 on DCs", "recommendation": "Reduce CachedLogonsCount to limit cached credential exposure on compromised machines", "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name CachedLogonsCount -Value 2"})
            except ValueError:
                pass
