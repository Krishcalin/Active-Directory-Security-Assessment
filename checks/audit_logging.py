"""Audit and logging security checks."""
import logging

logger = logging.getLogger(__name__)


class AuditLoggingChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running audit and logging checks...")
        if not self.winrm:
            self.findings.append({"id": "LOG-000", "title": "Audit logging checks require WinRM (skipped)", "severity": "INFO", "category": "Audit & Logging", "resource": self.ldap.domain, "actual": "WinRM not available", "expected": "WinRM for audit policy checks", "recommendation": "Re-run with WinRM enabled for complete audit logging assessment", "remediation_cmd": "Enable-PSRemoting -Force"})
            return self.findings
        self._check_audit_policy()
        self._check_event_log_size()
        self._check_powershell_logging()
        self._check_command_line_auditing()
        return self.findings

    def _check_audit_policy(self):
        output = self.winrm.get_audit_policy()
        if not output:
            self.findings.append({"id": "LOG-001", "title": "Unable to retrieve audit policy", "severity": "HIGH", "category": "Audit & Logging", "resource": self.ldap.server_addr, "actual": "Audit policy not readable", "expected": "Advanced audit policy configured", "recommendation": "Configure advanced audit policy via GPO for comprehensive security event logging", "remediation_cmd": "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"})
            return

        critical_categories = {
            "Logon": "LOG-002",
            "Account Lockout": "LOG-002",
            "Sensitive Privilege Use": "LOG-003",
            "Directory Service Changes": "LOG-004",
            "Process Creation": "LOG-005",
        }
        for category, fid in critical_categories.items():
            if category in output:
                section = output.split(category)[1][:100] if category in output else ""
                if "No Auditing" in section:
                    self.findings.append({
                        "id": fid, "title": f"'{category}' audit events not configured",
                        "severity": "HIGH", "category": "Audit & Logging",
                        "resource": self.ldap.server_addr,
                        "actual": f"{category}: No Auditing",
                        "expected": f"{category}: Success and Failure",
                        "recommendation": f"Enable auditing for '{category}' events (success and failure) for security monitoring and incident response",
                        "remediation_cmd": f"auditpol /set /subcategory:'{category}' /success:enable /failure:enable"
                    })

    def _check_event_log_size(self):
        log_cfg = self.winrm.get_event_log_config()
        if isinstance(log_cfg, dict):
            max_size = log_cfg.get("MaximumSizeInBytes", 0)
            try:
                max_size_mb = int(max_size) / 1024 / 1024
            except (TypeError, ValueError):
                max_size_mb = 0
            if max_size_mb < 1024:
                self.findings.append({
                    "id": "LOG-006", "title": f"Security event log size is {max_size_mb:.0f} MB (below 1 GB)",
                    "severity": "MEDIUM", "category": "Audit & Logging",
                    "resource": self.ldap.server_addr,
                    "actual": f"{max_size_mb:.0f} MB",
                    "expected": ">= 1024 MB (1 GB)",
                    "recommendation": "Increase Security event log size to at least 1 GB to retain sufficient history for incident investigation",
                    "remediation_cmd": "wevtutil sl Security /ms:1073741824"
                })
            log_mode = log_cfg.get("LogMode", "")
            if isinstance(log_mode, str) and "Circular" in log_mode:
                self.findings.append({
                    "id": "LOG-007", "title": "Security event log set to overwrite (circular mode)",
                    "severity": "MEDIUM", "category": "Audit & Logging",
                    "resource": self.ldap.server_addr,
                    "actual": f"LogMode: {log_mode}",
                    "expected": "AutoBackup or archive before overwrite",
                    "recommendation": "Configure event log to archive or forward to SIEM before overwriting to prevent evidence loss",
                    "remediation_cmd": "wevtutil sl Security /rt:false /ab:true"
                })

    def _check_powershell_logging(self):
        ps_cfg = self.winrm.get_powershell_logging()
        if isinstance(ps_cfg, dict):
            if not ps_cfg.get("ScriptBlockLogging"):
                self.findings.append({"id": "LOG-009", "title": "PowerShell script block logging not enabled", "severity": "HIGH", "category": "Audit & Logging", "resource": self.ldap.server_addr, "actual": "Disabled", "expected": "Enabled", "recommendation": "Enable PowerShell script block logging to capture obfuscated and malicious PowerShell activity", "remediation_cmd": "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"})

    def _check_command_line_auditing(self):
        val = self.winrm.run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessCreationIncludeCmdLine_Enabled")
        if not val or val.strip() != "1":
            self.findings.append({
                "id": "LOG-005", "title": "Command-line process auditing not enabled",
                "severity": "HIGH", "category": "Audit & Logging",
                "resource": self.ldap.server_addr,
                "actual": "Command-line not captured in process events",
                "expected": "Command-line included in Event ID 4688",
                "recommendation": "Enable 'Include command line in process creation events' to capture full command lines in security events for threat detection",
                "remediation_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1"
            })
