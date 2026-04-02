"""WinRM client for remote PowerShell read-only commands on Domain Controllers."""

import logging

logger = logging.getLogger(__name__)

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False


class ADWinRMClient:
    """Read-only WinRM client for PowerShell-based AD checks."""

    def __init__(self, server, username, password, domain=None,
                 use_ssl=False, port=None, timeout=60):
        self.server = server
        self.username = username
        self.password = password
        self.domain = domain
        self.use_ssl = use_ssl
        self.port = port or (5986 if use_ssl else 5985)
        self.timeout = timeout
        self.session = None

    def connect(self):
        """Establish WinRM session."""
        if not WINRM_AVAILABLE:
            logger.warning("pywinrm not installed — WinRM checks will be skipped")
            return False

        scheme = "https" if self.use_ssl else "http"
        endpoint = f"{scheme}://{self.server}:{self.port}/wsman"

        try:
            self.session = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport="ntlm",
                server_cert_validation="ignore" if self.use_ssl else "validate",
                read_timeout_sec=self.timeout,
                operation_timeout_sec=self.timeout
            )
            # Test connection with a simple command
            result = self.session.run_ps("$env:COMPUTERNAME")
            if result.status_code == 0:
                hostname = result.std_out.decode().strip()
                logger.info("WinRM connected to %s (%s)", self.server, hostname)
                return True
            else:
                logger.error("WinRM test failed: %s", result.std_err.decode())
                return False
        except Exception as e:
            logger.error("WinRM connection failed to %s: %s", self.server, e)
            return False

    def disconnect(self):
        """Close WinRM session."""
        self.session = None

    def run_ps(self, script):
        """Run a PowerShell script and return stdout as string. Read-only commands only."""
        if not self.session:
            return ""
        try:
            result = self.session.run_ps(script)
            if result.status_code == 0:
                return result.std_out.decode("utf-8", errors="replace").strip()
            else:
                stderr = result.std_err.decode("utf-8", errors="replace").strip()
                logger.debug("PowerShell error: %s", stderr[:200])
                return ""
        except Exception as e:
            logger.debug("WinRM command failed: %s", e)
            return ""

    def run_ps_json(self, script):
        """Run a PowerShell script that outputs JSON, return parsed dict/list."""
        import json
        output = self.run_ps(f"{script} | ConvertTo-Json -Depth 5")
        if not output:
            return {}
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {}

    def get_audit_policy(self):
        """Get advanced audit policy configuration."""
        return self.run_ps("auditpol /get /category:* /r")

    def get_smb_config(self):
        """Get SMB server configuration."""
        return self.run_ps_json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess")

    def get_credential_guard(self):
        """Check Credential Guard status."""
        return self.run_ps_json("Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus")

    def get_laps_config(self):
        """Check if LAPS is deployed."""
        return self.run_ps("Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {name -like 'ms-Mcs-AdmPwd'} | Select-Object Name")

    def get_event_log_config(self):
        """Get Security event log configuration."""
        return self.run_ps_json("Get-WinEvent -ListLog Security | Select-Object MaximumSizeInBytes,LogMode,RecordCount,IsEnabled")

    def get_wdigest_setting(self):
        """Check WDigest UseLogonCredential registry setting."""
        return self.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UseLogonCredential")

    def get_lm_hash_setting(self):
        """Check NoLMHash registry setting."""
        return self.run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoLMHash")

    def get_ntlm_settings(self):
        """Get NTLM authentication settings."""
        return self.run_ps_json("""
            @{
                LMCompatibilityLevel = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
                RestrictNTLM = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name RestrictReceivingNTLMTraffic -ErrorAction SilentlyContinue).RestrictReceivingNTLMTraffic
                AuditNTLM = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name AuditReceivingNTLMTraffic -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
            } | ConvertTo-Json
        """)

    def get_powershell_logging(self):
        """Get PowerShell script block and transcription logging settings."""
        return self.run_ps_json("""
            @{
                ScriptBlockLogging = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
                Transcription = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
                ModuleLogging = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
            } | ConvertTo-Json
        """)
