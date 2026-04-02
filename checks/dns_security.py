"""DNS security checks."""
import logging

logger = logging.getLogger(__name__)


class DnsSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running DNS security checks...")
        self._check_zone_transfers()
        self._check_dynamic_updates()
        self._check_scavenging()
        self._check_global_query_block()
        return self.findings

    def _check_zone_transfers(self):
        if not self.winrm:
            self.findings.append({"id": "DNS-001", "title": "DNS zone transfer check skipped (no WinRM)", "severity": "INFO", "category": "DNS Security", "resource": "DNS Server", "actual": "WinRM not available", "expected": "WinRM for DNS checks", "recommendation": "Re-run with WinRM to audit DNS zone transfer settings", "remediation_cmd": "Enable-PSRemoting -Force"})
            return
        output = self.winrm.run_ps("Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Primary'} | Select-Object ZoneName,SecureSecondaries | ConvertTo-Json")
        if output and "TransferAnyServer" in output:
            self.findings.append({"id": "DNS-001", "title": "DNS zone transfers allowed to any server", "severity": "HIGH", "category": "DNS Security", "resource": "DNS Zones", "actual": "Zone transfers: TransferAnyServer", "expected": "Zone transfers restricted to named servers only", "recommendation": "Restrict DNS zone transfers to specific secondary DNS servers only", "remediation_cmd": "Set-DnsServerPrimaryZone -Name 'corp.com' -SecureSecondaries TransferToSecureServers"})

    def _check_dynamic_updates(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Primary'} | Select-Object ZoneName,DynamicUpdate | ConvertTo-Json")
        if output and "NonsecureAndSecure" in output:
            self.findings.append({"id": "DNS-002", "title": "DNS dynamic updates set to Nonsecure and Secure", "severity": "HIGH", "category": "DNS Security", "resource": "DNS Zones", "actual": "NonsecureAndSecure", "expected": "Secure only", "recommendation": "Set dynamic DNS updates to 'Secure only' for AD-integrated zones to prevent DNS poisoning", "remediation_cmd": "Set-DnsServerPrimaryZone -Name 'corp.com' -DynamicUpdate Secure"})

    def _check_scavenging(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("Get-DnsServerScavenging | Select-Object ScavengingState | ConvertTo-Json")
        if output and ("False" in output or "false" in output):
            self.findings.append({"id": "DNS-004", "title": "DNS scavenging not enabled", "severity": "MEDIUM", "category": "DNS Security", "resource": "DNS Server", "actual": "Scavenging disabled", "expected": "Scavenging enabled with 7-day intervals", "recommendation": "Enable DNS scavenging to automatically remove stale DNS records that could be hijacked", "remediation_cmd": "Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00"})

    def _check_global_query_block(self):
        if not self.winrm:
            return
        output = self.winrm.run_ps("Get-DnsServerGlobalQueryBlockList | Select-Object -ExpandProperty List")
        if output:
            if "wpad" not in output.lower():
                self.findings.append({"id": "DNS-006", "title": "WPAD not in DNS global query block list", "severity": "HIGH", "category": "DNS Security", "resource": "DNS Server", "actual": "WPAD not blocked", "expected": "WPAD in global query block list", "recommendation": "Add WPAD to DNS global query block list to prevent WPAD-based NTLM relay attacks", "remediation_cmd": "Set-DnsServerGlobalQueryBlockList -List 'wpad','isatap'"})
        elif output == "":
            self.findings.append({"id": "DNS-006", "title": "DNS global query block list is empty", "severity": "HIGH", "category": "DNS Security", "resource": "DNS Server", "actual": "Empty block list", "expected": "WPAD and ISATAP blocked", "recommendation": "Configure DNS global query block list with WPAD and ISATAP entries", "remediation_cmd": "Set-DnsServerGlobalQueryBlockList -List 'wpad','isatap'"})
