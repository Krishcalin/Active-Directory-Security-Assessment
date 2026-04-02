"""Domain configuration security checks."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

FUNCTIONAL_LEVELS = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}


class DomainConfigChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running domain configuration checks...")
        domain = self.ldap.get_domain_info()
        dcs = self.ldap.get_domain_controllers()
        self._check_functional_level(domain)
        self._check_recycle_bin()
        self._check_tombstone(domain)
        self._check_machine_quota(domain)
        self._check_dc_os(dcs)
        self._check_stale_dcs(dcs)
        return self.findings

    def _check_functional_level(self, domain):
        level = domain.get("msds-behavior-version", None)
        try:
            level = int(level)
        except (TypeError, ValueError):
            level = -1
        level_name = FUNCTIONAL_LEVELS.get(level, f"Unknown ({level})")
        if level < 5:
            self.findings.append({
                "id": "DOM-001", "title": f"Domain functional level is {level_name}",
                "severity": "CRITICAL" if level < 4 else "HIGH",
                "category": "Domain Configuration", "resource": self.ldap.domain,
                "actual": level_name, "expected": "2016 (level 7) or higher",
                "recommendation": "Raise domain functional level to enable modern security features (Protected Users, Authentication Policies)",
                "remediation_cmd": "Set-ADDomainMode -Identity corp.com -DomainMode Windows2016Domain"
            })

    def _check_recycle_bin(self):
        results = self.ldap.search(
            base=f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{self.ldap.config_dn}",
            filter_str="(objectClass=msDS-OptionalFeature)",
            attributes=["msDS-EnabledFeatureBL"]
        )
        enabled = False
        if results:
            bl = results[0].get("msds-enabledfeaturebl", None)
            enabled = bl is not None and bl
        if not enabled:
            self.findings.append({
                "id": "DOM-003", "title": "AD Recycle Bin not enabled",
                "severity": "HIGH", "category": "Domain Configuration",
                "resource": self.ldap.domain, "actual": "Disabled", "expected": "Enabled",
                "recommendation": "Enable AD Recycle Bin to allow recovery of accidentally deleted objects",
                "remediation_cmd": "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target corp.com"
            })

    def _check_tombstone(self, domain):
        ts = domain.get("tombstonelifetime", 180)
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            ts = 180
        if ts < 180:
            self.findings.append({
                "id": "DOM-004", "title": f"Tombstone lifetime is {ts} days (below 180)",
                "severity": "MEDIUM", "category": "Domain Configuration",
                "resource": self.ldap.domain, "actual": f"{ts} days", "expected": ">= 180 days",
                "recommendation": "Increase tombstone lifetime to prevent lingering object issues and support backup recovery windows",
                "remediation_cmd": "Set-ADObject 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com' -Replace @{tombstoneLifetime=180}"
            })

    def _check_machine_quota(self, domain):
        quota = domain.get("ms-ds-machineaccountquota", 10)
        try:
            quota = int(quota)
        except (TypeError, ValueError):
            quota = 10
        if quota > 0:
            self.findings.append({
                "id": "DOM-005", "title": f"Machine account quota is {quota} (any user can join {quota} computers)",
                "severity": "HIGH", "category": "Domain Configuration",
                "resource": self.ldap.domain, "actual": str(quota), "expected": "0",
                "recommendation": "Set ms-DS-MachineAccountQuota to 0 to prevent unprivileged users from joining rogue computers to the domain",
                "remediation_cmd": "Set-ADDomain -Identity corp.com -Replace @{'ms-DS-MachineAccountQuota'=0}"
            })

    def _check_dc_os(self, dcs):
        for dc in dcs:
            os_ver = str(dc.get("operatingsystem", ""))
            name = dc.get("cn", dc.get("dnshostname", "unknown"))
            if any(old in os_ver for old in ["2008", "2003", "2000", "2012"]):
                self.findings.append({
                    "id": "DOM-008", "title": f"DC {name} running outdated OS: {os_ver}",
                    "severity": "HIGH" if "2008" in os_ver or "2003" in os_ver else "MEDIUM",
                    "category": "Domain Configuration", "resource": str(name),
                    "actual": os_ver, "expected": "Windows Server 2016 or later",
                    "recommendation": "Upgrade domain controller to Server 2019/2022 for latest security features and patches",
                    "remediation_cmd": "Plan DC migration: dcpromo to decommission old DC after promoting new Server 2022 DC"
                })

    def _check_stale_dcs(self, dcs):
        now = datetime.now(timezone.utc)
        for dc in dcs:
            name = dc.get("cn", dc.get("dnshostname", "unknown"))
            last_logon = dc.get("lastlogontimestamp", None)
            if last_logon:
                try:
                    if isinstance(last_logon, datetime):
                        ts = last_logon
                    else:
                        ticks = int(last_logon)
                        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + __import__('datetime').timedelta(microseconds=ticks // 10)
                    days = (now - ts).days
                    if days > 60:
                        self.findings.append({
                            "id": "DOM-009", "title": f"DC {name} last logon {days} days ago (possibly stale)",
                            "severity": "MEDIUM", "category": "Domain Configuration",
                            "resource": str(name), "actual": f"Last logon {days} days ago", "expected": "< 60 days",
                            "recommendation": "Investigate stale DC — demote and remove if decommissioned to prevent security risks",
                            "remediation_cmd": "Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartitions"
                        })
                except (ValueError, TypeError, OverflowError):
                    pass
