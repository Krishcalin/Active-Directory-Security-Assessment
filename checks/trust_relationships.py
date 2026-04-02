"""Trust relationship security checks."""
import logging

logger = logging.getLogger(__name__)

TRUST_DIR = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Windows NT", 2: "Active Directory"}


class TrustRelationshipsChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running trust relationship checks...")
        trusts = self.ldap.get_trusts()
        if not trusts:
            self.findings.append({"id": "TRUST-000", "title": "No domain trusts configured", "severity": "INFO", "category": "Trust Relationships", "resource": self.ldap.domain, "actual": "No trusts found", "expected": "N/A", "recommendation": "No action needed if single-domain forest", "remediation_cmd": "Get-ADTrust -Filter *"})
            return self.findings
        for trust in trusts:
            name = trust.get("cn", trust.get("trustpartner", "unknown"))
            attrs = int(trust.get("trustattributes", 0) or 0)
            direction = int(trust.get("trustdirection", 0) or 0)
            self._check_sid_filtering(name, attrs, direction)
            self._check_selective_auth(name, attrs)
            self._check_bidirectional(name, direction)
        return self.findings

    def _check_sid_filtering(self, name, attrs, direction):
        sid_filtered = bool(attrs & 0x4)
        if not sid_filtered and direction in (1, 3):
            self.findings.append({"id": "TRUST-001", "title": f"SID filtering disabled on trust to {name}", "severity": "CRITICAL", "category": "Trust Relationships", "resource": str(name), "actual": "SID filtering not enabled", "expected": "SID filtering quarantined", "recommendation": "Enable SID filtering to prevent SID history injection attacks from trusted domains", "remediation_cmd": f"netdom trust {name} /domain:corp.com /quarantine:yes"})

    def _check_selective_auth(self, name, attrs):
        selective = bool(attrs & 0x20)
        if not selective:
            self.findings.append({"id": "TRUST-004", "title": f"Selective authentication not enabled on trust to {name}", "severity": "MEDIUM", "category": "Trust Relationships", "resource": str(name), "actual": "Forest-wide authentication", "expected": "Selective authentication", "recommendation": "Enable selective authentication to restrict which users from the trusted domain can access resources", "remediation_cmd": f"Set-ADTrust -Identity {name} -SelectiveAuthentication $true"})

    def _check_bidirectional(self, name, direction):
        if direction == 3:
            self.findings.append({"id": "TRUST-003", "title": f"Bidirectional trust with {name}", "severity": "LOW", "category": "Trust Relationships", "resource": str(name), "actual": "Bidirectional trust", "expected": "Review if unidirectional would suffice", "recommendation": "Evaluate if bidirectional trust is necessary — unidirectional trusts reduce attack surface", "remediation_cmd": "Review trust requirements and consider reconfiguring as one-way trust if appropriate"})
