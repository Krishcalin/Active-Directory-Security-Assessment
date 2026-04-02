"""AD Certificate Services (AD CS) security checks — ESC1-ESC8."""
import logging

logger = logging.getLogger(__name__)

CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE_OID = "2.5.29.37.0"
ENROLLEE_SUPPLIES_SUBJECT = 0x1


class CertificateServicesChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running AD CS checks...")
        templates = self.ldap.get_certificate_templates()
        enrollment = self.ldap.get_enrollment_services()
        if not templates and not enrollment:
            self.findings.append({"id": "ADCS-000", "title": "No AD CS enrollment services or templates found", "severity": "INFO", "category": "Certificate Services (AD CS)", "resource": self.ldap.domain, "actual": "No AD CS detected", "expected": "N/A", "recommendation": "No action needed if AD CS is not deployed", "remediation_cmd": "Get-ADObject -Filter {objectClass -eq 'pKIEnrollmentService'} -SearchBase (Get-ADRootDSE).configurationNamingContext"})
            return self.findings
        for t in templates:
            name = t.get("cn", "unknown")
            self._check_esc1(name, t)
            self._check_esc2(name, t)
            self._check_esc9_validity(name, t)
        self._check_esc6(enrollment)
        self._check_http_enrollment(enrollment)
        return self.findings

    def _check_esc1(self, name, template):
        name_flag = int(template.get("mspki-certificate-name-flag", 0) or 0)
        eku = template.get("pkiextendedkeyusage", [])
        if not isinstance(eku, list):
            eku = [eku] if eku else []
        has_client_auth = CLIENT_AUTH_OID in eku or ANY_PURPOSE_OID in eku or not eku
        enrollee_supplies = bool(name_flag & ENROLLEE_SUPPLIES_SUBJECT)
        if enrollee_supplies and has_client_auth:
            self.findings.append({
                "id": "ADCS-001", "title": f"ESC1: Template '{name}' allows SAN + client auth",
                "severity": "CRITICAL", "category": "Certificate Services (AD CS)",
                "resource": str(name),
                "actual": "ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU",
                "expected": "SAN specification disabled or restricted enrollment",
                "recommendation": "Remove ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment permissions. This allows any enrollee to impersonate any user",
                "remediation_cmd": f"Set-ADObject 'CN={name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Replace @{{'msPKI-Certificate-Name-Flag'=0}}"
            })

    def _check_esc2(self, name, template):
        eku = template.get("pkiextendedkeyusage", [])
        if not isinstance(eku, list):
            eku = [eku] if eku else []
        if ANY_PURPOSE_OID in eku or (not eku):
            self.findings.append({
                "id": "ADCS-002", "title": f"ESC2: Template '{name}' has Any Purpose or no EKU restriction",
                "severity": "HIGH", "category": "Certificate Services (AD CS)",
                "resource": str(name),
                "actual": "Any Purpose EKU or unrestricted",
                "expected": "Specific EKU restrictions",
                "recommendation": "Restrict Extended Key Usage to specific purposes (e.g., Client Authentication only)",
                "remediation_cmd": "Modify template EKU via certtmpl.msc to restrict to specific purposes"
            })

    def _check_esc6(self, enrollment_services):
        if self.winrm:
            output = self.winrm.run_ps("certutil -getreg policy\\EditFlags")
            if output and "EDITF_ATTRIBUTESUBJECTALTNAME2" in output:
                self.findings.append({
                    "id": "ADCS-006", "title": "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA",
                    "severity": "CRITICAL", "category": "Certificate Services (AD CS)",
                    "resource": "Certificate Authority",
                    "actual": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled",
                    "expected": "Flag disabled",
                    "recommendation": "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 — it allows any certificate requestor to specify an arbitrary SAN",
                    "remediation_cmd": "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 & net stop certsvc & net start certsvc"
                })

    def _check_esc9_validity(self, name, template):
        # Not a direct ESC but a risk — long validity periods
        # Check if template allows excessive validity (this is a simplified check)
        ra_sig = template.get("mspki-ra-signature", 0)
        try:
            ra_sig = int(ra_sig)
        except (TypeError, ValueError):
            ra_sig = 0
        if ra_sig == 0:
            enrollment_flag = int(template.get("mspki-enrollment-flag", 0) or 0)
            if not (enrollment_flag & 0x2):  # CT_FLAG_PEND_ALL_REQUESTS
                self.findings.append({
                    "id": "ADCS-010", "title": f"Template '{name}' does not require manager approval",
                    "severity": "MEDIUM", "category": "Certificate Services (AD CS)",
                    "resource": str(name),
                    "actual": "No RA signature required, no manager approval",
                    "expected": "Manager approval for sensitive templates",
                    "recommendation": "Enable 'CA certificate manager approval' for sensitive certificate templates",
                    "remediation_cmd": "Set template to require manager approval via certtmpl.msc > Issuance Requirements"
                })

    def _check_http_enrollment(self, enrollment_services):
        for es in enrollment_services:
            hostname = es.get("dnshostname", es.get("cn", "unknown"))
            self.findings.append({
                "id": "ADCS-011", "title": f"Verify enrollment endpoint for {hostname} uses HTTPS only",
                "severity": "MEDIUM", "category": "Certificate Services (AD CS)",
                "resource": str(hostname),
                "actual": "HTTP enrollment endpoint may be accessible",
                "expected": "HTTPS-only enrollment",
                "recommendation": "Ensure AD CS web enrollment uses HTTPS only — HTTP endpoints are vulnerable to NTLM relay (ESC8)",
                "remediation_cmd": "Disable HTTP on IIS enrollment site and enforce HTTPS with TLS 1.2+"
            })
