"""Password policy security checks."""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def _ad_ts_to_days(ticks):
    """Convert AD timestamp (100ns intervals since 1601) to age in days."""
    try:
        if isinstance(ticks, datetime):
            return (datetime.now(timezone.utc) - ticks.replace(tzinfo=timezone.utc)).days
        ticks = int(ticks)
        if ticks == 0 or ticks == 9223372036854775807:
            return -1
        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
        return (datetime.now(timezone.utc) - ts).days
    except (ValueError, TypeError, OverflowError):
        return -1


class PasswordPolicyChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        logger.info("Running password policy checks...")
        domain = self.ldap.get_domain_info()
        self._check_min_length(domain)
        self._check_complexity(domain)
        self._check_max_age(domain)
        self._check_min_age(domain)
        self._check_history(domain)
        self._check_lockout(domain)
        self._check_reversible_encryption(domain)
        self._check_fgpp()
        self._check_never_expires()
        self._check_not_required()
        self._check_stale_passwords()
        return self.findings

    def _check_min_length(self, domain):
        val = int(domain.get("minpwdlength", 0) or 0)
        if val < 14:
            self.findings.append({
                "id": "PWD-001", "title": f"Minimum password length is {val} (below 14)",
                "severity": "HIGH" if val < 8 else "MEDIUM",
                "category": "Password Policy", "resource": self.ldap.domain,
                "actual": str(val), "expected": ">= 14 characters",
                "recommendation": "Increase minimum password length to 14+ characters per CIS benchmark",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14"
            })

    def _check_complexity(self, domain):
        props = int(domain.get("pwdproperties", 0) or 0)
        if not (props & 1):
            self.findings.append({
                "id": "PWD-002", "title": "Password complexity requirements disabled",
                "severity": "HIGH", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": "Disabled", "expected": "Enabled",
                "recommendation": "Enable password complexity to require uppercase, lowercase, digits, and special characters",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true"
            })

    def _check_max_age(self, domain):
        val = domain.get("maxpwdage", None)
        try:
            if isinstance(val, timedelta):
                days = abs(val.days)
            else:
                ticks = abs(int(val))
                days = ticks // 864000000000 if ticks > 0 else 0
        except (TypeError, ValueError):
            days = 0
        if days == 0 or days > 90:
            self.findings.append({
                "id": "PWD-003", "title": f"Maximum password age is {days} days" if days else "Passwords never expire",
                "severity": "HIGH" if days == 0 else "MEDIUM",
                "category": "Password Policy", "resource": self.ldap.domain,
                "actual": f"{days} days" if days else "Never expires", "expected": "<= 90 days",
                "recommendation": "Set maximum password age to 60-90 days",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00"
            })

    def _check_min_age(self, domain):
        val = domain.get("minpwdage", None)
        try:
            if isinstance(val, timedelta):
                days = abs(val.days)
            else:
                ticks = abs(int(val))
                days = ticks // 864000000000 if ticks > 0 else 0
        except (TypeError, ValueError):
            days = 0
        if days == 0:
            self.findings.append({
                "id": "PWD-004", "title": "Minimum password age is 0 (allows immediate cycling)",
                "severity": "MEDIUM", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": "0 days", "expected": ">= 1 day",
                "recommendation": "Set minimum password age to at least 1 day to prevent password cycling through history",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -MinPasswordAge 1.00:00:00"
            })

    def _check_history(self, domain):
        val = int(domain.get("pwdhistorylength", 0) or 0)
        if val < 24:
            self.findings.append({
                "id": "PWD-005", "title": f"Password history is {val} (below 24)",
                "severity": "MEDIUM", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": str(val), "expected": ">= 24",
                "recommendation": "Set password history to 24 to prevent password reuse",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24"
            })

    def _check_lockout(self, domain):
        threshold = int(domain.get("lockoutthreshold", 0) or 0)
        if threshold == 0:
            self.findings.append({
                "id": "PWD-006", "title": "Account lockout threshold is 0 (no lockout)",
                "severity": "HIGH", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": "0 (disabled)", "expected": "5-10 attempts",
                "recommendation": "Set account lockout threshold to 5-10 failed attempts to prevent brute-force attacks",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00"
            })

    def _check_reversible_encryption(self, domain):
        props = int(domain.get("pwdproperties", 0) or 0)
        if props & 16:
            self.findings.append({
                "id": "PWD-008", "title": "Reversible encryption enabled for passwords",
                "severity": "CRITICAL", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": "Enabled", "expected": "Disabled",
                "recommendation": "Disable reversible encryption immediately — it stores passwords in a recoverable format equivalent to plaintext",
                "remediation_cmd": "Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled $false"
            })

    def _check_fgpp(self):
        fgpp = self.ldap.get_fine_grained_password_policies()
        if not fgpp:
            self.findings.append({
                "id": "PWD-009", "title": "No fine-grained password policies configured",
                "severity": "MEDIUM", "category": "Password Policy", "resource": self.ldap.domain,
                "actual": "No FGPPs", "expected": "FGPPs for privileged and service accounts",
                "recommendation": "Create fine-grained password policies with stricter requirements for admin and service accounts",
                "remediation_cmd": "New-ADFineGrainedPasswordPolicy -Name 'Admin-FGPP' -Precedence 10 -MinPasswordLength 16 -ComplexityEnabled $true"
            })

    def _check_never_expires(self):
        users = self.ldap.get_users(filter_extra="(userAccountControl:1.2.840.113556.1.4.803:=65536)")
        enabled = [u for u in users if not (int(u.get("useraccountcontrol", 0) or 0) & 0x2)]
        if len(enabled) > 0:
            names = [u.get("samaccountname", "?") for u in enabled[:10]]
            self.findings.append({
                "id": "PWD-010", "title": f"{len(enabled)} enabled account(s) with PASSWORD_NEVER_EXPIRES",
                "severity": "HIGH" if len(enabled) > 20 else "MEDIUM",
                "category": "Password Policy", "resource": f"{len(enabled)} accounts",
                "actual": f"{len(enabled)} accounts: {', '.join(names)}{'...' if len(enabled) > 10 else ''}",
                "expected": "Password expiry enforced for all accounts",
                "recommendation": "Remove PASSWORD_NEVER_EXPIRES flag or use fine-grained policies for service accounts",
                "remediation_cmd": "Set-ADUser <account> -PasswordNeverExpires $false"
            })

    def _check_not_required(self):
        users = self.ldap.get_users(filter_extra="(userAccountControl:1.2.840.113556.1.4.803:=32)")
        enabled = [u for u in users if not (int(u.get("useraccountcontrol", 0) or 0) & 0x2)]
        if enabled:
            names = [u.get("samaccountname", "?") for u in enabled[:10]]
            self.findings.append({
                "id": "PWD-011", "title": f"{len(enabled)} account(s) with PASSWORD_NOT_REQUIRED",
                "severity": "CRITICAL", "category": "Password Policy",
                "resource": f"{len(enabled)} accounts",
                "actual": f"{len(enabled)} accounts: {', '.join(names)}",
                "expected": "No accounts with PASSWORD_NOT_REQUIRED",
                "recommendation": "Remove PASSWORD_NOT_REQUIRED flag — these accounts can have empty passwords",
                "remediation_cmd": "Set-ADAccountControl -Identity <account> -PasswordNotRequired $false"
            })

    def _check_stale_passwords(self):
        users = self.ldap.get_users()
        stale = []
        for u in users:
            uac = int(u.get("useraccountcontrol", 0) or 0)
            if uac & 0x2:
                continue
            pwd_set = u.get("pwdlastset", None)
            days = _ad_ts_to_days(pwd_set)
            if days > 365:
                stale.append(u.get("samaccountname", "?"))
        if stale:
            self.findings.append({
                "id": "PWD-012", "title": f"{len(stale)} enabled account(s) with passwords older than 365 days",
                "severity": "HIGH" if len(stale) > 50 else "MEDIUM",
                "category": "Password Policy", "resource": f"{len(stale)} accounts",
                "actual": f"{len(stale)} stale passwords: {', '.join(stale[:5])}{'...' if len(stale) > 5 else ''}",
                "expected": "Passwords rotated within policy maximum age",
                "recommendation": "Force password reset for accounts with stale passwords and investigate service accounts for rotation",
                "remediation_cmd": "Set-ADUser <account> -ChangePasswordAtLogon $true"
            })
