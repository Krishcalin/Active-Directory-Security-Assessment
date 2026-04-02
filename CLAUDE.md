# CLAUDE.md — Active Directory Security Assessment

## Project Overview

Open-source Python-based security assessment tool for Microsoft Active Directory environments. Connects via LDAP/LDAPS and WinRM to audit domain configuration, Kerberos security, group policy, privilege escalation paths, credential exposure, and trust relationships. Generates interactive HTML and JSON reports with posture scoring and remediation guidance.

## Planned Repository Structure

```
ad_security_scanner.py                # Main scanner entry point (CLI)
config/
  default_profile.yaml                # Default scan profile (all checks enabled)
  compliance_maps.yaml                # CIS AD Benchmark / NIST / MITRE ATT&CK mappings
checks/
  __init__.py
  domain_config.py                    # Domain functional level, FSMO roles, tombstone lifetime, AD Recycle Bin
  kerberos_security.py                # Kerberoastable accounts, AS-REP roasting, delegation, encryption types, ticket policies
  password_policy.py                  # Fine-grained password policies, password age, lockout thresholds, reversible encryption
  privileged_accounts.py              # Domain Admins, Enterprise Admins, Schema Admins, built-in admin, nested group membership
  group_policy.py                     # GPO security settings, audit policy, restricted groups, credential guard, LAPS
  ldap_security.py                    # LDAP signing, channel binding, anonymous bind, null sessions, LDAPS enforcement
  dns_security.py                     # DNS zone security, dynamic updates, zone transfers, DNSSEC, aging/scavenging
  trust_relationships.py              # Forest/domain trusts, SID filtering, selective authentication, trust direction
  certificate_services.py             # AD CS misconfigurations, ESC1-ESC8, vulnerable templates, enrollment permissions
  replication_security.py             # DCSync permissions, replication topology, SYSVOL replication, DFSR health
  object_permissions.py               # Dangerous ACLs (WriteDACL, GenericAll, GenericWrite), AdminSDHolder, orphaned SIDs
  service_accounts.py                 # Managed service accounts (gMSA), SPNs, service account privileges, password rotation
  authentication_security.py          # NTLM relay exposure, SMB signing, NTLMv1, credential caching, WDigest
  lateral_movement.py                 # Local admin mapping, RDP access, WinRM access, PSRemoting, admin shares
  audit_logging.py                    # Advanced audit policy, SIEM forwarding, event log size, command-line auditing
utils/
  ldap_client.py                      # LDAP/LDAPS connection handler (python-ldap3)
  winrm_client.py                     # WinRM/PSRemoting client for remote PowerShell queries
  report_generator.py                 # HTML + JSON report output with severity dashboard and remediation commands
  severity.py                         # Severity classification and posture scoring
tests/
  test_data/                          # Mock LDAP responses for offline testing
  test_scanner.py                     # Unit tests for all check modules
reports/                              # Generated scan reports (gitignored)
assets/
  banner.svg                          # Repository banner
README.md
CLAUDE.md
LICENSE                               # MIT
requirements.txt                      # ldap3, pywinrm, pyyaml, jinja2
.gitignore
```

## Architecture

### Data Sources

The scanner collects AD configuration data from two sources:

1. **LDAP/LDAPS** — Primary source for domain configuration, users, groups, GPOs, ACLs, trusts, certificates
   - Base DN auto-discovered from RootDSE
   - Supports LDAP (389), LDAPS (636), and Global Catalog (3268/3269)
   - Authentication: simple bind, NTLM, or Kerberos

2. **WinRM** (optional) — For checks requiring PowerShell on Domain Controllers
   - Audit policy, event log configuration, SMB signing, credential caching
   - Requires WinRM enabled on target DCs
   - Falls back gracefully if WinRM unavailable

### Scanner Flow

1. **Connect** — Authenticate to AD via LDAP/LDAPS, optionally establish WinRM sessions
2. **Discover** — Enumerate domain info, DCs, forest topology, naming contexts
3. **Assess** — Run all enabled check modules against collected configuration
4. **Score** — Calculate posture score: `Score = 100 - (CRIT×15 + HIGH×5 + MED×2 + LOW×0.5)`
5. **Report** — Generate HTML + JSON reports with findings, severity breakdown, compliance mapping, and remediation commands

### Check Module Pattern

Each check module follows a standard pattern:
```python
class KerberosSecurityChecker:
    def __init__(self, ldap_client, winrm_client=None):
        self.ldap = ldap_client
        self.winrm = winrm_client
        self.findings = []

    def run_all(self):
        self.check_kerberoastable_accounts()
        self.check_asrep_roastable()
        self.check_unconstrained_delegation()
        # ...
        return self.findings
```

## Security Check Categories

| Category | Checks | Focus Areas |
|----------|-------:|-------------|
| Domain Configuration | ~10 | Functional level, FSMO health, tombstone, AD Recycle Bin, schema version |
| Kerberos Security | ~15 | Kerberoasting, AS-REP roasting, delegation (unconstrained/constrained/RBCD), encryption types, ticket lifetime |
| Password Policy | ~12 | Fine-grained policies, password age, lockout, reversible encryption, password-never-expires accounts |
| Privileged Accounts | ~15 | DA/EA/SA membership, nested groups, stale admins, built-in Administrator, AdminCount, protected users |
| Group Policy | ~12 | Audit policy, credential guard, LAPS, restricted groups, PowerShell logging, AppLocker |
| LDAP Security | ~10 | LDAP signing, channel binding, anonymous bind, null sessions, LDAPS, MaxPageSize |
| DNS Security | ~8 | Zone transfers, dynamic updates, DNSSEC, aging/scavenging, dangling DNS records |
| Trust Relationships | ~8 | SID filtering, selective auth, trust type/direction, stale trusts, forest trust validation |
| Certificate Services (AD CS) | ~12 | ESC1–ESC8, vulnerable templates, enrollment permissions, CA configuration, NTLM relay to ADCS |
| Replication Security | ~8 | DCSync permissions, SYSVOL replication, replication topology, lingering objects |
| Object Permissions | ~12 | Dangerous ACLs, AdminSDHolder tampering, orphaned SIDs, schema object permissions |
| Service Accounts | ~10 | gMSA adoption, SPN hygiene, service account privileges, password rotation |
| Authentication Security | ~12 | NTLMv1, SMB signing, NTLM relay, credential caching, WDigest, LM hash storage |
| Lateral Movement | ~10 | Local admin mapping, RDP/WinRM access, admin shares, restricted admin mode |
| Audit & Logging | ~10 | Advanced audit policy, event log size, SIEM forwarding, command-line auditing, PowerShell transcription |

**Total: ~165 security checks across 15 categories**

## Key Conventions

- **Language:** Python 3.9+
- **AD connectivity:** ldap3 library (pure Python LDAP client)
- **Remote execution:** pywinrm for PowerShell-based checks (optional)
- **Output formats:** HTML (self-contained dark-theme report) + JSON
- **Severity levels:** CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Finding IDs:** `{CATEGORY}-{SEQ}` format (e.g., `KRB-001`, `PWD-003`, `PRIV-012`)
- **Compliance mapping:** CIS Microsoft AD Benchmark, MITRE ATT&CK, ANSSI AD Security Guide
- **No destructive operations** — read-only LDAP queries and PowerShell Get-* commands only
- **Remediation commands** — Each finding includes PowerShell remediation commands (display only, never executed)

## Development Guidelines

- All LDAP queries must be read-only (search operations only) — never modify AD objects
- All WinRM commands must be Get-* or read-only cmdlets — never Set-*, New-*, or Remove-*
- Handle LDAP connection failures and WinRM timeouts gracefully
- Each check module is independently testable with mock LDAP responses
- Findings must include actionable remediation steps with PowerShell commands
- HTML reports should be self-contained (inline CSS/JS) matching the Phalanx Cyber portal dark theme

## CLI Usage (Planned)

```bash
# Full scan via LDAPS
python ad_security_scanner.py --server dc01.corp.com --domain corp.com --user scanner@corp.com --password <pass> --html report.html --json report.json

# Scan with NTLM auth
python ad_security_scanner.py --server 10.0.0.1 --domain corp.com --user CORP\\scanner --password <pass> --auth ntlm

# Scan specific categories
python ad_security_scanner.py --server dc01.corp.com --domain corp.com --user scanner@corp.com --password <pass> --checks kerberos,password_policy,privileged_accounts

# LDAP only (no WinRM)
python ad_security_scanner.py --server dc01.corp.com --domain corp.com --user scanner@corp.com --password <pass> --no-winrm

# Use scan profile
python ad_security_scanner.py --server dc01.corp.com --domain corp.com --user scanner@corp.com --password <pass> --profile config/default_profile.yaml
```
