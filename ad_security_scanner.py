#!/usr/bin/env python3
"""
Active Directory Security Assessment Scanner
=============================================
Open-source security assessment tool for Microsoft Active Directory environments.
Connects via LDAP/LDAPS and WinRM to audit domain configuration, Kerberos security,
group policy, privilege escalation paths, credential exposure, and trust relationships.

Usage:
    python ad_security_scanner.py --server <dc> --domain <domain> --user <user> --password <pass> [options]

Author: Phalanx Cyber
License: MIT
"""

import argparse
import logging
import sys
import os
import yaml
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.ldap_client import ADLdapClient
from utils.winrm_client import ADWinRMClient
from utils.report_generator import generate_html_report, generate_json_report
from utils.severity import compute_posture_score, score_to_grade, severity_counts, SEVERITY_ORDER
from checks import ALL_CHECKERS

BANNER = r"""
    _        _   _             ____  _               _
   / \   ___| |_(_)_   _____  |  _ \(_)_ __ ___  ___| |_ ___  _ __ _   _
  / _ \ / __| __| \ \ / / _ \ | | | | | '__/ _ \/ __| __/ _ \| '__| | | |
 / ___ \ (__| |_| |\ V /  __/ | |_| | | | |  __/ (__| || (_) | |  | |_| |
/_/   \_\___|\__|_| \_/ \___| |____/|_|_|  \___|\___|\__\___/|_|   \__, |
                                                                     |___/
    Security Assessment Scanner v1.0.0
    https://github.com/Krishcalin/Active-Directory-Security-Assessment
"""


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_profile(profile_path):
    """Load scan profile from YAML file."""
    if not profile_path or not os.path.exists(profile_path):
        return None
    with open(profile_path, "r") as f:
        return yaml.safe_load(f)


def get_enabled_checks(args, profile):
    """Determine which check categories to run."""
    if args.checks:
        return [c.strip() for c in args.checks.split(",")]
    if profile and "checks" in profile:
        return [k for k, v in profile["checks"].items() if v]
    return list(ALL_CHECKERS.keys())


def print_summary(findings):
    """Print colored summary to console."""
    counts = severity_counts(findings)
    score = compute_posture_score(findings)
    grade = score_to_grade(score)

    colors = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
        "LOW": "\033[92m", "INFO": "\033[94m",
        "RESET": "\033[0m", "BOLD": "\033[1m", "WHITE": "\033[97m",
    }

    print(f"\n{colors['BOLD']}{'='*60}")
    print(f"  SCAN RESULTS SUMMARY")
    print(f"{'='*60}{colors['RESET']}\n")
    print(f"  {colors['WHITE']}Total Findings:{colors['RESET']}  {len(findings)}")
    print(f"  {colors['WHITE']}Posture Score:{colors['RESET']}   {score}/100 (Grade {grade})\n")
    print(f"  {colors['BOLD']}Severity Breakdown:{colors['RESET']}")
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c > 0:
            print(f"    {colors.get(sev, '')}{sev:10s}{colors['RESET']}  {c}")

    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1

    if categories:
        print(f"\n  {colors['BOLD']}Category Breakdown:{colors['RESET']}")
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"    {cat:35s}  {cnt}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Security Assessment Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --server dc01.corp.com --domain corp.com --user scanner@corp.com --password MyP@ss
  %(prog)s --server 10.0.0.1 --domain corp.com --user CORP\\scanner --password MyP@ss --auth ntlm
  %(prog)s --server dc01.corp.com --domain corp.com --user scanner@corp.com --password MyP@ss --checks kerberos_security,password_policy
  %(prog)s --server dc01.corp.com --domain corp.com --user scanner@corp.com --password MyP@ss --no-winrm --html report.html
""",
    )

    conn = parser.add_argument_group("Connection")
    conn.add_argument("--server", required=True, help="Domain Controller IP or hostname")
    conn.add_argument("--domain", required=True, help="AD domain name (e.g., corp.com)")
    conn.add_argument("--user", required=True, help="Username (user@domain or DOMAIN\\user)")
    conn.add_argument("--password", required=True, help="Password")
    conn.add_argument("--port", type=int, help="LDAP port (default: 389 or 636 with --ssl)")
    conn.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    conn.add_argument("--auth", choices=["simple", "ntlm"], default="simple",
                       help="Authentication method (default: simple)")
    conn.add_argument("--no-verify-ssl", action="store_true", help="Skip SSL certificate verification")
    conn.add_argument("--timeout", type=int, default=30, help="Connection timeout (default: 30s)")

    winrm = parser.add_argument_group("WinRM")
    winrm.add_argument("--no-winrm", action="store_true", help="Skip WinRM-based checks")
    winrm.add_argument("--winrm-port", type=int, help="WinRM port (default: 5985 or 5986)")
    winrm.add_argument("--winrm-ssl", action="store_true", help="Use HTTPS for WinRM")

    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("--checks", help="Comma-separated check categories to run")
    scan.add_argument("--profile", help="Path to YAML scan profile")

    output = parser.add_argument_group("Output")
    output.add_argument("--html", help="HTML report output path")
    output.add_argument("--json", help="JSON report output path")
    output.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    output.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and summary")

    args = parser.parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("scanner")

    if not args.quiet:
        print(BANNER)

    profile = load_profile(args.profile)
    enabled = get_enabled_checks(args, profile)
    logger.info("Enabled check categories: %s", ", ".join(enabled))

    # Connect via LDAP
    ldap_client = ADLdapClient(
        server=args.server,
        domain=args.domain,
        username=args.user,
        password=args.password,
        port=args.port,
        use_ssl=args.ssl,
        auth=args.auth,
        verify_ssl=not args.no_verify_ssl,
        timeout=args.timeout,
    )

    try:
        logger.info("Connecting to %s via %s...", args.server, "LDAPS" if args.ssl else "LDAP")
        ldap_client.connect()
        logger.info("LDAP connected, base DN: %s", ldap_client.base_dn)
    except Exception as e:
        logger.error("LDAP connection failed: %s", e)
        sys.exit(1)

    # Optionally connect via WinRM
    winrm_client = None
    if not args.no_winrm:
        winrm_client = ADWinRMClient(
            server=args.server,
            username=args.user,
            password=args.password,
            domain=args.domain,
            use_ssl=args.winrm_ssl,
            port=args.winrm_port,
            timeout=args.timeout,
        )
        try:
            if winrm_client.connect():
                logger.info("WinRM connected")
            else:
                logger.warning("WinRM connection failed — WinRM-dependent checks will be skipped")
                winrm_client = None
        except Exception as e:
            logger.warning("WinRM unavailable: %s — skipping WinRM checks", e)
            winrm_client = None

    # Run checks
    all_findings = []
    for check_name in enabled:
        if check_name not in ALL_CHECKERS:
            logger.warning("Unknown check category: %s (skipping)", check_name)
            continue
        checker_cls = ALL_CHECKERS[check_name]
        try:
            checker = checker_cls(ldap_client, winrm_client)
            findings = checker.run_all()
            all_findings.extend(findings)
            logger.info("  %s: %d findings", check_name, len(findings))
        except Exception as e:
            logger.error("  %s: error — %s", check_name, e)
            if args.verbose:
                import traceback
                traceback.print_exc()

    # Disconnect
    ldap_client.disconnect()
    if winrm_client:
        winrm_client.disconnect()
    logger.info("Disconnected")

    # Build metadata
    metadata = {
        "target": f"{args.domain} ({args.server})",
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": "1.0.0",
        "checks_run": enabled,
        "total_checks_available": len(ALL_CHECKERS),
        "winrm_used": winrm_client is not None,
    }

    if not args.quiet:
        print_summary(all_findings)

    if args.html:
        generate_html_report(all_findings, metadata, args.html)
        logger.info("HTML report: %s", args.html)
        if not args.quiet:
            print(f"  HTML report: {args.html}")

    if args.json:
        generate_json_report(all_findings, metadata, args.json)
        logger.info("JSON report: %s", args.json)
        if not args.quiet:
            print(f"  JSON report: {args.json}")

    if not args.html and not args.json:
        logger.info("No report output specified. Use --html and/or --json.")

    counts = severity_counts(all_findings)
    if counts.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif counts.get("HIGH", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
