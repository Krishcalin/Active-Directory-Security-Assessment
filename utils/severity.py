"""Severity classification and posture scoring."""

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_WEIGHTS = {
    "CRITICAL": 15,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 0.5,
    "INFO": 0,
}


def compute_posture_score(findings):
    """Compute posture score: 100 - (CRIT*15 + HIGH*5 + MED*2 + LOW*0.5). Clamped 0-100."""
    penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    return max(0, min(100, round(100 - penalty, 1)))


def score_to_grade(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def severity_counts(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
