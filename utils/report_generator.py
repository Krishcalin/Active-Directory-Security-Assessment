"""HTML and JSON report generator for AD security scan results."""

import json
import html
import os
from datetime import datetime
from .severity import compute_posture_score, score_to_grade, severity_counts, SEVERITY_ORDER


def generate_json_report(findings, metadata, output_path):
    """Write findings to a JSON report file."""
    report = {
        "scan_metadata": metadata,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts(findings),
            "posture_score": compute_posture_score(findings),
            "grade": score_to_grade(compute_posture_score(findings)),
        },
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return output_path


def generate_html_report(findings, metadata, output_path):
    """Generate a self-contained HTML report with dark theme."""
    score = compute_posture_score(findings)
    grade = score_to_grade(score)
    counts = severity_counts(findings)
    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1

    sev_colors = {
        "CRITICAL": "#ff4757",
        "HIGH": "#ff6b35",
        "MEDIUM": "#ffa502",
        "LOW": "#2ed573",
        "INFO": "#70a1ff",
    }

    grade_colors = {"A": "#2ed573", "B": "#7bed9f", "C": "#ffa502", "D": "#ff6b35", "F": "#ff4757"}

    findings_html = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        color = sev_colors.get(sev, "#70a1ff")
        rem_cmd = f.get("remediation_cmd", "")
        rem_row = f'<tr><th>Remediation</th><td><code class="remediation-cmd">{html.escape(str(rem_cmd))}</code></td></tr>' if rem_cmd else ''
        findings_html += f"""
        <div class="finding" data-severity="{sev}" data-category="{html.escape(f.get('category', 'Other'))}">
          <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
            <span class="finding-sev" style="background:{color}">{sev}</span>
            <span class="finding-id">{html.escape(f.get('id', ''))}</span>
            <span class="finding-title">{html.escape(f.get('title', ''))}</span>
            <span class="finding-resource">{html.escape(str(f.get('resource', '')))}</span>
            <span class="finding-toggle">&#9660;</span>
          </div>
          <div class="finding-body">
            <table>
              <tr><th>Resource</th><td>{html.escape(str(f.get('resource', '')))}</td></tr>
              <tr><th>Current Value</th><td>{html.escape(str(f.get('actual', '')))}</td></tr>
              <tr><th>Expected Value</th><td>{html.escape(str(f.get('expected', '')))}</td></tr>
              <tr><th>Recommendation</th><td>{html.escape(str(f.get('recommendation', '')))}</td></tr>
              {rem_row}
            </table>
          </div>
        </div>"""

    sev_cards = ""
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        color = sev_colors.get(sev, "#70a1ff")
        sev_cards += f"""
        <div class="sev-card" onclick="filterSeverity('{sev}')" style="border-top:3px solid {color}">
          <div class="sev-count" style="color:{color}">{c}</div>
          <div class="sev-label">{sev}</div>
        </div>"""

    cat_bars = ""
    max_cat = max(categories.values()) if categories else 1
    for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
        pct = (cnt / max_cat) * 100
        cat_bars += f"""
        <div class="cat-row">
          <span class="cat-name">{html.escape(cat)}</span>
          <div class="cat-bar-bg"><div class="cat-bar" style="width:{pct}%"></div></div>
          <span class="cat-count">{cnt}</span>
        </div>"""

    score_ring_color = grade_colors.get(grade, "#ffa502")

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Security Assessment — {html.escape(metadata.get('target', 'Unknown'))}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#0a0e1a;color:#c8ccd4;line-height:1.6}}
a{{color:#00d4ff;text-decoration:none}}
.container{{max-width:1200px;margin:0 auto;padding:24px}}
.back-link{{display:inline-flex;align-items:center;gap:8px;color:#8b92a5;margin-bottom:24px;font-size:14px}}
.back-link:hover{{color:#00d4ff}}

/* Logo */
.report-logo{{display:flex;align-items:center;gap:12px;margin-bottom:16px}}
.report-logo svg{{width:40px;height:40px;flex-shrink:0}}
.report-logo-text{{font-size:20px;font-weight:700;letter-spacing:-0.3px}}
.report-logo-text span:first-child{{color:#fff}}
.report-logo-text span:last-child{{color:#00d4ff}}
.report-logo-sub{{font-size:11px;color:#8b92a5;letter-spacing:0.5px;text-transform:uppercase}}

/* Header */
.report-header{{background:linear-gradient(135deg,rgba(0,212,255,.08),rgba(123,97,255,.08));border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:32px;margin-bottom:24px}}
.report-title{{font-size:24px;font-weight:700;color:#fff;margin-bottom:8px}}
.report-meta{{display:flex;gap:24px;flex-wrap:wrap;font-size:13px;color:#8b92a5}}
.report-meta span{{display:flex;align-items:center;gap:6px}}

/* Severity Cards */
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.sev-card{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:16px;text-align:center;cursor:pointer;transition:transform .15s}}
.sev-card:hover{{transform:translateY(-2px);background:rgba(255,255,255,.06)}}
.sev-card.active{{background:rgba(255,255,255,.08);box-shadow:0 0 0 2px rgba(0,212,255,.3)}}
.sev-count{{font-size:28px;font-weight:700}}
.sev-label{{font-size:12px;text-transform:uppercase;color:#8b92a5;margin-top:4px}}

/* Dashboard */
.dashboard{{display:grid;grid-template-columns:280px 1fr;gap:24px;margin-bottom:24px}}
.score-panel{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:32px;text-align:center}}
.score-ring{{position:relative;width:160px;height:160px;margin:0 auto 16px}}
.score-ring svg{{transform:rotate(-90deg)}}
.score-ring circle{{fill:none;stroke-width:10}}
.score-ring .bg{{stroke:rgba(255,255,255,.06)}}
.score-ring .fg{{stroke:{score_ring_color};stroke-linecap:round;transition:stroke-dashoffset .8s ease}}
.score-value{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}}
.score-value .num{{font-size:36px;font-weight:700;color:#fff}}
.score-value .grade{{font-size:18px;color:{score_ring_color};font-weight:600}}
.cat-panel{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:24px}}
.cat-panel h3{{color:#fff;margin-bottom:16px;font-size:16px}}
.cat-row{{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
.cat-name{{width:200px;font-size:13px;text-align:right;color:#8b92a5}}
.cat-bar-bg{{flex:1;height:20px;background:rgba(255,255,255,.04);border-radius:4px;overflow:hidden}}
.cat-bar{{height:100%;background:linear-gradient(90deg,#00d4ff,#7b61ff);border-radius:4px;transition:width .5s ease}}
.cat-count{{width:30px;font-size:13px;font-weight:600;color:#fff}}

/* Filters */
.filters{{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
.filters input,.filters select{{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:#c8ccd4;padding:8px 12px;border-radius:8px;font-size:13px;font-family:inherit}}
.filters input{{flex:1;min-width:200px}}
.filters select{{min-width:140px}}
.filters input:focus,.filters select:focus{{outline:none;border-color:#00d4ff}}

/* Remediation */
.remediation-cmd{{font-family:'JetBrains Mono',monospace;font-size:12px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.15);border-radius:6px;padding:8px 12px;display:block;white-space:pre-wrap;word-break:break-all;color:#00d4ff;line-height:1.5}}

/* Findings */
.finding{{background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:12px;margin-bottom:8px;overflow:hidden}}
.finding-header{{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;transition:background .15s}}
.finding-header:hover{{background:rgba(255,255,255,.04)}}
.finding-sev{{padding:2px 10px;border-radius:6px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase;white-space:nowrap}}
.finding-id{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#8b92a5;min-width:80px}}
.finding-title{{flex:1;color:#fff;font-weight:500;font-size:14px}}
.finding-resource{{font-size:12px;color:#8b92a5;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.finding-toggle{{color:#8b92a5;font-size:10px;transition:transform .2s}}
.finding.open .finding-toggle{{transform:rotate(180deg)}}
.finding-body{{display:none;padding:0 16px 16px}}
.finding.open .finding-body{{display:block}}
.finding-body table{{width:100%;border-collapse:collapse}}
.finding-body th{{text-align:left;padding:8px 12px;color:#8b92a5;font-size:12px;font-weight:500;width:140px;vertical-align:top}}
.finding-body td{{padding:8px 12px;font-size:13px;color:#c8ccd4}}
.finding-body tr+tr{{border-top:1px solid rgba(255,255,255,.04)}}

/* Footer */
.report-footer{{text-align:center;padding:32px 0;color:#5a6072;font-size:12px;border-top:1px solid rgba(255,255,255,.04);margin-top:32px}}

@media(max-width:768px){{
  .sev-grid{{grid-template-columns:repeat(3,1fr)}}
  .dashboard{{grid-template-columns:1fr}}
  .cat-name{{width:140px}}
}}
</style>
</head>
<body>
<div class="container">
  <a href="../index.html" class="back-link">&#8249; Back to Portal</a>

  <div class="report-header">
    <div class="report-logo">
      <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M20 2L6 9v12c0 9.33 5.97 18.06 14 20 8.03-1.94 14-10.67 14-20V9L20 2z" fill="rgba(0,212,255,0.08)" stroke="#00D4FF" stroke-width="1.5"/>
        <path d="M20 8l-9 4.5v7.5c0 6.22 3.63 12.04 9 13.5 5.37-1.46 9-7.28 9-13.5v-7.5L20 8z" fill="rgba(0,212,255,0.05)" stroke="#00D4FF" stroke-width="0.5" opacity="0.6"/>
        <circle cx="17" cy="18" r="1.5" fill="#00D4FF" opacity="0.8"/>
        <circle cx="23" cy="18" r="1.5" fill="#00D4FF" opacity="0.8"/>
        <circle cx="20" cy="23" r="1.5" fill="#00D4FF" opacity="0.8"/>
        <circle cx="17" cy="28" r="1" fill="#00D4FF" opacity="0.5"/>
        <circle cx="23" cy="28" r="1" fill="#00D4FF" opacity="0.5"/>
      </svg>
      <div>
        <div class="report-logo-text"><span>Phalanx</span><span>Cyber</span></div>
        <div class="report-logo-sub">Open-Source Security Tools</div>
      </div>
    </div>
    <div class="report-title">Active Directory Security Assessment</div>
    <div class="report-meta">
      <span>Domain: {html.escape(metadata.get('target', 'Unknown'))}</span>
      <span>Date: {html.escape(metadata.get('date', ''))}</span>
      <span>Findings: {len(findings)}</span>
      <span>Score: {score}/100 ({grade})</span>
    </div>
  </div>

  <div class="sev-grid">{sev_cards}</div>

  <div class="dashboard">
    <div class="score-panel">
      <div class="score-ring">
        <svg viewBox="0 0 160 160">
          <circle class="bg" cx="80" cy="80" r="70"/>
          <circle class="fg" cx="80" cy="80" r="70"
            stroke-dasharray="{2 * 3.14159 * 70}"
            stroke-dashoffset="{2 * 3.14159 * 70 * (1 - score / 100)}"/>
        </svg>
        <div class="score-value">
          <div class="num">{score}</div>
          <div class="grade">Grade {grade}</div>
        </div>
      </div>
      <div style="color:#8b92a5;font-size:13px">Security Posture Score</div>
    </div>
    <div class="cat-panel">
      <h3>Findings by Category</h3>
      {cat_bars}
    </div>
  </div>

  <div class="filters">
    <input type="text" id="searchInput" placeholder="Search findings..." oninput="filterFindings()">
    <select id="sevFilter" onchange="filterFindings()">
      <option value="">All Severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
      <option value="INFO">Info</option>
    </select>
    <select id="catFilter" onchange="filterFindings()">
      <option value="">All Categories</option>
      {"".join(f'<option value="{html.escape(c)}">{html.escape(c)}</option>' for c in sorted(categories.keys()))}
    </select>
  </div>

  <div id="findings">{findings_html}</div>

  <div class="report-footer">
    Active Directory Security Assessment &mdash; Generated by Phalanx Cyber Open-Source Scanner<br>
    {html.escape(metadata.get('date', ''))}
  </div>
</div>

<script>
function filterSeverity(sev) {{
  const cards = document.querySelectorAll('.sev-card');
  const filter = document.getElementById('sevFilter');
  const current = filter.value;
  if (current === sev) {{
    filter.value = '';
    cards.forEach(c => c.classList.remove('active'));
  }} else {{
    filter.value = sev;
    cards.forEach(c => {{
      c.classList.toggle('active', c.querySelector('.sev-label').textContent === sev);
    }});
  }}
  filterFindings();
}}

function filterFindings() {{
  const search = document.getElementById('searchInput').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const cat = document.getElementById('catFilter').value;
  document.querySelectorAll('.finding').forEach(f => {{
    const matchSev = !sev || f.dataset.severity === sev;
    const matchCat = !cat || f.dataset.category === cat;
    const text = f.textContent.toLowerCase();
    const matchSearch = !search || text.includes(search);
    f.style.display = (matchSev && matchCat && matchSearch) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
    return output_path
