import os
import datetime
import json

def generate_html_report(summary, findings, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.html")

    # HTML HEADER
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Security Report - {timestamp}</title>
<style>
    body {{
        background-color: #0d1117;
        color: #e6edf3;
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 20px;
    }}
    h1, h2, h3 {{
        color: #58a6ff;
    }}
    .summary-card {{
        background: #161b22;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 20px;
        border: 1px solid #30363d;
    }}
    .badge {{
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
        color: white;
    }}
    .CRITICAL {{ background-color: #da3633; }}
    .MEDIUM {{ background-color: #d29922; }}
    .LOW {{ background-color: #3fb950; }}
    .INFO {{ background-color: #58a6ff; }}

    details {{
        background: #161b22;
        padding: 10px;
        border-radius: 6px;
        margin-bottom: 10px;
        border: 1px solid #30363d;
    }}
    summary {{
        cursor: pointer;
        font-size: 1.1em;
        font-weight: bold;
    }}
    .finding {{
        margin-left: 20px;
        padding: 5px 0;
        border-bottom: 1px solid #30363d;
    }}
</style>
</head>
<body>

<h1>AWS Security Scan Report</h1>
<p><strong>Generated:</strong> {timestamp}</p>

<div class="summary-card">
    <h2>Summary</h2>
    <p><strong>Regions Scanned:</strong> {summary.get("regions_scanned")}</p>
    <p><strong>Total Findings:</strong> {summary.get("total_findings")}</p>
    <p><strong>Risk Score:</strong> {summary.get("risk_score")}/100</p>

    <h3>Severity Breakdown</h3>
    <p>
        <span class="badge CRITICAL">CRITICAL: {summary["severity_counts"].get("CRITICAL", 0)}</span>
        <span class="badge MEDIUM">MEDIUM: {summary["severity_counts"].get("MEDIUM", 0)}</span>
        <span class="badge LOW">LOW: {summary["severity_counts"].get("LOW", 0)}</span>
        <span class="badge INFO">INFO: {summary["severity_counts"].get("INFO", 0)}</span>
    </p>
</div>

<h2>Detailed Findings</h2>
"""

    # BODY CONTENT
    for service, regions in findings.items():
        html += f"<h3>{service}</h3>"
        for region, items in regions.items():
            html += f"<details><summary>{region}</summary>"
            for item in items:
                html += f"<div class='finding'>{item}</div>"
            html += "</details>"

    # FOOTER
    html += """
</body>
</html>
"""

    # WRITE FILE
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"HTML report saved to: {filename}")
    return filename
