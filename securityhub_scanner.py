import boto3
from botocore.exceptions import ClientError

def scan_security_hub(region):
    findings = []

    sh = boto3.client("securityhub")

    # 1. Check if Security Hub is enabled
    try:
        sh.get_enabled_standards()
        findings.append("✔ Security Hub is enabled in this account/region.")
    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code in ["SubscriptionRequiredException", "AccessDeniedException"]:
            findings.append("❌ Security Hub is NOT enabled in this account/region.")
            return findings

        findings.append(f"❌ Unexpected error: {e}")
        return findings

    # 2. List enabled standards
    standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
    if not standards:
        findings.append("⚠ No Security Hub standards are enabled (CIS, Foundational, PCI, etc.).")
    else:
        for std in standards:
            findings.append(f"ℹ Enabled standard: {std.get('StandardsArn')}")

    # 3. Pull findings
    response = sh.get_findings(MaxResults=20)
    results = response.get("Findings", [])

    if not results:
        findings.append("ℹ No Security Hub findings returned.")
        return findings

    for f in results:
        title = f.get("Title", "No title")
        severity = f.get("Severity", {}).get("Label", "UNKNOWN")
        resource = f.get("Resources", [{}])[0].get("Id", "Unknown resource")
        compliance = f.get("Compliance", {}).get("Status", "UNKNOWN")

        findings.append(
            f"Finding: '{title}' | Severity: {severity} | Compliance: {compliance} | Resource: {resource}"
        )

    return findings
