import boto3

def scan_guardduty(region):
    findings = []
    gd = boto3.client("guardduty")

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
    except Exception as e:
        findings.append(f"❌ Unable to list GuardDuty detectors: {e}")
        return findings

    if not detectors:
        findings.append("❌ GuardDuty is NOT enabled in this region.")
        return findings

    detector_id = detectors[0]
    findings.append("✔ GuardDuty is enabled.")

    try:
        results = gd.list_findings(DetectorId=detector_id)
        finding_ids = results.get("FindingIds", [])
    except Exception as e:
        findings.append(f"⚠ Unable to list GuardDuty findings: {e}")
        return findings

    if not finding_ids:
        findings.append("ℹ No GuardDuty findings detected.")
        return findings

    details = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)

    for f in details["Findings"]:
        title = f.get("Title", "Unknown finding")
        severity = f.get("Severity", 0)
        resource = f.get("Resource", {}).get("ResourceType", "Unknown")

        sev_label = (
            "CRITICAL" if severity >= 7 else
            "MEDIUM" if severity >= 4 else
            "LOW"
        )

        findings.append(
            f"Finding: '{title}' | Severity: {sev_label} | Resource: {resource}"
        )

    return findings
