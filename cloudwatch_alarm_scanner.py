import boto3

SECURITY_METRICS = {
    "Unauthorized API Calls": "UnauthorizedAPICalls",
    "Console Login Without MFA": "ConsoleLoginWithoutMFA",
    "Root Login": "RootLogin",
    "IAM Policy Changes": "IAMPolicyChanges",
    "CloudTrail Configuration Changes": "CloudTrailChanges",
}

def scan_cloudwatch_security_alarms(region):
    findings = []
    client = boto3.client("cloudwatch")

    try:
        alarms = client.describe_alarms().get("MetricAlarms", [])
        alarm_names = [a["AlarmName"] for a in alarms]

        for label, metric in SECURITY_METRICS.items():
            matches = [a for a in alarm_names if metric.lower() in a.lower()]

            if matches:
                findings.append(f"✔ Alarm exists for: {label}")
            else:
                findings.append(f"❌ Missing CloudWatch alarm for: {label}")

    except Exception as e:
        findings.append(f"⚠ Unable to check CloudWatch alarms: {e}")

    return findings
