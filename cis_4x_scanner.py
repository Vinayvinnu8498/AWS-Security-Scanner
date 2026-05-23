# cis_4x_scanner.py

import boto3

LOG_GROUP_NAME = "aws-cloudtrail-logs-257426645494-f702f63c"
NAMESPACE = "CISBenchmark"

REQUIRED_FILTERS = [
    "UnauthorizedAPICalls",
    "ConsoleLoginNoMFA",
    "RootLogin",
    "IAMPolicyChanges",
    "CloudTrailChanges",
]

REQUIRED_ALARMS = [
    "CIS-4.3-UnauthorizedAPICalls",
    "CIS-4.4-ConsoleLoginNoMFA",
    "CIS-4.5-RootLogin",
    "CIS-4.6-IAMPolicyChanges",
    "CIS-4.7-CloudTrailChanges",
]

def check_metric_filters(region):
    logs = boto3.client("logs", region_name=region)

    filters = []
    next_token = None

    while True:
        kwargs = {"logGroupName": LOG_GROUP_NAME}
        if next_token:
            kwargs["nextToken"] = next_token

        resp = logs.describe_metric_filters(**kwargs)
        filters.extend(resp.get("metricFilters", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break

    existing = {f["filterName"] for f in filters}
    missing = [f for f in REQUIRED_FILTERS if f not in existing]

    return missing


def check_alarms(region):
    cloudwatch = boto3.client("cloudwatch", region_name=region)

    alarms = []
    next_token = None

    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token

        resp = cloudwatch.describe_alarms(**kwargs)
        alarms.extend(resp.get("MetricAlarms", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    existing = {a["AlarmName"] for a in alarms}
    missing = [a for a in REQUIRED_ALARMS if a not in existing]

    return missing


def run_cis_4x_check(region):
    findings = []

    # Metric Filters
    missing_filters = check_metric_filters(region)
    if missing_filters:
        findings.append(f"❌ Missing Metric Filters: {', '.join(missing_filters)}")
    else:
        findings.append("✔ All required CIS 4.x Metric Filters exist")

    # Alarms
    missing_alarms = check_alarms(region)
    if missing_alarms:
        findings.append(f"❌ Missing CloudWatch Alarms: {', '.join(missing_alarms)}")
    else:
        findings.append("✔ All required CIS 4.x CloudWatch Alarms exist")

    # Overall
    if missing_filters or missing_alarms:
        findings.append("❌ CIS 4.x Overall Status: FAIL")
    else:
        findings.append("✔ CIS 4.x Overall Status: PASS")

    return findings
