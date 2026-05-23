import boto3
from botocore.exceptions import ClientError


def get_multi_region_trail():
    """
    Detect a multi-region CloudTrail trail from the home region (us-east-1).
    This supports CIS 3.1, 3.2, 3.3, 3.4 checks.
    """
    client = boto3.client("cloudtrail", region_name="us-east-1")
    try:
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
        for t in trails:
            if t.get("IsMultiRegionTrail", False):
                return t
    except ClientError:
        return None
    return None


def scan_cloudtrail(region):
    """
    CloudTrail scanner with CIS mapping.
    - CIS 3.1: Ensure CloudTrail is enabled in all regions
    - CIS 3.2: Ensure CloudTrail log file validation is enabled
    - CIS 3.3: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
    - CIS 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs
    """
    findings = []

    # Detect multi-region trail globally (home region)
    multi_region_trail = get_multi_region_trail()

    # If multi-region trail exists → unified Option B behavior for ALL regions
    if multi_region_trail:
        findings.extend(scan_multi_region_trail(multi_region_trail))
        return findings

    # If no multi-region trail exists → strict fallback (still mapped to CIS 3.1)
    findings.append(
        "⚠ MEDIUM - No multi-region CloudTrail trail detected. "
        "CloudTrail may not be enabled in all regions. (CIS 3.1)"
    )
    return findings


def scan_multi_region_trail(trail):
    """
    Evaluate a detected multi-region CloudTrail trail against CIS controls.
    """
    findings = []

    name = trail.get("Name")
    arn = trail.get("TrailARN")
    home_region = trail.get("HomeRegion")

    status_client = boto3.client("cloudtrail", region_name=home_region)
    try:
        status = status_client.get_trail_status(Name=arn)
    except ClientError as e:
        findings.append(
            f"⚠ MEDIUM - Could not get CloudTrail status for trail '{name}' "
            f"in {home_region}: {e}. (CIS 3.1)"
        )
        return findings

    # -------------------------------------------------
    # CIS 3.1 - CloudTrail enabled in all regions
    # -------------------------------------------------
    findings.append(
        f"✔ LOW - CloudTrail is enabled (multi-region trail '{name}' detected in {home_region}). (CIS 3.1)"
    )

    is_logging = status.get("IsLogging", False)
    latest_delivery = status.get("LatestDeliveryTime", None)

    if is_logging:
        if latest_delivery:
            findings.append(
                f"✔ LOW - CloudTrail is actively logging. "
                f"Last delivery: {latest_delivery}. (CIS 3.1)"
            )
        else:
            findings.append(
                "⚠ MEDIUM - CloudTrail is logging but no delivery timestamp is available yet. (CIS 3.1)"
            )
    else:
        findings.append(
            "❌ CRITICAL - CloudTrail exists but IsLogging=False. "
            "Logging is NOT active. (CIS 3.1)"
        )

    # -------------------------------------------------
    # CIS 3.2 - Log file validation
    # -------------------------------------------------
    if trail.get("LogFileValidationEnabled", False):
        findings.append(
            "✔ LOW - Log file validation is enabled. (CIS 3.2)"
        )
    else:
        findings.append(
            "⚠ MEDIUM - Log file validation is NOT enabled. (CIS 3.2)"
        )

    # -------------------------------------------------
    # CIS 3.3 - SSE-KMS encryption
    # -------------------------------------------------
    if trail.get("KmsKeyId"):
        findings.append(
            "✔ LOW - SSE-KMS encryption is enabled for CloudTrail logs. (CIS 3.3)"
        )
    else:
        findings.append(
            "⚠ MEDIUM - SSE-KMS encryption is NOT enabled for CloudTrail logs. (CIS 3.3)"
        )

    # -------------------------------------------------
    # CIS 3.4 - CloudWatch Logs integration
    # -------------------------------------------------
    if trail.get("CloudWatchLogsLogGroupArn"):
        findings.append(
            "✔ LOW - CloudTrail is integrated with CloudWatch Logs. (CIS 3.4)"
        )
    else:
        findings.append(
            "ℹ INFO - CloudTrail is not integrated with CloudWatch Logs. (CIS 3.4)"
        )

    return findings
