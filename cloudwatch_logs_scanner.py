import boto3
from botocore.exceptions import ClientError

def scan_cloudwatch_logs():
    findings = []

    logs = boto3.client("logs")

    try:
        log_groups = []
        next_token = None

        while True:
            if next_token:
                resp = logs.describe_log_groups(nextToken=next_token)
            else:
                resp = logs.describe_log_groups()

            log_groups.extend(resp.get("logGroups", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break

    except ClientError as e:
        findings.append(f"❌ Unexpected CloudWatch Logs error: {e}")
        return findings

    if not log_groups:
        findings.append("ℹ No CloudWatch log groups found in this region.")
        return findings

    for lg in log_groups:
        name = lg.get("logGroupName")
        findings.append(f"ℹ Log Group: {name}")

        # 1. Retention policy
        retention = lg.get("retentionInDays")
        if retention:
            findings.append(f"✔ Retention policy set: {retention} days.")
        else:
            findings.append(f"⚠ No retention policy set (logs kept indefinitely).")

        # 2. Encryption
        kms_key = lg.get("kmsKeyId")
        if kms_key:
            findings.append(f"✔ Encrypted with KMS key: {kms_key}.")
        else:
            findings.append(f"⚠ Log group is NOT encrypted with a customer-managed KMS key.")

        # 3. Resource policy (public access check)
        try:
            policy_resp = logs.get_resource_policy()
            policy_doc = policy_resp.get("policyDocument", "")
            if '"AWS":"*"' in policy_doc:
                findings.append(f"❌ Log group may be exposed via overly permissive resource policy.")
            else:
                findings.append(f"✔ No overly permissive resource policy detected.")
        except ClientError:
            findings.append(f"ℹ No resource policy attached to this log group.")

        # 4. Special service checks
        if name.startswith("/aws/lambda/"):
            findings.append("ℹ Lambda log group detected.")
        if "VPCFlowLogs" in name:
            findings.append("ℹ VPC Flow Logs group detected.")
        if "CloudTrail" in name:
            findings.append("ℹ CloudTrail log group detected.")

    return findings
