import boto3
from botocore.exceptions import ClientError

def scan_sns():
    findings = []

    sns = boto3.client("sns")

    try:
        topics = []
        next_token = None

        while True:
            if next_token:
                resp = sns.list_topics(NextToken=next_token)
            else:
                resp = sns.list_topics()

            topics.extend(resp.get("Topics", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break

    except ClientError as e:
        findings.append(f"❌ Unexpected SNS error: {e}")
        return findings

    if not topics:
        findings.append("ℹ No SNS topics found in this region.")
        return findings

    for t in topics:
        arn = t.get("TopicArn")
        findings.append(f"ℹ SNS Topic: {arn}")

        # 1. Encryption
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
        except ClientError as e:
            findings.append(f"❌ Could not get attributes for {arn}: {e}")
            continue

        kms_key = attrs.get("KmsMasterKeyId")
        if kms_key:
            findings.append(f"✔ Topic is encrypted with KMS key: {kms_key}.")
        else:
            findings.append(f"⚠ Topic is NOT encrypted with a customer-managed KMS key.")

        # 2. Access policy (public access)
        policy = attrs.get("Policy")
        if policy and '"AWS":"*"' in policy:
            findings.append(f"❌ Topic {arn} has an overly permissive access policy (AWS:*).")
        else:
            findings.append(f"✔ Access policy is not overly permissive.")

        # 3. Delivery status logging (optional hygiene)
        if attrs.get("HTTPStatusSuccessSamplingRate") or attrs.get("HTTPSuccessFeedbackRoleArn"):
            findings.append(f"ℹ Delivery status logging appears to be configured.")
        else:
            findings.append(f"⚠ Delivery status logging not clearly configured.")

    return findings
