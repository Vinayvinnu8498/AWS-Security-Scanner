import boto3
from botocore.exceptions import ClientError

def scan_sqs():
    findings = []

    sqs = boto3.client("sqs")

    try:
        queues = sqs.list_queues().get("QueueUrls", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected SQS error: {e}")
        return findings

    if not queues:
        findings.append("ℹ No SQS queues found in this region.")
        return findings

    for queue_url in queues:
        findings.append(f"ℹ SQS Queue: {queue_url}")

        # 1. Queue attributes
        try:
            attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["All"]
            ).get("Attributes", {})
        except ClientError as e:
            findings.append(f"❌ Could not get attributes for {queue_url}: {e}")
            continue

        # 2. Encryption
        kms_key = attrs.get("KmsMasterKeyId")
        if kms_key:
            findings.append(f"✔ Queue is encrypted with KMS key: {kms_key}.")
        else:
            findings.append(f"⚠ Queue is NOT encrypted with a customer-managed KMS key.")

        # 3. Access policy (public access)
        policy = attrs.get("Policy")
        if policy and '"AWS":"*"' in policy:
            findings.append(f"❌ Queue {queue_url} has an overly permissive access policy (AWS:*).")
        else:
            findings.append(f"✔ Access policy is not overly permissive.")

        # 4. Dead-letter queue
        redrive = attrs.get("RedrivePolicy")
        if redrive:
            findings.append(f"✔ Dead-letter queue (DLQ) is configured.")
        else:
            findings.append(f"⚠ No dead-letter queue configured.")

        # 5. Message retention
        retention = attrs.get("MessageRetentionPeriod")
        if retention:
            findings.append(f"ℹ Message retention: {retention} seconds.")

        # 6. Visibility timeout
        visibility = attrs.get("VisibilityTimeout")
        if visibility:
            findings.append(f"ℹ Visibility timeout: {visibility} seconds.")

    return findings
