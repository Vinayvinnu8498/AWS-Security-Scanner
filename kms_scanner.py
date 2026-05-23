import boto3
from botocore.exceptions import ClientError

def scan_kms():
    findings = []

    kms = boto3.client("kms")

    try:
        paginator = kms.get_paginator("list_keys")
        key_ids = []

        for page in paginator.paginate():
            for k in page.get("Keys", []):
                key_ids.append(k["KeyId"])

        if not key_ids:
            findings.append("ℹ No KMS customer-managed keys found in this account/region.")
            return findings

        for key_id in key_ids:
            try:
                meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError as e:
                findings.append(f"❌ Could not describe key {key_id}: {e}")
                continue

            key_arn = meta.get("Arn")
            key_state = meta.get("KeyState")
            key_manager = meta.get("KeyManager")  # AWS or CUSTOMER
            enabled = meta.get("Enabled", False)

            findings.append(f"ℹ KMS Key: {key_arn} | State: {key_state} | Manager: {key_manager}")

            if not enabled:
                findings.append(f"⚠ Key {key_arn} is DISABLED.")

            if key_manager == "AWS":
                findings.append(f"✔ Key {key_arn} is AWS-managed (service key).")
            else:
                findings.append(f"✔ Key {key_arn} is customer-managed.")

                # Rotation status (only for customer-managed keys)
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    if rotation.get("KeyRotationEnabled"):
                        findings.append(f"✔ Key rotation is ENABLED for {key_arn}.")
                    else:
                        findings.append(f"⚠ Key rotation is NOT enabled for {key_arn}.")
                except ClientError as e:
                    findings.append(f"⚠ Could not get rotation status for {key_arn}: {e}")

    except ClientError as e:
        findings.append(f"❌ Unexpected KMS error: {e}")

    return findings
