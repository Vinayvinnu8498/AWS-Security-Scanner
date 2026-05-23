import boto3
from botocore.exceptions import ClientError

def scan_secrets_manager():
    findings = []

    sm = boto3.client("secretsmanager")

    try:
        paginator = sm.get_paginator("list_secrets")
        secrets = []

        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))

    except ClientError as e:
        findings.append(f"❌ Unexpected Secrets Manager error: {e}")
        return findings

    if not secrets:
        findings.append("ℹ No Secrets Manager secrets found in this region.")
        return findings

    for secret in secrets:
        name = secret.get("Name")
        arn = secret.get("ARN")
        kms_key = secret.get("KmsKeyId")
        rotation_enabled = secret.get("RotationEnabled", False)
        last_accessed = secret.get("LastAccessedDate")
        last_changed = secret.get("LastChangedDate")
        desc = secret.get("Description")

        findings.append(f"ℹ Secret: {name} | ARN: {arn}")

        # 1. Encryption
        if kms_key:
            findings.append(f"✔ Secret is encrypted with KMS key: {kms_key}.")
        else:
            findings.append(f"❌ Secret is NOT encrypted with a customer-managed KMS key.")

        # 2. Rotation
        if rotation_enabled:
            findings.append(f"✔ Rotation is ENABLED for {name}.")
        else:
            findings.append(f"⚠ Rotation is NOT enabled for {name}.")

        # 3. Resource policy (public access check)
        try:
            policy = sm.get_resource_policy(SecretId=arn).get("ResourcePolicy")
            if policy and '"AWS":"*"' in policy:
                findings.append(f"❌ Secret {name} has an overly permissive resource policy (AWS:*).")
            else:
                findings.append(f"✔ Resource policy is not overly permissive.")
        except ClientError:
            findings.append(f"✔ No resource policy found (default deny).")

        # 4. Last accessed
        if last_accessed:
            findings.append(f"ℹ Last accessed: {last_accessed}")
        else:
            findings.append(f"⚠ Secret {name} has NEVER been accessed.")

        # 5. Description hygiene
        if desc:
            findings.append(f"✔ Description exists.")
        else:
            findings.append(f"⚠ Secret {name} has no description.")

    return findings
