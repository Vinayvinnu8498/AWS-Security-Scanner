import boto3
from botocore.exceptions import ClientError

def scan_s3_public_access(region):
    findings = []
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        findings.append(f"❌ Unable to list S3 buckets: {e}")
        return findings

    if not buckets:
        findings.append("ℹ No S3 buckets found in this region.")
        return findings

    for bucket in buckets:
        name = bucket["Name"]

        findings.append(f"ℹ Checking bucket: {name}")

        # -----------------------------
        # 1. Public Access Block
        # -----------------------------
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]

            if not all(config.values()):
                findings.append(f"❌ Bucket '{name}' does NOT fully block public access.")
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append(f"❌ Bucket '{name}' has NO Public Access Block configuration.")
            else:
                findings.append(f"⚠ Could not read Public Access Block for '{name}': {e}")

        # -----------------------------
        # 2. Bucket ACL
        # -----------------------------
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                permission = grant.get("Permission", "")

                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    findings.append(f"❌ Bucket '{name}' ACL allows PUBLIC access ({permission}).")
        except Exception as e:
            findings.append(f"⚠ Could not read ACL for '{name}': {e}")

        # -----------------------------
        # 3. Bucket Policy
        # -----------------------------
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            policy_text = policy["Policy"]

            if '"Effect":"Allow"' in policy_text and '"Principal":"*"' in policy_text:
                findings.append(f"❌ Bucket '{name}' policy allows PUBLIC access.")
        except ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                findings.append(f"ℹ Bucket '{name}' has no bucket policy.")
            else:
                findings.append(f"⚠ Could not read bucket policy for '{name}': {e}")

        # -----------------------------
        # 4. Encryption
        # -----------------------------
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            if not rules:
                findings.append(f"❌ Bucket '{name}' has NO default encryption.")
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                findings.append(f"❌ Bucket '{name}' has NO default encryption.")
            else:
                findings.append(f"⚠ Could not read encryption for '{name}': {e}")

        # -----------------------------
        # 5. Versioning
        # -----------------------------
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append(f"⚠ Bucket '{name}' does not have versioning enabled.")
        except Exception as e:
            findings.append(f"⚠ Could not read versioning for '{name}': {e}")

    return findings
