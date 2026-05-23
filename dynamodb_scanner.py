import boto3
from botocore.exceptions import ClientError

def scan_dynamodb():
    findings = []

    dynamodb = boto3.client("dynamodb")

    try:
        tables = dynamodb.list_tables().get("TableNames", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected DynamoDB error: {e}")
        return findings

    if not tables:
        findings.append("ℹ No DynamoDB tables found in this region.")
        return findings

    for table_name in tables:
        findings.append(f"ℹ DynamoDB Table: {table_name}")

        # Describe table
        try:
            desc = dynamodb.describe_table(TableName=table_name).get("Table", {})
        except ClientError as e:
            findings.append(f"❌ Could not describe table {table_name}: {e}")
            continue

        # 1. Encryption
        sse = desc.get("SSEDescription", {})
        if sse.get("Status") == "ENABLED":
            kms_key = sse.get("KMSMasterKeyArn")
            if kms_key:
                findings.append(f"✔ Table is encrypted with KMS key: {kms_key}.")
            else:
                findings.append(f"✔ Table is encrypted with AWS-managed key.")
        else:
            findings.append(f"❌ Table is NOT encrypted.")

        # 2. PITR (Point-in-Time Recovery)
        try:
            pitr = dynamodb.describe_continuous_backups(TableName=table_name)
            pitr_status = pitr.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {})
            if pitr_status.get("PointInTimeRecoveryStatus") == "ENABLED":
                findings.append(f"✔ PITR is ENABLED for {table_name}.")
            else:
                findings.append(f"⚠ PITR is NOT enabled for {table_name}.")
        except ClientError:
            findings.append(f"⚠ Could not determine PITR status for {table_name}.")

        # 3. Streams
        stream_spec = desc.get("StreamSpecification", {})
        if stream_spec.get("StreamEnabled"):
            findings.append(f"✔ Streams ENABLED (ViewType: {stream_spec.get('StreamViewType')}).")
        else:
            findings.append(f"⚠ Streams NOT enabled.")

        # 4. Billing mode
        billing = desc.get("BillingModeSummary", {}).get("BillingMode")
        if billing == "PAY_PER_REQUEST":
            findings.append(f"✔ Billing mode: On-Demand (PAY_PER_REQUEST).")
        else:
            findings.append(f"ℹ Billing mode: Provisioned.")

        # 5. TTL
        try:
            ttl = dynamodb.describe_time_to_live(TableName=table_name)
            ttl_status = ttl.get("TimeToLiveDescription", {}).get("TimeToLiveStatus")
            if ttl_status == "ENABLED":
                findings.append(f"✔ TTL is ENABLED.")
            else:
                findings.append(f"⚠ TTL is NOT enabled.")
        except ClientError:
            findings.append(f"⚠ Could not determine TTL status.")

        # 6. Global table check
        if desc.get("GlobalSecondaryIndexes"):
            findings.append(f"ℹ Table has Global Secondary Indexes (GSIs).")

        if desc.get("Replicas"):
            findings.append(f"✔ Table is part of a GLOBAL TABLE configuration.")
        else:
            findings.append(f"ℹ Table is NOT part of a global table.")

        # 7. Size + item count
        size = desc.get("TableSizeBytes", 0)
        items = desc.get("ItemCount", 0)
        findings.append(f"ℹ Table size: {size} bytes | Items: {items}")

    return findings
