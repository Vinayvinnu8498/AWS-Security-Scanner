import boto3
from botocore.exceptions import ClientError

def scan_rds():
    findings = []

    rds = boto3.client("rds")

    try:
        dbs = rds.describe_db_instances().get("DBInstances", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected RDS error: {e}")
        return findings

    if not dbs:
        findings.append("ℹ No RDS DB instances found in this region.")
        return findings

    for db in dbs:
        db_id = db.get("DBInstanceIdentifier")
        engine = db.get("Engine")
        version = db.get("EngineVersion")
        public = db.get("PubliclyAccessible", False)
        encrypted = db.get("StorageEncrypted", False)
        multi_az = db.get("MultiAZ", False)
        backup_retention = db.get("BackupRetentionPeriod", 0)
        deletion_protection = db.get("DeletionProtection", False)

        findings.append(f"ℹ RDS Instance: {db_id} | Engine: {engine} {version}")

        # Public exposure
        if public:
            findings.append(f"❌ RDS instance {db_id} is PUBLICLY ACCESSIBLE.")
        else:
            findings.append(f"✔ RDS instance {db_id} is private.")

        # Encryption
        if encrypted:
            findings.append(f"✔ RDS instance {db_id} is encrypted at rest.")
        else:
            findings.append(f"❌ RDS instance {db_id} is NOT encrypted.")

        # Multi-AZ
        if multi_az:
            findings.append(f"✔ Multi-AZ is enabled for {db_id}.")
        else:
            findings.append(f"⚠ Multi-AZ is NOT enabled for {db_id}.")

        # Backups
        if backup_retention > 0:
            findings.append(f"✔ Backups enabled (retention: {backup_retention} days).")
        else:
            findings.append(f"❌ Backups are DISABLED for {db_id}.")

        # Deletion protection
        if deletion_protection:
            findings.append(f"✔ Deletion protection is enabled for {db_id}.")
        else:
            findings.append(f"⚠ Deletion protection is NOT enabled for {db_id}.")

    return findings
