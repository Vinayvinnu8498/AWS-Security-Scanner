import boto3
from botocore.exceptions import ClientError

def scan_ebs():
    findings = []

    ec2 = boto3.client("ec2")

    # 1. Volumes
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected error while describing EBS volumes: {e}")
        return findings

    if not volumes:
        findings.append("ℹ No EBS volumes found in this region.")
    else:
        for vol in volumes:
            vol_id = vol.get("VolumeId")
            encrypted = vol.get("Encrypted", False)
            state = vol.get("State")
            attachments = vol.get("Attachments", [])

            findings.append(f"ℹ Volume {vol_id} | State: {state} | Encrypted: {encrypted}")

            if not encrypted:
                findings.append(f"❌ Volume {vol_id} is NOT encrypted.")

            if not attachments:
                findings.append(f"⚠ Volume {vol_id} is unattached (orphaned).")

    # 2. Public snapshots (owned by this account)
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected error while describing EBS snapshots: {e}")
        return findings

    if not snapshots:
        findings.append("ℹ No EBS snapshots found in this account/region.")
    else:
        for snap in snapshots:
            snap_id = snap.get("SnapshotId")
            encrypted = snap.get("Encrypted", False)

            findings.append(f"ℹ Snapshot {snap_id} | Encrypted: {encrypted}")

            if not encrypted:
                findings.append(f"⚠ Snapshot {snap_id} is NOT encrypted.")

        # Check for public snapshots via snapshot attributes
        for snap in snapshots:
            snap_id = snap.get("SnapshotId")
            try:
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snap_id,
                    Attribute="createVolumePermission"
                )
                perms = attrs.get("CreateVolumePermissions", [])
                for p in perms:
                    if p.get("Group") == "all":
                        findings.append(f"❌ Snapshot {snap_id} is PUBLIC (CreateVolumePermission: all).")
            except ClientError as e:
                findings.append(f"⚠ Could not read attributes for snapshot {snap_id}: {e}")

    return findings
