import boto3

def scan_ec2(region):
    findings = []

    ec2 = boto3.client("ec2")

    # 1. Describe all instances
    response = ec2.describe_instances()
    reservations = response.get("Reservations", [])

    if not reservations:
        findings.append("ℹ No EC2 instances found in this region.")
        return findings

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            state = instance.get("State", {}).get("Name", "unknown")
            public_ip = instance.get("PublicIpAddress")
            iam_profile = instance.get("IamInstanceProfile")
            metadata_options = instance.get("MetadataOptions", {})
            imdsv2_required = metadata_options.get("HttpTokens") == "required"

            # 1.1 Basic instance info
            findings.append(f"Instance {instance_id} is in state '{state}'.")

            # 1.2 Public IP check
            if public_ip:
                findings.append(f"⚠ Instance {instance_id} has a public IP: {public_ip}.")
            else:
                findings.append(f"✔ Instance {instance_id} has no public IP.")

            # 1.3 IAM role check
            if iam_profile:
                findings.append(f"✔ Instance {instance_id} has an IAM role attached.")
            else:
                findings.append(f"⚠ Instance {instance_id} does NOT have an IAM role attached.")

            # 1.4 IMDSv2 check
            if imdsv2_required:
                findings.append(f"✔ Instance {instance_id} enforces IMDSv2.")
            else:
                findings.append(f"⚠ Instance {instance_id} does NOT enforce IMDSv2.")

            # 1.5 Security groups + open ports
            for sg in instance.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")

                sg_details = ec2.describe_security_groups(GroupIds=[sg_id])
                for sg_info in sg_details.get("SecurityGroups", []):
                    for perm in sg_info.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        ip_ranges = perm.get("IpRanges", [])

                        for ip_range in ip_ranges:
                            cidr = ip_range.get("CidrIp")
                            if cidr == "0.0.0.0/0":
                                findings.append(
                                    f"❌ Security group {sg_name} ({sg_id}) for instance {instance_id} "
                                    f"allows 0.0.0.0/0 on ports {from_port}-{to_port}."
                                )

    return findings
