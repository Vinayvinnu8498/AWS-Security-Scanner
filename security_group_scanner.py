import boto3

DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
}

def scan_security_groups(region):
    findings = []
    ec2 = boto3.client("ec2")

    try:
        response = ec2.describe_security_groups()
    except Exception as e:
        findings.append(f"❌ Unable to describe security groups: {e}")
        return findings

    if not response.get("SecurityGroups"):
        findings.append("ℹ No security groups found in this region.")
        return findings

    for sg in response["SecurityGroups"]:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "Unnamed")

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")

                if cidr == "0.0.0.0/0":
                    if from_port in DANGEROUS_PORTS:
                        findings.append(
                            f"❌ Security Group '{sg_name}' ({sg_id}) exposes {DANGEROUS_PORTS[from_port]} "
                            f"port {from_port} to the world (0.0.0.0/0)."
                        )
                    else:
                        findings.append(
                            f"⚠ Security Group '{sg_name}' ({sg_id}) allows inbound access from 0.0.0.0/0 "
                            f"on port {from_port}."
                        )

            for ipv6_range in rule.get("Ipv6Ranges", []):
                cidr6 = ipv6_range.get("CidrIpv6")
                if cidr6 == "::/0":
                    findings.append(
                        f"⚠ Security Group '{sg_name}' ({sg_id}) allows inbound IPv6 access from ::/0 "
                        f"on port {from_port}."
                    )

    return findings
