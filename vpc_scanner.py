import boto3

def scan_vpc():
    findings = []

    ec2 = boto3.client("ec2")

    # 1. Get all VPCs
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    if not vpcs:
        findings.append("ℹ No VPCs found in this region.")
        return findings

    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        findings.append(f"ℹ VPC found: {vpc_id}")

        # 2. Check for Internet Gateway
        igw_response = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )
        igws = igw_response.get("InternetGateways", [])

        if igws:
            findings.append(f"⚠ VPC {vpc_id} has an Internet Gateway attached.")
        else:
            findings.append(f"✔ VPC {vpc_id} has no Internet Gateway attached.")

        # 3. Subnets
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("Subnets", [])

        for subnet in subnets:
            subnet_id = subnet.get("SubnetId")
            public = subnet.get("MapPublicIpOnLaunch", False)

            if public:
                findings.append(f"⚠ Subnet {subnet_id} is PUBLIC (auto-assigns public IPs).")
            else:
                findings.append(f"✔ Subnet {subnet_id} is PRIVATE.")

        # 4. Route tables
        route_tables = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("RouteTables", [])

        for rt in route_tables:
            rt_id = rt.get("RouteTableId")
            for route in rt.get("Routes", []):
                if route.get("GatewayId", "").startswith("igw-"):
                    findings.append(
                        f"❌ Route table {rt_id} exposes traffic to the Internet Gateway."
                    )

        # 5. NACLs
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("NetworkAcls", [])

        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId")
            for entry in nacl.get("Entries", []):
                if entry.get("Egress") is False:  # inbound rules
                    for cidr in entry.get("CidrBlock", [] if isinstance(entry.get("CidrBlock"), list) else [entry.get("CidrBlock")]):
                        if cidr == "0.0.0.0/0" and entry.get("RuleAction") == "allow":
                            findings.append(
                                f"❌ NACL {nacl_id} allows inbound 0.0.0.0/0 (rule {entry.get('RuleNumber')})."
                            )

        # 6. VPC Flow Logs
        flow_logs = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        ).get("FlowLogs", [])

        if flow_logs:
            findings.append(f"✔ VPC {vpc_id} has Flow Logs enabled.")
        else:
            findings.append(f"⚠ VPC {vpc_id} does NOT have Flow Logs enabled.")

    return findings
