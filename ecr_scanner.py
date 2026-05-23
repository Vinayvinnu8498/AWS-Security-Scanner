import boto3
from botocore.exceptions import ClientError

def scan(region):
    findings = []
    ecr = boto3.client("ecr", region_name=region)

    # ---------------------------
    # 1. List repositories
    # ---------------------------
    repos = []
    next_token = None

    try:
        while True:
            if next_token:
                resp = ecr.describe_repositories(nextToken=next_token)
            else:
                resp = ecr.describe_repositories()

            repos.extend(resp.get("repositories", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break

    except ClientError as e:
        findings.append({
            "severity": "CRITICAL",
            "message": f"Unexpected ECR error: {e}",
            "resource": "ECR"
        })
        return findings

    if not repos:
        findings.append({
            "severity": "INFO",
            "message": "No ECR repositories found in this region.",
            "resource": "ECR"
        })
        return findings

    # ---------------------------
    # 2. Registry-level scanning config (only once)
    # ---------------------------
    try:
        scan_config = ecr.get_registry_scanning_configuration()
        registry_rules = scan_config.get("scanningConfiguration", {}).get("rules", [])
        registry_scan_enabled = len(registry_rules) > 0
    except ClientError:
        registry_scan_enabled = False

    # ---------------------------
    # 3. Per-repository checks
    # ---------------------------
    for repo in repos:
        name = repo.get("repositoryName")
        arn = repo.get("repositoryArn")

        # Encryption
        encryption = repo.get("encryptionConfiguration", {})
        if encryption.get("encryptionType") == "KMS":
            pass
        else:
            findings.append({
                "severity": "LOW",
                "message": f"ECR repository '{name}' is NOT encrypted with a customer-managed KMS key.",
                "resource": arn
            })

        # Scan on push
        if not registry_scan_enabled:
            findings.append({
                "severity": "MEDIUM",
                "message": f"ECR repository '{name}' does NOT have image scanning enabled (registry-level).",
                "resource": arn
            })

        # Lifecycle policy
        try:
            ecr.get_lifecycle_policy(repositoryName=name)
        except ClientError:
            findings.append({
                "severity": "LOW",
                "message": f"ECR repository '{name}' has NO lifecycle policy.",
                "resource": arn
            })

        # Public access check
        try:
            policy = ecr.get_repository_policy(repositoryName=name).get("policyText", "")
            if '"AWS":"*"' in policy or '"Principal":"*"' in policy:
                findings.append({
                    "severity": "CRITICAL",
                    "message": f"ECR repository '{name}' is PUBLIC.",
                    "resource": arn
                })
        except ClientError:
            pass  # No policy = private

    return findings
