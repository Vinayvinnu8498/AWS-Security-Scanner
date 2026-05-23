import boto3
from datetime import datetime, timezone

def scan_iam(region):
    findings = []

    iam = boto3.client("iam")

    # 1. Check password policy
    try:
        policy = iam.get_account_password_policy()
        findings.append("✔ IAM password policy is set.")
    except iam.exceptions.NoSuchEntityException:
        findings.append("❌ No IAM password policy is set.")

    # 2. Check root account MFA
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append("❌ Root account does NOT have MFA enabled.")
    else:
        findings.append("✔ Root account MFA is enabled.")

    # 3. Check IAM users
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]

        # 3a. Check MFA
        mfa = iam.list_mfa_devices(UserName=username)
        if len(mfa["MFADevices"]) == 0:
            findings.append(f"❌ User '{username}' does NOT have MFA enabled.")
        else:
            findings.append(f"✔ User '{username}' has MFA enabled.")

        # 3b. Check access keys
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            key_id = key["AccessKeyId"]
            created = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - created).days

            if age_days > 90:
                findings.append(
                    f"⚠️ Access key '{key_id}' for user '{username}' is older than 90 days."
                )

    return findings
