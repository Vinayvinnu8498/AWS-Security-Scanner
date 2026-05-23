import boto3
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import datetime
import os

from config_loader import load_config
from logger import setup_logger
from html_report_generator import generate_html_report


# ---------------------------------------------------------
# JSON EXPORT (FIXED)
# ---------------------------------------------------------
def export_json(findings, summary, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.json")

    data = {
        "summary": summary,
        "findings": findings
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"JSON report saved to: {filename}")
    return filename


# ---------------------------------------------------------
# IMPORT SCANNERS
# ---------------------------------------------------------

# Core scanners
from s3_scanner import scan_s3
from s3_public_access_scanner import scan_s3_public_access
from iam_scanner import scan_iam
from ec2_scanner import scan_ec2
from cloudtrail_scanner import scan_cloudtrail
from securityhub_scanner import scan_security_hub

# Deep scanners
from security_group_scanner import scan_security_groups
from guardduty_scanner import scan_guardduty

# Optional scanners
from vpc_scanner import scan_vpc
from kms_scanner import scan_kms
from ebs_scanner import scan_ebs
from rds_scanner import scan_rds
from lambda_scanner import scan_lambda
from secrets_scanner import scan_secrets_manager
from dynamodb_scanner import scan_dynamodb
from sns_scanner import scan_sns
from sqs_scanner import scan_sqs
from cloudwatch_logs_scanner import scan_cloudwatch_logs

# New scanners
from ecr_scanner import scan as scan_ecr
from eventbridge_scanner import scan as scan_eventbridge
from config_scanner import scan_config
from cloudwatch_alarm_scanner import scan_cloudwatch_security_alarms

# ⭐ NEW — CIS 4.x scanner
from cis_4x_scanner import run_cis_4x_check


# ---------------------------------------------------------
# MODULE REGISTRY
# ---------------------------------------------------------

MODULE_FUNCTIONS = {
    "s3": scan_s3,
    "s3public": scan_s3_public_access,
    "iam": scan_iam,
    "ec2": scan_ec2,
    "cloudtrail": scan_cloudtrail,
    "securityhub": scan_security_hub,
    "securitygroups": scan_security_groups,
    "guardduty": scan_guardduty,
    "vpc": scan_vpc,
    "kms": scan_kms,
    "ebs": scan_ebs,
    "rds": scan_rds,
    "lambda": scan_lambda,
    "secretsmanager": scan_secrets_manager,
    "dynamodb": scan_dynamodb,
    "sns": scan_sns,
    "sqs": scan_sqs,
    "cloudwatchlogs": scan_cloudwatch_logs,
    "ecr": scan_ecr,
    "eventbridge": scan_eventbridge,
    "config": scan_config,
    "cloudwatchalarms": scan_cloudwatch_security_alarms,

    # ⭐ NEW MODULE
    "cis4x": run_cis_4x_check,
}

SERVICE_DISPLAY_NAMES = {
    "s3": "Amazon Simple Storage Service (S3)",
    "s3public": "Amazon S3 Public Access Analysis",
    "iam": "AWS Identity and Access Management (IAM)",
    "ec2": "Amazon Elastic Compute Cloud (EC2)",
    "cloudtrail": "AWS CloudTrail",
    "securityhub": "AWS Security Hub",
    "securitygroups": "Amazon EC2 Security Group Exposure Analysis",
    "guardduty": "Amazon GuardDuty Threat Detection",
    "vpc": "Amazon Virtual Private Cloud (VPC)",
    "kms": "AWS Key Management Service (KMS)",
    "ebs": "Amazon Elastic Block Store (EBS)",
    "rds": "Amazon Relational Database Service (RDS)",
    "lambda": "AWS Lambda",
    "secretsmanager": "AWS Secrets Manager",
    "dynamodb": "Amazon DynamoDB",
    "sns": "Amazon Simple Notification Service (SNS)",
    "sqs": "Amazon Simple Queue Service (SQS)",
    "cloudwatchlogs": "Amazon CloudWatch Logs",
    "ecr": "Amazon Elastic Container Registry (ECR)",
    "eventbridge": "Amazon EventBridge",
    "config": "AWS Config Recorder",
    "cloudwatchalarms": "CloudWatch Security Alarms",

    # ⭐ NEW MODULE
    "cis4x": "CIS Benchmark 4.x (Metric Filters + Alarms)",
}


# ---------------------------------------------------------
# SEVERITY + RISK SCORE
# ---------------------------------------------------------

def classify_severity(message):
    if "❌" in message or "CRITICAL" in message:
        return "CRITICAL"
    if "⚠" in message or "MEDIUM" in message:
        return "MEDIUM"
    if "✔" in message or "LOW" in message:
        return "LOW"
    return "INFO"


def calculate_risk_score(counts):
    score = 100
    score -= counts.get("CRITICAL", 0) * 5
    score -= counts.get("MEDIUM", 0) * 2
    score -= counts.get("LOW", 0) * 1
    return max(0, min(100, score))


def build_summary(all_findings, regions, logger):
    severity_counts = {"CRITICAL": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for category, items in all_findings.items():
        for region, msg in items:
            sev = classify_severity(msg)
            severity_counts[sev] += 1

    summary = {
        "regions_scanned": len(regions),
        "total_findings": sum(severity_counts.values()),
        "severity_counts": severity_counts,
        "risk_score": calculate_risk_score(severity_counts),
    }

    logger.info(f"Regions scanned: {summary['regions_scanned']}")
    logger.info(f"Total findings: {summary['total_findings']}")
    logger.info(f"Risk score: {summary['risk_score']}")

    return summary


# ---------------------------------------------------------
# CONSOLE OUTPUT
# ---------------------------------------------------------

def print_summary_dashboard(summary):
    print("\n==============================")
    print(" AWS Security Summary (All Regions)")
    print("==============================")
    print(f"Regions Scanned: {summary['regions_scanned']}")
    print(f"Total Findings: {summary['total_findings']}\n")

    print("Severity Breakdown:")
    for sev, count in summary["severity_counts"].items():
        print(f"  {sev}: {count}")
    print()

    print(f"Overall Risk Score: {summary['risk_score']}/100\n")


def print_grouped_findings(all_findings):
    print("\n==============================")
    print(" Detailed Findings (Grouped by Region)")
    print("==============================\n")

    for category, items in all_findings.items():
        print(f"{category} Findings:")

        region_map = defaultdict(list)
        for region, msg in items:
            region_map[region].append(msg)

        for region, messages in region_map.items():
            print(f"  {region}:")
            for m in messages:
                print(f"    - {m}")
            print()

        print()


# ---------------------------------------------------------
# SCANNER EXECUTION
# ---------------------------------------------------------

def run_module_for_region(module_name, region, logger):
    local_findings = defaultdict(list)

    if module_name not in MODULE_FUNCTIONS:
        logger.error(f"Module '{module_name}' enabled but no scanner exists.")
        return local_findings

    scanner_function = MODULE_FUNCTIONS[module_name]
    display_name = SERVICE_DISPLAY_NAMES.get(module_name, module_name.upper())

    try:
        logger.info(f"Running scanner: {module_name} in region: {region}")
        findings = scanner_function(region)
        for f in findings:
            local_findings[display_name].append((region, f))
    except Exception as e:
        logger.error(f"Error running {module_name} scanner in {region}: {e}")

    return local_findings


# ---------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------

def main():
    config = load_config("config.yaml")
    logger = setup_logger(config)

    regions = config.get_regions()
    enabled_modules = config.get_enabled_modules()

    print("Running AWS Security Scan across multiple regions...\n")

    all_findings = defaultdict(list)

    for region in regions:
        print(f"=== Scanning region: {region} ===")
        boto3.setup_default_session(region_name=region)

        modules_to_run = [m for m, enabled in enabled_modules.items() if enabled]
        max_workers = min(len(modules_to_run), 8) or 1

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(run_module_for_region, module_name, region, logger): module_name
                for module_name in modules_to_run
            }

            for future in as_completed(futures):
                local_findings = future.result()
                for category, items in local_findings.items():
                    all_findings[category].extend(items)

        print()

    summary = build_summary(all_findings, regions, logger)

    print_summary_dashboard(summary)
    print_grouped_findings(all_findings)

    # Prepare JSON structure
    json_ready = {}
    for category, items in all_findings.items():
        region_map = {}
        for region, msg in items:
            region_map.setdefault(region, []).append(msg)
        json_ready[category] = region_map

    export_json(json_ready, summary)
    generate_html_report(summary, json_ready)   # FIXED ORDER


if __name__ == "__main__":
    main()
